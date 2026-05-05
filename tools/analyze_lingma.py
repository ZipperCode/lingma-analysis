#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lingma.exe 签名函数分析工具
目标: Go 1.23 PE 64位, ImageBase = 0x140000000
"""

import struct
import sys
import re
from collections import defaultdict

EXE_PATH = "C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe"
IMAGE_BASE = 0x140000000

# ========== 简易 x86-64 反汇编器 ==========
# 我们使用 capstone 如果可用, 否则用简易实现

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_CALL
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

# ========== PE 解析 ==========

def read_file(path):
    with open(path, "rb") as f:
        return f.read()

def parse_pe(data):
    """解析 PE 文件头, 返回 sections 和关键信息"""
    # DOS Header
    assert data[0:2] == b"MZ"
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]

    # NT Headers
    assert data[e_lfanew:e_lfanew+4] == b"PE\x00\x00"
    off = e_lfanew + 4

    # COFF Header (20 bytes)
    machine, num_sections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, off)
    off += 20

    # Optional Header (PE32+)
    magic = struct.unpack_from("<H", data, off)[0]
    assert magic == 0x20b, f"Not PE32+: {hex(magic)}"
    image_base = struct.unpack_from("<Q", data, off + 24)[0]
    section_align = struct.unpack_from("<I", data, off + 32)[0]
    file_align = struct.unpack_from("<I", data, off + 36)[0]
    num_data_dirs = struct.unpack_from("<I", data, off + 112)[0]

    # Data directories
    dir_off = off + 116
    data_dirs = {}
    dir_names = ["Export", "Import", "Resource", "Exception", "Security",
                 "Relocation", "Debug", "Architecture", "GlobalPtr", "TLS",
                 "LoadConfig", "BoundImport", "IAT", "DelayImport", "COM"]
    for i in range(min(num_data_dirs, 15)):
        rva, size = struct.unpack_from("<II", data, dir_off + i*8)
        data_dirs[dir_names[i]] = (rva, size)

    # Sections
    sec_off = off + opt_size
    sections = []
    for i in range(num_sections):
        name = data[sec_off:sec_off+8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, vaddr, raw_size, raw_ptr, _, _, num_reloc, _, _ = \
            struct.unpack_from("<IIIIIHHI", data, sec_off + 8)
        sections.append({
            "name": name, "vaddr": vaddr, "vsize": vsize,
            "raw_ptr": raw_ptr, "raw_size": raw_size,
        })
        sec_off += 40

    return {
        "image_base": image_base,
        "sections": sections,
        "data_dirs": data_dirs,
    }

def rva_to_raw(rva, sections):
    for s in sections:
        if s["vaddr"] <= rva < s["vaddr"] + s["vsize"]:
            return rva - s["vaddr"] + s["raw_ptr"]
    return None

def read_bytes_at_rva(data, rva, size, sections):
    raw = rva_to_raw(rva, sections)
    if raw is None or raw + size > len(data):
        return None
    return data[raw:raw+size]

def parse_pdata(data, sections):
    """解析 .pdata 节获取函数边界"""
    for s in sections:
        if s["name"] == ".pdata":
            raw = data[s["raw_ptr"]:s["raw_ptr"]+s["raw_size"]]
            entries = {}
            num = len(raw) // 12
            for i in range(num):
                begin, end, unwind = struct.unpack_from("<III", raw, i*12)
                entries[begin] = (end, unwind)
            return entries
    return {}

# ========== 字符串扫描 ==========

def scan_strings(data, sections, min_len=6):
    """扫描所有 ASCII 和 UTF-16 字符串"""
    strings = {}
    text = read_bytes_at_rva(data, 0, len(data), sections)
    if text is None:
        return strings

    # ASCII strings
    current = b""
    offset = 0
    for i, byte in enumerate(text):
        if 0x20 <= byte < 0x7f:
            current += bytes([byte])
        else:
            if len(current) >= min_len:
                strings[i] = current.decode("ascii")
            current = b""
    if len(current) >= min_len:
        strings[len(text)] = current.decode("ascii")
    return strings

def find_string_refs(data, sections, target_str):
    """查找引用特定字符串的所有位置"""
    refs = []
    text_sec = None
    for s in sections:
        if s["name"] == ".text":
            text_sec = s
            break
    if text_sec is None:
        return refs

    text_data = data[text_sec["raw_ptr"]:text_sec["raw_ptr"]+text_sec["raw_size"]]

    # Go binaries use a technique where strings are stored in .rodata
    # and referenced via RIP-relative LEA instructions
    for sec in sections:
        if sec["name"] in (".rodata", ".rdata", ".text"):
            sec_data = data[sec["raw_ptr"]:sec["raw_ptr"]+sec["raw_size"]]
            idx = 0
            while True:
                idx = sec_data.find(target_str.encode(), idx)
                if idx == -1:
                    break
                rva = sec["vaddr"] + idx
                refs.append((rva, sec["name"]))
                idx += len(target_str)
    return refs

# ========== Go 特定分析 ==========

def get_go_string_at_rva(data, rva, sections):
    """在 Go 二进制中, 字符串通常是 (ptr, len) 对"""
    raw = rva_to_raw(rva, sections)
    if raw is None:
        return None
    # Go string: 8-byte pointer + 8-byte length
    ptr, length = struct.unpack_from("<QQ", data, raw)
    if ptr < 0x1000 or ptr > 0x140000000 + 0x10000000:
        # Try as direct string pointer
        ptr_raw = rva_to_raw(ptr - IMAGE_BASE, sections) if ptr >= IMAGE_BASE else None
        if ptr_raw is None:
            return None
        try:
            return data[ptr_raw:ptr_raw+length].decode("utf-8", errors="replace")
        except:
            return None
    return None

# ========== 反汇编 ==========

def disassemble_function(data, rva, func_end, sections, cs=None):
    """反汇编一个函数"""
    text_sec = None
    for s in sections:
        if s["name"] == ".text":
            text_sec = s
            break

    func_size = func_end - rva
    if func_size <= 0 or func_size > 0x10000:
        return None

    func_data = read_bytes_at_rva(data, rva, func_size, sections)
    if func_data is None:
        return None

    instructions = []

    if cs is not None:
        for insn in cs.disasm(func_data, rva):
            instructions.append({
                "address": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "size": insn.size,
                "bytes": insn.bytes,
            })
    else:
        # 简易反汇编 - 仅支持关键指令
        instructions = simple_disasm(func_data, rva)

    return instructions

def simple_disasm(code, base_rva):
    """简易 x86-64 反汇编器, 支持关键指令模式"""
    instructions = []
    i = 0
    while i < len(code):
        addr = base_rva + i
        b = code[i]

        # REX prefix
        rex = 0
        if 0x40 <= b <= 0x4F:
            rex = b
            i += 1
            if i >= len(code):
                break
            b = code[i]

        # Common opcodes
        if b == 0x48 and i+1 < len(code) and code[i+1] == 0x8D:
            # LEA R64, [RIP+disp32]
            if i+6 < len(code):
                modrm = code[i+2]
                if modrm == 0x05:  # [RIP+disp32]
                    disp = struct.unpack_from("<i", code, i+3)[0]
                    target = addr + 7 + disp
                    instructions.append({
                        "address": addr, "mnemonic": "lea",
                        "op_str": f"r64, [rip+{disp:#x}] => {hex(target)}",
                        "size": 7, "rip_ref": target,
                    })
                    i += 7
                    continue

        elif b == 0x48 and i+1 < len(code) and code[i+1] == 0x8B:
            # MOV R64, [RIP+disp32]
            if i+6 < len(code):
                modrm = code[i+2]
                if modrm == 0x05:
                    disp = struct.unpack_from("<i", code, i+3)[0]
                    target = addr + 7 + disp
                    instructions.append({
                        "address": addr, "mnemonic": "mov",
                        "op_str": f"r64, qword ptr [rip+{disp:#x}] => {hex(target)}",
                        "size": 7, "rip_ref": target,
                    })
                    i += 7
                    continue

        elif b == 0xE8:
            # CALL rel32
            if i+4 < len(code):
                rel = struct.unpack_from("<i", code, i+1)[0]
                target = addr + 5 + rel
                instructions.append({
                    "address": addr, "mnemonic": "call",
                    "op_str": f"{hex(target)}",
                    "size": 5, "call_target": target,
                })
                i += 5
                continue

        elif b == 0xE9:
            # JMP rel32
            if i+4 < len(code):
                rel = struct.unpack_from("<i", code, i+1)[0]
                target = addr + 5 + rel
                instructions.append({
                    "address": addr, "mnemonic": "jmp",
                    "op_str": f"{hex(target)}",
                    "size": 5, "jmp_target": target,
                })
                i += 5
                continue

        elif b == 0xEB:
            # JMP rel8
            rel = struct.unpack_from("<b", code, i+1)[0]
            target = addr + 2 + rel
            instructions.append({
                "address": addr, "mnemonic": "jmp",
                "op_str": f"short {hex(target)}",
                "size": 2,
            })
            i += 2
            continue

        elif b in (0x74, 0x75, 0x7C, 0x7F, 0x7D, 0x7E, 0x76, 0x77, 0x72, 0x73):
            # Jcc rel8
            rel = struct.unpack_from("<b", code, i+1)[0]
            target = addr + 2 + rel
            jcc_names = {0x74:"je",0x75:"jne",0x7c:"jl",0x7f:"jge",0x7d:"jge",0x7e:"jle",0x76:"jbe",0x77:"ja",0x72:"jb",0x73:"jae"}
            instructions.append({
                "address": addr, "mnemonic": jcc_names.get(b, f"jcc_{b:#x}"),
                "op_str": f"short {hex(target)}",
                "size": 2,
            })
            i += 2
            continue

        elif b == 0x0F and i+1 < len(code):
            b2 = code[i+1]
            if 0x80 <= b2 <= 0x8F:
                # Jcc rel32
                if i+5 < len(code):
                    rel = struct.unpack_from("<i", code, i+2)[0]
                    target = addr + 6 + rel
                    jcc32 = {0x84:"je",0x85:"jne",0x8C:"jl",0x8F:"jge",0x8E:"jle",0x86:"jbe",0x87:"ja"}
                    instructions.append({
                        "address": addr, "mnemonic": jcc32.get(b2, f"jcc_{b2:#x}"),
                        "op_str": f"{hex(target)}",
                        "size": 6,
                    })
                    i += 6
                    continue

        elif b == 0xC3:
            instructions.append({
                "address": addr, "mnemonic": "ret", "op_str": "",
                "size": 1,
            })
            i += 1
            continue

        elif b == 0x48 and i+1 < len(code) and code[i+1] == 0xC7:
            # MOV R64, imm32
            if i+10 < len(code) and code[i+2] == 0xC0:
                imm = struct.unpack_from("<I", code, i+3)[0]
                instructions.append({
                    "address": addr, "mnemonic": "mov",
                    "op_str": f"r64, {imm:#x}",
                    "size": 10,
                })
                i += 10
                continue

        elif b == 0x55:
            instructions.append({"address": addr, "mnemonic": "push", "op_str": "rbp", "size": 1})
            i += 1; continue
        elif b == 0x48 and i+1 < len(code) and code[i+1] == 0x89:
            instructions.append({"address": addr, "mnemonic": "mov", "op_str": "r64, r64", "size": 3})
            i += 3; continue
        elif b == 0x5D:
            instructions.append({"address": addr, "mnemonic": "pop", "op_str": "rbp", "size": 1})
            i += 1; continue
        elif b == 0x41 and i+1 < len(code) and code[i+1] == 0xFF:
            if i+2 < len(code) and code[i+2] == 0xD0:
                instructions.append({"address": addr, "mnemonic": "call", "op_str": "r10", "size": 3})
                i += 3; continue

        # Fallback: skip byte
        instructions.append({
            "address": addr, "mnemonic": f"db",
            "op_str": f"{b:#04x}", "size": 1,
        })
        i += 1

    return instructions

def print_disassembly(name, rva, func_end, data, sections, cs=None):
    """打印函数反汇编"""
    instructions = disassemble_function(data, rva, func_end, sections, cs)
    if instructions is None:
        print(f"  [!] 无法反汇编 {name} (RVA {hex(rva)})")
        return

    print(f"\n{'='*80}")
    print(f"  函数: {name}")
    print(f"  RVA: {hex(rva)}  边界: {hex(rva)} - {hex(func_end)}  大小: {func_end - rva} 字节")
    print(f"  指令数: {len(instructions)}")
    print(f"{'='*80}")

    call_targets = []
    rip_refs = []
    string_refs = []

    for insn in instructions:
        addr = insn["address"]
        mnem = insn["mnemonic"]
        op = insn.get("op_str", "")

        if mnem == "call":
            target = insn.get("call_target", None)
            if target is not None:
                call_targets.append((addr, target))

        if "rip_ref" in insn:
            rip_refs.append((addr, insn["rip_ref"]))

        # 打印格式化的指令
        print(f"  {hex(addr):10s}  {mnem:8s} {op}")

    print(f"\n  --- CALL 目标 ---")
    for addr, target in call_targets:
        print(f"    {hex(addr)} -> CALL {hex(target)}")

    if rip_refs:
        print(f"\n  --- RIP 相对引用 ---")
        for addr, target in rip_refs:
            # 尝试解析目标为字符串
            raw = rva_to_raw(target, sections)
            if raw is not None:
                try:
                    s = data[raw:raw+64]
                    printable = s.split(b"\x00")[0].decode("ascii", errors="replace")
                    if all(0x20 <= c < 0x7f for c in printable) and len(printable) >= 3:
                        print(f"    {hex(addr)} -> {hex(target)}  \"{printable}\"")
                    else:
                        # 尝试 UTF-16
                        try:
                            s16 = data[raw:raw+64]
                            decoded = s16.decode("utf-16-le", errors="replace").split("\x00")[0]
                            if len(decoded) >= 2:
                                print(f"    {hex(addr)} -> {hex(target)}  UTF16: \"{decoded}\"")
                            else:
                                print(f"    {hex(addr)} -> {hex(target)}  (data)")
                        except:
                            print(f"    {hex(addr)} -> {hex(target)}  (data)")
                except:
                    print(f"    {hex(addr)} -> {hex(target)}  (data)")
            else:
                print(f"    {hex(addr)} -> {hex(target)}  (outside sections)")

    return instructions

def search_binary_strings(data, sections, keywords):
    """在二进制中搜索特定字符串"""
    print(f"\n{'='*80}")
    print("  字符串引用搜索")
    print(f"{'='*80}")

    for kw in keywords:
        refs = find_string_refs(data, sections, kw)
        if refs:
            print(f"\n  [{kw}] 找到 {len(refs)} 个引用:")
            for rva, sec in refs[:20]:
                print(f"    RVA={hex(rva)}  Section={sec}")
        else:
            print(f"\n  [{kw}] 未找到引用")

def analyze_cross_refs(data, sections, pdata, cs=None):
    """分析目标函数的交叉引用"""
    targets = {
        0x882e40: "ExtractConfig_FormatTimestamp",
        0x884080: "ValidateFlags",
        0x885620: "ProcessSliceData",
        0x8840e0: "AddAuthHeaders",
    }

    for rva, name in targets.items():
        if rva in pdata:
            func_end, _ = pdata[rva]
            print_disassembly(name, rva, func_end, data, sections, cs)
        else:
            print(f"\n  [!] {name} (RVA {hex(rva)}) 不在 .pdata 中, 尝试估算边界...")
            # 尝试在附近找 RET
            est_end = rva + 0x500  # 估算
            print_disassembly(name, rva, est_end, data, sections, cs)

def find_getAppSalt_refs(data, sections, cs=None):
    """查找 getAppSalt 相关调用"""
    print(f"\n{'='*80}")
    print("  getAppSalt / Map 提取分析")
    print(f"{'='*80}")

    # 搜索 "AppSalt", "salt", "getAppSalt" 等
    for kw in ["AppSalt", "getAppSalt", "salt", "secret", "key"]:
        raw_idx = 0
        text_sec = None
        for s in sections:
            if s["name"] in (".rodata", ".rdata", ".gopclntab"):
                sec_data = data[s["raw_ptr"]:s["raw_ptr"]+s["raw_size"]]
                idx = 0
                found = []
                while True:
                    idx = sec_data.find(kw.encode(), idx)
                    if idx == -1:
                        break
                    found.append(s["vaddr"] + idx)
                    idx += len(kw)
                if found:
                    print(f"\n  '{kw}' 在 {s['name']} 中找到 {len(found)} 次:")
                    for rva in found[:10]:
                        print(f"    RVA={hex(rva)}")

def analyze_0xb11200(data, sections, pdata):
    """分析 0xb11200 函数"""
    print(f"\n{'='*80}")
    print("  分析 0xb11200 (被 AddAuthHeaders 调用的最终函数)")
    print(f"{'='*80}")

    if 0xb11200 in pdata:
        func_end, _ = pdata[0xb11200]
        print_disassembly("FinalHandler_0xb11200", 0xb11200, func_end, data, sections)
    else:
        print(f"  0xb11200 不在 .pdata 中")
        # 在 .pdata 中找最近的
        sorted_pdata = sorted(pdata.keys())
        for rva in sorted_pdata:
            if rva > 0xb11200:
                # 可能是这个
                print(f"  最近的 .pdata entry: {hex(rva)} -> {hex(pdata[rva][0])}")
                print_disassembly("NearbyFunc", rva, pdata[rva][0], data, sections)
                break

def main():
    print(f"[*] 读取: {EXE_PATH}")
    data = read_file(EXE_PATH)
    print(f"[+] 文件大小: {len(data)} bytes ({len(data)/1024/1024:.1f} MB)")

    print("\n[*] 解析 PE 结构...")
    pe = parse_pe(data)
    sections = pe["sections"]

    print(f"\n[*] ImageBase: {hex(pe['image_base'])}")
    print(f"[*] Sections:")
    for s in sections:
        print(f"    {s['name']:15s} RVA={hex(s['vaddr']):12s} Size={hex(s['vsize']):10s} Raw={hex(s['raw_ptr']):10s}")

    # 找 .text
    text_sec = None
    for s in sections:
        if s["name"] == ".text":
            text_sec = s
            break
    if text_sec:
        print(f"\n[+] .text: RVA={hex(text_sec['vaddr'])} RawOffset={hex(text_sec['raw_ptr'])} Size={hex(text_sec['vsize'])}")

    # 解析 .pdata
    print("\n[*] 解析 .pdata...")
    pdata = parse_pdata(data, sections)
    print(f"[+] .pdata entries: {len(pdata)}")

    # 初始化 capstone
    cs = None
    if HAS_CAPSTONE:
        cs = Cs(CS_ARCH_X86, CS_MODE_64)
        cs.detail = False
        print("[+] Capstone 可用")
    else:
        print("[-] Capstone 不可用, 使用简易反汇编器")
        print("    建议: pip install capstone")

    # 分析目标函数
    analyze_cross_refs(data, sections, pdata, cs)

    # 搜索关键字符串
    search_binary_strings(data, sections, [
        "Authorization", "X-", "hmac", "sha256", "hash",
        "app_id", "app_secret", "timestamp", "nonce", "sign",
    ])

    # getAppSalt 分析
    find_getAppSalt_refs(data, sections, cs)

    # 分析 0xb11200
    analyze_0xb11200(data, sections, pdata)

    print("\n[*] 分析完成")

if __name__ == "__main__":
    main()
