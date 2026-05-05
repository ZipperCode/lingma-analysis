#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lingma.exe 签名函数深度分析
完整的 x86-64 反汇编 + Go 运行时分析 + 字符串追踪

用法: python analyze_full.py
依赖: pip install capstone
"""

import struct
import sys
import json
from collections import defaultdict, OrderedDict

EXE_PATH = "C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe"
IMAGE_BASE = 0x140000000

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_CALL
    HAS_CAPSTONE = True
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
except ImportError:
    HAS_CAPSTONE = False
    print("[!] Capstone not available. Install with: pip install capstone")
    sys.exit(1)

# ============================================================
# PE 解析
# ============================================================

class PE:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.raw = f.read()
        self.size = len(self.raw)
        self._parse()

    def _parse(self):
        # DOS
        assert self.raw[0:2] == b"MZ"
        e_lfanew = struct.unpack_from("<I", self.raw, 0x3C)[0]
        assert self.raw[e_lfanew:e_lfanew+4] == b"PE\x00\x00"

        off = e_lfanew + 4
        machine, num_sections, _, _, _, opt_size, _ = \
            struct.unpack_from("<HHIIIHH", self.raw, off)
        off += 20

        magic = struct.unpack_from("<H", self.raw, off)[0]
        assert magic == 0x20b
        self.image_base = struct.unpack_from("<Q", self.raw, off + 24)[0]
        self.section_align = struct.unpack_from("<I", self.raw, off + 32)[0]
        self.file_align = struct.unpack_from("<I", self.raw, off + 36)[0]
        num_dirs = struct.unpack_from("<I", self.raw, off + 112)[0]

        # Data directories
        self.data_dirs = {}
        dir_names = ["Export", "Import", "Resource", "Exception", "Security",
                     "Relocation", "Debug", "Architecture", "GlobalPtr", "TLS",
                     "LoadConfig", "BoundImport", "IAT", "DelayImport", "COM"]
        doff = off + 116
        for i in range(min(num_dirs, 15)):
            rva, sz = struct.unpack_from("<II", self.raw, doff + i*8)
            self.data_dirs[dir_names[i]] = (rva, sz)

        # Sections
        soff = off + opt_size
        self.sections = []
        for i in range(num_sections):
            name = self.raw[soff:soff+8].rstrip(b"\x00").decode("ascii", errors="replace")
            vsize, vaddr, rawsz, rawptr, _, _, nr, _, _ = \
                struct.unpack_from("<IIIIIHHI", self.raw, soff + 8)
            self.sections.append({
                "name": name, "vaddr": vaddr, "vsize": vsize,
                "raw_ptr": rawptr, "raw_size": rawsz,
                "chars": struct.unpack_from("<I", self.raw, soff + 36)[0],
            })
            soff += 40

    def rva_to_raw(self, rva):
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["raw_size"]):
                return rva - s["vaddr"] + s["raw_ptr"]
        return None

    def read_rva(self, rva, size):
        raw = self.rva_to_raw(rva)
        if raw is None:
            return None
        end = raw + size
        if end > len(self.raw):
            return self.raw[raw:]
        return self.raw[raw:end]

    def read_string_at_rva(self, rva, max_len=256):
        """读取 C 风格字符串"""
        raw = self.rva_to_raw(rva)
        if raw is None:
            return None
        data = self.raw[raw:raw+max_len]
        if b"\x00" in data:
            data = data[:data.index(b"\x00")]
        try:
            return data.decode("ascii")
        except:
            return None

    def read_go_string(self, rva):
        """读取 Go string (ptr, len) 对"""
        raw = self.rva_to_raw(rva)
        if raw is None:
            return None
        try:
            ptr, length = struct.unpack_from("<QQ", self.raw, raw)
        except:
            return None
        if ptr == 0 or length == 0:
            return None, 0
        ptr_raw = self.rva_to_raw(ptr - self.image_base) if ptr >= self.image_base else None
        if ptr_raw is None:
            return None, length
        try:
            s = self.raw[ptr_raw:ptr_raw+length]
            return s.decode("utf-8", errors="replace"), length
        except:
            return None, length

    def get_section_by_rva(self, rva):
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["raw_size"]):
                return s["name"]
        return None

    def get_section_data(self, name):
        for s in self.sections:
            if s["name"] == name:
                return self.raw[s["raw_ptr"]:s["raw_ptr"]+s["raw_size"]]
        return None


class PDataTable:
    """解析 .pdata 获取函数边界"""
    def __init__(self, pe):
        self.entries = {}
        self.sorted_begins = []
        pdata = pe.get_section_data(".pdata")
        if pdata is None:
            return
        num = len(pdata) // 12
        for i in range(num):
            begin, end, unwind = struct.unpack_from("<III", pdata, i*12)
            self.entries[begin] = {"end": end, "unwind": unwind}
        self.sorted_begins = sorted(self.entries.keys())

    def get_function_end(self, rva):
        return self.entries.get(rva, {}).get("end", None)

    def find_function_containing(self, rva):
        """找到包含给定 RVA 的函数"""
        for i, begin in enumerate(self.sorted_begins):
            end = self.entries[begin]["end"]
            if begin <= rva < end:
                return begin, end
        return None, None

    def estimate_function_end(self, rva, max_scan=0x2000):
        """如果不在 .pdata 中, 扫描寻找 RET"""
        pe = None  # 需要传入
        # 尝试从 .pdata 找最近的函数
        for begin in self.sorted_begins:
            if begin > rva:
                return begin  # 下一个函数开始作为当前函数结束
        return rva + 0x500  # 兜底


# ============================================================
# 反汇编引擎
# ============================================================

class Disassembler:
    def __init__(self, pe):
        self.pe = pe
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True

    def disasm_range(self, rva, size):
        code = self.pe.read_rva(rva, size)
        if code is None:
            return []
        return list(self.cs.disasm(code, rva))

    def disasm_function(self, rva, end_rva):
        size = end_rva - rva
        if size <= 0 or size > 0x20000:
            return []
        return self.disasm_range(rva, size)

    def analyze_function(self, rva, end_rva, name=""):
        """深度分析函数"""
        insns = self.disasm_function(rva, end_rva)
        result = {
            "name": name,
            "rva": rva,
            "end_rva": end_rva,
            "size": end_rva - rva,
            "num_instructions": len(insns),
            "instructions": [],
            "calls": [],
            "jmps": [],
            "rip_refs": [],
            "string_refs": [],
            "data_refs": [],
            "stack_ops": [],
        }

        for insn in insns:
            entry = {
                "addr": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "size": insn.size,
            }

            # CALL
            if insn.group(CS_GRP_CALL):
                # 解析调用目标
                if len(insn.bytes) >= 5 and insn.bytes[0] == 0xE8:
                    rel = struct.unpack("<i", insn.bytes[1:5])[0]
                    target = insn.address + 5 + rel
                    result["calls"].append({
                        "addr": insn.address,
                        "target": target,
                    })
                    entry["call_target"] = target

            # JMP
            if insn.group(CS_GRP_JUMP):
                if insn.bytes[0] in (0xEB,):  # rel8
                    rel = struct.unpack("<b", insn.bytes[1:2])[0]
                    target = insn.address + 2 + rel
                    entry["jmp_target"] = target
                elif insn.bytes[0] == 0xE9:  # rel32
                    rel = struct.unpack("<i", insn.bytes[1:5])[0]
                    target = insn.address + 5 + rel
                    entry["jmp_target"] = target
                elif len(insn.bytes) >= 2 and insn.bytes[0] == 0x0F and 0x80 <= insn.bytes[1] <= 0x8F:
                    rel = struct.unpack("<i", insn.bytes[2:6])[0]
                    target = insn.address + 6 + rel
                    entry["jmp_target"] = target
                else:
                    # 尝试从 op_str 解析
                    if insn.op_str.startswith("0x"):
                        try:
                            entry["jmp_target"] = int(insn.op_str.split(",")[-1].strip(), 16)
                        except:
                            pass
                result["jmps"].append(entry)

            # RIP-relative references
            rip_ref = self._extract_rip_ref(insn)
            if rip_ref:
                result["rip_refs"].append({
                    "addr": insn.address,
                    "target": rip_ref["target"],
                    "type": rip_ref["type"],
                })
                # 尝试解析为字符串
                sec_name = self.pe.get_section_by_rva(rip_ref["target"])
                if sec_name in (".rodata", ".rdata", ".data"):
                    s = self.pe.read_string_at_rva(rip_ref["target"])
                    if s and len(s) >= 3 and all(0x20 <= ord(c) < 0x7f for c in s):
                        result["string_refs"].append({
                            "addr": insn.address,
                            "target": rip_ref["target"],
                            "string": s,
                        })

            result["instructions"].append(entry)

        return result

    def _extract_rip_ref(self, insn):
        """提取 RIP 相对引用的目标地址"""
        # 检查操作数
        try:
            for op in insn.operands:
                if op.type == 1:  # X86_OP_MEM
                    if op.value.mem.base == 0 and op.value.mem.index == 0:
                        # [disp32] - 不太可能
                        pass
                    if op.value.mem.base == 5:  # RIP = register 5 in capstone
                        # [rip + disp]
                        target = insn.address + insn.size + op.value.mem.disp
                        # 确定指令类型
                        if insn.mnemonic == "lea":
                            return {"target": target, "type": "lea"}
                        elif insn.mnemonic == "mov":
                            return {"target": target, "type": "mov"}
                        elif insn.mnemonic == "cmp":
                            return {"target": target, "type": "cmp"}
                        else:
                            return {"target": target, "type": insn.mnemonic}
        except:
            pass
        return None


# ============================================================
# 字符串搜索
# ============================================================

def search_strings_in_sections(pe, keywords):
    """在 PE 的多个 section 中搜索字符串"""
    results = defaultdict(list)
    search_sections = [".rodata", ".rdata", ".data", ".text"]

    for sec in pe.sections:
        if sec["name"] not in search_sections:
            continue
        sec_data = pe.raw[sec["raw_ptr"]:sec["raw_ptr"]+sec["raw_size"]]
        for kw in keywords:
            kw_bytes = kw.encode("utf-8")
            idx = 0
            while True:
                idx = sec_data.find(kw_bytes, idx)
                if idx == -1:
                    break
                rva = sec["vaddr"] + idx
                # 提取上下文
                start = max(0, idx - 20)
                end = min(len(sec_data), idx + len(kw_bytes) + 50)
                context = sec_data[start:end]
                try:
                    context_str = context.decode("ascii", errors="replace")
                except:
                    context_str = repr(context)
                results[kw].append({
                    "rva": rva,
                    "section": sec["name"],
                    "context": context_str,
                })
                idx += 1
    return results


# ============================================================
# 主分析流程
# ============================================================

def format_hex(val):
    return f"0x{val:x}"

def analyze_calls(func_result, pdata, all_func_results):
    """分析函数调用链"""
    print(f"\n  --- 调用目标分析 ({len(func_result['calls'])} 个调用) ---")
    for call in func_result["calls"]:
        addr = call["addr"]
        target = call["target"]
        # 检查是否在已知函数中
        known = all_func_results.get(target)
        if known:
            print(f"    {format_hex(addr)} -> CALL {format_hex(target)} [{known['name']}]")
        elif target in pdata.entries:
            print(f"    {format_hex(addr)} -> CALL {format_hex(target)} [func, size={pdata.entries[target]['end']-target}]")
        else:
            sec = pe.get_section_by_rva(target)
            if sec:
                print(f"    {format_hex(addr)} -> CALL {format_hex(target)} (in {sec})")
            else:
                print(f"    {format_hex(addr)} -> CALL {format_hex(target)} (unknown)")

def analyze_rip_refs(func_result):
    """分析 RIP 相对引用"""
    if not func_result["rip_refs"]:
        return

    print(f"\n  --- RIP 引用 ({len(func_result['rip_refs'])} 个) ---")
    for ref in func_result["rip_refs"]:
        addr = ref["addr"]
        target = ref["target"]
        ref_type = ref["type"]
        sec = pe.get_section_by_rva(target)

        # 尝试读取字符串
        s = pe.read_string_at_rva(target, 128)
        if s and len(s) >= 3 and all(0x20 <= ord(c) < 0x7f for c in s):
            print(f"    {format_hex(addr)} [{ref_type:4s}] -> {format_hex(target)} ({sec})  \"{s}\"")
        else:
            # 尝试读取 16 字节数据
            raw = pe.read_rva(target, 16)
            if raw:
                hex_str = " ".join(f"{b:02x}" for b in raw)
                print(f"    {format_hex(addr)} [{ref_type:4s}] -> {format_hex(target)} ({sec})  [{hex_str}]")
            else:
                print(f"    {format_hex(addr)} [{ref_type:4s}] -> {format_hex(target)} ({sec})")

def analyze_strings(func_result):
    """分析字符串引用"""
    if not func_result["string_refs"]:
        return
    print(f"\n  --- 字符串引用 ({len(func_result['string_refs'])} 个) ---")
    for sr in func_result["string_refs"]:
        print(f"    {format_hex(sr['addr'])} -> {format_hex(sr['target'])}  \"{sr['string']}\"")


def print_full_disassembly(func_result):
    """打印完整反汇编"""
    name = func_result["name"]
    rva = func_result["rva"]
    end = func_result["end_rva"]
    insns = func_result["instructions"]

    print(f"\n{'='*90}")
    print(f"  函数: {name}")
    print(f"  RVA: {format_hex(rva)}  End: {format_hex(end)}  Size: {func_result['size']} 字节")
    print(f"  指令数: {func_result['num_instructions']}")
    print(f"{'='*90}")

    # 按地址分组打印
    for entry in insns:
        addr = format_hex(entry["addr"])
        mnem = entry["mnemonic"]
        op = entry["op_str"]

        # 高亮 CALL
        if "call_target" in entry:
            target = entry["call_target"]
            print(f"  {addr}  {mnem:10s} {op:30s}  --> CALL {format_hex(target)}")
        elif "jmp_target" in entry:
            target = entry["jmp_target"]
            print(f"  {addr}  {mnem:10s} {op:30s}  --> JMP  {format_hex(target)}")
        else:
            print(f"  {addr}  {mnem:10s} {op}")


# ============================================================
# 运行
# ============================================================

print("[*] 加载 PE 文件...")
pe = PE(EXE_PATH)
print(f"[+] 文件大小: {pe.size} bytes ({pe.size/1024/1024:.1f} MB)")
print(f"[+] ImageBase: {format_hex(pe.image_base)}")
print(f"[+] Sections:")
for s in pe.sections:
    print(f"    {s['name']:15s} RVA={format_hex(s['vaddr']):12s} VSize={format_hex(s['vsize']):10s} Raw={format_hex(s['raw_ptr']):10s}")

pdata = PDataTable(pe)
print(f"\n[+] .pdata entries: {len(pdata.entries)}")

# 查找 .text 信息
text_sec = None
for s in pe.sections:
    if s["name"] == ".text":
        text_sec = s
        break
if text_sec:
    print(f"\n[*] .text section:")
    print(f"    RVA:      {format_hex(text_sec['vaddr'])}")
    print(f"    RawOffset:{format_hex(text_sec['raw_ptr'])}")
    print(f"    Size:     {format_hex(text_sec['vsize'])}")
    print(f"    偏移量:   {format_hex(text_sec['vaddr'] - text_sec['raw_ptr'])}")

# 目标函数
targets = {
    0x882e40: "ExtractConfig_FormatTimestamp",
    0x884080: "ValidateFlags",
    0x885620: "ProcessSliceData",
    0x8840e0: "AddAuthHeaders",
}

# 也分析 Caller 和 Main Signing
extra_targets = {
    0x880da0: "Caller_MainSigning",
    0x8821e0: "MainSigning",
}

all_targets = {**extra_targets, **targets}

# 额外分析 0xb11200
analysis_targets = {**all_targets, 0xb11200: "FinalHandler"}

disasm = Disassembler(pe)

# 先收集所有函数的结果用于交叉引用
all_func_results = {}

for rva, name in analysis_targets.items():
    end = pdata.get_function_end(rva)
    if end is None:
        # 在 .pdata 中找最近的下一个函数作为边界
        for begin in pdata.sorted_begins:
            if begin > rva:
                end = begin
                break
        if end is None:
            end = rva + 0x1000
        print(f"  [*] {name} ({format_hex(rva)}): 不在.pdata中, 估算边界={format_hex(end)}")

    result = disasm.analyze_function(rva, end, name)
    if result:
        all_func_results[rva] = result

# 打印每个函数的完整分析
print(f"\n{'#'*90}")
print("# 第一部分: PE 结构信息")
print(f"{'#'*90}")

for rva, name in analysis_targets.items():
    if rva in all_func_results:
        print_full_disassembly(all_func_results[rva])
        analyze_calls(all_func_results[rva], pdata, all_func_results)
        analyze_rip_refs(all_func_results[rva])
        analyze_strings(all_func_results[rva])

# ============================================================
# 字符串搜索
# ============================================================

print(f"\n{'#'*90}")
print("# 第二部分: 关键字符串搜索")
print(f"{'#'*90}")

keywords = [
    "Authorization", "X-", "hmac", "sha256", "hash",
    "app_id", "app_secret", "timestamp", "nonce", "sign",
    "Content-Type", "X-Request-Id", "X-Signature",
    "Bearer", "Digest", "AWS4",
    "access_key", "secret_key",
    "app_salt", "AppSalt", "getAppSalt",
    "ak_", "sk_",
]

str_results = search_strings_in_sections(pe, keywords)
for kw, refs in str_results.items():
    if refs:
        print(f"\n  [{kw}] 找到 {len(refs)} 个引用:")
        for ref in refs[:15]:
            ctx = ref["context"][:100].replace("\n", "\\n")
            print(f"    RVA={format_hex(ref['rva'])}  Sec={ref['section']}  ...{ctx}...")

# ============================================================
# 交叉引用分析
# ============================================================

print(f"\n{'#'*90}")
print("# 第三部分: 调用链分析")
print(f"{'#'*90}")

print(f"\n  调用链:")
print(f"  Caller (0x880da0)")
print(f"    -> MainSigning (0x8821e0)")

if 0x8821e0 in all_func_results:
    for call in all_func_results[0x8821e0]["calls"]:
        target = call["target"]
        name = targets.get(target, f"func_{format_hex(target)}")
        print(f"      -> {name} ({format_hex(target)})")

# 分析 0x8840e0 调用了什么
if 0x8840e0 in all_func_results:
    print(f"\n  0x8840e0 (AddAuthHeaders) 的调用:")
    for call in all_func_results[0x8840e0]["calls"]:
        target = call["target"]
        name = targets.get(target, analysis_targets.get(target, f"func_{format_hex(target)}"))
        print(f"    {format_hex(call['addr'])} -> CALL {format_hex(target)} [{name}]")
        if target == 0xb11200:
            print(f"      *** 0xb11200 是最终处理函数 ***")

# 分析 0x882e40
if 0x882e40 in all_func_results:
    print(f"\n  0x882e40 (ExtractConfig_FormatTimestamp) 的分析:")
    for sr in all_func_results[0x882e40]["string_refs"]:
        print(f"    字符串: \"{sr['string']}\" at {format_hex(sr['target'])}")

    for ref in all_func_results[0x882e40]["rip_refs"]:
        sec = pe.get_section_by_rva(ref["target"])
        raw = pe.read_rva(ref["target"], 32)
        if raw:
            # 检查是否是 Go map 相关
            hex_str = " ".join(f"{b:02x}" for b in raw)
            print(f"    数据引用: {format_hex(ref['addr'])} -> {format_hex(ref['target'])} ({sec}) [{hex_str}]")

# 分析 0xb11200
if 0xb11200 in all_func_results:
    print(f"\n  0xb11200 (FinalHandler) 的深度分析:")
    print_full_disassembly(all_func_results[0xb11200])
    analyze_calls(all_func_results[0xb11200], pdata, all_func_results)
    analyze_rip_refs(all_func_results[0xb11200])
    analyze_strings(all_func_results[0xb11200])

# ============================================================
# Go 运行时字符串分析
# ============================================================

print(f"\n{'#'*90}")
print("# 第四部分: Go 运行时分析")
print(f"{'#'*90}")

# 搜索 .gopclntab (Go PC/Line table)
for sec in pe.sections:
    if "pclntab" in sec["name"].lower() or "gopclntab" in sec["name"].lower():
        print(f"  [*] 找到 Go PC/Line table: {sec['name']} RVA={format_hex(sec['vaddr'])}")
        # 读取 Go 版本
        data = pe.read_rva(sec["vaddr"], 64)
        if data:
            print(f"      头部: {data[:16].hex()}")
            if b"go1." in data:
                idx = data.find(b"go1.")
                print(f"      版本: {data[idx:idx+20].decode('ascii', errors='replace')}")

# 搜索 .gosymtab
for sec in pe.sections:
    if "symtab" in sec["name"].lower():
        print(f"  [*] 找到 Go symbol table: {sec['name']}")

print(f"\n[*] 分析完成")
print(f"\n请运行: python analyze_full.py")
