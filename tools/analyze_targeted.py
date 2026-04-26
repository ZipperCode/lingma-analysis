#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lingma.exe 签名函数深度逆向分析 - 精简针对性版本
专注 4 个辅助函数 + 0xb11200
输出: 每个函数的完整反汇编 + 关键发现

用法: python analyze_targeted.py > analysis_output.txt 2>&1
依赖: pip install capstone
"""

import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP

EXE_PATH = "C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe"
IMAGE_BASE = 0x140000000

# ============================================================
# 最小化 PE 解析
# ============================================================

class MinimalPE:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        self._parse()

    def _parse(self):
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        off = e_lfanew + 24  # skip to optional header
        self.image_base = struct.unpack_from("<Q", self.data, off + 24)[0]
        opt_size = struct.unpack_from("<H", self.data, off - 4)[0]
        num_sections = struct.unpack_from("<H", self.data, e_lfanew + 6)[0]

        self.sections = []
        soff = off + opt_size
        for _ in range(num_sections):
            name = self.data[soff:soff+8].rstrip(b"\x00").decode("ascii", errors="replace")
            vsize, vaddr, rawsz, rawptr = struct.unpack_from("<IIII", self.data, soff + 8)
            self.sections.append({"name": name, "vaddr": vaddr, "vsize": vsize,
                                  "raw_ptr": rawptr, "raw_size": rawsz})
            soff += 40

    def rva_to_raw(self, rva):
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["raw_size"] + 100):
                return rva - s["vaddr"] + s["raw_ptr"]
        return None

    def read(self, rva, size):
        raw = self.rva_to_raw(rva)
        if raw is None:
            return None
        return self.data[raw:raw+size]

    def read_string(self, rva, max_len=200):
        raw = self.rva_to_raw(rva)
        if raw is None:
            return None
        end = self.data.find(b"\x00", raw, raw + max_len)
        if end == -1:
            return None
        try:
            return self.data[raw:end].decode("ascii")
        except:
            return None

    def get_section_name(self, rva):
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["raw_size"] + 100):
                return s["name"]
        return None

    def pdata_lookup(self, rva):
        for s in self.sections:
            if s["name"] == ".pdata":
                raw_data = self.data[s["raw_ptr"]:s["raw_ptr"]+s["raw_size"]]
                num = len(raw_data) // 12
                for i in range(num):
                    begin, end, uw = struct.unpack_from("<III", raw_data, i*12)
                    if begin == rva:
                        return end
        return None


# ============================================================
# 高级反汇编分析器
# ============================================================

class FuncAnalyzer:
    def __init__(self, pe):
        self.pe = pe
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.pdata_end_cache = {}

    def get_func_end(self, rva):
        if rva not in self.pdata_end_cache:
            end = self.pe.pdata_lookup(rva)
            if end is None:
                # Scan for next function in .pdata or RET pattern
                end = self._scan_for_ret(rva)
            self.pdata_end_cache[rva] = end
        return self.pdata_end_cache[rva]

    def _scan_for_ret(self, rva, max_bytes=0x2000):
        """Scan for RET to estimate function boundary"""
        code = self.pe.read(rva, max_bytes)
        if code is None:
            return rva + 0x500
        for insn in self.cs.disasm(code, rva):
            if insn.mnemonic == "ret":
                return insn.address + 1
        return rva + max_bytes

    def analyze(self, rva, name=""):
        end = self.get_func_end(rva)
        size = end - rva
        if size <= 0 or size > 0x20000:
            return None

        code = self.pe.read(rva, size)
        if code is None:
            return None

        result = {
            "name": name, "rva": rva, "end": end, "size": size,
            "insns": [], "calls": [], "rips": [], "strings": [],
            "jmps": [], "mov_imm": [], "interesting": [],
        }

        for insn in self.cs.disasm(code, rva):
            entry = {"addr": insn.address, "mnem": insn.mnemonic, "op": insn.op_str, "bytes": insn.bytes.hex()}

            # CALL target
            if insn.group(CS_GRP_CALL):
                if insn.bytes[0] == 0xE8 and len(insn.bytes) >= 5:
                    rel = struct.unpack("<i", insn.bytes[1:5])[0]
                    target = insn.address + 5 + rel
                    entry["call_target"] = target
                    sec = self.pe.get_section_name(target)
                    result["calls"].append({"addr": insn.address, "target": target, "section": sec})
                    # Check if it resolves to known string
                    s = self.pe.read_string(target)
                    if s and len(s) >= 3:
                        entry["resolved_string"] = s

            # JMP target
            if insn.group(CS_GRP_JUMP):
                target = self._get_jump_target(insn)
                if target:
                    entry["jmp_target"] = target
                    result["jmps"].append({"addr": insn.address, "target": target})

            # RIP-relative
            for op in insn.operands:
                if hasattr(op, 'value') and hasattr(op.value, 'mem'):
                    mem = op.value.mem
                    # Check for RIP-relative (base=0 in some cases, or disp-only)
                    # In capstone x86, RIP is reg 5
                    if mem.base == 5:  # X86_REG_RIP
                        target = insn.address + insn.size + mem.disp
                        entry["rip_target"] = target
                        sec = self.pe.get_section_name(target)

                        # Try to resolve as string
                        s = self.pe.read_string(target, 256)
                        if s and len(s) >= 3 and all(0x20 <= ord(c) < 0x7f for c in s):
                            entry["resolved_string"] = s
                            result["strings"].append({"addr": insn.address, "target": target, "value": s})

                        result["rips"].append({
                            "addr": insn.address,
                            "target": target,
                            "type": insn.mnemonic,
                            "section": sec,
                            "string": s if s and len(s) >= 3 else None,
                        })

            # MOV with large immediate (likely pointers/constants)
            if insn.mnemonic == "mov":
                for op in insn.operands:
                    if op.type == 2:  # IMM
                        val = op.value.imm
                        if val > 0x10000:
                            result["mov_imm"].append({"addr": insn.address, "value": val})

            result["insns"].append(entry)

        return result

    def _get_jump_target(self, insn):
        if insn.bytes[0] == 0xEB and len(insn.bytes) >= 2:
            rel = struct.unpack("<b", insn.bytes[1:2])[0]
            return insn.address + 2 + rel
        elif insn.bytes[0] == 0xE9 and len(insn.bytes) >= 5:
            rel = struct.unpack("<i", insn.bytes[1:5])[0]
            return insn.address + 5 + rel
        elif len(insn.bytes) >= 6 and insn.bytes[0] == 0x0F and 0x80 <= insn.bytes[1] <= 0x8F:
            rel = struct.unpack("<i", insn.bytes[2:6])[0]
            return insn.address + 6 + rel
        return None


# ============================================================
# 格式化输出
# ============================================================

def H(val):
    return f"0x{val:x}"

KNOWN_FUNCS = {
    0x880da0: "Caller",
    0x8821e0: "MainSigning",
    0x882e40: "ExtractConfig_FormatTimestamp",
    0x884080: "ValidateFlags",
    0x8840e0: "AddAuthHeaders",
    0x885620: "ProcessSliceData",
    0xb11200: "FinalHandler",
}

def resolve_call(target):
    if target in KNOWN_FUNCS:
        return KNOWN_FUNCS[target]
    return f"sub_{H(target)}"

def print_analysis(name, result):
    print(f"\n{'='*100}")
    print(f"  函数: {name}")
    print(f"  RVA: {H(result['rva'])}  End: {H(result['end'])}  Size: {result['size']} bytes  "
          f"Instructions: {len(result['insns'])}")
    print(f"{'='*100}")

    # Full disassembly
    print(f"\n  [反汇编]")
    for entry in result["insns"]:
        addr = H(entry["addr"])
        mnem = entry["mnem"]
        op = entry["op"]

        suffix = ""
        if "call_target" in entry:
            t = entry["call_target"]
            resolved = resolve_call(t)
            suffix = f"  ; CALL -> {H(t)} ({resolved})"
        if "resolved_string" in entry:
            suffix += f'  ; STR: "{entry["resolved_string"]}"'
        if "rip_target" in entry:
            suffix += f"  ; RIP -> {H(entry['rip_target'])}"

        print(f"  {addr:12s}  {mnem:8s} {op:35s}{suffix}")

    # Calls summary
    if result["calls"]:
        print(f"\n  [调用目标] ({len(result['calls'])} calls)")
        for c in result["calls"]:
            resolved = resolve_call(c["target"])
            print(f"    {H(c['addr'])} -> CALL {H(c['target'])} [{resolved}]  (section: {c['section']})")

    # RIP refs
    if result["rips"]:
        print(f"\n  [RIP 引用] ({len(result['rips'])} refs)")
        for r in result["rips"]:
            if r["string"]:
                print(f"    {H(r['addr'])} [{r['type']:4s}] -> {H(r['target'])} ({r['section']}) \"{r['string']}\"")
            else:
                # Show data at target
                raw = pe.read(r["target"], 16)
                if raw:
                    hex_s = " ".join(f"{b:02x}" for b in raw)
                    print(f"    {H(r['addr'])} [{r['type']:4s}] -> {H(r['target'])} ({r['section']}) [{hex_s}]")

    # String refs
    if result["strings"]:
        print(f"\n  [字符串引用] ({len(result['strings'])} strings)")
        for s in result["strings"]:
            print(f"    {H(s['addr'])} -> {H(s['target'])}  \"{s['value']}\"")

    # Key findings
    print(f"\n  [关键发现]")
    if result["calls"]:
        print(f"    * 调用了 {len(result['calls'])} 个函数")
    if result["strings"]:
        for s in result["strings"]:
            print(f"    * 字符串: \"{s['value']}\"")
    for c in result["calls"]:
        resolved = resolve_call(c["target"])
        if "hash" in resolved.lower() or "hmac" in resolved.lower() or "sha" in resolved.lower():
            print(f"    * [CRYPTO] 调用: {resolved}")
        if "header" in resolved.lower() or "auth" in resolved.lower():
            print(f"    * [AUTH] 调用: {resolved}")


# ============================================================
# 字符串全文件搜索
# ============================================================

def search_all_strings(pe, keywords):
    """Search entire binary for keywords"""
    results = {}
    search_secs = [".rodata", ".rdata", ".data", ".text"]

    for sec in pe.sections:
        if sec["name"] not in search_secs:
            continue
        sec_data = pe.data[sec["raw_ptr"]:sec["raw_ptr"]+sec["raw_size"]]
        for kw in keywords:
            kw_bytes = kw.encode()
            idx = 0
            while True:
                idx = sec_data.find(kw_bytes, idx)
                if idx == -1:
                    break
                rva = sec["vaddr"] + idx
                # Get context
                start = max(0, idx - 30)
                end = min(len(sec_data), idx + len(kw) + 80)
                ctx = sec_data[start:end]
                try:
                    ctx_s = ctx.decode("ascii", errors="replace")
                except:
                    ctx_s = repr(ctx)
                if kw not in results:
                    results[kw] = []
                results[kw].append({"rva": rva, "section": sec["name"], "context": ctx_s})
                idx += 1
    return results


# ============================================================
# Main
# ============================================================

print(f"[*] Loading: {EXE_PATH}")
pe = MinimalPE(EXE_PATH)
print(f"[+] Size: {len(pe.data)} bytes ({len(pe.data)/1024/1024:.1f} MB)")
print(f"[+] ImageBase: {H(pe.image_base)}")

# .text info
text_sec = None
for s in pe.sections:
    if s["name"] == ".text":
        text_sec = s
        break
print(f"\n[*] .text section:")
print(f"    RVA={H(text_sec['vaddr'])}  RawOffset={H(text_sec['raw_ptr'])}  "
      f"Size={H(text_sec['vsize'])}  RawSize={H(text_sec['raw_size'])}")

analyzer = FuncAnalyzer(pe)

# ============================================================
# Part 1: All target functions
# ============================================================

print(f"\n{'#'*100}")
print(f"# PART 1: 函数反汇编")
print(f"{'#'*100}")

all_results = {}
for rva, name in KNOWN_FUNCS.items():
    result = analyzer.analyze(rva, name)
    if result:
        all_results[rva] = result
        print_analysis(name, result)
    else:
        print(f"\n[!] Failed to analyze {name} at {H(rva)}")

# ============================================================
# Part 2: Call chain reconstruction
# ============================================================

print(f"\n{'#'*100}")
print(f"# PART 2: 调用链重建")
print(f"{'#'*100}")

print(f"\n  调用链:")
print(f"    Caller (0x880da0)")
if 0x880da0 in all_results:
    for c in all_results[0x880da0]["calls"]:
        if c["target"] == 0x8821e0:
            print(f"      -> MainSigning (0x8821e0) ✓")

if 0x8821e0 in all_results:
    print(f"\n    MainSigning (0x8821e0) 的内部调用:")
    for c in all_results[0x8821e0]["calls"]:
        name = resolve_call(c["target"])
        print(f"      -> {name} ({H(c['target'])})  @ {H(c['addr'])}")

# 分析 0x8840e0 -> 0xb11200 链
if 0x8840e0 in all_results:
    print(f"\n    AddAuthHeaders (0x8840e0) 的调用:")
    for c in all_results[0x8840e0]["calls"]:
        name = resolve_call(c["target"])
        print(f"      -> {name} ({H(c['target'])})  @ {H(c['addr'])}")
        if c["target"] == 0xb11200:
            print(f"        ^^^ 这是最终的 HTTP/header 处理函数 ^^^")

# ============================================================
# Part 3: String search
# ============================================================

print(f"\n{'#'*100}")
print(f"# PART 3: 关键字字符串搜索")
print(f"{'#'*100}")

keywords = [
    "Authorization", "X-", "hmac", "sha256", "hash",
    "Content-Type", "X-Request-Id", "X-Signature", "X-Timestamp",
    "app_id", "app_secret", "timestamp", "nonce", "sign",
    "app_salt", "AppSalt", "getAppSalt", "secret",
    "Bearer", "Digest",
    "http.Header", "Set", "Add",
    "Ak", "Sk",
]

str_results = search_all_strings(pe, keywords)
for kw, refs in str_results.items():
    if refs:
        print(f"\n  >>> [{kw}] 找到 {len(refs)} 处引用:")
        for ref in refs[:20]:
            ctx = ref["context"][:120].replace("\n", "\\n").replace("\r", "\\r")
            print(f"      RVA={H(ref['rva'])}  Sec={ref['section']}  ...{ctx}...")

# ============================================================
# Part 4: Deep analysis of specific questions
# ============================================================

print(f"\n{'#'*100}")
print(f"# PART 4: 关键问题解答")
print(f"{'#'*100}")

print(f"\n  Q1: 0x882e40 如何从 getAppSalt 的 map 中提取值?")
if 0x882e40 in all_results:
    r = all_results[0x882e40]
    # Look for map access patterns
    map_accesses = []
    for insn in r["insns"]:
        if "mapaccess" in insn["op"].lower() or "mapiter" in insn["op"].lower():
            map_accesses.append(insn)
    if map_accesses:
        print(f"    [Map 操作]")
        for m in map_accesses:
            print(f"      {H(m['addr'])}  {m['mnem']} {m['op']}")

    # Look for string formatting
    fmt_refs = []
    for s in r["strings"]:
        if "%" in s["value"] or "time" in s["value"].lower() or "date" in s["value"].lower():
            fmt_refs.append(s)
    if fmt_refs:
        print(f"    [时间格式化]")
        for f in fmt_refs:
            print(f"      \"{f['value']}\"")

    # Check calls to time-related functions
    for c in r["calls"]:
        t = c["target"]
        if t in KNOWN_FUNCS:
            print(f"    [调用] {KNOWN_FUNCS[t]} ({H(t)})")

print(f"\n  Q2: 0x8840e0 添加什么授权 headers? 0xb11200 是什么?")
if 0x8840e0 in all_results:
    r = all_results[0x8840e0]
    print(f"    [字符串引用 - 可能的 header names]")
    for s in r["strings"]:
        print(f"      \"{s['value']}\"")

    print(f"\n    [调用链]")
    for c in r["calls"]:
        name = resolve_call(c["target"])
        print(f"      {H(c['addr'])} -> {name} ({H(c['target'])})")

if 0xb11200 in all_results:
    r = all_results[0xb11200]
    print(f"\n    [0xb11200 函数分析]")
    print(f"    大小: {r['size']} bytes, {len(r['insns'])} instructions")
    print(f"\n    [字符串]")
    for s in r["strings"]:
        print(f"      \"{s['value']}\"")
    print(f"\n    [调用]")
    for c in r["calls"]:
        name = resolve_call(c["target"])
        print(f"      -> {name} ({H(c['target'])})")

print(f"\n{'='*100}")
print(f"[*] 分析完成")
