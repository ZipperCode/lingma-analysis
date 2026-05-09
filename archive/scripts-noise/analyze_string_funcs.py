"""
详细分析所有返回字符串常量的函数
重点寻找 getAppSalt - 一个返回短字符串的函数
"""
import struct
import mmap
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

SECTIONS = {
    '.text': {'va': 0x1000, 'size': 0x1f3f246, 'raw': 0x400},
    '.rdata': {'va': 0x1f41000, 'size': 0x3cfc250, 'raw': 0x1f3f800},
    '.data': {'va': 0x5c3e000, 'size': 0x518d80, 'raw': 0x5c3bc00},
    '.pdata': {'va': 0x6157000, 'size': 0x973ec, 'raw': 0x60a6400},
}

def rva_to_file(rva):
    for name, sec in SECTIONS.items():
        if sec['va'] <= rva < sec['va'] + sec['size']:
            return sec['raw'] + (rva - sec['va']), name
    return None, None

def file_to_rva(file_offset):
    for name, sec in SECTIONS.items():
        if sec['raw'] <= file_offset < sec['raw'] + sec['size']:
            return sec['va'] + (file_offset - sec['raw'])
    return None

def main():
    with open(BINARY_PATH, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    text = SECTIONS['.text']
    rdata = SECTIONS['.rdata']
    pdata = SECTIONS['.pdata']

    # Get all functions
    pdata_raw = pdata['raw']
    pdata_size = pdata['size']
    num_funcs = pdata_size // 12

    func_starts = []
    for i in range(num_funcs):
        offset = pdata_raw + i * 12
        begin = struct.unpack('<I', mm[offset:offset+4])[0]
        if text['va'] <= begin < text['va'] + text['size']:
            func_starts.append(begin)

    func_starts.sort()

    # Get function sizes
    func_info = []
    for i in range(len(func_starts)):
        begin = func_starts[i]
        if i + 1 < len(func_starts):
            end = func_starts[i+1]
        else:
            end = begin + 100
        size = end - begin
        func_info.append((begin, size))

    # getAppSalt likely:
    # 1. Very small (<=32 bytes)
    # 2. Returns a Go string (LEA + RET pattern)
    # 3. In the cosy/remoting region

    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # Focus on the region from 0x870000 to 0x890380 (trimQueryPath to getAuthPayload)
    # This is where cosy/remoting functions are clustered
    print("=== Analyzing string-returning functions in remoting region ===\n")

    target_funcs = [(rva, size) for rva, size in func_info
                    if 0x870000 <= rva <= 0x891000 and 4 <= size <= 48]

    print(f"Target region functions: {len(target_funcs)}\n")

    string_funcs = []
    for begin_rva, size in target_funcs:
        func_file = text['raw'] + (begin_rva - text['va'])
        func_code = mm[func_file:func_file + size]

        has_ret = False
        rdata_leas = []
        const_len = None

        for insn in md.disasm(func_code, begin_rva):
            if insn.mnemonic == 'ret':
                has_ret = True
            elif insn.mnemonic == 'lea':
                if 'rip' in insn.op_str:
                    try:
                        disp = insn.disp
                        next_addr = insn.address + insn.size
                        target = next_addr + disp
                        if rdata['va'] <= target < rdata['va'] + rdata['size']:
                            target_file, _ = rva_to_file(target)
                            if target_file:
                                data = mm[target_file:target_file+80]
                                s = ''.join(chr(c) if 32 <= c < 127 else '.' for c in data)
                                rdata_leas.append((insn.mnemonic, insn.op_str, target, s))
                    except:
                        pass
            elif insn.mnemonic.startswith('mov'):
                # Check for MOV to register with immediate (string length)
                if '0x' in insn.op_str and '[' not in insn.op_str:
                    const_len = insn.op_str

        if has_ret and rdata_leas:
            string_funcs.append((begin_rva, size, rdata_leas, const_len, func_code))

    print(f"String-returning functions: {len(string_funcs)}\n")

    # Show ALL of them sorted by RVA
    string_funcs.sort(key=lambda x: x[0])
    for begin_rva, size, rdata_leas, const_len, func_code in string_funcs:
        delta = begin_rva - 0x882c80  # relative to trimQueryPath
        sign = "+" if delta >= 0 else ""
        print(f"RVA 0x{begin_rva:x} (size={size}, {sign}0x{abs(delta):x}):")

        for _, op_str, target, s in rdata_leas:
            print(f"  LEA {op_str} -> 0x{target:x}: {s[:70]}")

        if const_len:
            print(f"  CONST: {const_len}")

        # Show full disassembly
        for insn in md.disasm(func_code, begin_rva):
            print(f"    {insn.mnemonic} {insn.op_str}")
        print()

    # ===== Analysis: Which one is getAppSalt? =====
    print("\n=== CANDIDATE ANALYSIS ===")
    print("getAppSalt should return:")
    print("  - A short string (like 'AppSalt' or some key)")
    print("  - The string is likely 5-50 chars")
    print("  - The function is probably very small (< 20 bytes)")
    print()

    # Filter to very small functions with short strings
    very_small = [(rva, size, refs, const_len, code)
                  for rva, size, refs, const_len, code in string_funcs
                  if size <= 24]

    print(f"Very small candidates (<=24 bytes): {len(very_small)}\n")
    for begin_rva, size, refs, const_len, func_code in very_small:
        for _, _, target, s in refs:
            # Check string length
            str_len = len(s.split('.')[0]) if '.' in s else len(s)
            if str_len < 100:  # Short string
                delta = begin_rva - 0x882c80
                sign = "+" if delta >= 0 else ""
                print(f"*** RVA 0x{begin_rva:x} (size={size}, {sign}0x{abs(delta):x}) ***")
                print(f"    String: {s[:80]}")
                print(f"    Code:")
                for insn in md.disasm(func_code, begin_rva):
                    print(f"      {insn.mnemonic} {insn.op_str}")
                print()

    mm.close()

if __name__ == '__main__':
    main()
