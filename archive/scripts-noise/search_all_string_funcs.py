"""
扩大范围搜索所有返回字符串的函数
同时搜索 "AppSalt" 字符串的代码引用
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

    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # ===== Step 1: Find "AppSalt" string location =====
    print("=== Finding 'AppSalt' string ===")
    appsalt_idx = mm.find(b'AppSalt')
    if appsalt_idx >= 0:
        appsalt_rva = file_to_rva(appsalt_idx)
        print(f"'AppSalt' at file offset 0x{appsalt_idx:x}, RVA 0x{appsalt_rva:x}")

        # Show context
        ctx = mm[appsalt_idx-20:appsalt_idx+50]
        print(f"Context: {ctx}")

        # ===== Step 2: Search ALL of .text for LEA references to this =====
        print(f"\nSearching .text for LEA references to 'AppSalt' (RVA 0x{appsalt_rva:x})...")

        text_data = mm[text['raw']:text['raw'] + text['size']]

        refs = []
        i = 0
        while i < len(text_data) - 6:
            # LEA REG, [RIP+disp32]: bytes XX 8D XX 05 [disp32]
            if text_data[i+1] == 0x8D:
                modrm = text_data[i+2]
                # mod=00, rm=101 => [RIP+disp32]
                if (modrm & 0xC0 == 0x00) and (modrm & 0x07 == 0x05):
                    disp = struct.unpack('<i', text_data[i+3:i+7])[0]
                    rip = text['va'] + i + 7
                    target = rip + disp
                    if target == appsalt_rva:
                        refs.append(text['va'] + i)
            i += 1

        if refs:
            for ref_rva in refs:
                print(f"\n  Found at RVA 0x{ref_rva:x}")
                ref_file = text['raw'] + (ref_rva - text['va'])
                # Get surrounding code
                code = mm[max(0, ref_file-50):ref_file+100]
                code_rva = ref_rva - 50 if ref_rva >= 50 else 0

                for insn in md.disasm(code, code_rva):
                    marker = ">>>" if insn.address == ref_rva else "   "
                    print(f"    {marker} {insn.address:x}: {insn.mnemonic} {insn.op_str}")
        else:
            print("  No code references found to 'AppSalt' string")
            print("  It may only appear in function names, not as a data string")

    # ===== Step 3: Search ALL .text for ALL string-returning functions =====
    print("\n\n=== ALL string-returning functions in .text (any size) ===")

    # Get function list
    pdata_raw = SECTIONS['.pdata']['raw']
    pdata_size = SECTIONS['.pdata']['size']
    num_funcs = pdata_size // 12

    func_starts = []
    for i in range(num_funcs):
        offset = pdata_raw + i * 12
        begin = struct.unpack('<I', mm[offset:offset+4])[0]
        if SECTIONS['.text']['va'] <= begin < SECTIONS['.text']['va'] + SECTIONS['.text']['size']:
            func_starts.append(begin)

    func_starts.sort()

    # Check ALL functions for string-returning pattern
    # This will take a while, so focus on interesting sizes
    all_string_funcs = []

    # Focus on small functions for efficiency
    small_funcs = []
    for i in range(len(func_starts)):
        begin = func_starts[i]
        end = func_starts[i+1] if i+1 < len(func_starts) else begin + 100
        size = end - begin
        if 4 <= size <= 64:
            small_funcs.append((begin, size))

    print(f"Small functions (4-64 bytes): {len(small_funcs)}")

    # Check each for LEA to .rdata + RET
    for begin_rva, size in small_funcs:
        func_file = text['raw'] + (begin_rva - text['va'])
        func_code = mm[func_file:func_file + size]

        has_ret = False
        rdata_refs = []

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
                                rdata_refs.append((target, s))
                    except:
                        pass

        if has_ret and rdata_refs:
            all_string_funcs.append((begin_rva, size, rdata_refs, func_code))

    print(f"String-returning functions: {len(all_string_funcs)}\n")

    # Sort by RVA and show all
    all_string_funcs.sort(key=lambda x: x[0])

    # Group by proximity to trimQueryPath
    trim_rva = 0x882c80
    near = [(rva, size, refs, code) for rva, size, refs, code in all_string_funcs
            if abs(rva - trim_rva) < 0x50000]  # Within 320KB

    print(f"Near trimQueryPath (within 320KB): {len(near)}\n")

    for begin_rva, size, refs, func_code in near[:50]:
        delta = begin_rva - trim_rva
        sign = "+" if delta >= 0 else ""
        print(f"RVA 0x{begin_rva:x} (size={size}, {sign}0x{abs(delta):x}):")
        for target, s in refs:
            print(f"  -> 0x{target:x}: {s[:70]}")
        print(f"  Code:")
        for insn in md.disasm(func_code, begin_rva):
            print(f"    {insn.mnemonic} {insn.op_str}")
        print()

    # ===== Step 4: Search for functions that might call getAppSalt =====
    # addBigModelSignatureHeaders likely calls getAppSalt
    # Let's find addBigModelSignatureHeaders
    print("\n=== Finding addBigModelSignatureHeaders ===")
    # It should be a larger function that sets headers
    # Look for functions near trimQueryPath that reference "Signature" or "X-" strings

    for name_rva in [0x3b9f37c]:  # addBigModelSignatureHeaders name
        target_file, _ = rva_to_file(name_rva)
        if target_file:
            data = mm[target_file:target_file+60]
            s = ''.join(chr(c) if 32 <= c < 127 else '.' for c in data)
            print(f"  Name: {s[:60]}")

    # Search .text for LEA to this name
    refs = []
    i = 0
    while i < len(text_data) - 6:
        if text_data[i+1] == 0x8D:
            modrm = text_data[i+2]
            if (modrm & 0xC0 == 0x00) and (modrm & 0x07 == 0x05):
                disp = struct.unpack('<i', text_data[i+3:i+7])[0]
                rip = text['va'] + i + 7
                target = rip + disp
                if target == name_rva:
                    refs.append(text['va'] + i)
        i += 1

    print(f"  Code references: {len(refs)}")
    for ref in refs[:5]:
        print(f"    At RVA 0x{ref:x}")
        # Find which function this belongs to
        import bisect
        idx = bisect.bisect_right(func_starts, ref) - 1
        if idx >= 0:
            func_begin = func_starts[idx]
            next_begin = func_starts[idx+1] if idx+1 < len(func_starts) else func_begin + 100
            print(f"    In function: RVA 0x{func_begin:x} - 0x{next_begin:x}")

            # Show the function's code
            func_file = text['raw'] + (func_begin - text['va'])
            func_code = mm[func_file:func_file + (next_begin - func_begin)]
            print(f"    Disassembly:")
            for insn in md.disasm(func_code[:200], func_begin):
                print(f"      {insn.mnemonic} {insn.op_str}")
            print()

    mm.close()

if __name__ == '__main__':
    main()
