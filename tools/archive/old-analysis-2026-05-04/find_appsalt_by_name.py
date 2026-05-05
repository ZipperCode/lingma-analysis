"""
基于函数名顺序推断 getAppSalt 的代码偏移
Go 链接器通常将同一包的函数放在一起
addBigModelSignatureHeaders 和 trimQueryPath 之间的函数很可能就是 getAppSalt
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

    # ===== Get all function addresses from .pdata =====
    print("Parsing .pdata...")
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
    print(f"Total functions: {len(func_starts)}")

    # ===== Known offsets =====
    # trimQueryPath = 0x882c80
    # getAuthSignature = 0x890140
    # getAuthPayload = 0x890380

    # Find trimQueryPath in the function list
    trim_rva = 0x882c80
    idx = func_starts.index(trim_rva) if trim_rva in func_starts else -1
    print(f"\ntrimQueryPath (0x{trim_rva:x}) is at index {idx} in function list")

    if idx >= 0:
        print(f"  Prev func: 0x{func_starts[idx-1]:x} (-0x{trim_rva - func_starts[idx-1]:x})")
        print(f"  This func: 0x{func_starts[idx]:x}")
        print(f"  Next func: 0x{func_starts[idx+1]:x} (+0x{func_starts[idx+1] - trim_rva:x})")

    # ===== Based on name table ordering =====
    # addBigModelSignatureHeaders -> getAppSalt -> addBigModelAuthorizationHeaders -> ... -> trimQueryPath
    # So getAppSalt should be BEFORE trimQueryPath in the .text section
    # Let's list all functions between 0x800000 and trimQueryPath

    print("\n=== Functions between 0x800000 and trimQueryPath ===")
    between = [(i, f) for i, f in enumerate(func_starts) if 0x800000 <= f <= trim_rva]
    print(f"Found {len(between)} functions")

    if between:
        print("First 20:")
        for i, f in between[:20]:
            size = func_starts[i+1] - f if i+1 < len(func_starts) else 0
            print(f"  [{i}] 0x{f:x} (size ~{size})")

    # ===== getAppSalt should be near addBigModelSignatureHeaders =====
    # Let's find addBigModelSignatureHeaders by searching for its name reference

    print("\n=== Searching for functions by string references ===")

    # Known name locations in .rdata:
    names = {
        'addBigModelSignatureHeaders': 0x3b9f37c,  # RVA
        'getAppSalt': 0x3b9f3a6,  # RVA
        'addBigModelAuthorizationHeaders': 0x3b9f3bf,  # RVA
        'trimQueryPath': 0x3b9f3ed,  # RVA (confirms at 0x882c80)
    }

    for name, rva in names.items():
        file_off, sec = rva_to_file(rva)
        data = mm[file_off:file_off+60]
        s = ''.join(chr(c) if 32 <= c < 127 else '.' for c in data)
        print(f"  {name}: RVA 0x{rva:x}, file 0x{file_off:x}, str: {s[:80]}")

    # ===== Search .text for LEA references to these strings =====
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    text_data = mm[text['raw']:text['raw'] + min(text['size'], 0x3000000)]  # First 48MB

    print("\n=== Searching for code referencing these names ===")
    for name, name_rva in names.items():
        refs = []
        for i in range(0, len(text_data) - 7, 1):
            # LEA REG, [RIP+disp32] - mod=00, rm=101, reg=any, opcode=8D
            # This is: 48 8D XX 05 [disp32] or 4C 8D XX 05 [disp32]
            # Simplified: just check for bytes 48/4C 8D followed by valid ModR/M with rip-relative
            if text_data[i+1] == 0x8D:
                modrm = text_data[i+2]
                # mod=00, rm=101 (5) => [RIP+disp32]
                if (modrm & 0xC0 == 0x00) and (modrm & 0x07 == 0x05):
                    disp = struct.unpack('<i', text_data[i+3:i+7])[0]
                    rip = text['va'] + i + 7
                    target = rip + disp
                    if target == name_rva:
                        refs.append(text['va'] + i)

        print(f"  {name} (RVA 0x{name_rva:x}): {len(refs)} references")
        for ref in refs[:10]:
            # Get surrounding code (100 bytes)
            ref_file = text['raw'] + (ref - text['va'])
            code = mm[ref_file - 10:ref_file + 100]
            print(f"    At RVA 0x{ref:x}:")
            for insn in md.disasm(code, ref - 10):
                marker = ">>>" if insn.address == ref else "   "
                print(f"      {marker} {insn.address:x}: {insn.mnemonic} {insn.op_str}")
            print()

    # ===== Alternative: Just list ALL functions and their sizes =====
    # Then manually look for getAppSalt near trimQueryPath
    print("\n=== ALL functions from 0x870000 to 0x8a0000 ===")
    relevant = [(i, f) for i, f in enumerate(func_starts) if 0x870000 <= f <= 0x8a0000]

    for idx_in_list, f in relevant:
        size = func_starts[idx_in_list+1] - f if idx_in_list+1 < len(func_starts) else 0

        # Get first few bytes
        func_file = text['raw'] + (f - text['va'])
        first_bytes = mm[func_file:func_file + min(32, size)]
        code_hex = first_bytes.hex()

        # Read string reference if any
        str_ref = ""
        for j in range(0, len(first_bytes) - 4, 1):
            # Check for RIP-relative LEA
            if j+6 < len(first_bytes) and first_bytes[j+1] == 0x8D:
                modrm = first_bytes[j+2]
                if (modrm & 0xC0 == 0x00) and (modrm & 0x07 == 0x05):
                    disp = struct.unpack('<i', first_bytes[j+3:j+7])[0]
                    rip = f + j + 7
                    target = rip + disp
                    if rdata['va'] <= target < rdata['va'] + rdata['size']:
                        target_file, _ = rva_to_file(target)
                        if target_file:
                            s = mm[target_file:target_file+50]
                            str_ref = ''.join(chr(c) if 32 <= c < 127 else '.' for c in s)[:60]
                        break

        delta = f - trim_rva
        sign = "+" if delta >= 0 else ""
        print(f"  0x{f:x} (size={size:3d}, {sign}0x{abs(delta):x}) | {str_ref[:40]}")
        if str_ref:
            for insn in md.disasm(first_bytes, f):
                print(f"    {insn.mnemonic} {insn.op_str}")

    mm.close()

if __name__ == '__main__':
    main()
