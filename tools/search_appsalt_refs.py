"""
搜索代码中引用 "AppSalt" 字符串的位置
之前发现 "AppSalt" 字符串在 .rdata offset 0x1c5e3b7
"""
import struct
import mmap

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

    # "AppSalt" string location from previous analysis
    appsalt_file = 0x1c5e3b7
    appsalt_rva = file_to_rva(appsalt_file)
    appsalt_va = IMAGE_BASE + appsalt_rva

    print(f"'AppSalt' string:")
    print(f"  File offset: 0x{appsalt_file:x}")
    print(f"  RVA: 0x{appsalt_rva:x}")
    print(f"  VA: 0x{appsalt_va:x}")

    # Show the string context
    context = mm[appsalt_file-20:appsalt_file+30]
    print(f"  Context: {context}")

    text = SECTIONS['.text']
    text_data = mm[text['raw']:text['raw'] + text['size']]

    # Search .text for RIP-relative references to this .rdata address
    # Pattern: LEA REG, [RIP + disp32] where target = getAppSalt string VA
    print(f"\nSearching .text for references to AppSalt string (RVA 0x{appsalt_rva:x})...")

    # 48 8D XX 05 [disp32] - LEA REG, [RIP+disp32]
    # 4C 8D XX 05 [disp32] - LEA REG, [RIP+disp32] (R8-R15)
    count = 0
    for i in range(0, len(text_data) - 7, 1):
        # LEA with RIP-relative
        if (text_data[i+1] == 0x8D and text_data[i+2] >= 0x05 and
            i+6 < len(text_data)):
            # Check if it's RIP-relative LEA (mod=0, rm=5 => [RIP+disp32])
            modrm = text_data[i+2]
            if modrm & 0xC7 == 0x05:  # mod=0, rm=5
                disp = struct.unpack('<i', text_data[i+3:i+7])[0]
                rip = text['va'] + i + 7
                target = rip + disp

                if target == appsalt_rva:
                    func_rva = text['va'] + i
                    func_file = text['raw'] + i
                    reg = modrm & 0x07
                    if modrm & 0x04 == 0x04:
                        reg = (modrm & 0x07) + 8  # REX.B extension

                    print(f"  Found LEA at RVA 0x{func_rva:x} (file 0x{func_file:x}): target={target:x}")
                    count += 1

                    if count > 50:
                        print("  ... (too many, stopping)")
                        break

    if count == 0:
        print("  No direct references found")
        print("  'AppSalt' may be part of function name only, not referenced in code")

    # ===== Alternative approach: find ALL small string-returning functions =====
    print(f"\n\n=== ALL small string-returning functions in .text ===")

    # Get function list from .pdata
    pdata = SECTIONS['.pdata']
    pdata_raw = pdata['raw']
    pdata_size = pdata['size']
    num_funcs = pdata_size // 12

    func_list = []
    for i in range(num_funcs):
        offset = pdata_raw + i * 12
        begin = struct.unpack('<I', mm[offset:offset+4])[0]
        end = struct.unpack('<I', mm[offset+4:offset+8])[0]
        if begin != 0 and end > begin:
            if SECTIONS['.text']['va'] <= begin < SECTIONS['.text']['va'] + SECTIONS['.text']['size']:
                size = end - begin
                if 4 <= size <= 48:  # Very small functions
                    func_list.append((begin, end, size))

    print(f"Small functions (4-48 bytes): {len(func_list)}")

    # Find ones that return string constants (LEA to .rdata + RET)
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    rdata = SECTIONS['.rdata']
    string_returners = []

    for begin_rva, end_rva, size in func_list:
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
                            # Read the string at target
                            target_file, _ = rva_to_file(target)
                            if target_file:
                                data = mm[target_file:target_file+60]
                                s = ''.join(chr(c) if 32 <= c < 127 else '.' for c in data)
                                rdata_leas.append((insn.op_str, target, s))
                    except:
                        pass
            elif insn.mnemonic.startswith('mov') and '0x' in insn.op_str:
                # Check for constant (likely string length)
                pass

        if has_ret and rdata_leas:
            string_returners.append((begin_rva, size, rdata_leas, func_code))

    print(f"String-returning functions: {len(string_returners)}")

    # Focus on the region around trimQueryPath
    trim_rva = 0x882c80
    nearby = [(rva, size, refs, code) for rva, size, refs, code in string_returners
              if abs(rva - trim_rva) < 0x100000]

    print(f"Near trimQueryPath (within 1MB): {len(nearby)}")

    nearby.sort(key=lambda x: x[0])
    for rva, size, refs, code in nearby[:20]:
        delta = rva - trim_rva
        sign = "+" if delta >= 0 else "-"
        print(f"\n  RVA 0x{rva:x} (size={size}, {sign}0x{abs(delta):x}):")
        for op_str, target, s in refs:
            print(f"    LEA {op_str} -> 0x{target:x}: {s[:80]}")

        # Show full disassembly
        print(f"    Code:")
        for insn in md.disasm(code, rva):
            print(f"      {insn.mnemonic} {insn.op_str}")

    mm.close()

if __name__ == '__main__':
    main()
