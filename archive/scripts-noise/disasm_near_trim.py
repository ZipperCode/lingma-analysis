"""
直接反汇编 trimQueryPath 附近的所有函数
逐个查看，识别 getAppSalt
"""
import struct
import mmap
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

SECTIONS = {
    '.text': {'va': 0x1000, 'size': 0x1f3f246, 'raw': 0x400},
    '.rdata': {'va': 0x1f41000, 'size': 0x3cfc250, 'raw': 0x1f3f800},
    '.pdata': {'va': 0x6157000, 'size': 0x973ec, 'raw': 0x60a6400},
}

def rva_to_file(rva):
    for name, sec in SECTIONS.items():
        if sec['va'] <= rva < sec['va'] + sec['size']:
            return sec['raw'] + (rva - sec['va']), name
    return None, None

def main():
    with open(BINARY_PATH, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    text = SECTIONS['.text']
    rdata = SECTIONS['.rdata']

    # Get function list
    pdata_raw = SECTIONS['.pdata']['raw']
    num_funcs = SECTIONS['.pdata']['size'] // 12

    func_starts = []
    for i in range(num_funcs):
        offset = pdata_raw + i * 12
        begin = struct.unpack('<I', mm[offset:offset+4])[0]
        if text['va'] <= begin < text['va'] + text['size']:
            func_starts.append(begin)

    func_starts.sort()

    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # trimQueryPath index
    trim_rva = 0x882c80
    trim_idx = func_starts.index(trim_rva)

    print(f"trimQueryPath is at index {trim_idx}\n")

    # Show 50 functions BEFORE trimQueryPath
    print("=== 50 functions BEFORE trimQueryPath ===\n")

    start_idx = max(0, trim_idx - 50)
    for i in range(start_idx, trim_idx):
        begin_rva = func_starts[i]
        end_rva = func_starts[i+1]
        size = end_rva - begin_rva

        func_file = text['raw'] + (begin_rva - text['va'])
        func_code = mm[func_file:func_file + min(size, 200)]

        delta = begin_rva - trim_rva

        print(f"--- [{i}] RVA 0x{begin_rva:x} (size={size}, delta=0x{delta:x}) ---")

        # Check for string references
        has_string_ref = False
        for insn in md.disasm(func_code, begin_rva):
            if insn.mnemonic == 'ret':
                break
            if insn.mnemonic == 'lea':
                if 'rip' in insn.op_str:
                    try:
                        disp = insn.disp
                        next_addr = insn.address + insn.size
                        target = next_addr + disp
                        if rdata['va'] <= target < rdata['va'] + rdata['size']:
                            target_file, _ = rva_to_file(target)
                            if target_file:
                                data = mm[target_file:target_file+60]
                                s = ''.join(chr(c) if 32 <= c < 127 else '.' for c in data)
                                if len(s.strip('.')) > 2:
                                    has_string_ref = True
                                    print(f"  String ref: {s[:60]}")
                    except:
                        pass

        # Show first 15 instructions
        count = 0
        for insn in md.disasm(func_code, begin_rva):
            if count >= 15:
                break
            print(f"  {insn.address:x}: {insn.mnemonic} {insn.op_str}")
            count += 1

        if not has_string_ref:
            print(f"  (no string refs)")
        print()

    mm.close()

if __name__ == '__main__':
    main()
