"""Find all getAppSalt references in caller 0x880da0"""
import struct
import capstone

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

def parse_sections(data):
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    coff = pe_offset + 4
    num_sections = struct.unpack('<H', data[coff + 2:coff + 4])[0]
    opt_size = struct.unpack('<H', data[coff + 16:coff + 18])[0]
    sec_off = coff + 20 + opt_size
    sections = []
    for i in range(num_sections):
        off = sec_off + i * 40
        name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vaddr = struct.unpack('<I', data[off+12:off+16])[0]
        vsize = struct.unpack('<I', data[off+8:off+12])[0]
        raw_size = struct.unpack('<I', data[off+16:off+20])[0]
        raw_addr = struct.unpack('<I', data[off+20:off+24])[0]
        sections.append({'name': name, 'vaddr': vaddr, 'vsize': vsize,
                        'raw_size': raw_size, 'raw_addr': raw_addr})
    return sections

def rva_to_file(rva, sections):
    for sec in sections:
        if sec['vaddr'] <= rva < sec['vaddr'] + sec['raw_size']:
            return sec['raw_addr'] + (rva - sec['vaddr'])
    return None

def main():
    with open(LINGMA, 'rb') as f:
        data = f.read()
    sections = parse_sections(data)

    # Get caller function data (larger range)
    caller_off = rva_to_file(0x880da0, sections)
    caller_data = data[caller_off:caller_off + 5000]

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    getAppSalt_target = IMAGE_BASE + 0x882760

    # Find all CALL instructions and their targets
    print("=== All CALLs in caller 0x880da0 ===\n")
    for insn in md.disasm(caller_data, IMAGE_BASE + 0x880da0):
        if insn.size == 0:
            break
        if insn.mnemonic == 'call':
            # Extract the target from the instruction bytes
            if insn.op_str.startswith('0x'):
                target_str = insn.op_str.split()[0]
                try:
                    target = int(target_str, 16)
                    marker = ""
                    if target == getAppSalt_target:
                        marker = " <<< getAppSalt!"
                    print(f"  0x{insn.address:010x}: call {target_str}{marker}")
                except:
                    pass

    # Also search for the raw bytes pattern for CALL rel32 to 0x882760
    print("\n=== Raw byte search for CALL to 0x882760 ===")
    # CALL rel32: E8 <rel32>
    # rel32 = target - (addr + 5)
    # For each CALL in the function, check if target = 0x140882760
    for insn in md.disasm(caller_data, IMAGE_BASE + 0x880da0):
        if insn.size == 0:
            break
        if insn.mnemonic == 'call' and len(insn.bytes) >= 5 and insn.bytes[0] == 0xE8:
            rel32 = struct.unpack('<i', insn.bytes[1:5])[0]
            target = insn.address + rel32
            marker = ""
            if target == getAppSalt_target:
                marker = " <<< getAppSalt!"
            if abs(rel32) < 0x100000:  # Only show nearby calls
                print(f"  0x{insn.address:010x}: CALL -> 0x{target:010x} (rel=0x{rel32:x}){marker}")

if __name__ == '__main__':
    main()
