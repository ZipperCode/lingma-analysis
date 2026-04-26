"""
Deep analysis of getAppSalt call in caller 0x880da0.
Need to understand exactly how return values flow.
"""
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
        chars = struct.unpack('<I', data[off+36:off+40])[0]
        sections.append({'name': name, 'vaddr': vaddr, 'vsize': vsize,
                        'raw_size': raw_size, 'raw_addr': raw_addr, 'chars': chars})
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
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    # Disassemble caller starting from entry
    caller_off = rva_to_file(0x880da0, sections)
    caller_data = data[caller_off:caller_off + 300]

    print("=== Caller 0x880da0: Full disassembly ===\n")

    getAppSalt_call_addr = None

    for insn in md.disasm(caller_data, IMAGE_BASE + 0x880da0):
        if insn.size == 0:
            break

        extra = ""

        # Check if this is the getAppSalt call
        if insn.mnemonic == 'call':
            if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
                callee = insn.operands[0].imm - IMAGE_BASE
                if callee == 0x882760:
                    getAppSalt_call_addr = insn.address
                    extra = " <<< getAppSalt CALL"

        # Resolve RIP-relative memory refs
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                target = insn.address + insn.size + op.mem.disp
                target_rva = target - IMAGE_BASE
                off = rva_to_file(target_rva, sections)
                if off and 0 < off < len(data):
                    end = data.find(b'\x00', off)
                    if end > off and end - off < 200:
                        s = data[off:end].decode('utf-8', errors='replace')
                        extra = f'  => "{s[:80]}"'

        if insn.mnemonic == 'ret':
            extra = "  [RET]"

        print(f"  0x{insn.address:010x}: {insn.mnemonic:8s} {insn.op_str:45s}{extra}")

        # Stop after getAppSalt call + some instructions
        if getAppSalt_call_addr and insn.address > getAppSalt_call_addr + 200:
            print("  ... (truncated)")
            break

    print(f"\n=== Key observation ===")
    if getAppSalt_call_addr:
        # Show 5 instructions before call
        print("\nInstructions BEFORE getAppSalt call:")
        for insn in md.disasm(data[caller_off:caller_off + 300], IMAGE_BASE + 0x880da0):
            if insn.address == getAppSalt_call_addr - 10:
                for insn2 in md.disasm(data[rva_to_file(insn.address - IMAGE_BASE, sections):caller_off + 300], insn.address):
                    if insn2.address <= getAppSalt_call_addr + 100:
                        marker = " <<< CALL" if insn2.address == getAppSalt_call_addr else ""
                        print(f"  0x{insn2.address:010x}: {insn2.mnemonic:8s} {insn2.op_str}{marker}")
                        if insn2.address == getAppSalt_call_addr + 50:
                            break
                break

if __name__ == '__main__':
    main()
