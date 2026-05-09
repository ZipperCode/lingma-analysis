"""Show the getAppSalt call and surrounding context in caller 0x880da0"""
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
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    caller_off = rva_to_file(0x880da0, sections)
    caller_data = data[caller_off:caller_off + 2000]

    # Find all instructions, collect those around getAppSalt call
    all_insns = []
    for insn in md.disasm(caller_data, IMAGE_BASE + 0x880da0):
        if insn.size == 0:
            break
        all_insns.append(insn)
        if insn.mnemonic == 'ret':
            break

    # Find getAppSalt call index
    call_idx = None
    for i, insn in enumerate(all_insns):
        if insn.mnemonic == 'call' and insn.operands:
            if insn.operands[0].type == capstone.x86.X86_OP_IMM:
                callee = insn.operands[0].imm - IMAGE_BASE
                if callee == 0x882760:
                    call_idx = i
                    break

    if call_idx is None:
        print("getAppSalt call not found!")
        return

    # Show 30 instructions before and after
    start = max(0, call_idx - 20)
    end = min(len(all_insns), call_idx + 40)

    print(f"=== Context around getAppSalt call (at index {call_idx}) ===\n")

    for i in range(start, end):
        insn = all_insns[i]
        marker = ""
        if i == call_idx:
            marker = "  <<< getAppSalt"
        elif i == call_idx + 1:
            marker = "  <<< RIGHT AFTER CALL"

        # Resolve RIP-relative
        extra = ""
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                target = insn.address + insn.size + op.mem.disp
                target_rva = target - IMAGE_BASE
                off = rva_to_file(target_rva, sections)
                if off and 0 < off < len(data):
                    end_idx = data.find(b'\x00', off)
                    if end_idx > off and end_idx - off < 200:
                        s = data[off:end_idx].decode('utf-8', errors='replace')
                        extra = f'  => "{s[:60]}"'

        if insn.mnemonic == 'ret':
            marker += "  [RET]"

        print(f"  {i:3d} 0x{insn.address:010x}: {insn.mnemonic:8s} {insn.op_str:45s}{extra}{marker}")

if __name__ == '__main__':
    main()
