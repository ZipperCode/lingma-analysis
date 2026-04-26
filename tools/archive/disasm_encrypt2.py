import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

def parse_sections(pe_data):
    e_lfanew = struct.unpack('<I', pe_data[60:64])[0]
    coff_offset = e_lfanew + 4
    num_sections = struct.unpack('<H', pe_data[coff_offset+2:coff_offset+4])[0]
    opt_header_size = struct.unpack('<H', pe_data[coff_offset+16:coff_offset+18])[0]
    section_offset = coff_offset + 20 + opt_header_size

    sections = []
    for i in range(num_sections):
        sec = pe_data[section_offset + i*40 : section_offset + (i+1)*40]
        sections.append({
            'name': sec[0:8].rstrip(b'\x00').decode('ascii', errors='replace'),
            'virtual_address': struct.unpack('<I', sec[12:16])[0],
            'virtual_size': struct.unpack('<I', sec[8:12])[0],
            'raw_offset': struct.unpack('<I', sec[20:24])[0],
            'raw_size': struct.unpack('<I', sec[16:20])[0],
        })
    return sections

def rva_to_file_offset(sections, rva):
    for sec in sections:
        va = sec['virtual_address']
        vs = sec['virtual_size']
        if va <= rva < va + max(vs, sec['raw_size']):
            return sec['raw_offset'] + (rva - va)
    return None

with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

sections = parse_sections(pe_data)
md = Cs(CS_ARCH_X86, CS_MODE_64)

# Go function calling convention (register-based for Go 1.22+):
# Arguments are passed in registers (AX, BX, CX, DI, SI, R8-R15)
# Return values in AX, BX, CX

def disasm_function(name, rva, max_instructions=200):
    """Disassemble a Go function, stopping at RET"""
    offset = rva_to_file_offset(sections, rva)
    if offset is None:
        print(f"  Could not find file offset for {name} (RVA 0x{rva:x})")
        return

    # Get enough bytes for the function
    data = pe_data[offset:offset+10000]

    print(f"\n{'='*80}")
    print(f"Function: {name} (RVA 0x{rva:x}, file offset 0x{offset:x})")
    print(f"{'='*80}")

    instructions = []
    consecutive_ret = 0
    padding_count = 0

    for insn in md.disasm(data, rva):
        mnemonic = insn.mnemonic
        op_str = insn.op_str

        # Go adds NOP padding between functions
        if mnemonic == 'nop':
            padding_count += 1
            if padding_count > 5:
                break
        else:
            padding_count = 0

        if mnemonic == 'ret':
            consecutive_ret += 1
            instructions.append(f"  {insn.address:#010x}:  ret")
            if consecutive_ret >= 2 and len(instructions) > 10:
                break
        else:
            consecutive_ret = 0
            instructions.append(f"  {insn.address:#010x}:  {mnemonic:<8} {op_str}")

        if len(instructions) > max_instructions:
            instructions.append(f"  ... (truncated, >{max_instructions} instructions)")
            break

    for insn in instructions:
        print(insn)

    # Also print string/constant references found
    print(f"\n  --- References and constants ---")
    for insn in md.disasm(data, rva):
        # LEA with RIP-relative addressing
        if insn.mnemonic == 'lea' and 'rip' in insn.op_str.lower():
            # Extract the displacement
            op = insn.op_str
            if '+' in op:
                parts = op.split('+')
                if len(parts) == 2:
                    try:
                        disp = int(parts[-1].strip(']'), 16)
                        ref_addr = insn.address + insn.size + disp
                        ref_rva = ref_addr - IMAGE_BASE
                        ref_offset = rva_to_file_offset(sections, ref_rva)
                        if ref_offset:
                            ref_data = pe_data[ref_offset:ref_offset+50]
                            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ref_data)
                            print(f"  LEA reference -> RVA 0x{ref_rva:x}: {printable[:80]}")
                    except:
                        pass

# Disassemble the key functions
disasm_function('AesEncryptWithBase64', 0x455da0, max_instructions=300)
disasm_function('CustomEncryptV1', 0x455800, max_instructions=300)
disasm_function('pkcs5Padding', 0x456280, max_instructions=100)
disasm_function('shuffle', 0x454a40, max_instructions=100)
disasm_function('newEncoding', 0x5be20, max_instructions=100)
