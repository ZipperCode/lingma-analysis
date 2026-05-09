#!/usr/bin/env python3
"""
Analyze each Md5Encode call site to understand the function signature.
"""
import struct
import pefile
from capstone import *

LINGMA = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
MD5_ENCODE_RVA = 0x4563c0
CALL_SITES = [0x8829b2, 0x8902ef, 0xc87f54, 0x153d6cf]

pe = pefile.PE(LINGMA)
image_base = pe.OPTIONAL_HEADER.ImageBase

def rva_to_foffset(rva):
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
            return section.PointerToRawData + (rva - section.VirtualAddress)
    return None

def read_bytes(foffset, size):
    with open(LINGMA, 'rb') as f:
        f.seek(foffset)
        return f.read(size)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

for call_rva in CALL_SITES:
    print("=" * 80)
    print(f"Call site: 0x{call_rva:06x}")
    print("=" * 80)

    # Read a chunk around the call site
    start = max(0, call_rva - 0x80)
    size = 0x100
    foff = rva_to_foffset(start)
    code = read_bytes(foff, size)

    for insn in md.disasm(code, image_base + start):
        addr = insn.address - image_base
        if addr < call_rva - 0x60:
            continue
        if addr > call_rva + 0x20:
            break

        line = f"0x{addr:06x}:  {insn.mnemonic:<8} {insn.op_str}"

        if addr == call_rva:
            line += "   <<< CALL Md5Encode"
        elif insn.mnemonic in ('call', 'jmp', 'je', 'jne'):
            target = insn.operands[0].imm if insn.operands[0].type == CS_OP_IMM else 0
            if target:
                target_rva = target - image_base
                line += f"   [-> 0x{target_rva:06x}]"

        # Highlight register moves into AX/BX/CX/DI/SI
        if insn.mnemonic == 'mov' and any(reg in insn.op_str for reg in ['rax', 'rbx', 'rcx', 'rdi', 'rsi']):
            line += "   [REG]"
        if insn.mnemonic == 'lea' and 'rax' in insn.op_str:
            line += "   [REG]"

        print(line)
    print()
