#!/usr/bin/env python3
"""
Full disassembly of 0x2dafa0 to understand its return value.
"""
import pefile
from capstone import *

LINGMA = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
TARGET_RVA = 0x2dafa0

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

foff = rva_to_foffset(TARGET_RVA)
code = read_bytes(foff, 0x400)  # Read more to cover both branches

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

print(f"DISASSEMBLY of 0x{TARGET_RVA:06x}")
print("=" * 80)

for insn in md.disasm(code, image_base + TARGET_RVA):
    addr = insn.address - image_base
    line = f"0x{addr:06x}:  {insn.mnemonic:<8} {insn.op_str}"
    if insn.mnemonic in ('call', 'jmp', 'je', 'jne'):
        if len(insn.operands) > 0:
            target = insn.operands[0].imm if insn.operands[0].type == CS_OP_IMM else 0
            if target:
                target_rva = target - image_base
                line += f"   [-> 0x{target_rva:06x}]"
    if 'rax' in insn.op_str or 'rbx' in insn.op_str:
        line += "   [RAX/RBX]"
    print(line)
    if insn.mnemonic == 'ret' and addr > 0x2db000:
        break
