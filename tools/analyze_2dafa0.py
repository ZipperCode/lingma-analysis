#!/usr/bin/env python3
"""
Analyze function at 0x2dafa0 and its callers to understand string operations.
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

# Disassemble function at 0x2dafa0
foff = rva_to_foffset(TARGET_RVA)
# Read a reasonable chunk (we don't know exact size, read 0x200)
code = read_bytes(foff, 0x200)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

print("=" * 80)
print(f"DISASSEMBLY of 0x{TARGET_RVA:06x}")
print("=" * 80)

for insn in md.disasm(code, image_base + TARGET_RVA):
    addr = insn.address - image_base
    line = f"0x{addr:06x}:  {insn.mnemonic:<8} {insn.op_str}"
    if insn.mnemonic == 'ret':
        print(line)
        break
    if insn.mnemonic in ('call', 'jmp', 'je', 'jne'):
        target = insn.operands[0].imm if insn.operands[0].type == CS_OP_IMM else 0
        if target:
            target_rva = target - image_base
            line += f"   [-> 0x{target_rva:06x}]"
    print(line)

# Also check 0x2dd360 (used at 0x8829e2)
print("\n" + "=" * 80)
print("DISASSEMBLY of 0x2dd360")
print("=" * 80)
foff2 = rva_to_foffset(0x2dd360)
code2 = read_bytes(foff2, 0x200)
for insn in md.disasm(code2, image_base + 0x2dd360):
    addr = insn.address - image_base
    line = f"0x{addr:06x}:  {insn.mnemonic:<8} {insn.op_str}"
    if insn.mnemonic == 'ret':
        print(line)
        break
    if insn.mnemonic in ('call', 'jmp', 'je', 'jne'):
        target = insn.operands[0].imm if insn.operands[0].type == CS_OP_IMM else 0
        if target:
            target_rva = target - image_base
            line += f"   [-> 0x{target_rva:06x}]"
    print(line)
