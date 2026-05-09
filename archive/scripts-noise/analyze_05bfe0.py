#!/usr/bin/env python3
"""
Disassemble 0x05bfe0 to understand string concatenation in Md5Encode.
"""
import pefile
from capstone import *

LINGMA = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
TARGET_RVA = 0x05bfe0

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

# Find function size
func_size = 0x200
for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
    begin = entry.struct.BeginAddress
    end = entry.struct.EndAddress
    if begin <= TARGET_RVA < end:
        func_size = end - begin
        break

foff = rva_to_foffset(TARGET_RVA)
code = read_bytes(foff, func_size)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

print(f"DISASSEMBLY of 0x{TARGET_RVA:06x} (func size=0x{func_size:x})")
print("=" * 80)

for insn in md.disasm(code, image_base + TARGET_RVA):
    addr = insn.address - image_base
    line = f"0x{addr:06x}:  {insn.mnemonic:<8} {insn.op_str}"
    if insn.mnemonic in ('call', 'jmp', 'je', 'jne', 'jg', 'jl', 'ja', 'jb', 'ret'):
        if len(insn.operands) > 0:
            target = insn.operands[0].imm if insn.operands[0].type == CS_OP_IMM else 0
            if target:
                target_rva = target - image_base
                line += f"   [-> 0x{target_rva:06x}]"
    print(line)
    if insn.mnemonic == 'ret':
        break
