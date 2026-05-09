#!/usr/bin/env python3
"""
Disassemble Md5Encode (0x4563c0) to understand how it handles multiple strings.
"""
import pefile
from capstone import *

LINGMA = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
MD5_ENCODE_RVA = 0x4563c0

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

# Find function size from .pdata
# Look for unwind info for 0x4563c0
for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
    begin = entry.struct.BeginAddress
    end = entry.struct.EndAddress
    if begin <= MD5_ENCODE_RVA < end:
        print(f"Md5Encode function range: 0x{begin:06x} - 0x{end:06x} (size=0x{end-begin:x})")
        func_size = end - begin
        break
else:
    print("Could not find function size in .pdata, using default 0x200")
    func_size = 0x200

foff = rva_to_foffset(MD5_ENCODE_RVA)
code = read_bytes(foff, func_size)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

print(f"\nDISASSEMBLY of Md5Encode (0x{MD5_ENCODE_RVA:06x})")
print("=" * 80)

for insn in md.disasm(code, image_base + MD5_ENCODE_RVA):
    addr = insn.address - image_base
    line = f"0x{addr:06x}:  {insn.mnemonic:<8} {insn.op_str}"
    if insn.mnemonic in ('call', 'jmp', 'je', 'jne', 'jg', 'jl', 'ja', 'jb'):
        if len(insn.operands) > 0:
            target = insn.operands[0].imm if insn.operands[0].type == CS_OP_IMM else 0
            if target:
                target_rva = target - image_base
                line += f"   [-> 0x{target_rva:06x}]"
    if 'rsp' in insn.op_str:
        line += "   [STACK]"
    print(line)
