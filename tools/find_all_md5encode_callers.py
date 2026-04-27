#!/usr/bin/env python3
"""
Find all callers of Md5Encode (0x4563c0) in the binary to understand its signature.
"""
import pefile
from capstone import *
from capstone.x86 import *

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

# Disassemble the entire .text section to find all call instructions
text_section = None
for s in pe.sections:
    if s.Name.decode('utf-8').strip('\x00') == '.text':
        text_section = s
        break

if not text_section:
    print(".text section not found")
    exit(1)

foff = text_section.PointerToRawData
code = read_bytes(foff, text_section.SizeOfRawData)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

insns = list(md.disasm(code, image_base + text_section.VirtualAddress))

# Find all call 0x1404563c0
call_sites = []
for i, insn in enumerate(insns):
    if insn.mnemonic == 'call':
        target = insn.operands[0].imm if insn.operands[0].type == CS_OP_IMM else 0
        if target and (target - image_base) == MD5_ENCODE_RVA:
            call_rva = insn.address - image_base
            call_sites.append((i, call_rva))

print(f"Found {len(call_sites)} call sites to Md5Encode\n")

# For each call site, print surrounding instructions
for idx, (insn_idx, call_rva) in enumerate(call_sites):
    print(f"=== Call site {idx+1}: 0x{call_rva:06x} ===")
    start = max(0, insn_idx - 12)
    end = min(len(insns), insn_idx + 5)
    for j in range(start, end):
        a = insns[j].address - image_base
        marker = " >>>" if j == insn_idx else ""
        print(f"  0x{a:06x}:  {insns[j].mnemonic:<8} {insns[j].op_str}{marker}")
    print()
