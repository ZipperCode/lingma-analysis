#!/usr/bin/env python3
"""Analyze Md5Encode call site 2 at 0x8902ef (COSY signature)."""
import pefile
from capstone import *
from capstone.x86 import *

LINGMA = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
TARGET_RVA = 0x8902ef

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

def read_str_at_rva(rva, maxlen=256):
    off = rva_to_foffset(rva)
    if off is None:
        return None
    with open(LINGMA, 'rb') as f:
        f.seek(off)
        data = f.read(maxlen)
        end = data.find(b'\x00')
        if end >= 0:
            data = data[:end]
        try:
            return data.decode('utf-8')
        except:
            return data.hex()

# Disassemble around the call site
start_rva = TARGET_RVA - 0x300  # Go back 0x300 bytes
end_rva = TARGET_RVA + 0x30

foff = rva_to_foffset(start_rva)
code = read_bytes(foff, end_rva - start_rva)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

print(f"CONTEXT AROUND Md5Encode CALL SITE 2 (0x{TARGET_RVA:06x})")
print("=" * 100)

for insn in md.disasm(code, image_base + start_rva):
    addr = insn.address - image_base
    line = f"0x{addr:06x}:  {insn.mnemonic:<8} {insn.op_str}"

    # Annotate string loads
    if insn.mnemonic == 'lea' and 'rip' in insn.op_str:
        for op in insn.operands:
            if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
                target = insn.address + insn.size + op.mem.disp
                target_rva = target - image_base
                s = read_str_at_rva(target_rva, maxlen=80)
                if s:
                    preview = s[:70].replace('\n', '\\n')
                    line += f"   ['{preview}']"
                break

    # Highlight the call
    if insn.mnemonic == 'call':
        target = insn.operands[0].imm if insn.operands[0].type == CS_OP_IMM else 0
        if target:
            target_rva = target - image_base
            if target_rva == 0x4563c0:
                line += "   <<< Md5Encode"
            else:
                line += f"   [CALL 0x{target_rva:06x}]"

    # Highlight some stack references
    if 'rsp + 0x' in insn.op_str or 'rsp+0x' in insn.op_str:
        if 'rsp + 0x' in insn.op_str:
            offset = insn.op_str.split('rsp + 0x')[1].split(']')[0]
        else:
            offset = insn.op_str.split('rsp+0x')[1].split(']')[0]
        try:
            val = int(offset, 16)
            if val >= 0x80:
                line += "   <== STR ARRAY?"
        except:
            pass

    print(line)
    if addr >= end_rva - 0x10:
        break
