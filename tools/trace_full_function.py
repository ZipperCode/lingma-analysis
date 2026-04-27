#!/usr/bin/env python3
"""
Trace addBigModelSignatureHeaders from start to Md5Encode call.
"""
import pefile
from capstone import *
from capstone.x86 import *

LINGMA = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
ADD_BIG_MODEL_RVA = 0x882760

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

# Disassemble from 0x882760 to 0x8829c0
start_rva = ADD_BIG_MODEL_RVA
end_rva = 0x8829c0

foff = rva_to_foffset(start_rva)
code = read_bytes(foff, end_rva - start_rva)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

print(f"FULL TRACE: 0x{start_rva:06x} - 0x{end_rva:06x}")
print("=" * 100)

for insn in md.disasm(code, image_base + start_rva):
    addr = insn.address - image_base
    line = f"0x{addr:06x}:  {insn.mnemonic:<8} {insn.op_str}"

    # Annotate calls
    if insn.mnemonic == 'call':
        target = insn.operands[0].imm if insn.operands[0].type == CS_OP_IMM else 0
        if target:
            target_rva = target - image_base
            line += f"   [CALL 0x{target_rva:06x}]"
    elif insn.mnemonic in ('je', 'jne', 'jmp'):
        target = insn.operands[0].imm - image_base if insn.operands[0].type == CS_OP_IMM else 0
        if target:
            line += f"   [JUMP 0x{target:06x}]"

    # Annotate string loads
    if insn.mnemonic == 'lea' and 'rip' in insn.op_str:
        for op in insn.operands:
            if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
                target = insn.address + insn.size + op.mem.disp
                target_rva = target - image_base
                s = read_str_at_rva(target_rva, maxlen=64)
                if s:
                    preview = s[:60].replace('\n', '\\n')
                    line += f"   ['{preview}']"
                break

    # Highlight key instructions
    if 'rsp + 0xe8' in insn.op_str or 'rsp+0xe8' in insn.op_str:
        line += "   <== DATE STR"
    if 'rsp + 0xb8' in insn.op_str or 'rsp+0xb8' in insn.op_str:
        line += "   <== MD5 ARGS"
    if 'rsp + 0x40' in insn.op_str or 'rsp+0x40' in insn.op_str:
        line += "   <== FLAG"
    if addr == 0x8829b2:
        line += "   <<< Md5Encode"

    print(line)
