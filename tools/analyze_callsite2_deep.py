#!/usr/bin/env python3
"""Deep analysis of Md5Encode call site 2 (COSY signature) @ 0x8902ef."""
import pefile
from capstone import *
from capstone.x86 import *

LINGMA = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
pe = pefile.PE(LINGMA)
image_base = pe.OPTIONAL_HEADER.ImageBase

def rva_to_foffset(rva):
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
            return section.PointerToRawData + (rva - section.VirtualAddress)
    return None

def read_bytes_at_rva(rva, size):
    off = rva_to_foffset(rva)
    if off is None: return None
    with open(LINGMA, 'rb') as f:
        f.seek(off)
        return f.read(size)

def read_str_at_rva(rva, maxlen=128):
    off = rva_to_foffset(rva)
    if off is None: return None
    with open(LINGMA, 'rb') as f:
        f.seek(off)
        data = f.read(maxlen)
        end = data.find(b'\x00')
        if end >= 0: data = data[:end]
        try: return data.decode('utf-8')
        except: return data.hex()

# Analyze call site 2 at 0x8902ef - go back 0x200 bytes for context
start_rva = 0x8902ef - 0x200
end_rva = 0x8902ef + 0x10

foff = rva_to_foffset(start_rva)
code = read_bytes_at_rva(start_rva, end_rva - start_rva)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

print(f"CALL SITE 2 (COSY signature) @ 0x8902ef - FULL CONTEXT")
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
                    preview = s[:60].replace('\n', '\\n')
                    line += f"   ['{preview}']"
                break

    if insn.mnemonic == 'call':
        for op in insn.operands:
            if op.type == CS_OP_IMM:
                target_rva = op.imm - image_base
                if target_rva == 0x4563c0:
                    line += "   <<< Md5Encode"
                else:
                    line += f"   [CALL 0x{target_rva:06x}]"
                break

    if addr == 0x8902ef:
        line += "   <<<<<<<<<< CALL SITE"

    if abs(addr - 0x8902ef) < 0x30:
        if 'ebx' in insn.op_str or 'rbx' in insn.op_str:
            line += "   (count?)"

    print(line)
