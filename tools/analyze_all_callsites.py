#!/usr/bin/env python3
"""Analyze all 4 Md5Encode call sites context."""
import pefile
from capstone import *
from capstone.x86 import *

LINGMA = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
CALL_SITES = [
    (0x8829b2, "addBigModelSignatureHeaders"),
    (0x8902ef, "COSY signature"),
    (0xc87f54, "unknown3"),
    (0x153d6cf, "unknown4"),
]

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

def read_str_at_rva(rva, maxlen=128):
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

for cs_rva, cs_name in CALL_SITES:
    start = cs_rva - 0x100
    end = cs_rva + 0x10

    foff = rva_to_foffset(start)
    if foff is None:
        print(f"CANNOT READ at {start:06x}")
        continue

    code = read_bytes(foff, end - start)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print(f"\n{'='*80}")
    print(f"CALL SITE: {cs_name} @ 0x{cs_rva:06x}")
    print(f"{'='*80}")

    for insn in md.disasm(code, image_base + start):
        addr = insn.address - image_base
        line = f"0x{addr:06x}:  {insn.mnemonic:<8} {insn.op_str}"

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
                    break

        if addr == cs_rva:
            line += "   <<<<<<<<<< CALL SITE"

        # Track ebx/ecx near the call to see count
        if 'ebx' in insn.op_str and abs(addr - cs_rva) < 0x20:
            line += "   (count?)"

        print(line)
