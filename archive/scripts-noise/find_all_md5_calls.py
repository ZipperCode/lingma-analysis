#!/usr/bin/env python3
"""
Find all calls to Md5Encode within addBigModelSignatureHeaders.
"""
import pefile
from capstone import *
from capstone.x86 import *

LINGMA = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
ADD_BIG_MODEL_RVA = 0x882760
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

start_rva = ADD_BIG_MODEL_RVA
end_rva = ADD_BIG_MODEL_RVA + 0x840

foff = rva_to_foffset(start_rva)
code = read_bytes(foff, end_rva - start_rva)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

insns = list(md.disasm(code, image_base + start_rva))

print("All calls to Md5Encode in addBigModelSignatureHeaders:")
for i, insn in enumerate(insns):
    addr = insn.address - image_base
    if insn.mnemonic == 'call':
        target = insn.operands[0].imm if insn.operands[0].type == CS_OP_IMM else 0
        if target and (target - image_base) == MD5_ENCODE_RVA:
            print(f"\n=== Call at 0x{addr:06x} ===")
            # Print 10 instructions before
            start_idx = max(0, i - 15)
            for j in range(start_idx, i + 1):
                a = insns[j].address - image_base
                print(f"  0x{a:06x}:  {insns[j].mnemonic:<8} {insns[j].op_str}")
            # Print 5 instructions after
            for j in range(i + 1, min(len(insns), i + 6)):
                a = insns[j].address - image_base
                print(f"  0x{a:06x}:  {insns[j].mnemonic:<8} {insns[j].op_str}")

# Also find any references to "cosy" string in the binary
print("\n" + "=" * 80)
print("Searching for 'cosy' references in code...")
print("=" * 80)
for i, insn in enumerate(insns):
    addr = insn.address - image_base
    if insn.mnemonic == 'lea' and 'rip' in insn.op_str:
        target = None
        for op in insn.operands:
            if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
                target = insn.address + insn.size + op.mem.disp
                break
        if target:
            target_rva = target - image_base
            # Read string
            off = rva_to_foffset(target_rva)
            if off:
                with open(LINGMA, 'rb') as f:
                    f.seek(off)
                    data = f.read(64)
                    end = data.find(b'\x00')
                    if end >= 0:
                        data = data[:end]
                    if data.startswith(b'cosy'):
                        try:
                            s = data.decode('utf-8')
                            print(f"0x{addr:06x}: lea -> 'cosy' @ 0x{target_rva:08x}: '{s[:60]}'")
                        except:
                            pass
