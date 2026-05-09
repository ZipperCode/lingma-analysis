#!/usr/bin/env python3
"""
Deep disassembly of addBigModelSignatureHeaders to trace MD5 preimage construction.
"""
import pefile
from capstone import *
from capstone.x86 import *

LINGMA = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"

# Offsets
ADD_BIG_MODEL_RVA = 0x882760
MD5_ENCODE_RVA    = 0x4563c0

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

# Disassemble a range around the critical area
start_rva = ADD_BIG_MODEL_RVA
end_rva   = ADD_BIG_MODEL_RVA + 0x840  # full function

foff = rva_to_foffset(start_rva)
code = read_bytes(foff, end_rva - start_rva)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# First pass: collect instructions
insns = list(md.disasm(code, image_base + start_rva))
insn_map = {i.address: i for i in insns}

# Find string references via LEA RIP-relative
def get_lea_target(insn):
    if len(insn.operands) >= 2 and insn.operands[1].type == CS_OP_MEM:
        op = insn.operands[1]
        if op.mem.base == X86_REG_RIP:
            disp = op.mem.disp
            return insn.address + insn.size + disp
    return None

# Scan for interesting patterns
print("=" * 80)
print("CRITICAL CONTROL FLOW ANALYSIS")
print("=" * 80)

for i, insn in enumerate(insns):
    addr = insn.address - image_base  # RVA
    line = f"0x{addr:06x}:  {insn.mnemonic:<8} {insn.op_str}"

    # Highlight je/jmp/cmovne/call
    if insn.mnemonic in ('je', 'jne', 'jmp', 'cmovne', 'call'):
        if insn.mnemonic == 'call':
            target = insn.operands[0].imm if insn.operands[0].type == CS_OP_IMM else 0
            if target:
                target_rva = target - image_base
                if target_rva == MD5_ENCODE_RVA:
                    line += f"   <=== CALL Md5Encode @ 0x{target_rva:06x}"
                else:
                    line += f"   <=== CALL 0x{target_rva:06x}"
        elif insn.mnemonic in ('je', 'jne'):
            target = insn.operands[0].imm - image_base if insn.operands[0].type == CS_OP_IMM else 0
            line += f"   <=== jump to 0x{target:06x}"
        elif insn.mnemonic == 'cmovne':
            line += "   <=== CONDITIONAL SELECT"
        print(line)
        continue

    # Highlight rsp references
    if 'rsp' in insn.op_str:
        print(line)
        continue

    # Highlight string loads
    if insn.mnemonic == 'lea' and 'rip' in insn.op_str:
        target = get_lea_target(insn)
        if target:
            target_rva = target - image_base
            s = read_str_at_rva(target_rva)
            if s and len(s) > 5:
                preview = s[:80].replace('\n', '\\n')
                print(f"0x{addr:06x}:  {insn.mnemonic:<8} {insn.op_str}   -> string@{target_rva:06x}: '{preview}'")
                continue

# Detailed trace of 0x882900 - 0x882a00
print("\n" + "=" * 80)
print("DETAILED TRACE [0x882900 - 0x882a00]")
print("=" * 80)

for insn in insns:
    addr = insn.address - image_base
    if 0x882900 <= addr <= 0x882a00:
        line = f"0x{addr:06x}:  {insn.mnemonic:<8} {insn.op_str}"
        # Annotate
        if insn.mnemonic == 'call':
            target = insn.operands[0].imm if insn.operands[0].type == CS_OP_IMM else 0
            if target:
                target_rva = target - image_base
                if target_rva == MD5_ENCODE_RVA:
                    line += "   [CALL Md5Encode]"
                else:
                    line += f"   [CALL 0x{target_rva:06x}]"
        elif insn.mnemonic in ('je', 'jne'):
            target = insn.operands[0].imm - image_base if insn.operands[0].type == CS_OP_IMM else 0
            line += f"   [BRANCH to 0x{target:06x}]"
        elif insn.mnemonic == 'cmovne':
            line += "   [COND MOVE]"
        print(line)

# Check 0x8829a5 target area
print("\n" + "=" * 80)
print("ALTERNATIVE PATH [0x8829a5 - 0x882a50]")
print("=" * 80)

for insn in insns:
    addr = insn.address - image_base
    if 0x8829a5 <= addr <= 0x882a50:
        line = f"0x{addr:06x}:  {insn.mnemonic:<8} {insn.op_str}"
        if insn.mnemonic == 'call':
            target = insn.operands[0].imm if insn.operands[0].type == CS_OP_IMM else 0
            if target:
                target_rva = target - image_base
                line += f"   [CALL 0x{target_rva:06x}]"
        elif insn.mnemonic in ('je', 'jne', 'jmp'):
            target = insn.operands[0].imm - image_base if insn.operands[0].type == CS_OP_IMM else 0
            line += f"   [JUMP to 0x{target:06x}]"
        print(line)

# Check what writes to [rsp+0x40] earlier in function
print("\n" + "=" * 80)
print("TRACE [rsp+0x40] ORIGIN")
print("=" * 80)
for insn in insns:
    addr = insn.address - image_base
    if '[rsp + 0x40]' in insn.op_str or '[rsp+0x40]' in insn.op_str:
        line = f"0x{addr:06x}:  {insn.mnemonic:<8} {insn.op_str}"
        print(line)

# Check what writes to [rsp+0xb8]
print("\n" + "=" * 80)
print("TRACE [rsp+0xb8] ORIGIN")
print("=" * 80)
for insn in insns:
    addr = insn.address - image_base
    if '0xb8' in insn.op_str and 'rsp' in insn.op_str:
        line = f"0x{addr:06x}:  {insn.mnemonic:<8} {insn.op_str}"
        print(line)
