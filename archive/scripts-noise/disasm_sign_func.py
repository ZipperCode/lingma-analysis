"""Disassemble actual functions in signing area from .pdata."""
import struct
from capstone import *

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
md = Cs(CS_ARCH_X86, CS_MODE_64)
IMAGE_BASE = 0x140000000

with open(LINGMA, 'rb') as f:
    binary = f.read()

pe_off = struct.unpack('<I', binary[0x3c:0x40])[0]
opt_size = struct.unpack('<H', binary[pe_off + 20:pe_off + 22])[0]
sect_start = pe_off + 24 + opt_size
text_raw = text_va = pdata_raw = pdata_va = 0
for i in range(6):
    off = sect_start + i * 40
    name = binary[off:off + 8].rstrip(b'\x00').decode()
    va = struct.unpack('<I', binary[off + 12:off + 16])[0]
    rp = struct.unpack('<I', binary[off + 20:off + 24])[0]
    if name == '.text':
        text_raw, text_va = rp, va
    elif name == '.pdata':
        pdata_raw, pdata_va = rp, va

def rva_to_offset(rva):
    return text_raw + (rva - text_va)

def read_at_rva(rva, size=0x1000):
    offset = rva_to_offset(rva)
    return binary[offset:offset + size]

# Known functions from .pdata in the signing area:
# 0x8821e0 - 0x882525 (size 0x345) <- THIS IS THE SIGNING FUNCTION
# 0x882540 - 0x88267e (size 0x13e)
# 0x882680 - 0x88274b (size 0xcb) <- addBigModelSignatureHeaders
# 0x882760 - 0x882b9f (size 0x43f) <- getAppSalt

print("=" * 70)
print("Main signing function @ RVA 0x8821e0 (size 0x345)")
print("=" * 70)
code = read_at_rva(0x8821e0, 0x400)
for insn in md.disasm_lite(code, IMAGE_BASE + 0x8821e0):
    addr, size, mnem, opstr = insn
    print(f"  0x{addr - IMAGE_BASE:04x} (0x{addr:x}): {mnem:12s} {opstr}")
    if addr - IMAGE_BASE > 0x330:
        print("  ... (truncated)")
        break

print()

# Also: what calls 0x8821e0?
print("=" * 70)
print("Finding callers of 0x8821e0")
print("=" * 70)
# Scan .text for CALL instructions targeting 0x8821e0
# The CALL relative displacement = target - (call_addr + 5)
# So call_addr + 5 + disp = 0x8821e0
# disp = 0x8821e0 - call_addr - 5
# We need to search the entire .text section for this pattern
# This is slow, so let's just check known callers

# The caller 0x880da0 might call 0x8821e0 somewhere
# From the disassembly:
# At offset 0x4a1: jne 0x51e
# At 0x4f7: mov rax, [rsp+0x98]
# At 0x504: call 0x1440 -> target = 0x880da0 + 0x504 + 5 + disp
# Capstone shows: call 0x1440 which is the display of the displacement
# Actual target: 0x880da0 + 0x504 + 5 + 0x1440 = 0x8826e9
# Hmm, that's between addBigModelSignatureHeaders (0x882680) and getAppSalt (0x882760)

# Let me check: 0x880da0 + 0x504 = 0x8812a4
# Call instruction at 0x8812a4
# Next instruction at 0x8812a9
# If displacement is 0x1440: target = 0x8812a9 + 0x1440 = 0x8826e9

# But .pdata says no function starts at 0x8826e9. Let me check what's there.
print(f"\nChecking area around 0x8826e9:")
code_check = read_at_rva(0x8826e0, 0x20)
for insn in md.disasm_lite(code_check, IMAGE_BASE + 0x8826e0):
    addr, size, mnem, opstr = insn
    print(f"  0x{addr - IMAGE_BASE:04x}: {mnem:12s} {opstr}")

# Let me also check if 0x8821e0 is called from 0x880da0
# Looking at the caller disassembly again...
# At offset 0x4f7 in caller: call 0x1440
# This is 0x880da0 + 0x4f7 = 0x881297
# Wait, that's the MOV instruction. Let me look again.

# From the full caller disassembly:
# 0x04f7 (0x140881297): mov          rax, qword ptr [rsp + 0x98]
# 0x0504 (0x1408812a4): call         0x1440

# So the call is at 0x8812a4, and the relative operand is 0x1440
# Target = 0x8812a4 + 5 + 0x1440 = 0x8826e9
# But 0x8826e9 is not a function start in .pdata!

# Wait - Capstone displays the RELATIVE offset as the operand.
# The operand shown is `0x1440` which is the 32-bit signed displacement.
# Target = next_instruction + displacement = 0x8812a9 + 0x1440 = 0x8826e9

# Hmm but this could also be a CALL ABSOLUTE if Capstone is parsing it wrong.
# Let me check the actual bytes at that offset
code_at_call = read_at_rva(0x8812a4, 10)
print(f"\nBytes at 0x8812a4: {code_at_call.hex(' ')}")
# If it's e8 XX XX XX XX, it's a relative call
# If it's ff XX ..., it could be an absolute call

# Let me also look at what's at 0x8826e9
print(f"\nBytes at 0x8826e9: {read_at_rva(0x8826e9, 10).hex(' ')}")
for insn in md.disasm_lite(read_at_rva(0x8826e9, 20), IMAGE_BASE + 0x8826e9):
    addr, size, mnem, opstr = insn
    print(f"  0x{addr - IMAGE_BASE:04x}: {mnem:12s} {opstr}")

print()

# The function at 0x8821e0 is the one we need to focus on.
# Let me also check the function at 0x882540 (between addBigModelSignatureHeaders and getAppSalt)
print("=" * 70)
print("Function @ RVA 0x882540 (size 0x13e)")
print("=" * 70)
code = read_at_rva(0x882540, 0x150)
for insn in md.disasm_lite(code, IMAGE_BASE + 0x882540):
    addr, size, mnem, opstr = insn
    print(f"  0x{addr - IMAGE_BASE:04x}: {mnem:12s} {opstr}")
    if addr - IMAGE_BASE > 0x130:
        break
