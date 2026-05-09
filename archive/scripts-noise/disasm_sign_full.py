"""Full disassembly of the main signing function at 0x8821e0."""
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
text_raw = text_va = 0
for i in range(6):
    off = sect_start + i * 40
    name = binary[off:off + 8].rstrip(b'\x00').decode()
    va = struct.unpack('<I', binary[off + 12:off + 16])[0]
    rp = struct.unpack('<I', binary[off + 20:off + 24])[0]
    if name == '.text':
        text_raw, text_va = rp, va
        break

def rva_to_offset(rva):
    return text_raw + (rva - text_va)

def read_at_rva(rva, size=0x1000):
    offset = rva_to_offset(rva)
    return binary[offset:offset + size]

def resolve_rip(buf_offset, insn, func_rva):
    """Resolve RIP-relative reference."""
    actual_addr = IMAGE_BASE + func_rva + buf_offset
    rip = actual_addr + insn.size
    op = insn.op_str
    if 'rip +' in op:
        disp = int(op.split('rip + ')[1].rstrip(']'), 16)
    elif 'rip -' in op:
        disp = -int(op.split('rip - ')[1].rstrip(']'), 16)
    else:
        return None
    eff_addr = rip + disp
    return eff_addr - IMAGE_BASE

# Full disassembly of signing function 0x8821e0
FUNC_RVA = 0x8821e0
code = read_at_rva(FUNC_RVA, 0x400)

print("=" * 70)
print(f"Signing function @ RVA 0x{FUNC_RVA:x} (full)")
print("=" * 70)

rip_refs = []
calls = []

for insn in md.disasm(code, 0):
    addr = IMAGE_BASE + FUNC_RVA + insn.address
    mnem = insn.mnemonic
    opstr = insn.op_str

    # Track RIP references
    if 'rip' in opstr and mnem in ('lea', 'mov', 'cmp'):
        rva = resolve_rip(insn.address, insn, FUNC_RVA)
        if rva and 0 < rva < 0x6000000:
            rip_refs.append((insn.address, mnem, opstr, rva))

    # Track calls
    if mnem == 'call':
        # Calculate target
        if opstr.startswith('0xffff'):
            # Relative negative offset
            disp = int(opstr, 16)
            if disp > 0x80000000:
                disp -= 0x100000000
            target = addr + insn.size + disp - IMAGE_BASE
        else:
            target = int(opstr, 16) - IMAGE_BASE if opstr.startswith('0x') else '?'
        calls.append((insn.address, opstr, target))

    # Print instruction
    print(f"  0x{insn.address:04x} (0x{addr:x}): {mnem:12s} {opstr}")

    # Stop at ret
    if mnem == 'ret' and insn.address > 0x100:
        print("  [RET - function end]")
        break
    if insn.address > 0x3f0:
        print("  ... (truncated)")
        break

print()

# Print all RIP references
print("=" * 70)
print("RIP references in signing function")
print("=" * 70)
for off, mnem, opstr, rva in rip_refs:
    # Read content at target
    data = read_at_rva(rva, 30)
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in data)
    print(f"  0x{off:04x}: {mnem:6s} {opstr:40s} -> RVA 0x{rva:x} '{printable[:35]}'")

print()

# Print all calls
print("=" * 70)
print("Calls in signing function")
print("=" * 70)
for off, opstr, target in calls:
    print(f"  0x{off:04x}: call {opstr} -> RVA {target if isinstance(target, str) else f'0x{target:x}'}")

# Now let's look at key areas referenced by the signing function
print()
print("=" * 70)
print("Key string/data references")
print("=" * 70)

# Check specific interesting RIP refs
interesting_rvas = [rva for _, _, _, rva in rip_refs if rva < 0x3000000]
for rva in sorted(set(interesting_rvas)):
    data = read_at_rva(rva, 50)
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in data)
    # Check if it looks like a string
    if any(printable[i:i+4].isascii() and printable[i:i+4].isprintable()
           for i in range(min(20, len(printable)-4))):
        print(f"  RVA 0x{rva:x}: '{printable[:45]}'")
