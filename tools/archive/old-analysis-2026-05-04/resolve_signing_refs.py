"""Resolve key string/data references in signing functions."""
import struct
from capstone import *

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000
md = Cs(CS_ARCH_X86, CS_MODE_64)

with open(LINGMA, 'rb') as f:
    binary = f.read()

pe_off = struct.unpack('<I', binary[0x3c:0x40])[0]
opt_size = struct.unpack('<H', binary[pe_off + 20:pe_off + 22])[0]
sect_start = pe_off + 24 + opt_size
sections = {}
for i in range(6):
    off = sect_start + i * 40
    name = binary[off:off + 8].rstrip(b'\x00').decode()
    va = struct.unpack('<I', binary[off + 12:off + 16])[0]
    rp = struct.unpack('<I', binary[off + 20:off + 24])[0]
    vs = struct.unpack('<I', binary[off + 16:off + 20])[0]
    sections[name] = (va, rp, vs)

text_va, text_raw, text_vs = sections['.text']
rdata_va, rdata_raw, rdata_vs = sections['.rdata']
data_va, data_raw, data_vs = sections['.data']

def rva_to_offset(rva):
    for name, (va, rp, vs) in sections.items():
        if va <= rva < va + vs:
            return rp + (rva - va), name
    return None, 'unknown'

def read_at_rva(rva, size=0x100):
    off, sec = rva_to_offset(rva)
    if off is None:
        return None, sec
    return binary[off:off + size], sec

def read_string_at_rva(rva, max_len=100):
    off, sec = rva_to_offset(rva)
    if off is None:
        return '<invalid>', sec
    end = binary.find(b'\x00', off, off + max_len)
    if end == -1:
        return binary[off:off + min(max_len, 50)].decode('utf-8', errors='replace'), sec
    return binary[off:end].decode('utf-8', errors='replace'), sec

def resolve_rip(insn_addr_rva, insn):
    """Resolve RIP-relative address."""
    op = insn.op_str
    if 'rip' not in op:
        return None
    if '+' in op:
        # Handle "rip + 0xXXXX], 1" -> extract just the hex number
        part = op.split('rip + ')[1]
        hex_part = part.split(']')[0].split(',')[0]
        disp = int(hex_part, 16)
    elif '-' in op:
        hex_part = op.split('rip - ')[1].split(']')[0].split(',')[0]
        disp = -int(hex_part, 16)
    else:
        return None
    insn_va = IMAGE_BASE + insn_addr_rva
    rip = insn_va + insn.size
    eff_addr = rip + disp
    return eff_addr - IMAGE_BASE

print("=" * 70)
print("String/data references in MainSigning (0x8821e0)")
print("=" * 70)

func_rva = 0x8821e0
code, sec = read_at_rva(func_rva, 0x400)
for insn in md.disasm(code, func_rva):
    if 'rip' in insn.op_str and insn.mnemonic in ('lea', 'mov', 'cmp', 'test'):
        target_rva = resolve_rip(insn.address, insn)
        if target_rva and 0 < target_rva < 0x6000000:
            content, sec = read_at_rva(target_rva, 40)
            if content is None:
                continue
            # Try as string
            try:
                s = content.split(b'\x00')[0].decode('utf-8', errors='replace')
                if s and all(32 <= ord(c) < 127 or c in '\r\n\t' for c in s[:20]):
                    print(f"  0x{insn.address:04x}: {insn.mnemonic:6s} {insn.op_str:45s} -> RVA 0x{target_rva:x} str='{s[:60]}'")
                    continue
            except:
                pass
            # Show as hex
            hex_str = ' '.join(f'{b:02x}' for b in content[:20])
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in content[:20])
            print(f"  0x{insn.address:04x}: {insn.mnemonic:6s} {insn.op_str:45s} -> RVA 0x{target_rva:x} ({sec}) hex={hex_str} '{printable}'")

print()
print("=" * 70)
print("String/data references in ExtractConfig (0x882e40)")
print("=" * 70)

func_rva = 0x882e40
code, sec = read_at_rva(func_rva, 0x200)
for insn in md.disasm(code, func_rva):
    if 'rip' in insn.op_str and insn.mnemonic in ('lea', 'mov', 'cmp'):
        target_rva = resolve_rip(insn.address, insn)
        if target_rva and 0 < target_rva < 0x6000000:
            content, sec = read_at_rva(target_rva, 40)
            if content is None:
                continue
            try:
                s = content.split(b'\x00')[0].decode('utf-8', errors='replace')
                if s and len(s) > 1 and all(32 <= ord(c) < 127 or c in '\r\n\t' for c in s[:20]):
                    print(f"  0x{insn.address:04x}: {insn.mnemonic:6s} {insn.op_str:45s} -> RVA 0x{target_rva:x} str='{s[:60]}'")
                    continue
            except:
                pass
            hex_str = ' '.join(f'{b:02x}' for b in content[:20])
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in content[:20])
            print(f"  0x{insn.address:04x}: {insn.mnemonic:6s} {insn.op_str:45s} -> RVA 0x{target_rva:x} ({sec}) hex={hex_str} '{printable}'")

print()
print("=" * 70)
print("Identify key runtime functions")
print("=" * 70)

# Key functions to identify
funcs_to_check = {
    0x102e0: "frequent call target (string conversion?)",
    0x11b9e0: "map operation?",
    0x136040: "mapassign_faststr?",
    0x25c7e0: "time/format function?",
    0x258960: "ProcessSliceData calls this",
    0x871620: "flag check?",
    0x871880: "flag check?",
    0x871a60: "AddAuthHeaders calls this",
    0xb10980: "FinalHandler internal call",
    0xb7c40: "FinalHandler -> this near end",
}

for func_rva, desc in funcs_to_check.items():
    # Look at first few instructions
    code, sec = read_at_rva(func_rva, 0x30)
    if code is None:
        print(f"  RVA 0x{func_rva:x}: NOT FOUND ({desc})")
        continue
    insns = list(md.disasm_lite(code, IMAGE_BASE + func_rva))[:5]
    print(f"\n  RVA 0x{func_rva:x} ({desc}):")
    for addr, size, mnem, opstr in insns:
        print(f"    0x{addr - IMAGE_BASE:05x}: {mnem:12s} {opstr}")

# Also check: what strings does ExtractConfig reference?
# Specifically 0x30a8b64 (comparison target at 0x882e75)
print()
print("=" * 70)
print("Global variable references")
print("=" * 70)

globals_to_check = [
    (0x5fa7cc0, "cosy Go string ptr (from earlier analysis)"),
    (0x5fe1c68, "MainSigning global check"),
    (0x5fe1c78, "MainSigning global check"),
    (0x582806a, "Caller global at 0x880f0f"),
]

for rva, desc in globals_to_check:
    content, sec = read_at_rva(rva, 20)
    if content is None:
        print(f"  RVA 0x{rva:x}: NOT IN ANY SECTION ({desc})")
        continue
    hex_str = ' '.join(f'{b:02x}' for b in content)
    # Check if Go string {ptr, len}
    if len(content) >= 16:
        ptr = struct.unpack('<Q', content[0:8])[0]
        length = struct.unpack('<Q', content[8:16])[0]
        if 0 < ptr < 0x6000000 and 0 < length < 1000:
            str_content, str_sec = read_at_rva(ptr - IMAGE_BASE, length)
            if str_content is not None:
                print(f"  RVA 0x{rva:x} ({sec}): Go string -> ptr=0x{ptr:x}, len={length} -> '{str_content.decode('utf-8', errors='replace')}'")
            else:
                print(f"  RVA 0x{rva:x} ({sec}): Go string -> ptr=0x{ptr:x}, len={length} (can't read)")
        else:
            print(f"  RVA 0x{rva:x} ({sec}): {hex_str} ({desc})")
    else:
        print(f"  RVA 0x{rva:x} ({sec}): {hex_str} ({desc})")
