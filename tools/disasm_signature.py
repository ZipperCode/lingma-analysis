"""Static analysis: disassemble signature-related functions."""
import struct
from capstone import *

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

IMAGE_BASE = 0x140000000

# Read entire binary
with open(LINGMA, 'rb') as f:
    binary = f.read()

# Parse PE
pe_off = struct.unpack('<I', binary[0x3c:0x40])[0]
opt_size = struct.unpack('<H', binary[pe_off + 20:pe_off + 22])[0]
sect_start = pe_off + 24 + opt_size

text_raw = text_va = text_vs = 0
for i in range(6):
    off = sect_start + i * 40
    name = binary[off:off + 8].rstrip(b'\x00').decode()
    vs = struct.unpack('<I', binary[off + 8:off + 12])[0]
    va = struct.unpack('<I', binary[off + 12:off + 16])[0]
    rs = struct.unpack('<I', binary[off + 16:off + 20])[0]
    rp = struct.unpack('<I', binary[off + 20:off + 24])[0]
    if name == '.text':
        text_raw, text_va, text_vs = rp, va, vs
        break

def rva_to_offset(rva):
    return text_raw + (rva - text_va)

def read_at_rva(rva, size=0x2000):
    offset = rva_to_offset(rva)
    return binary[offset:offset + size]

def disasm_range(rva, max_size=0x500, max_insns=500, stop_on_ret=True):
    """Disassemble from RVA until ret or max."""
    code = read_at_rva(rva, max_size)
    base_addr = IMAGE_BASE + rva
    lines = []
    count = 0
    for insn in md.disasm(code, 0):
        addr = base_addr + insn.address
        lines.append(f"  0x{insn.address:04x} (0x{addr:x}): {insn.mnemonic:12s} {insn.op_str}")
        count += 1
        if count >= max_insns:
            lines.append("  ... (truncated)")
            break
        if stop_on_ret and insn.mnemonic == 'ret' and count > 10:
            lines.append("  [RET]")
            break
        if insn.address > max_size - 20:
            lines.append("  ... (truncated)")
            break
    return "\n".join(lines)


# 1. addBigModelSignatureHeaders @ 0x882680
print("=" * 70)
print("addBigModelSignatureHeaders @ RVA 0x882680")
print("=" * 70)
print(disasm_range(0x882680, max_size=0x300))

print()

# 2. getAppSalt @ 0x882760
print("=" * 70)
print("getAppSalt @ RVA 0x882760")
print("=" * 70)
print(disasm_range(0x882760, max_size=0x500))

print()

# 3. Caller function @ 0x880da0 - getAppSalt call around 0x88114f (offset 0x3af)
print("=" * 70)
print("Caller @ RVA 0x880da0 (second half, offset 0x2a0-0x700)")
print("=" * 70)
print(disasm_range(0x880da0, max_size=0x700, stop_on_ret=False))

print()

# 4. Extract strings referenced in caller function
print("=" * 70)
print("String constants referenced in caller function")
print("=" * 70)

def read_string_at_rva(rva, max_len=64):
    """Read null-terminated or length-delimited string."""
    offset = rva_to_offset(rva)
    data = binary[offset:offset + max_len]
    try:
        # Find null terminator
        null_idx = data.find(b'\x00')
        if null_idx > 0:
            return data[:null_idx].decode('utf-8', errors='replace')
        return data.decode('utf-8', errors='replace')
    except:
        return data.hex()

# Strings from getAppSalt
# At 0x8827e6: lea rdi, [rip + 0x1c5e4bc] -> string "Date" (length 4)
str1_rva = 0x8827ea + 0x1c5e4bc  # RIP is at next instruction
print(f"  getAppSalt key1 string @ RVA 0x{str1_rva - IMAGE_BASE:x}: '{read_string_at_rva(str1_rva - IMAGE_BASE, 10)}'")

# At 0x882844: lea rax, [rip + 0x1c0c693] -> string key for first map entry
str2_rva = 0x88284b + 0x1c0c693
print(f"  getAppSalt key1 @ RVA 0x{str2_rva - IMAGE_BASE:x}: '{read_string_at_rva(str2_rva - IMAGE_BASE, 10)}'")

# At 0x8829d6: lea rax, [rip + 0x1c17cf2] -> string key for second map entry
str3_rva = 0x8829dd + 0x1c17cf2
print(f"  getAppSalt key2 @ RVA 0x{str3_rva - IMAGE_BASE:x}: '{read_string_at_rva(str3_rva - IMAGE_BASE, 15)}'")

# At 0x882ac7: lea rax, [rip + 0x1c12cb0] -> string key for third map entry
str4_rva = 0x882ace + 0x1c12cb0
print(f"  getAppSalt key3 @ RVA 0x{str4_rva - IMAGE_BASE:x}: '{read_string_at_rva(str4_rva - IMAGE_BASE, 15)}'")

# Global variable at 0x5fa7cc0 -> "cosy"
# This is in .data section, need to convert to offset
appcode_rva = 0x5fa7cc0
print(f"  Appcode global @ RVA 0x{appcode_rva:x}: '{read_string_at_rva(appcode_rva, 20)}'")

# Date format string from previous analysis: RVA 0x24e0c9d
date_fmt_rva = 0x24e0c9d
print(f"  Date format @ RVA 0x{date_fmt_rva:x}: '{read_string_at_rva(date_fmt_rva, 40)}'")

# Caller string comparisons: 0x68747561 = "auth", 0x6e676973 = "sign"
# Let's find the actual strings
print()
print("  Caller string comparison values:")
print(f"    0x68747561 = '{bytes.fromhex('68747561')[::-1].decode()}' (little-endian)")
print(f"    0x6e676973 = '{bytes.fromhex('6e676973')[::-1].decode()}' (little-endian)")
print(f"    0x6f6c7075 = '{bytes.fromhex('6f6c7075')[::-1].decode()}' (little-endian)")
print(f"    0x6461 = '{bytes.fromhex('6461')[::-1].decode()}' (little-endian)")
print(f"    0x5550 = '{bytes.fromhex('5550')[::-1].decode()}' (little-endian)")
print(f"    0x54 = '{chr(0x54)}' (single byte)")

print()

# 5. Extract the signature computation flow
print("=" * 70)
print("Signature computation flow analysis")
print("=" * 70)
print("""
1. Caller (0x880da0) iterates through a slice of strings
2. Checks if string == "auth", "signing", "upload", or "PUT"
3. If "auth" (0x399 je 0x3c6):
   - 0x3c6: xor eax, eax (set return to 0)
   - 0x3c8: cleanup and call 0x1e00
   - NO getAppSalt call
4. If "signing" (0x3a1 jne 0x494):
   - Falls through to 0x3a7 -> 0x3af: call getAppSalt!
5. If string ends with other paths, getAppSalt may or may not be called

Key insight: getAppSalt is called ONLY when the API endpoint contains "signing"!
""")

# 6. Deep dive into getAppSalt's map construction
print("=" * 70)
print("getAppSalt map construction detail")
print("=" * 70)

# Let me identify the 3 mapassign_faststr calls and their values
code = read_at_rva(0x882760, 0x500)

# Find all call instructions and their targets
print("\nKey calls in getAppSalt:")
for insn in md.disasm(code, 0):
    addr = IMAGE_BASE + 0x882760 + insn.address
    if insn.mnemonic == 'call':
        # Calculate target
        target = insn.address + 5  # next instruction
        # The operand is relative
        print(f"  0x{insn.address:04x}: call {insn.op_str} (absolute: 0x{addr + insn.size + int(insn.op_str, 16) if insn.op_str.startswith('0x') or insn.op_str.startswith('-') else '?':x})")
    if insn.mnemonic == 'ret' and insn.address > 0x400:
        break

# 7. Analyze addBigModelSignatureHeaders callers
print()
print("=" * 70)
print("addBigModelSignatureHeaders analysis")
print("=" * 70)
print("""
addBigModelSignatureHeaders (0x882680) is very short:
1. 0x2c: lea rcx, [rip + 0x1c36574] -> load some config pointer
2. 0x38: call 0xffffffffff8b39c0 -> helper function (likely get config value)
3. 0x40: test rax, rax -> check result
4. 0x43: jge 0x91 -> if >= 0, skip error
5. 0x4f: lea rcx, [rip + 0x1c51662] -> load another config
6. 0x60: call same helper
7. 0x65: test rax, rax
8. 0x68: jl 0x72 -> if < 0, error
9. 0x6a: xor eax, eax -> return 0 (success)

This function likely:
- Retrieves/validates the signing configuration
- Returns 0 on success, non-zero on failure
- The caller (0x880da0) at 0x14f calls this to check if signing is available
- If success (al != 0 in test), continues to check for "signing" endpoint
""")
