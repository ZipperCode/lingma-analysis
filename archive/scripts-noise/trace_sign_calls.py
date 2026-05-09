"""Trace signing function's internal calls."""
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

# Calculate actual call targets from the signing function
# Signing function at 0x8821e0
# Internal calls:
# At offset 0x1d0: call 0xc60 -> target = 0x8821e0 + 0x1d0 + 5 + 0xc60 = 0x882e40
# At offset 0x1e0: call 0x1ea0 -> target = 0x8821e0 + 0x1e0 + 5 + 0x1ea0 = 0x884085
# At offset 0x200: call 0x3440 -> target = 0x8821e0 + 0x200 + 5 + 0x3440 = 0x885625
# At offset 0x205: call 0x1f00 -> target = 0x8821e0 + 0x205 + 5 + 0x1f00 = 0x8840ea

# Let me verify by reading the actual bytes
print("Verifying call targets:")
for offset, disp_hex in [(0x1d0, 0xc60), (0x1e0, 0x1ea0), (0x200, 0x3440), (0x205, 0x1f00)]:
    addr = 0x8821e0 + offset
    code = read_at_rva(addr, 5)
    if code[0] == 0xe8:
        actual_disp = struct.unpack('<i', code[1:5])[0]
        target = addr + 5 + actual_disp
        rva = target - IMAGE_BASE
        print(f"  offset 0x{offset:04x} (addr 0x{addr:x}): call disp=0x{actual_disp:x} -> RVA 0x{rva:x} (claimed 0x{0x8821e0+offset+5+disp_hex:x})")

print()

# Now disassemble each target function
targets = []
for offset in [0x1d0, 0x1e0, 0x200, 0x205]:
    addr = 0x8821e0 + offset
    code = read_at_rva(addr, 5)
    if code[0] == 0xe8:
        actual_disp = struct.unpack('<i', code[1:5])[0]
        target_rva = addr + 5 + actual_disp - IMAGE_BASE
        targets.append((offset, target_rva))

for offset, target_rva in targets:
    # Find function start by looking backwards for a function prologue
    # Or just use .pdata
    print(f"\n{'='*70}")
    print(f"Internal function called at signing offset 0x{offset:04x} -> RVA 0x{target_rva:x}")
    print(f"{'='*70}")

    # Check .pdata for function containing this RVA
    pdata_raw_val = pdata_va_val = 0
    for i in range(6):
        off = sect_start + i * 40
        name = binary[off:off + 8].rstrip(b'\x00').decode()
        va = struct.unpack('<I', binary[off + 12:off + 16])[0]
        rp = struct.unpack('<I', binary[off + 20:off + 24])[0]
        if name == '.pdata':
            pdata_raw_val, pdata_va_val = rp, va
            break

    # Find containing function
    found_func = None
    for poff in range(pdata_raw_val, pdata_raw_val + 0x0973ec - 12, 12):
        begin = struct.unpack('<I', binary[poff:poff + 4])[0]
        end = struct.unpack('<I', binary[poff + 4:poff + 8])[0]
        if begin <= target_rva < end:
            found_func = (begin, end)
            break

    if found_func:
        begin, end = found_func
        print(f"  Function in .pdata: RVA 0x{begin:x} - 0x{end:x} (size 0x{end-begin:x})")
        code = read_at_rva(begin, min(end - begin + 0x50, 0x300))
        count = 0
        for insn in md.disasm_lite(code, IMAGE_BASE + begin):
            addr, size, mnem, opstr = insn
            print(f"    0x{addr - IMAGE_BASE:04x}: {mnem:12s} {opstr}")
            count += 1
            if addr - IMAGE_BASE >= end:
                print("    [RET - end of function]")
                break
            if count > 100:
                print("    ... (truncated)")
                break
    else:
        print(f"  NOT FOUND in .pdata! Disassembling from 0x{target_rva:x}:")
        code = read_at_rva(target_rva, 0x200)
        for insn in md.disasm_lite(code, IMAGE_BASE + target_rva):
            addr, size, mnem, opstr = insn
            print(f"    0x{addr - IMAGE_BASE:04x}: {mnem:12s} {opstr}")
            if mnem == 'ret' and insn[0] > 0x50:
                break

# Also check: does the signing function use any crypto/hash functions?
print(f"\n{'='*70}")
print("Looking for crypto-related strings near signing function")
print(f"{'='*70}")

# Search for common crypto-related strings
crypto_strings = ['hmac', 'sha256', 'sha384', 'sha512', 'sha1', 'md5', 'hash',
                   'sign', 'signature', 'secret', 'token', 'salt', 'key']
for cs in crypto_strings:
    idx = 0
    count = 0
    while idx < len(binary) - len(cs):
        pos = binary.find(cs.encode().lower(), idx)
        if pos == -1:
            break
        rva = pos - text_raw + text_va if pos >= text_raw else None
        if rva and 0x880000 <= rva <= 0x886000:
            context = binary[max(0,pos-5):pos+len(cs)+10]
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in context)
            print(f"  '{cs}' at RVA 0x{rva:x}: {printable}")
            count += 1
            if count >= 3:
                break
        idx = pos + 1
