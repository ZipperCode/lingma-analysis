"""Trace crypto functions to understand signing algorithm.
Search for crypto/hmac, crypto/sha256, crypto/sha512 usage near signing code."""
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

# 1. Find all crypto package strings in .rdata
print("=" * 70)
print("Crypto-related package strings in .rdata")
print("=" * 70)

crypto_pkgs = [
    b'crypto/hmac', b'crypto/sha256', b'crypto/sha512', b'crypto/sha1',
    b'crypto/md5', b'hash/fnv', b'hash/crc32', b'hash/maphash',
    b'hmacSHA', b'HMAC', b'NewSHA', b'Sum256', b'Sum512',
    b'hmac.go', b'sha256.go', b'sha512.go',
    b'Authorization', b'X-Date', b'X-Signature', b'X-Appcode',
    b'Signature ', b'secret_key', b'app_secret', b'signing_key',
    b'big_model_sign', b'bigmodel',
]

rdata_end = rdata_raw + rdata_vs
for pkg in crypto_pkgs:
    idx = rdata_raw
    count = 0
    while idx < rdata_end - len(pkg):
        pos = binary.find(pkg, idx, rdata_end)
        if pos == -1:
            break
        rva = pos - rdata_raw + rdata_va
        # Show context
        ctx_start = max(rdata_raw, pos - 10)
        ctx_end = min(rdata_end, pos + len(pkg) + 30)
        ctx = binary[ctx_start:ctx_end]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
        marker = '.' * 10 + pkg.decode() + '.' * 30
        print(f'  {pkg.decode():25s} @ RVA 0x{rva:x} (offset 0x{pos:x}): {printable[:60]}')
        count += 1
        if count >= 3:
            break
        idx = pos + 1

# 2. Find pdata entries for crypto-related functions
print()
print("=" * 70)
print("Functions in the signing/crypto RVA range (0x880000 - 0x886000)")
print("=" * 70)

pdata_va, pdata_raw, pdata_vs = sections['.pdata']
pdata_end = pdata_raw + pdata_vs
funcs_in_range = []
for poff in range(pdata_raw, pdata_end - 12, 12):
    begin = struct.unpack('<I', binary[poff:poff + 4])[0]
    end = struct.unpack('<I', binary[poff + 4:poff + 8])[0]
    if 0x880000 <= begin < 0x886000:
        funcs_in_range.append((begin, end))

print(f"  Found {len(funcs_in_range)} functions in 0x880000-0x886000 range:")
for begin, end in sorted(funcs_in_range):
    size = end - begin
    # Read first 30 bytes to look for string references
    code, sec = read_at_rva(begin, 50)
    if code is None:
        continue
    # Check for RIP-relative string refs in first 10 instructions
    str_refs = []
    for insn in md.disasm(code, IMAGE_BASE + begin):
        if 'rip' in insn.op_str and insn.mnemonic == 'lea':
            op = insn.op_str
            if 'rip +' in op:
                disp = int(op.split('rip + ')[1].split(']')[0].split(',')[0], 16)
            elif 'rip -' in op:
                disp = -int(op.split('rip - ')[1].split(']')[0].split(',')[0], 16)
            else:
                continue
            rip = insn.address + insn.size
            eff_addr = rip + disp - IMAGE_BASE
            if eff_addr > 0x1000:
                content, csec = read_at_rva(eff_addr, 30)
                if content:
                    try:
                        s = content.split(b'\x00')[0].decode('utf-8', errors='replace')
                        if len(s) > 3 and all(32 <= ord(c) < 127 for c in s[:15]):
                            str_refs.append(s[:50])
                    except:
                        pass
        if insn.address > IMAGE_BASE + begin + 80:
            break
    if str_refs:
        print(f"    RVA 0x{begin:x} - 0x{end:x} (size 0x{size:4x}): {' | '.join(str_refs[:2])}")
    else:
        print(f"    RVA 0x{begin:x} - 0x{end:x} (size 0x{size:4x})")

# 3. Look for functions that reference "Authorization" header
print()
print("=" * 70)
print("Functions referencing 'Authorization' string")
print("=" * 70)

auth_rvas = []
idx = rdata_raw
while idx < rdata_end - 14:
    pos = binary.find(b'Authorization', idx, rdata_end)
    if pos == -1:
        break
    rva = pos - rdata_raw + rdata_va
    auth_rvas.append(rva)
    ctx = binary[max(0,pos-5):pos+20]
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
    print(f"  'Authorization' @ RVA 0x{rva:x}: {printable}")
    idx = pos + 1
    if len(auth_rvas) >= 10:
        break

# 4. Find the caller that references 0x8821e0 (MainSigning)
# and trace what type of endpoint triggers it
print()
print("=" * 70)
print("Endpoint string analysis (what triggers signing)")
print("=" * 70)

# From Caller function: endpoint strings compared
# 0x68747561 = "auth" (little-endian)
# 0x6e676973 = "sign"
# 0x6f6c7075 + 0x6461 = "upload"
endpoint_str_rvas = []
# Find where these endpoint strings are defined in .rdata
for ep in [b'auth', b'sign', b'signing', b'upload', b'bigmodel', b'algo']:
    idx = rdata_raw
    while idx < rdata_end - len(ep):
        pos = binary.find(ep, idx, rdata_end)
        if pos == -1:
            break
        # Check if this is a standalone string (surrounded by non-alpha chars or at boundary)
        before = binary[pos-1] if pos > rdata_raw else 0
        after = binary[pos+len(ep)] if pos+len(ep) < rdata_end else 0
        if not (65 <= before <= 90 or 97 <= before <= 122) and not (65 <= after <= 90 or 97 <= after <= 122):
            rva = pos - rdata_raw + rdata_va
            ctx = binary[max(0,pos-3):pos+len(ep)+10]
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
            print(f"  '{ep.decode()}' @ RVA 0x{rva:x}: ...{printable}...")
            endpoint_str_rvas.append(rva)
            break  # Just first match
        idx = pos + 1

# 5. Trace the cosy/remoting/api package functions
print()
print("=" * 70)
print("cosy/remoting/api functions (likely HTTP request builders)")
print("=" * 70)

# Search for strings that indicate API endpoint construction
api_patterns = [
    b'cosy/remoting/api',
    b'GetAuthorizationHeader',
    b'GetBigModelEndpoint',
    b'BuildBigModelAuthRequest',
    b'RemoteConfig',
    b'BigModelEndpoint',
    b'AppSalt',
    b'appSalt',
]

for pat in api_patterns:
    idx = 0
    count = 0
    while idx < len(binary) - len(pat):
        pos = binary.find(pat, idx)
        if pos == -1:
            break
        # Check which section
        for sname, (va, rp, vs) in sections.items():
            if rp <= pos < rp + vs:
                rva = pos - rp + va
                ctx = binary[max(0,pos-3):pos+len(pat)+15]
                printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
                print(f"  {pat.decode():35s} @ RVA 0x{rva:x} ({sname}): {printable[:50]}")
                count += 1
                if count >= 3:
                    break
                break
        idx = pos + 1
