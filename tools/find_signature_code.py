"""
在二进制中搜索签名计算代码
"""
import struct

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

# Search for signature-related strings
print("=== Searching for signature-related strings ===")
sig_strings = [
    b'Signature',
    b'signature',
    b'cosy-sign',
    b'SignBody',
    b'SignRequest',
    b'ComputeSignature',
    b'CalculateSignature',
    b'signBody',
    b'requestSign',
    b'signRequest',
    b'HmacMD5',
    b'HmacSHA',
    b'md5.Encode',
    b'MD5Encode',
]

for s in sig_strings:
    pos = pe_data.find(s)
    if pos >= 0:
        count = 0
        start = 0
        positions = []
        while True:
            p = pe_data.find(s, start)
            if p < 0:
                break
            positions.append(p)
            start = p + 1
            count += 1
            if count > 5:
                break

        print(f"\n  '{s.decode()}' found at {count}+ positions:")
        for pos in positions[:3]:
            ctx_start = max(0, pos - 40)
            ctx_end = min(len(pe_data), pos + len(s) + 60)
            ctx = pe_data[ctx_start:ctx_end]
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
            print(f"    0x{pos:07x}: ...{printable}...")

# Also search for MD5-related function names
print("\n\n=== Searching for MD5 functions ===")
md5_funcs = [
    b'MD5',
    b'md5',
    b'Md5Encode',
    b'md5Encode',
    b'crypto/md5',
    b'NewMD5',
    b'HashMD5',
    b'hmac',
    b'HMAC',
]

for func in md5_funcs:
    # Look for function name in pclntab (full qualified name)
    positions = []
    start = 0
    while True:
        pos = pe_data.find(func, start)
        if pos < 0:
            break
        # Check if this is part of a function name
        # Function names in pclntab look like: package.Function
        # or are surrounded by null bytes
        ctx = pe_data[max(0, pos-1):pos+len(func)+1]
        if len(ctx) > len(func) + 1:
            before = ctx[0]
            after = ctx[len(func)]
            # If surrounded by non-printable chars, it's likely a separate string
            if (before < 32 or before >= 127) and (after < 32 or after >= 127):
                positions.append(pos)
        start = pos + 1

    if positions:
        print(f"\n  '{func.decode()}' found at {len(positions)} positions as standalone string")
        for pos in positions[:5]:
            ctx_start = max(0, pos - 30)
            ctx_end = min(len(pe_data), pos + 50)
            ctx = pe_data[ctx_start:ctx_end]
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
            print(f"    0x{pos:07x}: ...{printable}...")

# Search for the signing function name in the cosy package
print("\n\n=== Searching for cosy signing functions ===")
sign_patterns = [
    b'cosy/auth',
    b'cosy/sign',
    b'cosy/crypto',
    b'cosy/util.Sign',
    b'cosy/network.Sign',
    b'cosy/client.Sign',
    b'cosy/http.Sign',
    b'cosy/remoting.Sign',
    b'cosy/middleware',
    b'cosy/interceptor',
]

for pattern in sign_patterns:
    pos = pe_data.find(pattern)
    if pos >= 0:
        # Show context
        ctx = pe_data[pos:pos+200]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
        print(f"\n  Found '{pattern.decode()}' at 0x{pos:x}")
        print(f"  Context: {printable}")

# The signature might also be computed in the IDE plugin side (not the binary)
# Let's check if there are any JS/TS files in the capture or project
print("\n\n=== Checking for plugin source code ===")
import glob
js_files = glob.glob('**/*.js', recursive=True)[:10]
ts_files = glob.glob('**/*.ts', recursive=True)[:10]
if js_files:
    print(f"Found {len(js_files)} JS files")
    if ts_files:
        print(f"Found {len(ts_files)} TS files")
