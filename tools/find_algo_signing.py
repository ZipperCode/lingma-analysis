"""
分析 algo API 相关的签名和编码函数
"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

def parse_sections(pe_data):
    e_lfanew = struct.unpack('<I', pe_data[60:64])[0]
    coff_offset = e_lfanew + 4
    num_sections = struct.unpack('<H', pe_data[coff_offset+2:coff_offset+4])[0]
    opt_header_size = struct.unpack('<H', pe_data[coff_offset+16:coff_offset+18])[0]
    section_offset = coff_offset + 20 + opt_header_size
    sections = []
    for i in range(num_sections):
        sec = pe_data[section_offset + i*40 : section_offset + (i+1)*40]
        sections.append({
            'name': sec[0:8].rstrip(b'\x00').decode('ascii', errors='replace'),
            'virtual_address': struct.unpack('<I', sec[12:16])[0],
            'virtual_size': struct.unpack('<I', sec[8:12])[0],
            'raw_offset': struct.unpack('<I', sec[20:24])[0],
            'raw_size': struct.unpack('<I', sec[16:20])[0],
        })
    return sections

def va_to_file_offset(sections, va):
    for sec in sections:
        va_start = sec['virtual_address']
        va_end = va_start + max(sec['virtual_size'], sec['raw_size'])
        if va_start <= va < va_end:
            return sec['raw_offset'] + (va - va_start)
    return None

sections = parse_sections(pe_data)
md = Cs(CS_ARCH_X86, CS_MODE_64)

# Find all algo-related function names
print("=== Algo-related function names ===")
algo_funcs = [
    b'cosy/remoting.BuildAlgoForRequestUrl',
    b'cosy/remoting.GetMessageEncode',
    b'cosy/remoting.encodeRequestBody',
    b'cosy/remoting.createHTTPReq',
    b'cosy/remoting.createHTTPRequest',
    b'cosy/algo',
    b'algo/handler',
    b'algo/client',
    b'algo.Sign',
    b'algo.ComputeSign',
    b'algo.GetSign',
    b'algoSign',
]

for func in algo_funcs:
    pos = pe_data.find(func)
    if pos >= 0:
        # Show surrounding function names
        print(f"\n  Found '{func.decode()}' at 0x{pos:x}")
        # Print function names in the 500 bytes before and after
        region = pe_data[max(0, pos-300):pos+300]
        # Extract null-separated strings
        current = []
        for b in region:
            if 32 <= b < 127:
                current.append(chr(b))
            else:
                if current:
                    s = ''.join(current)
                    if '.' in s and len(s) > 10:  # Looks like a Go function name
                        offset_in_region = len(region) - len(current)
                        abs_offset = max(0, pos-300) + offset_in_region
                        print(f"    0x{abs_offset:07x}: {s}")
                    current = []
        if current:
            s = ''.join(current)
            if '.' in s and len(s) > 10:
                offset_in_region = len(region) - len(current)
                abs_offset = max(0, pos-300) + offset_in_region
                print(f"    0x{abs_offset:07x}: {s}")

# Now let's look for the signing function more directly
# Search for functions that compute a hash/signature over request body
print("\n\n=== Searching for body signing code ===")
# The heartbeat uses MD5 (32 hex chars). Let's find where MD5 is called
# for request signing.

# Search for md5.New or md5.Sum
md5_new = b'md5.New'
md5_sum = b'md5.Sum'

for pattern in [md5_new, md5_sum]:
    pos = pe_data.find(pattern)
    if pos >= 0:
        print(f"\n  Found '{pattern.decode()}' at 0x{pos:x}")
        ctx = pe_data[max(0, pos-50):pos+50]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
        print(f"  Context: {printable}")

# Search for "Sum" calls in the context of signing
print("\n\n=== Functions referencing Sum and Sign ===")
# Find functions that reference both MD5 and signing
sum_funcs = [
    b'Sum(',
    b'.Sum',
    b'Sum256',
    b'Sum512',
]

for pattern in sum_funcs:
    pos = pe_data.find(pattern)
    if pos >= 0:
        count = 0
        start = 0
        positions = []
        while True:
            p = pe_data.find(pattern, start)
            if p < 0:
                break
            positions.append(p)
            start = p + 1
            count += 1
            if count > 20:
                break
        if count <= 20:
            print(f"  '{pattern.decode()}' at {count} positions")
        else:
            print(f"  '{pattern.decode()}' at {count}+ positions")

# Let's search for a more specific pattern: the signing key or algorithm
# The signature might use a fixed key like "cosy" or the machine ID
print("\n\n=== Searching for signing key constants ===")
# Common signing key patterns
key_patterns = [
    b'cosy-sign-key',
    b'sign-key',
    b'secretKey',
    b'secret_key',
    b'SecretKey',
    b'SignKey',
    b'signKey',
    b'sign_key',
    b'apiKey',
    b'api_key',
    b'accessKey',
    b'access_key',
    b'token',
    b'Token',
    b'clientSecret',
]

for pattern in key_patterns:
    pos = pe_data.find(pattern)
    if pos >= 0:
        # Count occurrences
        count = 0
        start = 0
        while True:
            p = pe_data.find(pattern, start)
            if p < 0:
                break
            count += 1
            start = p + 1
            if count > 3:
                break
        print(f"  '{pattern.decode()}' found {count}+ times")

# Let's try another approach: search for the actual signing algorithm in Go code
# In Go, HMAC-MD5 would look like: hmac.New(md5.New, key)
# Let's search for this pattern
print("\n\n=== Searching for hmac.New calls ===")
hmac_new = pe_data.find(b'hmac.New')
if hmac_new >= 0:
    print(f"Found 'hmac.New' at 0x{hmac_new:x}")
    ctx = pe_data[max(0, hmac_new-100):hmac_new+200]
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
    print(f"Context: {printable}")
else:
    print("hmac.New not found as string")

# Search for the actual signing function in the cosy package
print("\n\n=== Cosy package signing functions ===")
# These are the most likely candidates:
sign_candidates = [
    b'cosy/remoting.sign',
    b'cosy/remoting.Sign',
    b'cosy/network.sign',
    b'cosy/network.Sign',
    b'cosy/client.sign',
    b'cosy/client.Sign',
    b'cosy/http.sign',
    b'cosy/http.Sign',
    b'cosy/auth.sign',
    b'cosy/auth.Sign',
    b'cosy/util.sign',
    b'cosy/util.Sign',
    b'cosy/middleware.sign',
    b'cosy/middleware.Sign',
    b'cosy/core/sign',
    b'cosy/signer',
    b'cosy/signature',
]

for candidate in sign_candidates:
    pos = pe_data.find(candidate)
    if pos >= 0:
        print(f"  Found: {candidate.decode()} at 0x{pos:x}")
        ctx = pe_data[pos:pos+200]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
        print(f"    Context: {printable}")
