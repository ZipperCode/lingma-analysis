"""
分析 cosy/remoting.BuildBigModelSignRequest 和 buildRequest
这些函数负责计算请求签名
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

# Find BuildBigModelSignRequest function
print("=== BuildBigModelSignRequest function ===")
func_name = b'cosy/remoting.BuildBigModelSignRequest'
pos = pe_data.find(func_name)
if pos >= 0:
    print(f"Function name string at 0x{pos:x}")
    # Show bytes after name (should contain function VA)
    end = pos + len(func_name)
    print(f"Bytes after: {pe_data[end:end+20].hex()}")

    # The function name is stored in pclntab, followed by function metadata
    # For Go 1.22, the format is: name length + name + PC data
    # Let's find the actual code

# Find all references to BuildBigModelSignRequest
print("\n\n=== Callers of BuildBigModelSignRequest ===")
# Search for call instructions targeting this function
text_section = sections[0]
text_raw = pe_data[text_section['raw_offset']:text_section['raw_offset'] + text_section['raw_size']]

# We need to find the function VA first
# Let's search for the function name and then look at the associated code

# Alternative: search for the string "BuildBigModelSignRequest" in the context of call instructions
func_str = b'BuildBigModelSignRequest'
pos = pe_data.find(func_str)
if pos >= 0:
    print(f"String found at 0x{pos:x}")
    # Show surrounding strings (other function names nearby)
    for offset in range(max(0, pos-200), pos+300, 50):
        chunk = pe_data[offset:offset+50]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
        print(f"  0x{offset:07x}: {printable}")

# Now find buildRequest
print("\n\n=== buildRequest function ===")
# Search for the string
build_req = b'cosy/remoting.buildRequest'
pos = pe_data.find(build_req)
if pos >= 0:
    print(f"Found at 0x{pos:x}")
    end = pos + len(build_req)
    print(f"Bytes after: {pe_data[end:end+20].hex()}")

    # Show surrounding function names
    for offset in range(max(0, pos-200), pos+300, 50):
        chunk = pe_data[offset:offset+50]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
        print(f"  0x{offset:07x}: {printable}")

# Also search for functions related to signing
print("\n\n=== Other signing-related functions ===")
sign_funcs = [
    b'cosy/remoting.Sign',
    b'cosy/remoting.ComputeSign',
    b'cosy/remoting.signBody',
    b'cosy/remoting.calculateSign',
    b'SignHeartbeat',
    b'heartbeatSign',
    b'signHeartbeat',
]

for func in sign_funcs:
    pos = pe_data.find(func)
    if pos >= 0:
        print(f"  Found '{func.decode()}' at 0x{pos:x}")

# Search for the specific algorithm used
print("\n\n=== Searching for signing algorithm strings ===")
algo_strings = [
    b'HMAC',
    b'hmac',
    b'SHA256',
    b'sha256',
    b'MD5',
    b'md5',
    b'hex.EncodeToString',
    b'hex.Encode',
    b'fmt.Sprintf("%x"',
    b'encoding/hex',
    b'crypto/hmac',
    b'crypto/sha256',
]

for s in algo_strings:
    pos = pe_data.find(s)
    if pos >= 0:
        # Find ALL positions
        positions = []
        start = 0
        while True:
            p = pe_data.find(s, start)
            if p < 0:
                break
            positions.append(p)
            start = p + 1

        print(f"\n  '{s.decode()}' found at {len(positions)} positions")
        if len(positions) <= 10:
            for p in positions[:5]:
                ctx = pe_data[max(0, p-20):p+len(s)+40]
                printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
                print(f"    0x{p:07x}: ...{printable}...")
