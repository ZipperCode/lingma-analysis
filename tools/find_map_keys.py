"""Extract getAppSalt map keys by searching for expected strings."""
import struct

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

with open(LINGMA, 'rb') as f:
    binary = f.read()

pe_off = struct.unpack('<I', binary[0x3c:0x40])[0]
opt_size = struct.unpack('<H', binary[pe_off + 20:pe_off + 22])[0]
sect_start = pe_off + 24 + opt_size
rdata_raw = rdata_va = 0
data_raw = data_va = 0
text_raw = text_va = 0
for i in range(6):
    off = sect_start + i * 40
    name = binary[off:off + 8].rstrip(b'\x00').decode()
    va = struct.unpack('<I', binary[off + 12:off + 16])[0]
    rp = struct.unpack('<I', binary[off + 20:off + 24])[0]
    if name == '.rdata':
        rdata_raw, rdata_va = rp, va
    elif name == '.data':
        data_raw, data_va = rp, va
    elif name == '.text':
        text_raw, text_va = rp, va

def rva_to_offset(rva):
    if rva - text_va < 0x1f3f246:
        return text_raw + (rva - text_va)
    elif rva - rdata_va < 0x3cfc250:
        return rdata_raw + (rva - rdata_va)
    elif rva - data_va < 0x518d80:
        return data_raw + (rva - data_va)
    return None

def read_at_rva(rva, size):
    offset = rva_to_offset(rva)
    if offset is None:
        return None
    return binary[offset:offset + size]

print("=" * 70)
print("Searching for getAppSalt map key/value strings")
print("=" * 70)

# 1. Search for "Date" in .rdata near the LEA target
target_rva = 0x248eede
data = read_at_rva(target_rva - 20, 100)
if data:
    print(f"\n  Around RVA 0x248eede (Key 1):")
    for i in range(len(data)):
        chunk = data[i:i+4]
        if chunk == b'Date':
            print(f"    'Date' found at RVA 0x{target_rva - 20 + i:x}")
        # Also print all 4-byte ASCII sequences
        if all(32 <= b < 127 for b in chunk) and chunk.isascii():
            try:
                s = chunk.decode('ascii')
                if len(s) == 4 and s.isalpha():
                    print(f"    RVA 0x{target_rva - 20 + i:x}: '{s}'")
            except:
                pass

# 2. Search for key strings directly
print("\nSearching for 'Date' string:")
rdata_start = rdata_raw
rdata_end = rdata_raw + 0x3cfc250
idx = rdata_start
while idx < rdata_end - 4:
    pos = binary.find(b'Date', idx, rdata_end)
    if pos == -1:
        break
    rva = pos - rdata_raw + rdata_va
    context = binary[max(0,pos-5):pos+15]
    print(f"  RVA 0x{rva:x}: context = {context.hex(' ')}")
    idx = pos + 4

# 3. Search for the date format string
print("\nSearching for date format 'Mon, 02 Jan 2006':")
fmt = b'Mon, 02 Jan 2006'
idx = 0
while True:
    pos = binary.find(fmt, idx)
    if pos == -1:
        break
    rva = pos - rdata_raw + rdata_va if pos >= rdata_raw else pos - text_raw + text_va
    print(f"  Found at file offset 0x{pos:x}, RVA 0x{rva:x}")
    context = binary[pos:pos+40]
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in context)
    print(f"    '{printable}'")
    idx = pos + len(fmt)
    if idx > pos + 1000:  # Only find first few
        break

# 4. The Go string struct: {ptr, len}. At 0x8827da, lea rdi loads the string ptr
# The string ptr is then passed to time.Format
# Let me check what the string at 0x24e0c9d actually is
print("\n\nDate format string analysis:")
fmt_rva = 0x24e0c9d
data = read_at_rva(fmt_rva, 50)
if data:
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in data)
    print(f"  Raw bytes: {data.hex(' ')}")
    print(f"  ASCII: '{printable}'")
    # The 'es' prefix might be part of a larger string table
    # Look for "Mon" nearby
    for i in range(len(data) - 3):
        if data[i:i+3] == b'Mon':
            print(f"  'Mon' at offset {i}, RVA 0x{fmt_rva + i:x}")
        if data[i:i+4] == b'Jan ':
            print(f"  'Jan ' at offset {i}")

# 5. Let's look at the actual go.string section
# Go embeds strings in .rdata as go.string.* symbols
# The key strings should be small strings embedded there
print("\n\nScanning for short strings near key LEA targets:")
# Key 1 at 0x248eede -> scan around there
for target_rva, expected_len in [(0x248eede, 4), (0x249a6cf, 9), (0x249577e, 7)]:
    data = read_at_rva(target_rva, 50)
    if data:
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in data)
        print(f"\n  RVA 0x{target_rva:x}: '{printable[:40]}'")
        # Look for the expected-length string
        for offset in range(0, 20):
            chunk = data[offset:offset+expected_len]
            if len(chunk) == expected_len and all(32 <= b < 127 for b in chunk):
                print(f"    +{offset}: '{chunk.decode('ascii')}'")
