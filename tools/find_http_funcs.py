"""Find Go HTTP send functions to hook. This is the most direct approach -
intercept the actual HTTP request after all signing is applied."""
import struct
from capstone import *

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

with open(LINGMA, 'rb') as f:
    binary = f.read()

pe_off = struct.unpack('<I', binary[0x3c:0x40])[0]
opt_size = struct.unpack('<H', binary[pe_off + 20:pe_off + 22])[0]
sect_start = pe_off + 24 + opt_size
rdata_raw = rdata_va = text_raw = text_va = 0
for i in range(6):
    off = sect_start + i * 40
    name = binary[off:off + 8].rstrip(b'\x00').decode()
    va = struct.unpack('<I', binary[off + 12:off + 16])[0]
    rp = struct.unpack('<I', binary[off + 20:off + 24])[0]
    if name == '.rdata':
        rdata_raw, rdata_va = rp, va
    elif name == '.text':
        text_raw, text_va = rp, va

def find_string_in_rdata(s, max_results=10):
    results = []
    idx = rdata_raw
    while idx < rdata_raw + 0x3cfc250:
        pos = binary.find(s, idx)
        if pos == -1:
            break
        rva = pos - rdata_raw + rdata_va
        results.append((rva, pos))
        if len(results) >= max_results:
            break
        idx = pos + 1
    return results

# Search for HTTP-related Go package names and function names
http_strings = [
    b'net/http.(*Client).do',
    b'net/http.(*Transport).roundTrip',
    b'net/http.NewRequest',
    b'net/http.(*Request).Write',
    b'net/textproto',
    b'Header.Set',
    b'cosy/remoting',
    b'cosy/api',
    b'algo/',
    b'/algo',
    b'big_model',
    b'BigModel',
]

print("=" * 70)
print("HTTP and API-related strings in binary")
print("=" * 70)

for s in http_strings:
    results = find_string_in_rdata(s, 3)
    if results:
        for rva, pos in results:
            ctx = binary[max(0,pos-5):pos+len(s)+15]
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
            print(f'  {s.decode()[:40]:40s} @ RVA 0x{rva:x}: {printable}')

# Also search for the pipe handler that processes LSP requests
print()
print("=" * 70)
print("Pipe/IPC-related strings")
print("=" * 70)
for s in [b'\\\\.\\pipe\\lingma', b'lingma-', b'ipcServer', b'jsonrpc']:
    results = find_string_in_rdata(s, 5)
    if results:
        for rva, pos in results:
            ctx = binary[max(0,pos-5):pos+len(s)+15]
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
            print(f'  {s.decode()[:30]:30s} @ RVA 0x{rva:x}: {printable}')

# Search for cosy package functions in .pdata
print()
print("=" * 70)
print("Functions in cosy package area (looking for API/HTTP handlers)")
print("=" * 70)

# Look for strings that might indicate API handler names
api_strings = find_string_in_rdata(b'cosy/', 15)
for rva, pos in api_strings:
    ctx = binary[pos:pos+50]
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
    print(f'  @ RVA 0x{rva:x}: {printable}')
