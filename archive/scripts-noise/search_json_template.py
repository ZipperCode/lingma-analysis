"""
在二进制文件中搜索 heartbeat/tracking JSON 模板
"""
import struct
import re

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

# Search for JSON template strings
search_strings = [
    b'"session_id"',
    b'"request_id"',
    b'"expr_features"',
    b'"host_system"',
    b'"ide_type"',
    b'"product_type"',
    b'"machine_id"',
    b'"os_arch"',
    b'"os_version"',
    b'"ide_version"',
    b'"ide_types"',
    b'"tag"',
    b'"mcp_server_enable_count"',
    b'"event_time"',
    b'"event_type"',
    b'"uuid"',
    b'"mid"',
]

print("=== Searching for JSON field strings in binary ===")
for s in search_strings:
    pos = pe_data.find(s)
    if pos >= 0:
        context = pe_data[max(0,pos-30):pos+len(s)+80]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in context)
        print(f"\n  Found '{s.decode()}' at offset 0x{pos:x}")
        print(f"  Context: {printable}")

# Also search for JSON template patterns
print("\n\n=== Searching for JSON templates ===")
templates = [
    b'{"session',
    b'{"request',
    b'{"expr',
    b'{"host',
    b'{"machine',
    b'{"product',
    b'"heartbeat"',
    b'heartbeat',
    b'algo/api',
    b'Encode=1',
]

for t in templates:
    pos = pe_data.find(t)
    if pos >= 0:
        context = pe_data[max(0,pos-50):pos+200]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in context)
        print(f"\n  Found template '{t.decode()}' at offset 0x{pos:x}")
        print(f"  Context: {printable}")

# Search for the cosy package path which might contain heartbeat builder code
print("\n\n=== Searching for cosy package paths ===")
cosy_paths = [
    b'cosy/',
    b'code.alibaba-inc.com',
    b'heartbeat',
    b'tracking',
]

for p in cosy_paths:
    positions = []
    start = 0
    while True:
        pos = pe_data.find(p, start)
        if pos < 0:
            break
        positions.append(pos)
        start = pos + 1

    if positions:
        print(f"\n  Found '{p.decode()}' at {len(positions)} positions:")
        for pos in positions[:5]:
            context = pe_data[max(0,pos-20):pos+60]
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in context)
            print(f"    0x{pos:x}: ...{printable}...")
        if len(positions) > 5:
            print(f"    ... and {len(positions) - 5} more positions")
