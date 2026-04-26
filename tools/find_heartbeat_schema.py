"""
反向分析: 从已知字段推断完整 JSON 结构

已知 heartbeat JSON 片段从偏移 38 开始:
6-A0BA-64C697DA4599","expr_features":"{}","host_system":...

我们缺少前 38 字节。需要找出:
1. 缺失的 JSON 前缀是什么
2. 偏移 244 之后的 492 字节是什么

思路: 从 Lingma 源码或其他地方推断 heartbeat 的完整字段
"""
import json

# First, let's look at what fields we CAN see
json_fragment = '''{"expr_features":"{}","host_system":"x86_64_windows","ide_type":"plugin","ide_types":"","ide_version":"","os_arch":"windows_amd64","os_version":"Microsoft Windows [Version 10.0.26200.8037]","product_type":"lingma","tag":""}}'''

# This ends with }} which suggests nested JSON
# The outer { is missing, and the inner { for expr_features is present

# What field ends with "6-A0BA-64C697DA4599"?
# It's probably something like:
# "session_id":"XXXX-XXXX-XXXX-6A0BA-64C697DA4599"
# or
# "machine_id":"35346164-3866-492d-a339-6A0BA-64C697DA4599"

# The known machine_id is: 35346164-3866-492d-a339-30773a32652d
# That doesn't match. So it's a different ID field.

# Let's look at the COSY/Lingma source code for heartbeat structure
# Search for "heartbeat" related code

print("=== Searching for heartbeat-related source code ===")

# Also, let's look at the tracking body which might have a clearer structure
CUSTOM_ALPHABET = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
alpha_index = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}

def custom_base64_decode(text: str) -> bytes:
    bits = []
    for ch in text:
        if ch in alpha_index:
            idx = alpha_index[ch]
            for i in range(5, -1, -1):
                bits.append((idx >> i) & 1)
    n_bytes = len(bits) // 8
    result = bytearray()
    for i in range(n_bytes):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i * 8 + j]
        result.append(byte)
    return bytes(result)

print("\n=== Analyzing tracking body (might have clearer structure) ===")
with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'tracking' in obj.get('path', ''):
            body_utf8 = obj['body_utf8']
            decoded = custom_base64_decode(body_utf8)
            text = decoded.decode('latin-1')

            print(f"Tracking body: {len(body_utf8)} chars -> {len(decoded)} bytes")
            print(f"\nFirst 200 chars (ASCII):")
            for i in range(0, min(200, len(text)), 80):
                chunk = text[i:i+80]
                printable = ''.join(c if 32 <= ord(c) < 127 else '.' for c in chunk)
                print(f"  [{i:4d}] {printable}")

            # Try to extract JSON
            print(f"\nJSON analysis:")
            # Count braces
            open_braces = text.count('{')
            close_braces = text.count('}')
            print(f"  Open braces: {open_braces}")
            print(f"  Close braces: {close_braces}")

            # If close_braces > open_braces, we're missing opening braces
            if close_braces > open_braces:
                missing = close_braces - open_braces
                print(f"  Missing {missing} opening brace(s) at the start")

            # Find all JSON field names
            import re
            fields = re.findall(r'"(\w+)":', text)
            print(f"  Fields found: {fields}")
            break

# Now let's search the binary for heartbeat-related strings
print("\n\n=== Searching binary for heartbeat JSON structure ===")
import struct

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

# Search for heartbeat-related JSON templates
search_strings = [
    b'"heartbeat"',
    b'"session_id"',
    b'"request_id"',
    b'"expr_features"',
    b'"host_system"',
    b'"ide_type"',
    b'"product_type"',
    b'"machine_id"',
    b'heartbeat',
    b'algo/api/v1',
]

for s in search_strings:
    pos = pe_data.find(s)
    if pos >= 0:
        context = pe_data[max(0,pos-20):pos+len(s)+50]
        print(f"\n  Found '{s.decode()}' at offset 0x{pos:x}")
        # Show surrounding strings
        printable = ''.join(c if 32 <= c < 127 else '\n' for c in context)
        print(f"  Context: {printable[:200]}")
