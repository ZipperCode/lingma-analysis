"""
搜索 Part 2 对应的 JSON struct 定义

Part 2 字段:
request_type(?), aid, uid, rid, yid, oid, event_data

需要找到构建此 JSON 的 Go struct
"""
import struct

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

# Search for the fields that appear in Part 2
print("=== Searching for Part 2 JSON fields ===")
part2_fields = [
    b'"aid"',
    b'"uid"',
    b'"rid"',
    b'"yid"',
    b'"oid"',
    b'event_data',
    b'cosy_version',
    b'device_disk_serial_num',
    b'device_hardware_id',
    b'device_mac_address',
    b'device_machine_serial_num',
    b'event_type',
    b'event_time',
    b'cosy_heartbeat',
    b'request_type',
    b'"plugin"',
]

for field in part2_fields:
    positions = []
    start = 0
    while True:
        pos = pe_data.find(field, start)
        if pos < 0:
            break
        positions.append(pos)
        start = pos + 1

    if positions:
        print(f"\n  '{field.decode()}' found at {len(positions)} positions:")
        for pos in positions[:3]:
            ctx_start = max(0, pos - 30)
            ctx_end = min(len(pe_data), pos + len(field) + 50)
            ctx = pe_data[ctx_start:ctx_end]
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
            print(f"    0x{pos:07x}: ...{printable}...")

# Now search for the tracking body which might have a clearer structure
print("\n\n=== Analyzing tracking body ===")
import json

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

with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'tracking' in obj.get('path', ''):
            body_utf8 = obj['body_utf8']
            # Check for $ separator
            if '$' in body_utf8:
                parts = body_utf8.split('$')
                print(f"Tracking body has {len(parts)} parts (split by $)")
                for i, part in enumerate(parts):
                    if part:
                        decoded_part = custom_base64_decode(part)
                        text = decoded_part.decode('latin-1')
                        printable = ''.join(c if 32 <= ord(c) < 127 else '.' for c in text)
                        print(f"  Part {i}: {len(part)} chars -> {len(decoded_part)} bytes")
                        print(f"    First 100: {printable[:100]}")
                        print(f"    Last 50: {printable[-50:]}")
            else:
                decoded = custom_base64_decode(body_utf8)
                text = decoded.decode('latin-1')
                printable = ''.join(c if 32 <= ord(c) < 127 else '.' for c in text)
                print(f"Tracking body (no $): {len(body_utf8)} chars -> {len(decoded)} bytes")
                print(f"  First 200: {printable[:200]}")
            break

# Now let's try to reconstruct the full heartbeat JSON
# Based on what we know:
# Part 1 should start with: {"session_id":"[UUID]
# Part 2 should start with: {"request_type":"plugin"

print("\n\n=== Reconstructing full heartbeat body ===")

# Part 1 prefix: we need {"<field>":"<value_prefix>
# The decoded starts with: 6-A0BA-64C697DA4599","expr_features":"
# So the value ends with ...6-A0BA-64C697DA4599
# And the field is before this value

# From Part 2, we know the machine_id (mid) is: 35346164-3866-492d-a339-30773a32652d
# Part 1's truncated value: ...6-A0BA-64C697DA4599
# These don't match, so Part 1's ID is NOT the machine_id.
# It could be session_id or request_id.

# Part 1 missing prefix calculation:
# We have: 6-A0BA-64C697DA4599","expr_features":
# We need: {"<field>":"<full_value>","expr_features":
# The value is: ??? + "6-A0BA-64C697DA4599"
# If it's a 36-char UUID: 36 - 22 = 14 chars missing from value
# Plus JSON prefix: {" + field_name + ":" = 15 + len(field_name)
# Total missing: 14 + 15 + len(field_name) = 29 + len(field_name)

# If field = "session_id" (10 chars): missing = 39 bytes
# If field = "request_id" (10 chars): missing = 39 bytes
# But the decoded Part 1 is 244 bytes, and the full body should be...
# Actually, we don't know the full size because the capture may have truncated it.

# Let me try a different approach: search for the JSON template in the binary
# by looking for consecutive field names

print("\n=== Searching for consecutive JSON field patterns ===")
# Look for patterns like `"aid":"` followed by `"uid":"` etc.
patterns = [
    b'"aid":"","uid":"',
    b'"uid":"","rid":"',
    b'"rid":"","yid":"',
    b'"yid":"","oid":"',
    b'"oid":"","event_data":',
    b'"expr_features":"{}"',
    b'"host_system":"',
    b'"product_type":"',
]

for pattern in patterns:
    pos = pe_data.find(pattern)
    if pos >= 0:
        ctx = pe_data[max(0, pos-50):pos+len(pattern)+50]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
        print(f"\n  Found '{pattern.decode()}' at 0x{pos:x}")
        print(f"  Context: {printable}")
    else:
        print(f"\n  NOT FOUND: '{pattern.decode()}'")
