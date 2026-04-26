"""
深入分析 Heartbeat 解码后的完整结构
"""
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

# Load heartbeat body
with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', ''):
            body_utf8 = obj['body_utf8']
            decoded = custom_base64_decode(body_utf8)
            break

# The data starts mid-JSON. Let's look at it differently.
# Maybe the ENTIRE 736 bytes is a single JSON object,
# but our decoding is losing some bytes at the start?

# Let's check: how many bits are we losing?
# 982 valid chars * 6 bits = 5892 bits
# 5892 / 8 = 736.5 bytes
# We're losing 4 bits of precision!

# This means the FIRST byte might be wrong by up to 16 values
# (the first byte uses only 4 of 8 bits from the first char)

# Actually wait - let's reconsider.
# In base64, 3 bytes -> 4 chars (24 bits each)
# 736 bytes -> ceil(736 * 8 / 6) = ceil(981.33) = 982 chars + 2 padding

# So 982 chars encode ceil(982 * 6 / 8) = 736.5 -> 736 bytes (truncated)
# The last 4 bits of the last char are padding/ignored

# But what about the FIRST few bits? If the encoding is:
# [byte0][byte1][byte2] -> [char0][char1][char2][char3]
# Then char0 has bits: b0[7:2], char1 has: b0[1:0] + b1[7:4], etc.

# So our decode should be correct... unless the encoding is shifted.

# Let me try: what if the actual JSON starts at offset 0?
# The text starts with: 6-A0BA-64C697DA4599","expr_features":"{}"...
# This looks like: ...[some UUID]","expr_features":"{}"...
# So we're missing the JSON prefix!

# Let's check: is the decode missing the first N bytes?
# In base64, if there are 4 leftover bits, they could be prepended
# to form an extra byte.

# Try: prepend 4 zero bits and re-decode
def custom_base64_decode_with_offset(text: str, offset_bits: int) -> bytes:
    """Decode with N leading zero bits prepended"""
    bits = [0] * offset_bits
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

print("=== Testing different bit offsets ===")
for offset in range(0, 6):
    decoded_test = custom_base64_decode_with_offset(body_utf8, offset)
    text = decoded_test.decode('latin-1')
    print(f"\nOffset {offset} bits: {len(decoded_test)} bytes")
    print(f"  First 80: {text[:80]}")

    # Check if it starts with {
    if text.startswith('{'):
        print("  *** STARTS WITH { ! ***")

    # Find first { position
    first_brace = text.find('{')
    if first_brace >= 0:
        print(f"  First '{{' at offset: {first_brace}")

# Now let's also check: does the heartbeat response tell us the expected format?
# Look at the HTTP headers
print("\n\n=== Checking HTTP headers ===")
with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', ''):
            print(f"Method: {obj.get('method')}")
            print(f"Path: {obj.get('path')}")
            print(f"Headers: {json.dumps(obj.get('headers', {}), indent=2)}")
            print(f"Status: {obj.get('status')}")
            break

# Also check: maybe the JSON structure we know
# and the "binary" data is actually TWO separate fields
# Let's look at the raw capture more carefully
print("\n\n=== Checking all capture entries ===")
with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        path = obj.get('path', '')
        method = obj.get('method', '')
        body = obj.get('body_utf8', '')
        if body:
            print(f"{method} {path} - body: {len(body)} chars")
