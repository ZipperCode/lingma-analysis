"""
重构 Heartbeat 完整 JSON 结构，分析二进制区域
"""
import json
import struct

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
print("=== Loading heartbeat body ===")
with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', ''):
            body_utf8 = obj['body_utf8']
            decoded = custom_base64_decode(body_utf8)
            print(f"Encoded length: {len(body_utf8)}")
            print(f"Decoded length: {len(decoded)}")
            break

# Convert to text for analysis
text = decoded.decode('latin-1')

print(f"\n=== Full decoded content ===")
print(f"Total length: {len(text)}")

# Show in chunks
for i in range(0, len(text), 80):
    chunk = text[i:i+80]
    printable = ''.join(c if 32 <= ord(c) < 127 else '.' for c in chunk)
    print(f"  [{i:4d}] {printable}")

# Try to extract JSON
print(f"\n=== JSON extraction ===")
# Find all JSON-like structures
json_start = text.find('{')
if json_start >= 0:
    print(f"First '{{' at offset: {json_start}")
    # Extract everything from first { to last }
    json_end = text.rfind('}')
    if json_end >= 0:
        json_candidate = text[json_start:json_end+1]
        print(f"JSON candidate length: {len(json_candidate)}")
        print(f"JSON candidate: {json_candidate[:500]}...")

        # Try to parse
        try:
            parsed = json.loads(json_candidate)
            print(f"\nJSON parsed successfully!")
            print(f"Keys: {list(parsed.keys())}")
            for k, v in parsed.items():
                print(f"  {k}: {repr(v)[:100]}")
        except json.JSONDecodeError as e:
            print(f"\nJSON parse error: {e}")
            # Try to find what's wrong
            print(f"  Error at position: {e.pos}")
            if e.pos:
                print(f"  Context: ...{json_candidate[max(0,e.pos-20):e.pos+20]}...")

# Analyze what's before the JSON
if json_start > 0:
    print(f"\n=== Data before JSON (offset 0-{json_start}) ===")
    prefix = decoded[:json_start]
    print(f"Length: {len(prefix)} bytes")
    print(f"Hex: {prefix.hex()}")
    if len(prefix) >= 4:
        # Check if it's a length prefix
        val32_le = struct.unpack('<I', prefix[:4])[0]
        val32_be = struct.unpack('>I', prefix[:4])[0]
        print(f"First 4 bytes as uint32 LE: {val32_le}")
        print(f"First 4 bytes as uint32 BE: {val32_be}")
        print(f"JSON length: {json_end + 1 - json_start}")
        print(f"Remaining after JSON: {len(decoded) - (json_end + 1)}")

# Analyze the binary region after JSON
if json_end > 0:
    after_json = decoded[json_end+1:]
    print(f"\n=== Data after JSON (offset {json_end+1}-{len(decoded)}) ===")
    print(f"Length: {len(after_json)} bytes")
    print(f"Mod 16: {len(after_json) % 16}")
    print(f"Hex (first 64): {after_json[:64].hex()}")

    # Check if it could be AES-CBC ciphertext
    # Ciphertext should have uniform byte distribution
    from collections import Counter
    freq = Counter(after_json)
    print(f"Unique bytes: {len(freq)}/256")

    # Chi-squared test for uniform distribution
    expected = len(after_json) / 256
    chi_sq = sum((count - expected)**2 / expected for count in freq.values())
    print(f"Chi-squared: {chi_sq:.1f} (expected ~256 for uniform)")

    # Check for repeated 16-byte blocks
    blocks = [after_json[i:i+16] for i in range(0, len(after_json) - 15, 16)]
    unique_blocks = set(blocks)
    print(f"16-byte blocks: {len(blocks)} total, {len(unique_blocks)} unique")
    if len(blocks) > len(unique_blocks):
        block_counts = Counter(blocks)
        for block, count in block_counts.most_common(3):
            if count > 1:
                print(f"  Block {block.hex()} appears {count} times")
