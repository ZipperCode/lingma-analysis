import base64
import json

CUSTOM_ALPHABET = "!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
ALPHABET_INDEX = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}

# Get the actual body from capture
with open('capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl') as f:
    for line in f:
        d = json.loads(line)
        path = d.get('path', '')
        if 'user/status' in path:
            body_b64 = d.get('body_base64_preview', '')
            body = base64.b64decode(body_b64).decode('utf-8')
            break

print(f"Body: {len(body)} chars")
print(f"Body: {body[:80]}...")

# Method: map each char to 6 bits using CUSTOM alphabet index
bits = []
for ch in body:
    if ch in ALPHABET_INDEX:
        idx = ALPHABET_INDEX[ch]
        if idx < 64:
            # 6 bits, MSB first
            bits.extend([(idx >> 5) & 1, (idx >> 4) & 1, (idx >> 3) & 1,
                         (idx >> 2) & 1, (idx >> 1) & 1, idx & 1])

print(f"Total bits: {len(bits)}")
print(f"Expected bytes: {len(bits) // 8}")

# Pack into bytes
n_bytes = len(bits) // 8
result = bytearray(n_bytes)
for i in range(n_bytes):
    b = 0
    for j in range(8):
        b = (b << 1) | bits[i * 8 + j]
    result[i] = b

print(f"Result: {len(result)} bytes")
print(f"First 16 bytes: {result[:16].hex()}")

# Alternative: use bitstring-like approach
def decode_v3(text, alphabet_index):
    """Decode by treating as base-64 with custom alphabet."""
    # Filter to valid chars
    chars = [ch for ch in text if ch in alphabet_index and alphabet_index[ch] < 64]
    n = len(chars)

    # Convert from base-64 to bytes
    # Group by 4 chars -> 3 bytes (like standard base64)
    import base64
    std_b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    # Map custom alphabet to standard base64
    mapped = []
    for ch in chars:
        idx = alphabet_index[ch]
        mapped.append(std_b64[idx])

    # Pad to multiple of 4
    while len(mapped) % 4 != 0:
        mapped.append('=')

    return base64.b64decode(''.join(mapped))

decoded_v3 = decode_v3(body, ALPHABET_INDEX)
print(f"\nMethod v3 (base64-style): {len(decoded_v3)} bytes")
print(f"First 16 bytes: {decoded_v3[:16].hex()}")

# Compare methods
print(f"\nBitstream vs base64-style:")
print(f"  Bitstream first 16: {result[:16].hex()}")
print(f"  Base64-style first 16: {decoded_v3[:16].hex()}")
print(f"  Same? {result[:16] == decoded_v3[:16]}")
print(f"  Bitstream len: {len(result)}")
print(f"  Base64-style len: {len(decoded_v3)}")
