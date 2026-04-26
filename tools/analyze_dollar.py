"""
分析 $ 字符在编码中的作用
"""
import json

CUSTOM_ALPHABET = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
alpha_index = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}

with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', ''):
            body = obj['body_utf8']
            print(f"Body length: {len(body)} chars")

            # Show context around $ characters
            print(f"\nContext around $ at positions 326-327:")
            print(f"  Positions 320-330: {body[320:335]}")
            print(f"  Position 325: {repr(body[325])}")
            print(f"  Position 326: {repr(body[326])}")
            print(f"  Position 327: {repr(body[327])}")
            print(f"  Position 328: {repr(body[328])}")

            # Check if $ at 326-327 is in the alphabet
            print(f"\n  $ in alphabet: {'$' in CUSTOM_ALPHABET}")
            print(f"  $ index: {alpha_index.get('$', 'NOT FOUND')}")

            # Decode character by character to see what happens at $ positions
            print(f"\nCharacter-by-character decode around $:")
            bits = []
            for i in range(320, 335):
                ch = body[i]
                if ch in alpha_index:
                    idx = alpha_index[ch]
                    for j in range(5, -1, -1):
                        bits.append((idx >> j) & 1)
                    print(f"  [{i}] '{ch}' → index {idx} (0b{idx:06b})")
                elif ch == '$':
                    print(f"  [{i}] '$' → SKIPPED")

            # Count total bits before and after $
            bits_before = 0
            bits_after = 0
            for i, ch in enumerate(body):
                if ch in alpha_index:
                    if i < 326:
                        bits_before += 6
                    else:
                        bits_after += 6

            print(f"\n  Bits before $: {bits_before} = {bits_before // 8} bytes + {bits_before % 8} leftover")
            print(f"  Bits after $: {bits_after} = {bits_after // 8} bytes + {bits_after % 8} leftover")
            print(f"  Total valid bits: {bits_before + bits_after}")
            print(f"  Total decoded bytes: {(bits_before + bits_after) // 8}")

            # Now let's figure out the $ role
            # 326 valid chars before position 326 → 326 × 6 = 1956 bits
            # 656 valid chars after position 327 → 656 × 6 = 3936 bits
            # Total: 5892 bits = 736.5 bytes
            # So there are 4 leftover bits

            # Check the 4 leftover bits
            total_bits = bits_before + bits_after
            leftover = total_bits % 8
            print(f"\n  Leftover bits after full decoding: {leftover}")

            # What if $ is padding?
            # Standard base64 uses '=' for padding
            # Maybe '$' is the padding char in this custom encoding
            # 736 bytes = 5888 bits
            # 5888 / 6 = 981.33... → need 982 chars + padding
            # But we have 982 chars + 2 $ = 984 chars total
            # That means 2 $ are padding (like "==")

            print(f"\n  If $ is padding:")
            print(f"  736 bytes need: {(736 * 8 + 5) // 6} chars (no padding)")
            # 5888 / 6 = 981.33... → ceil to 982
            # 982 * 6 = 5892 bits → 5892 - 5888 = 4 extra bits
            # With standard base64 padding: 984 total chars, last 2 are padding
            print(f"  736 bytes need (with $$ padding): {(736 * 8 + 5) // 6 + 2} chars")

            # Verify: in standard base64, 3 bytes → 4 chars
            # 736 / 3 = 245.33... → 246 groups of 4 chars = 984 chars
            # But the last group has only 1 byte (736 = 245*3 + 1)
            # So the last group is 1 byte → 2 chars + 2 padding chars
            print(f"\n  Standard base64 grouping:")
            print(f"  736 = {736 // 3} * 3 + {736 % 3}")
            print(f"  Groups: {736 // 3 + 1} groups of 4 chars")
            print(f"  Total: {(736 // 3 + 1) * 4} chars")
            print(f"  Padding chars needed: {4 - (736 % 3) * 2}")

            break

# Now test: can we construct a valid heartbeat by encoding the full 736 bytes?
print("\n\n=== Constructing custom base64 with $ padding ===")

# Re-implement encoding with proper $ padding
def custom_base64_encode_padded(data: bytes) -> str:
    """Encode with $ padding (like base64 with = padding)"""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    # Pad bits to multiple of 6
    while len(bits) % 6 != 0:
        bits.append(0)

    result = []
    for i in range(0, len(bits), 6):
        idx = 0
        for j in range(6):
            idx = (idx << 1) | bits[i + j]
        result.append(CUSTOM_ALPHABET[idx])

    # Add $ padding to make total length a multiple of 4
    # (like base64 padding to multiple of 4)
    while len(result) % 4 != 0:
        result.append('$')

    return ''.join(result)

# Decode function that handles $ padding
def custom_base64_decode_padded(text: str) -> bytes:
    """Decode with $ padding handling"""
    bits = []
    for ch in text:
        if ch in alpha_index:
            idx = alpha_index[ch]
            for i in range(5, -1, -1):
                bits.append((idx >> i) & 1)
        # Skip $ (padding)

    n_bytes = len(bits) // 8
    result = bytearray()
    for i in range(n_bytes):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i * 8 + j]
        result.append(byte)
    return bytes(result)

# Test round-trip with padding
test_data = b"Hello, World!"
encoded = custom_base64_encode_padded(test_data)
decoded = custom_base64_decode_padded(encoded)
print(f"Round-trip with padding:")
print(f"  Original:  {test_data}")
print(f"  Encoded:   {encoded}")
print(f"  Decoded:   {decoded}")
print(f"  Match:     {test_data == decoded}")

# Test with 736-byte data
with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', ''):
            original_encoded = obj['body_utf8']
            original_decoded = custom_base64_decode_padded(original_encoded)

            re_encoded = custom_base64_encode_padded(original_decoded)
            print(f"\n736-byte round-trip:")
            print(f"  Original encoded: {len(original_encoded)} chars")
            print(f"  Re-encoded:       {len(re_encoded)} chars")
            print(f"  Match: {re_encoded == original_encoded}")

            if re_encoded != original_encoded:
                # Find differences
                for i in range(min(len(re_encoded), len(original_encoded))):
                    if re_encoded[i] != original_encoded[i]:
                        print(f"  First diff at position {i}: '{re_encoded[i]}' vs '{original_encoded[i]}'")
                        print(f"  Context original:  ...{original_encoded[max(0,i-5):i+10]}...")
                        print(f"  Context re-encoded: ...{re_encoded[max(0,i-5):i+10]}...")
                        break
            break
