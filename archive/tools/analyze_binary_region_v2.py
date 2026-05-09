"""
重点分析: Heartbeat Body 偏移 244-735 的 492 字节到底是什么?

之前观察:
- Chi-squared = 2754.5 (均匀分布期望 256)
- 69/256 唯一字节值
- 重复模式: &FWf, &WfV, fW'6
- ASCII 字节占比较高

结论: 这不是 AES 密文, 而是某种结构化数据

可能的解释:
1. HMAC/签名 (但 492 字节对 HMAC 来说太长了)
2. 第二个 JSON 对象 (编码后看起来像二进制)
3. 自定义加密/编码的数据
4. 多个字段的编码组合
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

with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', ''):
            body_utf8 = obj['body_utf8']
            decoded = custom_base64_decode(body_utf8)
            break

# The 492-byte region
binary = decoded[244:]

# Let's check if this is base64-encoded data
# (i.e., the 492 bytes are base64 of some binary data)
import base64
try:
    inner_decoded = base64.b64decode(binary)
    print(f"Base64 decode succeeded: {len(inner_decoded)} bytes")
    print(f"First 50: {inner_decoded[:50].hex()}")
except:
    print("Base64 decode failed")

# Let's check if the region is structured as length-prefixed fields
print("\n=== Checking for length-prefixed structure ===")
import struct

# Check for various length-prefix patterns
offset = 0
while offset < len(binary) - 4:
    # Try 4-byte LE length prefix
    length = struct.unpack('<I', binary[offset:offset+4])[0]
    if 0 < length < len(binary) - offset - 4:
        print(f"  Offset {offset}: LE length = {length}, next {length} bytes: {binary[offset+4:offset+4+min(20,length)].hex()}")
        offset += 4 + length
        if offset > 200:
            break
        continue

    # Try 4-byte BE length prefix
    length = struct.unpack('>I', binary[offset:offset+4])[0]
    if 0 < length < len(binary) - offset - 4:
        print(f"  Offset {offset}: BE length = {length}, next {length} bytes: {binary[offset+4:offset+4+min(20,length)].hex()}")
        offset += 4 + length
        if offset > 200:
            break
        continue

    offset += 1
    if offset > 50:
        break

# Let's try a completely different approach:
# What if the binary region is ALSO JSON, but encoded differently?
# Maybe using the alphabet in a different way?

print("\n=== Alternative decode: treating encoded chars differently ===")

# What if the $ padding chars are not just padding but encode something?
# Let's check the raw encoded text around positions 326-327
print(f"\nEncoded text around $ positions:")
print(f"  Chars 320-330: {body_utf8[320:330]}")
print(f"  Char 326: {repr(body_utf8[326])}")
print(f"  Char 327: {repr(body_utf8[327])}")

# Count total $ in the encoded text
dollar_count = body_utf8.count('$')
print(f"Total $ chars: {dollar_count}")

# Check if there are $ chars elsewhere
dollar_positions = [i for i, c in enumerate(body_utf8) if c == '$']
print(f"$ positions: {dollar_positions}")

# Now let's try: what if the encoded text has a different structure?
# Maybe it's TWO separate encoded strings concatenated with $ as separator?
print("\n=== Checking for concatenated encoded strings ===")

# Split by $
parts = body_utf8.split('$')
print(f"Parts when split by $: {len(parts)}")
for i, part in enumerate(parts):
    if part:
        decoded_part = custom_base64_decode(part)
        text = decoded_part.decode('latin-1')
        printable = ''.join(c if 32 <= ord(c) < 127 else '.' for c in text)
        print(f"  Part {i}: {len(part)} chars -> {len(decoded_part)} bytes: {printable[:80]}")

# Hmm, what if $ is not a separator but part of the encoding?
# What if $ encodes to specific bit pattern?

# Let's try: $ = 0x00 (6 bits of zeros)
def custom_base64_decode_with_dollar(text: str) -> bytes:
    bits = []
    for ch in text:
        if ch in alpha_index:
            idx = alpha_index[ch]
        elif ch == '$':
            idx = 0  # $ = 0
        else:
            continue
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

decoded_with_dollar = custom_base64_decode_with_dollar(body_utf8)
print(f"\n=== Decode with $ as zeros ===")
print(f"Length: {len(decoded_with_dollar)} bytes")
print(f"Diff from original decode: {sum(1 for a, b in zip(decoded, decoded_with_dollar) if a != b)}")

# Now the key question: is the ENTIRE 736-byte body the "plaintext"
# for AES encryption? Or is there a more complex structure?

# Let's check the second capture for comparison
print("\n=== Comparing binary regions between captures ===")
with open('capture/lingma-http-capture-proxynofrida-20260424-235210.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', ''):
            body2_utf8 = obj['body_utf8']
            decoded2 = custom_base64_decode(body2_utf8)
            binary2 = decoded2[244:]
            break

# Compare binary regions
diffs = []
for i in range(min(len(binary), len(binary2))):
    if binary[i] != binary2[i]:
        diffs.append(i)

print(f"Binary region differences: {len(diffs)} out of {min(len(binary), len(binary2))}")
if len(diffs) <= 50:
    for pos in diffs:
        print(f"  offset {pos}: 0x{binary[pos]:02x} -> 0x{binary2[pos]:02x}")

# Check: are the differences in the same byte ranges as the JSON portion?
# If BOTH the JSON and binary portions change in the same way,
# they're likely part of the same encryption/encoding pipeline
