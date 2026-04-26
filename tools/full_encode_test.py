"""
尝试完整复现 Heartbeat 编码管道

已知:
1. 编码字母表 (64字符, 6-bit编码)
2. bitstream 编码/解码函数
3. Heartbeat body 结构 (736 bytes)
4. AesEncryptWithBase64 的函数签名

未知:
1. AES 密钥
2. IV
3. 二进制区域的含义

目标:
1. 验证编码管道: 明文 → AES-CBC → PKCS5 → Custom Base64
2. 找出正确的密钥或确认是否使用了 AES
"""
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

CUSTOM_ALPHABET = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
alpha_index = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}

def custom_base64_encode(data: bytes) -> str:
    """将字节编码为自定义 base64 字符串"""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    # 补位到 6 的倍数
    while len(bits) % 6 != 0:
        bits.append(0)

    result = []
    for i in range(0, len(bits), 6):
        idx = 0
        for j in range(6):
            idx = (idx << 1) | bits[i + j]
        result.append(CUSTOM_ALPHABET[idx])

    return ''.join(result)

def custom_base64_decode(text: str) -> bytes:
    """将自定义 base64 字符串解码为字节"""
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

# 测试编码/解码往返
test_data = b"Hello, World!"
encoded = custom_base64_encode(test_data)
decoded = custom_base64_decode(encoded)
print(f"Round-trip test:")
print(f"  Original:  {test_data}")
print(f"  Encoded:   {encoded}")
print(f"  Decoded:   {decoded}")
print(f"  Match:     {test_data == decoded}")

# Load heartbeat body
print("\n\n=== Loading heartbeat body ===")
with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', ''):
            original_encoded = obj['body_utf8']
            original_decoded = custom_base64_decode(original_encoded)
            print(f"Original encoded length: {len(original_encoded)}")
            print(f"Original decoded length: {len(original_decoded)}")
            break

# Try: re-encode the decoded data and compare with original
re_encoded = custom_base64_encode(original_decoded)
print(f"\nRe-encoded length: {len(re_encoded)}")
print(f"Original length: {len(original_encoded)}")
print(f"Match: {re_encoded == original_encoded}")

# If the re-encoded data doesn't match, there might be:
# 1. Padding differences
# 2. $ characters (special meaning)
# 3. Bit alignment issues

if re_encoded != original_encoded:
    # Find differences
    diffs = 0
    for i in range(min(len(re_encoded), len(original_encoded))):
        if re_encoded[i] != original_encoded[i]:
            diffs += 1
    print(f"Differences: {diffs} characters")

    # Check for $ positions
    dollar_positions = [i for i, ch in enumerate(original_encoded) if ch == '$']
    print(f"$ positions in original: {dollar_positions}")

    # Check if the issue is trailing bits
    print(f"\nOriginal body length in bits: {len(original_encoded) * 6}")
    print(f"Decoded length in bits: {len(original_decoded) * 8}")
    print(f"Bit difference: {len(original_encoded) * 6 - len(original_decoded) * 8}")

# Now let's try to figure out if the 736-byte body is AES-encrypted
# by checking various key/IV combinations

print("\n\n=== Trying all key/IV combinations ===")

# Possible keys to try:
keys_to_try = [
    (b'QbgzpWzN7tfe43gf', "hardcoded key from binary"),
    (b'\x00' * 16, "all zeros"),
    (hashlib.md5(b'QbgzpWzN7tfe43gf').digest(), "MD5 of hardcoded key"),
    (hashlib.md5(b'lingma').digest(), "MD5('lingma')"),
    (hashlib.md5(b'cosy').digest(), "MD5('cosy')"),
    (hashlib.md5(b'encrypt').digest(), "MD5('encrypt')"),
    (hashlib.md5(b'35346164-3866-492d-a339-30773a32652d').digest(), "MD5(machine_id)"),
    (hashlib.sha256(b'QbgzpWzN7tfe43gf').digest()[:16], "SHA256(key)[:16]"),
    (hashlib.sha256(b'lingma').digest()[:16], "SHA256('lingma')[:16]"),
]

# The JSON portion suggests the data might NOT be encrypted
# Let's try: is the 736 bytes just raw JSON with some binary appended?

text = original_decoded.decode('latin-1')
print(f"\nText analysis:")
print(f"  Total length: {len(text)}")
print(f"  First 244 chars: {text[:244]}")
print(f"  Chars 244-260: {repr(text[244:260])}")

# Count JSON-like characters
json_chars = sum(1 for c in text if c in '{}":,[]\n\r\t ')
print(f"  JSON-like chars: {json_chars}/{len(text)} ({json_chars/len(text)*100:.0f}%)")

# Look for the JSON start
if text.count('"') > 20:
    print(f"  Quote count: {text.count('"')}")
    print(f"  This looks like JSON-like structure!")

# Check: is the binary data at offset 244 a valid encoding of some kind?
binary_part = original_decoded[244:]
print(f"\nBinary part analysis (offset 244-735):")
print(f"  Length: {len(binary_part)} bytes")
print(f"  Mod 16: {len(binary_part) % 16}")

# Byte frequency distribution
from collections import Counter
freq = Counter(binary_part)
print(f"  Unique byte values: {len(freq)}")
print(f"  Most common bytes: {freq.most_common(10)}")

# If the most common bytes are ASCII-like, it's probably not AES
ascii_count = sum(1 for b in binary_part if 32 <= b < 127)
print(f"  ASCII bytes: {ascii_count}/{len(binary_part)} ({ascii_count/len(binary_part)*100:.0f}%)")

# The key insight: if the data was AES-encrypted, ALL bytes would be random
# If there are patterns, it's either:
# 1. Not encrypted at all
# 2. Using a custom encryption
# 3. Using ECB mode with repeating plaintext

# Check for repeated 16-byte blocks
blocks = [binary_part[i:i+16] for i in range(0, len(binary_part) - 15, 16)]
unique_blocks = set(blocks)
print(f"\n  16-byte blocks: {len(blocks)} total, {len(unique_blocks)} unique")
if len(blocks) > len(unique_blocks):
    print(f"  REPEATED BLOCKS detected!")
    # Find the repeated blocks
    from collections import Counter
    block_counts = Counter(tuple(b) for b in blocks)
    for block, count in block_counts.most_common(5):
        if count > 1:
            print(f"    Block {bytes(block).hex()} appears {count} times")

# Check full 736-byte blocks too
full_blocks = [original_decoded[i:i+16] for i in range(0, 736 - 15, 16)]
full_unique = set(tuple(b) for b in full_blocks)
print(f"\n  Full 736-byte blocks: {len(full_blocks)} total, {len(full_unique)} unique")
if len(full_blocks) > len(full_unique):
    print(f"  REPEATED full blocks!")
