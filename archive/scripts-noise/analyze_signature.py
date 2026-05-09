"""
分析 Signature 计算方式

已知:
- Signature: 8d915d7d99452c143dc52ce040b9a355 (32 字符 = MD5 长度)
- Headers 包含: Cosy-Machineid, Cosy-Machineos, Cosy-Version, Date 等
- Body: 984 字符的自定义 base64 编码数据
- Path: /algo/api/v1/heartbeat?Encode=1

猜测签名可能使用:
1. MD5(body + timestamp)
2. HMAC-SHA256(body, key)
3. MD5(headers + body 的组合)
4. 简单的 MD5(body)
"""
import json
import hashlib
import hmac

CUSTOM_ALPHABET = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'

# Load capture data
with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', ''):
            body_utf8 = obj['body_utf8']
            headers = obj['headers']
            path = obj['path']
            method = obj['method']
            ts = obj['ts']
            expected_sig = obj.get('headers', {}).get('Signature', '')
            break

print(f"Expected Signature: {expected_sig}")
print(f"Body (first 50 chars): {body_utf8[:50]}")
print(f"Body length: {len(body_utf8)}")

# Test 1: Simple MD5 of body
md5_body = hashlib.md5(body_utf8.encode('utf-8')).hexdigest()
print(f"\nTest 1 - MD5(body): {md5_body}")
print(f"  Match: {md5_body == expected_sig}")

# Test 2: MD5 of body bytes
md5_body_bytes = hashlib.md5(body_utf8.encode('utf-8', errors='replace')).hexdigest()
print(f"\nTest 2 - MD5(body bytes): {md5_body_bytes}")
print(f"  Match: {md5_body_bytes == expected_sig}")

# Test 3: MD5 of path + body
md5_path_body = hashlib.md5((path + body_utf8).encode('utf-8')).hexdigest()
print(f"\nTest 3 - MD5(path + body): {md5_path_body}")
print(f"  Match: {md5_path_body == expected_sig}")

# Test 4: MD5 of method + path + body
md5_full = hashlib.md5((method + path + body_utf8).encode('utf-8')).hexdigest()
print(f"\nTest 4 - MD5(method + path + body): {md5_full}")
print(f"  Match: {md5_full == expected_sig}")

# Test 5: HMAC-MD5 with various keys
keys_to_try = [
    b'QbgzpWzN7tfe43gf',  # known hardcoded key
    b'cosy',
    b'lingma',
    b'35346164-3866-492d-a339-30773a32652d',  # machine_id
    b'',  # empty key
    b'encrypt',
]

print("\n=== Testing HMAC-MD5 ===")
for key in keys_to_try:
    sig = hmac.new(key, body_utf8.encode('utf-8'), hashlib.md5).hexdigest()
    match = sig == expected_sig
    print(f"  Key: {key!r}")
    print(f"    HMAC-MD5: {sig}")
    print(f"    Match: {match}")
    if match:
        print(f"    *** MATCH! ***")

# Test 6: HMAC-SHA256 with various keys (truncated to 32 chars)
print("\n=== Testing HMAC-SHA256 (truncated) ===")
for key in keys_to_try:
    sig = hmac.new(key, body_utf8.encode('utf-8'), hashlib.sha256).hexdigest()[:32]
    match = sig == expected_sig
    print(f"  Key: {key!r}")
    print(f"    HMAC-SHA256[:32]: {sig}")
    print(f"    Match: {match}")
    if match:
        print(f"    *** MATCH! ***")

# Test 7: Maybe signature uses specific header values
# Common pattern: MD5(key + timestamp + body)
date_header = headers.get('Date', '')
machine_id = headers.get('Cosy-Machineid', '')
version = headers.get('Cosy-Version', '')

print("\n=== Testing with header combinations ===")
combinations = [
    (machine_id + date_header + body_utf8).encode(),
    (machine_id + body_utf8).encode(),
    (date_header + body_utf8).encode(),
    (version + machine_id + body_utf8).encode(),
    (method.encode() + b'\n' + path.encode() + b'\n' + body_utf8.encode()),
]

labels = [
    "machine_id + date + body",
    "machine_id + body",
    "date + body",
    "version + machine_id + body",
    "method\\npath\\nbody",
]

for i, (data, label) in enumerate(zip(combinations, labels)):
    md5_sig = hashlib.md5(data).hexdigest()
    match = md5_sig == expected_sig
    print(f"  MD5({label}): {md5_sig}")
    print(f"    Match: {match}")
    if match:
        print(f"    *** MATCH! ***")

# Test 8: Check if signature is MD5 of the DECODED body
import struct

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

decoded_body = custom_base64_decode(body_utf8)

print("\n=== Testing with decoded body ===")
md5_decoded = hashlib.md5(decoded_body).hexdigest()
print(f"  MD5(decoded_body): {md5_decoded}")
print(f"  Match: {md5_decoded == expected_sig}")

# MD5 of decoded + encoded
md5_combined = hashlib.md5(decoded_body + body_utf8.encode()).hexdigest()
print(f"  MD5(decoded + encoded): {md5_combined}")
print(f"  Match: {md5_combined == expected_sig}")

# Test 9: Maybe the signature is computed BEFORE encoding
# i.e., MD5 of the original plaintext JSON
# We don't have the full JSON, but let's see if the known portion helps
# Actually, we can check: is the SHA256 in the capture related?
body_sha256 = obj.get('body_sha256', '')
if body_sha256:
    print(f"\nBody SHA256 from capture: {body_sha256}")
    computed_sha256 = hashlib.sha256(body_utf8.encode()).hexdigest()
    print(f"Computed SHA256 of body_utf8: {computed_sha256}")
    print(f"Match: {body_sha256 == computed_sha256}")

    # Maybe signature is related to SHA256
    computed_sha256_decoded = hashlib.sha256(decoded_body).hexdigest()
    print(f"SHA256 of decoded body: {computed_sha256_decoded}")
    print(f"Match with capture SHA256: {body_sha256 == computed_sha256_decoded}")

# Test 10: Check if signature uses the body_base64_preview
body_base64_preview = obj.get('body_base64_preview', '')
if body_base64_preview:
    print(f"\nBody base64 preview length: {len(body_base64_preview)}")
    md5_preview = hashlib.md5(body_base64_preview.encode()).hexdigest()
    print(f"MD5 of body_base64_preview: {md5_preview}")
    print(f"Match with Signature: {md5_preview == expected_sig}")
