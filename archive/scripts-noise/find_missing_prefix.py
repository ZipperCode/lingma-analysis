"""
精确推断缺失的 38 字节 JSON 前缀

已知:
- decoded 偏移 0-37: `6-A0BA-64C697DA4599","expr_features":"`
- 这是 38 字节
- 格式为: <value尾部>","expr_features":"
- value 以 `6-A0BA-64C697DA4599` 结尾

分析:
- `6-A0BA-64C697DA4599` = 22 字符
- 如果是标准 UUID (36字符), 缺失前 14 字符
- 但总共缺失 38 字节, 所以 JSON 前缀 = 38 - 22 = 16 字节
- 16 字节 = `{"session_id":"` 或 `{"request_id":"` 或 `{"machine_id":"`

尝试: 如果是 session_id, UUID 缺失 14 字符
缺失 = 14 (UUID) + 2 (`{"`) + 12 (session_id) + 2 (`":"`) = 30 字节
但实际缺失 38 字节, 多了 8 字节

所以可能:
1. 不是 session_id, 是更长的字段名
2. 有其他字段在 session_id 之前
3. UUID 不是标准 36 字符格式
"""
import json

CUSTOM_ALPHABET = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
alpha_index = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}

def custom_base64_encode(data: bytes) -> str:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
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

# Load original
with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', ''):
            original_encoded = obj['body_utf8']
            original_decoded = custom_base64_decode(original_encoded)
            break

# The known suffix starting at offset 38
known_suffix = original_decoded[38:].decode('latin-1')
print(f"Known suffix (offset 38+): {known_suffix[:100]}...")
print(f"Known suffix length: {len(known_suffix)}")

# The full decoded is 736 bytes
# We have 698 bytes from offset 38
# Missing prefix is 38 bytes

# What JSON field comes before expr_features?
# Let's enumerate possibilities:
field_candidates = [
    ('session_id', '35346164-3866-492d-a339-30773a32652d'),  # known machine_id as session_id
    ('request_id', '35346164-3866-492d-a339-30773a32652d'),
    ('machine_id', '35346164-3866-492d-a339-30773a32652d'),
    ('session_id', '00000000-0000-0000-0000-000000000000'),
    ('chat_id', '00000000-0000-0000-0000-000000000000'),
    ('conversation_id', '00000000-0000-0000-0000-000000000000'),
    ('trace_id', '00000000-0000-0000-0000-000000000000'),
]

print("\n=== Testing field candidates ===")
for field_name, field_value in field_candidates:
    # Construct: {"field_name":"field_value
    prefix = '{"' + field_name + '":"' + field_value
    if len(prefix) == 38:
        print(f"\n  MATCH! {field_name} with value length {len(field_value)}")
        print(f"  Prefix: {prefix}")
        full = prefix + known_suffix
        print(f"  Full start: {full[:80]}")
        print(f"  Full length: {len(full)}")

        # Now encode and compare
        encoded = custom_base64_encode(full.encode('utf-8'))
        print(f"  Encoded length: {len(encoded)} (original: {len(original_encoded)})")
        if len(encoded) == len(original_encoded):
            print(f"  Encoded matches length!")
            # Compare character by character
            diffs = sum(1 for a, b in zip(encoded, original_encoded) if a != b)
            print(f"  Character differences: {diffs}")
            if diffs < 10:
                for i in range(min(len(encoded), len(original_encoded))):
                    if encoded[i] != original_encoded[i]:
                        print(f"    Diff at {i}: '{encoded[i]}' vs '{original_encoded[i]}'")
                        if diffs > 5:
                            break
            elif diffs == 0:
                print(f"  *** PERFECT MATCH! ***")

# If no exact match, let's figure out the field length
print("\n=== Computing required field+value length ===")
missing_bytes = 38
# Format: {"<field_name>":"<value_prefix>
# Minimum: {"X":"Y = 7 chars for field name 1 + value 1
# {"session_id":" = 16 chars
# Remaining: 38 - 16 = 22 chars for value prefix

# The value we see starts with "6-A0BA-64C697DA4599"
# If the value is a 36-char UUID, prefix = 36 - 22 = 14 chars
# But 38 - 16 = 22 != 14

# So either:
# 1. Field name is longer than session_id (10 chars)
#    e.g., conversation_id (15 chars): {"conversation_id":" = 21 chars
#    Remaining: 38 - 21 = 17 chars
#    Value: 36 - 22 = 14 chars needed, but 17 available
#    Doesn't match either.

# 2. There are TWO fields before expr_features
#    e.g., {"session_id":"<uuid>","request_id":"<uuid-prefix>
#    This would account for more bytes

# Let's check: what if the text `6-A0BA-64C697DA4599` is
# actually TWO values concatenated?
# Like: ...<session_id_tail>,<request_id_prefix>-A0BA-64C697DA4599
# Hmm, but the "," separator suggests it's one value

# Actually, let me re-examine:
# `6-A0BA-64C697DA4599","expr_features":"`
# The `","` pattern means: end of value, start of new key
# So `6-A0BA-64C697DA4599` is ONE complete value
# And `expr_features` is the NEXT key

# The value length is 22 characters.
# What field has a 22-char value?
# - Truncated UUID?
# - Some kind of short ID?
# - Hash?

# Let's just try all field names with a 22-char value
print("\n=== Trying 22-char value with various fields ===")
test_value = "X" * 14 + "6-A0BA-64C697DA4599"  # 36 char UUID
field_names = ['session_id', 'request_id', 'machine_id', 'chat_id',
               'user_id', 'device_id', 'trace_id', 'msg_id',
               'login_id', 'instance_id', 'client_id', 'connection_id']

for fn in field_names:
    prefix_str = '{"' + fn + '":"'
    needed = 38 - len(prefix_str)
    if needed > 0:
        # Value would be: (needed chars) + the rest
        # The decoded starts with "6-A0BA..."
        # So the first 'needed' chars of value are missing
        # And we see the remaining 22 chars
        total_value_len = needed + 22
        print(f"  {fn}: prefix={len(prefix_str)}, missing_value={needed}, total_value={total_value_len}")

# The key question: what's the actual field before expr_features?
# Let's search the binary for the heartbeat struct definition

print("\n\n=== Searching binary for heartbeat struct ===")
BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

# Search for struct definitions near heartbeat
# Look for the struct that contains expr_features
search_terms = [
    b'ExprFeatures',
    b'expr_features',
    b'ExprFeature',
    b'HeartbeatData',
    b'HeartbeatBody',
    b'HeartbeatReq',
    b'HeartbeatInput',
    b'HeartbeatParam',
]

for term in search_terms:
    pos = pe_data.find(term)
    if pos >= 0:
        ctx = pe_data[max(0, pos-50):pos+100]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
        print(f"\n  Found '{term.decode()}' at 0x{pos:x}")
        print(f"  Context: {printable}")
