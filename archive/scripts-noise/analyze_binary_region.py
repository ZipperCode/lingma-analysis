"""
详细分析 Heartbeat "二进制" 区域
之前我们看到偏移 244-735 是 492 字节的"二进制"数据
但实际上 chi-squared = 2754.5，说明不是随机数据
让我们逐字节检查这些内容
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

# Let's look at the "binary" region more carefully
# The region starts at offset 244
binary = decoded[244:]

print("=== 492-byte region, byte by byte ===")
print("Offset | Hex                                          | ASCII")
print("-" * 80)

for i in range(0, len(binary), 16):
    chunk = binary[i:i+16]
    hex_str = ' '.join(f'{b:02x}' for b in chunk)
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f"{244+i:4d}   | {hex_str:<48s} | {ascii_str}")

# Now let's see: is this actually embedded JSON?
print("\n\n=== Extracting text from the region ===")
text_segments = []
current = []
start_offset = 0
for i, b in enumerate(binary):
    if 32 <= b < 127:
        if not current:
            start_offset = 244 + i
        current.append(chr(b))
    else:
        if current:
            text_segments.append((start_offset, ''.join(current)))
            current = []
if current:
    text_segments.append((start_offset, ''.join(current)))

for offset, text in text_segments:
    if len(text) >= 4:
        print(f"  [{offset}] {text[:100]}{'...' if len(text) > 100 else ''}")

# Check: does the region contain JSON field names?
all_text = ' '.join(t[1] for t in text_segments if len(t[1]) >= 3)
json_fields = ['plugin', 'host_system', 'ide_type', 'version', 'windows', 'lingma',
               'event', 'session', 'request', 'response', 'model', 'code', 'user']
for field in json_fields:
    if field in all_text.lower():
        print(f"  Found field reference: '{field}'")

# Most importantly: let's see if the ENTIRE 736 bytes is valid JSON
# We just need to figure out the missing prefix
print("\n\n=== Trying to reconstruct full JSON ===")
# The text we have starts at offset 38 with a partial value
# What field could end with "6-A0BA-64C697DA4599"?
# This looks like a UUID suffix: XXXXXXXX-XXXX-XXXX-6A0BA-64C697DA4599
# Wait, UUIDs are 8-4-4-4-12 format
# So: XXXXXXXX-XXXX-XXXX-A0BA-64C697DA4599
# The full UUID would be: [8chars]-[4chars]-6A0BA-64C697DA4599
# Hmm, but 6A0BA doesn't fit the 4-char format
# Let me re-read: "6-A0BA-64C697DA4599"
# This could be: [prefix]6-A0BA-64C697DA4599
# Which is a truncated: ...XXX6-A0BA-64C697DA4599"
# Full pattern might be: "...session_id\":\"SOME-UUID-6A0BA-64C697DA4599\""

# Common Lingma UUID fields:
# - session_id
# - request_id
# - machine_id (we know: 35346164-3866-492d-a339-30773a32652d)
# - user_id

# The known machine_id: 35346164-3866-492d-a339-30773a32652d
# This does NOT match the pattern "6-A0BA-64C697DA4599"

# Let's check the full response from the heartbeat
# Maybe we have the response body too?
print("\n=== Looking for heartbeat response ===")
with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        path = obj.get('path', '')
        if 'heartbeat' in path:
            print(f"Entry: {json.dumps({k: v for k, v in obj.items() if k != 'body_utf8'}, indent=2)}")
            # Check if there's a response
            if 'response_body' in obj:
                print(f"Response body: {obj['response_body'][:200]}")
            break
