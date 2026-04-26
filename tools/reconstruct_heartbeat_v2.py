"""
尝试从 struct 定义反向推断 heartbeat JSON 结构

从二进制中找到的 JSON tag:
- SessionId: "session_id"
- IdeType: "ide_type,omitempty"
- IdeVersion: "ide_version,omitempty"
- OsArch: "os_arch,omitempty"
- OsVersion: "os_version,omitempty"
- Tag: "tag,omitempty"
- etc.

已知 decoded 片段:
6-A0BA-64C697DA4599","expr_features":"{}","host_system":...

推断: 缺失的前缀应该是一个字段名和值, 如:
{"session_id":"SOME-UUID-6A0BA-64C697DA4599"

目标: 构造完整 JSON 并重新编码, 比较与原始编码的差异
"""
import json
import struct

CUSTOM_ALPHABET = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
alpha_index = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

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
            print(f"Original: {len(original_encoded)} encoded -> {len(original_decoded)} decoded")
            break

# The decoded text fragment we know
known_fragment = '6-A0BA-64C697DA4599","expr_features":"{}","host_system":"x86_64_windows","ide_type":"plugin","ide_types":"","ide_version":"","os_arch":"windows_amd64","os_version":"Microsoft Windows [Version 10.0.26200.8037]","product_type":"lingma","tag":""}}'

# The missing prefix is the start of the JSON object
# Based on the struct tags, it should start with something like:
# {"session_id":"<uuid>

# The fragment starts with "6-A0BA-64C697DA4599"
# This is the END of a UUID value
# What JSON key would have this value?
# Candidates: session_id, request_id, machine_id

# Let's figure out how many bytes are missing
# The fragment `6-A0BA-64C697DA4599"` looks like:
# [end of UUID value]"[separator]
# So the value ends with ...6A0BA-64C697DA4599
# And after it is: ","expr_features":
# So the JSON continues to the next field

# Full UUID format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
# A value ending in 6A0BA-64C697DA4599 would be:
# ????????-????-????-6A0BA-64C697DA4599
# Wait, that's not standard UUID format (8-4-4-4-12)
# Standard: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX (36 chars with dashes)
# "6A0BA-64C697DA4599" = 5 + 1 + 12 = 18 chars
# So the full UUID would be: [17 chars]-6A0BA-64C697DA4599
# Hmm, that's 17 + 1 + 18 = 36 chars total
# So the missing part of the value is the first 17 chars + dash

# Actually let me recount. The decoded starts with "6-A0BA-64C697DA4599"
# If this is a UUID: ...6-A0BA-64C697DA4599
# UUID: 8-4-4-4-12
# Breaking down: X-XXXX-XXXX-XXXX-XXXXXXXXXXXX
# The "6" could be the last char of the first 8-char group
# So: [7chars]6-A0BA-64C697DA4599
# Full: ???????6-A0BA-64C697DA4599

# Let's try the machine_id we know: 35346164-3866-492d-a339-30773a32652d
# Does it end with ...6-A0BA-64C697DA4599? No.
# 30773a32652d != 6A0BA-64C697DA4599

# So it's a different UUID. Let's just try common prefixes.
# The prefix before "6-A0BA..." would be:
# {"session_id":"[prefix]
# or {"request_id":"[prefix]
# etc.

# Let's compute what prefix length would make sense
# If the full JSON is N bytes, and we have 736 bytes of decoded data,
# the missing part is N - 736 bytes.

# Let's estimate the full JSON:
# {"session_id":"36-char-uuid-here","expr_features":"{}",...}
# The value we know is 22 chars: "6-A0BA-64C697DA4599"
# A full UUID is 36 chars
# So the missing UUID prefix is: 36 - 22 = 14 chars
# Plus the JSON prefix: {"session_id":" = 16 chars
# Total missing: 16 + 14 = 30 chars

# But wait, the fragment starts at offset 38 in the decoded data
# So 38 bytes are missing
# {"session_id":" = 16 chars
# 38 - 16 = 22 chars of UUID missing
# Full UUID = 22 (missing) + 22 (we have) = 44 chars
# That's longer than a standard UUID (36 chars)

# Maybe it's not session_id. Let me try other fields.
# Or maybe it's a composite ID.

# Actually, the known text at offset 0-37 is:
# 6-A0BA-64C697DA4599","expr_features":"
prefix_text = original_decoded[:38].decode('latin-1')
print(f"\nPrefix text (0-37): {repr(prefix_text)}")
print(f"Prefix length: {len(prefix_text)}")

# The value starts with '6-A0BA...' and ends with '":"' before expr_features
# So the value is: 6-A0BA-64C697DA4599
# And the key is: expr_features
# And the separator before expr_features is: ","
# So the field before expr_features has value ending in 6-A0BA-64C697DA4599

# What field comes before expr_features?
# From the heartbeat code, the order might be:
# session_id, expr_features, host_system, ...
# or some other order

# Let's search the binary for the field order
print("\n=== Searching for field order in binary ===")
# Look for the sequence: "expr_features" followed by other fields
pos = pe_data.find(b'expr_features')
if pos >= 0:
    ctx_before = pe_data[max(0, pos-100):pos]
    ctx_after = pe_data[pos:pos+100]
    print(f"  expr_features at 0x{pos:x}")
    print(f"  Before: {''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx_before)}")
    print(f"  After: {''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx_after)}")

# Also search for the full JSON template
print("\n=== Searching for heartbeat JSON template ===")
# The template should contain the full field list
# Search for patterns like '{"...":"...","...":"..."'
# Or search for the known fields together

# Search for "host_system" which we know is in the JSON
pos = pe_data.find(b'host_system')
if pos >= 0:
    ctx = pe_data[max(0, pos-100):pos+100]
    print(f"  host_system at 0x{pos:x}")
    print(f"  Context: {''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)}")

# Now let's try to construct the full JSON and encode it
print("\n\n=== Constructing candidate JSON ===")

# We know these fields from the struct tags and decoded fragment:
# session_id: UUID (36 chars) - UNKNOWN
# expr_features: "{}"
# host_system: "x86_64_windows"
# ide_type: "plugin"
# ide_types: ""
# ide_version: ""
# os_arch: "windows_amd64"
# os_version: "Microsoft Windows [Version 10.0.26200.8037]"
# product_type: "lingma"
# tag: ""

# Try with a placeholder UUID
test_uuid = "35346164-3866-492d-a339-30773a32652d"  # known machine_id

# Construct JSON matching the known fragment
# The fragment is:
# 6-A0BA-64C697DA4599","expr_features":"{}","host_system":"x86_64_windows",...
# So the value ends with "6-A0BA-64C697DA4599"
# and the field before expr_features has this value

# If session_id = "X-XXXX-XXXX-XXXX-6A0BA-64C697DA4599"
# That would be 36 chars, ending with ...6A0BA-64C697DA4599
# But the decoded starts with "6-A0BA..." not "6A0BA..."
# Wait: "6-A0BA-64C697DA4599" = 22 chars
# In a UUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
# Position:  0123456789...
# "6" at position ? Let's count from the end:
# ...6-A0BA-64C697DA4599
# -64C697DA4599 = 13 chars (last segment)
# A0BA- = 5 chars (4th segment + dash)
# 6- = 2 chars (part of 3rd segment)
# So 6 is the last char of the 3rd segment (which should be 4 chars)
# Full: XXXXXXXX-XXXX-X6A0-BA-64C697DA4599
# Hmm, that doesn't work either. Let me recount.

# Actually in the decoded text: "6-A0BA-64C697DA4599"
# If this is a UUID suffix, we need to figure out where the dashes are
# Standard UUID: 8-4-4-4-12
# "6-A0BA-64C697DA4599" contains dashes at positions 1, 6
# So: "6" + "-" + "A0BA" + "-" + "64C697DA4599"
# This matches: [last char of 3rd group]-[4th group]-[5th group]
# 3rd group = ???6 (4 chars)
# 4th group = A0BA (4 chars)
# 5th group = 64C697DA4599 (12 chars)
# Full UUID = XXXXXXXX-XXXX-???6-A0BA-64C697DA4599

# So the missing prefix of the UUID is: XXXXXXXX-XXXX-???
# = 8 + 1 + 4 + 1 + 3 = 17 chars
# Plus the JSON prefix: {"session_id":" = 16 chars
# Total missing: 16 + 17 = 33 chars

# But we decoded 736 bytes and the prefix is at offset 0-37 (38 bytes)
# 38 != 33, so either:
# 1. It's not session_id
# 2. The JSON has extra fields
# 3. The UUID is non-standard format

# Let me just try encoding with a guess and compare
candidate_json = f'{{"session_id":"00000000-0000-0006-A0BA-64C697DA4599","expr_features":"{{}}","host_system":"x86_64_windows","ide_type":"plugin","ide_types":"","ide_version":"","os_arch":"windows_amd64","os_version":"Microsoft Windows [Version 10.0.26200.8037]","product_type":"lingma","tag":""}}'

print(f"Candidate JSON: {len(candidate_json)} bytes")
print(f"Known fragment length: {len(known_fragment)} bytes")
print(f"Expected prefix length: {len(candidate_json) - len(known_fragment)} bytes")

# Check if the tail matches
tail = candidate_json[-len(known_fragment):]
print(f"Tail match: {tail == known_fragment}")
if tail != known_fragment:
    # Find first diff
    for i in range(min(len(tail), len(known_fragment))):
        if tail[i] != known_fragment[i]:
            print(f"  First diff at {i}: '{tail[i]}' vs '{known_fragment[i]}'")
            break

# Also check the full JSON + binary region
# The decoded data is 736 bytes total
# JSON portion: 206 bytes (from offset 38 to 243)
# Binary portion: 492 bytes
# Missing prefix: 38 bytes
# Full expected: 38 + 206 + 492 = 736 ✓

# So the missing 38 bytes is just the JSON prefix
# Let's check: 38 bytes for {"session_id":"<17 chars of UUID>
# {"session_id":" = 16 chars
# 38 - 16 = 22 chars of UUID
# Full UUID would be: 22 (missing) + remaining
# But we only see "6-A0BA-64C697DA4599" (22 chars) at the start
# So the full UUID = 22 + 22 = 44 chars? That's not standard.

# Unless the field is NOT session_id but something else with a longer ID.

# Let me check: what if the full body includes more than just the JSON?
# The "binary" region (offset 244-735) might be additional JSON fields
# that look binary but are actually just encoded differently.

# Let's look at what comes after "tag":""}} in the fragment
after_json = original_decoded[244:]
print(f"\nAfter JSON (492 bytes), first 100:")
printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in after_json[:100])
print(f"  {printable}")

# The first bytes after JSON are: 07 06 c7 56 76 96 e2 22 c2 26 16 96 42 23 a2 22
# 22 is ASCII ", so positions 7 and 15 have "
# This looks like more JSON data, possibly with some encoding or compression

# Let me check: is the 492-byte region also text that survived the decode?
text_after = after_json.decode('latin-1')
text_portion = ''.join(c if 32 <= ord(c) < 127 else '.' for c in text_after)
print(f"\nASCII representation: {text_portion[:200]}")
