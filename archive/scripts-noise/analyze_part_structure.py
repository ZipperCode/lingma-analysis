"""
分析 Part 2 (492 字节) 的 JSON 结构

Part 2 解码后开头: plugin","aid":"","uid":"","rid":"","yid":"","oid":"","event_data":{"cosy_version

这明显是 JSON 的中间部分, 缺少开头的 {"...":"

目标:
1. 重构完整的 Part 2 JSON
2. 确定 Part 1 和 Part 2 的关系
3. 推断缺失的 38 字节前缀
"""
import json
import re

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
            break

# Split by $
parts = body_utf8.split('$')
part1_encoded = parts[0]  # 326 chars
part2_encoded = parts[2]   # 656 chars (after $$)

part1_decoded = custom_base64_decode(part1_encoded)
part2_decoded = custom_base64_decode(part2_encoded)

print("=== Part 1 Analysis ===")
print(f"Encoded: {len(part1_encoded)} chars")
print(f"Decoded: {len(part1_decoded)} bytes")
text1 = part1_decoded.decode('latin-1')
print(f"Text: {text1}")

print("\n=== Part 2 Analysis ===")
print(f"Encoded: {len(part2_encoded)} chars")
print(f"Decoded: {len(part2_decoded)} bytes")
text2 = part2_decoded.decode('latin-1')
print(f"Full decoded:")
for i in range(0, len(text2), 80):
    chunk = text2[i:i+80]
    printable = ''.join(c if 32 <= ord(c) < 127 else '.' for c in chunk)
    print(f"  [{i:4d}] {printable}")

# Analyze Part 2 structure
print("\n=== Part 2 JSON structure ===")
# Count braces
open_braces = text2.count('{')
close_braces = text2.count('}')
print(f"Open braces: {open_braces}")
print(f"Close braces: {close_braces}")

# Find all JSON field names
fields = re.findall(r'"(\w+)":', text2)
print(f"Fields found ({len(fields)}): {fields}")

# Extract the full text from first { to last }
first_brace = text2.find('{')
last_brace = text2.rfind('}')
if first_brace >= 0 and last_brace >= 0:
    json_inner = text2[first_brace:last_brace+1]
    print(f"\nInner JSON ({len(json_inner)} chars):")
    print(f"  {json_inner[:300]}...")

    try:
        parsed = json.loads(json_inner)
        print(f"\nParsed successfully!")
        print(f"Keys: {list(parsed.keys())}")
        for k, v in parsed.items():
            val_str = str(v)[:100]
            print(f"  {k}: {val_str}")
    except json.JSONDecodeError as e:
        print(f"\nJSON parse error: {e}")
        print(f"  Error at position: {e.pos}")
        if e.pos:
            print(f"  Context: ...{json_inner[max(0,e.pos-20):e.pos+20]}...")

# What's before the first {?
if first_brace > 0:
    prefix = text2[:first_brace]
    print(f"\nPart 2 prefix (before first '{{'): {repr(prefix)}")
    print(f"Prefix length: {len(prefix)}")
    # This tells us the missing field name

# Also: try to parse the NESTED event_data
event_data_start = text2.find('"event_data":{')
if event_data_start >= 0:
    # Find the matching closing brace
    depth = 0
    start_idx = event_data_start + len('"event_data":')
    for i in range(start_idx, len(text2)):
        if text2[i] == '{':
            depth += 1
        elif text2[i] == '}':
            depth -= 1
            if depth == 0:
                event_data = text2[start_idx:i+1]
                print(f"\nevent_data ({len(event_data)} chars):")
                try:
                    ed = json.loads(event_data)
                    print(f"  Keys: {list(ed.keys())}")
                    for k, v in ed.items():
                        val_str = str(v)[:100]
                        print(f"  {k}: {val_str}")
                except json.JSONDecodeError as e:
                    print(f"  Parse error: {e}")
                break

# Now let's compare Part 2 between the two captures
print("\n\n=== Comparing Part 2 between captures ===")
with open('capture/lingma-http-capture-proxynofrida-20260424-235210.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', ''):
            body2_utf8 = obj['body_utf8']
            parts2 = body2_utf8.split('$')
            part2_decoded_2 = custom_base64_decode(parts2[2])
            text2_2 = part2_decoded_2.decode('latin-1')
            break

diffs = []
for i in range(min(len(text2), len(text2_2))):
    if text2[i] != text2_2[i]:
        diffs.append(i)

print(f"Part 2 differences: {len(diffs)} characters")
if len(diffs) <= 50:
    for pos in diffs:
        print(f"  offset {pos}: '{text2[pos]}' -> '{text2_2[pos]}'")
        # Show context
        start = max(0, pos - 20)
        end = min(len(text2), pos + 20)
        print(f"    Context: ...{text2[start:end]}...")

# Now reconstruct the complete picture
print("\n\n=== Complete Heartbeat Body Structure ===")
print("Part 1 (244 bytes): device information JSON")
print("  Starts with: [MISSING PREFIX]6-A0BA-64C697DA4599\",\"expr_features\":\"{}\",...")
print("  Ends with: ...\"product_type\":\"lingma\",\"tag\":\"\"}}")
print()
print("Part 2 (492 bytes): event/telemetry JSON")
print("  Starts with: [MISSING PREFIX]plugin\",\"aid\":\"\",\"uid\":\"\",...")
print("  Ends with: ...}")
print()
print("The $$ separator divides two independently-encoded JSON objects")
