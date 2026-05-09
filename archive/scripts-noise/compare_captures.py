import json

# Load the second capture file
capture2_path = 'capture/lingma-http-capture-proxynofrida-20260424-235210.jsonl'
capture1_path = 'capture/lingma-http-capture-body-20260424-222313.jsonl'

CUSTOM_ALPHABET = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
alpha_index = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}

def bitstream_decode(text):
    bits = []
    for ch in text:
        if ch not in alpha_index:
            continue
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

print("=== Capture 2 entries ===")
with open(capture2_path, 'r') as f:
    for line in f:
        obj = json.loads(line)
        path = obj.get('path', '')
        method = obj.get('method', '')
        body_utf8 = obj.get('body_utf8', '')
        body_len = obj.get('body_len', 0)
        headers = obj.get('headers', {})

        if method == 'POST':
            print(f"\n  {method} {path}")
            print(f"  body_len: {body_len}, body_utf8: {len(body_utf8)} chars")

            if body_utf8:
                decoded = bitstream_decode(body_utf8)
                print(f"  decoded: {len(decoded)} bytes")

                # Show first 100 bytes
                printable = sum(1 for b in decoded if 32 <= b < 127)
                print(f"  printable: {printable}/{len(decoded)} ({printable/len(decoded)*100:.0f}%)")
                print(f"  first 100 ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded[:100])}")

                # Check for JSON structure
                text = decoded.decode('latin-1')
                if '{"' in text or '"{' in text:
                    print(f"  Contains JSON markers!")
                    # Extract JSON-like portion
                    start = text.find('{')
                    if start >= 0:
                        # Try to find the full JSON
                        depth = 0
                        end = start
                        for i in range(start, len(text)):
                            if text[i] == '{':
                                depth += 1
                            elif text[i] == '}':
                                depth -= 1
                                if depth == 0:
                                    end = i + 1
                                    break
                        json_str = text[start:end]
                        print(f"  JSON portion ({len(json_str)} chars): {json_str[:200]}")

# Also compare heartbeat bodies between captures
print("\n\n=== Comparing heartbeat bodies ===")
hb1_body = None
hb2_body = None

with open(capture1_path, 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', '') and obj.get('body_utf8'):
            hb1_body = obj['body_utf8']
            break

with open(capture2_path, 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', '') and obj.get('body_utf8'):
            hb2_body = obj['body_utf8']
            break

if hb1_body and hb2_body:
    print(f"Capture 1 heartbeat: {len(hb1_body)} chars")
    print(f"Capture 2 heartbeat: {len(hb2_body)} chars")

    if hb1_body == hb2_body:
        print("Heartbeat bodies are IDENTICAL")
    else:
        # Find differences
        d1 = bitstream_decode(hb1_body)
        d2 = bitstream_decode(hb2_body)
        print(f"Capture 1 decoded: {len(d1)} bytes")
        print(f"Capture 2 decoded: {len(d2)} bytes")

        diffs = []
        for i in range(min(len(d1), len(d2))):
            if d1[i] != d2[i]:
                diffs.append(i)

        print(f"Differences at {len(diffs)} positions")
        if len(diffs) <= 20:
            for pos in diffs:
                print(f"  offset {pos}: 0x{d1[pos]:02x} -> 0x{d2[pos]:02x}")
        else:
            print(f"  First 10: {[f'{p}:{d1[p]:02x}->{d2[p]:02x}' for p in diffs[:10]]}")
            print(f"  Last 10: {[f'{p}:{d1[p]:02x}->{d2[p]:02x}' for p in diffs[-10:]]}")
elif not hb1_body:
    print("No heartbeat in capture 1")
elif not hb2_body:
    print("No heartbeat in capture 2")
