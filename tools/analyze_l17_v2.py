import json, base64, math

ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

def cb64dec(encoded):
    converted = ''.join(STD_B64[ALPHA.index(c)] for c in encoded if c in ALPHA)
    pad = (4 - len(converted) % 4) % 4
    return base64.b64decode(converted + '=' * pad)

def decode_v2(body):
    ds = body.find('$')
    if ds < 0:
        rev = body
        E = len(body)
    else:
        pad = 0
        pos = ds
        while pos < len(body) and body[pos] == '$':
            pad += 1
            pos += 1
        rev = body[:ds] + body[ds + pad:]
        E = len(rev)
    BS = math.ceil(E / 3)
    lb = E - 2 * BS
    return cb64dec(rev[lb+BS:] + rev[lb:lb+BS] + rev[:lb])

fn = 'capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl'
with open(fn, 'r', errors='replace') as f:
    lines = f.readlines()

# L17 v2 decode
d = decode_v2(json.loads(lines[17])['body_utf8'])
print(f"L17 decoded: {len(d)} bytes")

# Find valid UTF-8 boundary
try:
    d.decode('utf-8')
    utf8_end = len(d)
except UnicodeDecodeError as e:
    utf8_end = e.start

# Carefully find the longest valid UTF-8 prefix (might be mid-character)
# Walk backwards to find clean boundary
while utf8_end > 0:
    try:
        d[:utf8_end].decode('utf-8')
        break
    except:
        utf8_end -= 1

valid_text = d[:utf8_end].decode('utf-8')
binary_part = d[utf8_end:]

print(f"Valid UTF-8: {utf8_end} bytes = {len(valid_text)} chars")
print(f"Binary after: {len(binary_part)} bytes")

# Parse JSON from the valid text
dec2 = json.JSONDecoder(strict=False)
try:
    obj, jend = dec2.raw_decode(valid_text)
    after_json_text = valid_text[jend:]
    after_json_bytes = d[len(valid_text[:jend].encode('utf-8')):]

    print(f"\nJSON ends at char {jend}")
    print(f"Keys: {list(obj.keys())[:6]}")
    print(f"task_id: {obj.get('task_id', '')}")
    print(f"agent_id: {obj.get('agent_id', '')}")
    for m in obj.get('messages', []):
        print(f"  role={m['role']}, content_len={len(m.get('content', ''))}")
    if 'business' in obj:
        biz = obj['business']
        print(f"  business.name: {biz.get('name','')}")
        print(f"  business.type: {biz.get('type','')}")

    # After JSON text
    json_byte_end = len(valid_text[:jend].encode('utf-8'))
    all_after = d[json_byte_end:]
    print(f"\nAfter JSON: {len(after_json_text)} chars left in text, {len(all_after)} bytes total")
    if all_after:
        print(f"  hex[:40]: {all_after[:40].hex()}")
        # Is this binary more UTF-8 Chinese text?
        try:
            after_text = all_after.decode('utf-8')
            print(f"  After JSON is valid UTF-8: {after_text[:200]}")
        except UnicodeDecodeError as e2:
            chunk = all_after[:e2.start]
            if len(chunk) > 0:
                print(f"  Partial UTF-8 ({len(chunk)} bytes): {chunk.decode('utf-8')[:100]}")
except json.JSONDecodeError as e:
    print(f"JSON error: {e}")
    # Show context
    print(f"  First 200 of text: {valid_text[:200]}")
