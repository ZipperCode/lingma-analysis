import json, base64, math

ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

def cb64dec(encoded):
    converted = ''.join(STD_B64[ALPHA.index(c)] for c in encoded if c in ALPHA)
    pad = (4 - len(converted) % 4) % 4
    return base64.b64decode(converted + '=' * pad)

def lingma_decode(body):
    ds = body.find('$')
    if ds < 0:
        re_str = body
        E = len(body)
    else:
        pad = 0
        pos = ds
        while pos < len(body) and body[pos] == '$':
            pad += 1
            pos += 1
        re_str = body[:ds] + body[ds + pad:]
        E = len(re_str)
    BS = math.ceil(E / 3)
    lb = E - 2 * BS
    return cb64dec(re_str[lb+BS:] + re_str[lb:lb+BS] + re_str[:lb])

fn = 'capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl'
with open(fn, 'r', errors='replace') as f:
    lines = f.readlines()

# L17 agent_chat 34040
decoded = lingma_decode(json.loads(lines[17])['body_utf8'])
text_part = decoded[:8508].decode('utf-8')

# Use raw_decode to find JSON boundary (handles braces in strings correctly)
full_text = decoded.decode('utf-8', errors='replace')
decoder = json.JSONDecoder()
try:
    obj, end_idx = decoder.raw_decode(full_text)
    binary = decoded[end_idx:]
    print(f"JSON: {end_idx} bytes")
    print(f"Keys: {list(obj.keys())[:6]}")
    print(f"task_id: {obj.get('task_id', '')}")
    print(f"agent_id: {obj.get('agent_id', '')}")
    for m in obj.get('messages', []):
        print(f"  role={m['role']}, content_len={len(m.get('content', ''))}")
    if 'business' in obj:
        biz = obj['business']
        print(f"  business.name: {biz.get('name','')}")
    print(f"\nBinary: {len(binary)} bytes")
    print(f"Binary hex[:40]: {binary[:40].hex()}")
except json.JSONDecodeError as e:
    print(f"JSON error: {e}")

# Also L12 successful (pure JSON)
dec12 = lingma_decode(json.loads(lines[12])['body_utf8'])
data12 = json.loads(dec12.decode('utf-8'))
print(f"\nL12 (pure JSON): {len(dec12)} bytes, task_id={data12.get('task_id','')}")
for m in data12.get('messages', []):
    print(f"  role={m['role']}, content_len={len(m.get('content', ''))}")

# Compare L12 vs L17: what's different?
print(f"\nL12 task_id: {data12.get('task_id','')}")
# L17 task_id will be printed above
