import json, base64, math

ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

def cb64dec(encoded):
    converted = ''.join(STD_B64[ALPHA.index(c)] for c in encoded if c in ALPHA)
    pad = (4 - len(converted) % 4) % 4
    return base64.b64decode(converted + '=' * pad)

def lingma_decode_v2(body):
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
    b2 = rev[:lb]
    b1 = rev[lb:lb+BS]
    b0 = rev[lb+BS:]
    return cb64dec(b0 + b1 + b2)

def lingma_decode_old(body):
    ds = body.find('$')
    if ds < 0:
        return cb64dec(body)
    pad = 0
    pos = ds
    while pos < len(body) and body[pos] == '$':
        pad += 1
        pos += 1
    E = len(body) - pad
    BS = math.ceil(E / 3)
    b2 = body[:ds]
    rest = body[ds + pad:]
    b1 = rest[:BS]
    b0 = rest[BS:]
    return cb64dec(b0 + b1 + b2)

fn = 'capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl'
with open(fn, 'r', errors='replace') as f:
    lines = f.readlines()

for line_num in [12, 17]:
    body = json.loads(lines[line_num])['body_utf8']
    dc = body.count('$')

    for name, decode_fn in [('old', lingma_decode_old), ('v2', lingma_decode_v2)]:
        decoded = decode_fn(body)

        utf8_end = 0
        try:
            decoded.decode('utf-8')
            utf8_end = len(decoded)
        except UnicodeDecodeError as e:
            utf8_end = e.start

        is_json = False
        if utf8_end > 10:
            try:
                text = decoded[:utf8_end].decode('utf-8')
                dec2 = json.JSONDecoder(strict=False)
                obj, jend = dec2.raw_decode(text)
                is_json = True
            except:
                pass

        print(f"L{line_num} ${dc} {name:4s}: dec={len(decoded):6d} utf8_end={utf8_end:6d} json={'YES' if is_json else 'no'}")
        if is_json:
            print(f"  JSON ends at char {jend}, binary after: {len(decoded)-jend} bytes")
            print(f"  task_id: {obj.get('task_id','')}")
            msg_count = len(obj.get('messages', []))
            print(f"  messages: {msg_count}")
