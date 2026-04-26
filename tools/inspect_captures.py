import json
import os

CUSTOM_ALPHABET = "!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
ALPHABET_INDEX = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}

def decode_method1(text):
    bits = []
    for ch in text:
        if ch in ALPHABET_INDEX:
            idx = ALPHABET_INDEX[ch]
            if idx < 64:
                for i in range(5, -1, -1):
                    bits.append((idx >> i) & 1)
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)

# Look at the proxynofrida capture
for cf in ['lingma-http-capture-proxynofrida-20260424-224555.jsonl',
           'lingma-http-capture-proxynofrida-20260424-235500.jsonl']:
    filepath = os.path.join('capture', cf)
    if not os.path.exists(filepath):
        continue

    print(f"=== {cf} ===")
    with open(filepath, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
                # Find entries with encoded bodies
                for key in ['body', 'encoded_body', 'requestBody', 'body_encoded']:
                    if key in entry:
                        body = entry[key]
                        if isinstance(body, str) and len(body) > 50:
                            decoded = decode_method1(body)
                            print(f"  {entry.get('method', '?')} {entry.get('endpoint', entry.get('path', entry.get('url', '?')))}")
                            print(f"    {key}: {len(body)} chars -> {len(decoded)} bytes")
                            print(f"    First 8 bytes: {decoded[:8].hex()}")
                            print(f"    Last 8 bytes: {decoded[-8:].hex()}")
            except:
                pass
    print()
