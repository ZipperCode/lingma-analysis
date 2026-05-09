import json
import re

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

with open('D:/Project/lingma/capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', ''):
            body = obj['body_utf8']
            decoded = bitstream_decode(body)

            # Try to find a JSON-like structure in the non-printable region
            # The text from offset 244 might contain:
            # - A nested JSON object
            # - Base64 data
            # - AES-CTR encrypted data

            # Method 1: Try to find JSON key patterns in the bytes
            # Search for common JSON key patterns
            region = decoded[244:]
            for pattern in [b'"aid"', b'"uid"', b'"rid"', b'"token"', b'"session"', b'"data"', b'"payload"', b'"features"']:
                pos = region.find(pattern)
                if pos >= 0:
                    print(f"Found {pattern} at offset {244 + pos}")
                    # Print context around it
                    start = max(0, pos - 5)
                    end = min(len(region), pos + len(pattern) + 30)
                    context = region[start:end]
                    print(f"  Context: {context.hex()}")
                    print(f"  ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in context)}")

            # Method 2: Maybe the 492 non-printable bytes are actually the
            # AES-CTR encrypted version of additional JSON fields
            # If so, we can try to find the key by known-plaintext attack

            # Expected plaintext structure after the heartbeat JSON:
            # ,"session_id":"","token":"","timestamp":1234567890}
            # But we only have the first 244 bytes of the JSON ending with }}

            # Let's look at the COMPLETE decoded text
            text = decoded.decode('latin-1')

            # Print ALL JSON key-like patterns
            print("\n=== All JSON key-value patterns ===")
            # Find all "key":"value" patterns
            for m in re.finditer(r'"([a-zA-Z_]+)"\s*:\s*"([^"]*)"', text):
                print(f"  {m.group(1)}: {m.group(2)[:50]}")

            # Find all "key":value patterns (numeric/boolean)
            for m in re.finditer(r'"([a-zA-Z_]+)"\s*:\s*([a-zA-Z0-9]+)', text):
                print(f"  {m.group(1)}: {m.group(2)[:50]}")

            break
