import json

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
            text = decoded.decode('latin-1')

            # Try prepending various prefixes to make valid JSON
            prefixes = [
                '{"machine_id":"',
                '{"sessionId":"',
                '{"id":"',
                '{"data":{',
                '{"',
                '{',
            ]
            for prefix in prefixes:
                try:
                    candidate = prefix + text
                    json.loads(candidate)
                    print(f"VALID JSON with prefix: {repr(prefix)}")
                    print(candidate[:200])
                    break
                except json.JSONDecodeError as e:
                    pass

            # Print the headers
            print()
            print("Headers:")
            for k, v in obj.get('headers', {}).items():
                print(f"  {k}: {str(v)[:100]}")

            # Also check: does the body look like AES-CBC ciphertext?
            # Check if first 16 bytes == any other 16-byte block
            print()
            print("Block uniqueness (AES-CBC check):")
            blocks = {}
            for i in range(0, len(decoded) - 15, 16):
                block = decoded[i:i+16].hex()
                if block in blocks:
                    print(f"  Block {i//16} == Block {blocks[block]}")
                blocks[block] = i // 16
            print(f"  {len(blocks)} unique blocks out of {len(decoded)//16} total")

            break
