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

            # The heartbeat JSON fragment ends at offset 243
            # Let's reconstruct the full JSON by guessing what's missing at the start
            # The text starts with: 6-A0BA-64C697DA4599","expr_features":"{}",...

            # This looks like the end of a key-value pair
            # The key is something ending with "machine_id" or similar
            # The value is a UUID suffix: "...-A0BA-64C697DA4599"

            # Full machine ID from headers: 35346164-3866-492d-a339-30773a32652d
            # The visible suffix: -64C697DA4599
            # That doesn't match exactly

            # Actually the visible part is: 6-A0BA-64C697DA4599
            # Machine ID: 35346164-3866-492d-a339-30773a32652d
            # Hmm, these don't match. So the heartbeat body has a DIFFERENT ID

            # The header has: Cosy-Machineid: 35346164-3866-492d-a339-30773a32652d
            # But the body has: 6-A0BA-64C697DA4599
            # These are different IDs! The body might have a session ID or device ID

            # Let's reconstruct the full JSON
            # The body starts at: 6-A0BA-64C697DA4599","expr_features"...
            # So the full body starts with: {"some_id":"XXX-6-A0BA-64C697DA4599","expr_features"...

            # Actually let me try prepending {"session_id":"
            # The total JSON before the binary data is 244 bytes
            # Let's figure out the prefix length

            # Count chars from start to first ":
            colon_pos = text.find('":"')
            print(f'First colon-quote at offset: {colon_pos}')
            prefix_text = text[:colon_pos]
            print(f'Prefix text: {prefix_text}')
            print(f'Prefix length: {len(prefix_text)}')

            # Try various prefix strings
            prefixes_to_try = [
                '{"session_id":"',
                '{"device_id":"',
                '{"client_id":"',
                '{"request_id":"',
                '{"trace_id":"',
                '{"correlation_id":"',
                '{"heartbeat_id":"',
            ]

            for prefix in prefixes_to_try:
                full = prefix + text[:244]
                try:
                    json.loads(full)
                    print(f"\nVALID JSON with prefix: {repr(prefix)}")
                    parsed = json.loads(full)
                    print(f"Parsed: {json.dumps(parsed, indent=2)[:300]}")
                    break
                except json.JSONDecodeError as e:
                    pass
            else:
                # The JSON fragment itself is not valid even with prefixes
                # Let's check the structure more carefully
                print("\nNo valid JSON reconstruction found")

                # The text structure is:
                # VALUE","key1":"value1","key2":"value2",...,"tag":""}}
                # We need to find what VALUE is and what key precedes it

                # Count the number of key-value pairs
                import re
                keys = re.findall(r'"([a-z_]+)"\s*:', text[:244])
                print(f"Keys found: {keys}")

            break
