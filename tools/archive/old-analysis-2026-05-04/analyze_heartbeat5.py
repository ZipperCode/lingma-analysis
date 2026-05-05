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

            # The region after the JSON (offset 244+) has 57% printable bytes
            # This is NOT AES-CBC ciphertext (which would be ~12% printable)

            # Let's check: is the ENTIRE 736 bytes actually plaintext JSON
            # that's just slightly corrupted or has extra data appended?

            # Look at it differently: maybe the JSON wraps around and continues
            # The JSON ends at offset 243 with "tag":""}}
            # Then bytes 244+ might be additional appended JSON

            # Let's try: is it valid JSON if we wrap everything?
            region = decoded[244:]

            # Look for JSON-like patterns
            print("Searching for JSON-like patterns in region 244+...")

            # Count braces in this region
            opens = sum(1 for b in region if b == ord('{'))
            closes = sum(1 for b in region if b == ord('}'))
            quotes = sum(1 for b in region if b == ord('"'))
            colons = sum(1 for b in region if b == ord(':'))
            commas = sum(1 for b in region if b == ord(','))

            print(f"Braces: {{ = {opens}, }} = {closes}")
            print(f"Quotes: {quotes}")
            print(f"Colons: {colons}")
            print(f"Commas: {commas}")

            # If this were JSON, we'd expect:
            # - Balanced braces (or at least some pattern)
            # - Even number of quotes (key-value pairs)
            # - Colons between keys and values
            # - Commas between entries

            # The region has 0 open braces and 0 close braces
            if opens == 0 and closes == 0:
                print("\nNo braces found in region 244+ - this is NOT JSON")
                print("It's binary data appended after the JSON")

            # Let's try: what if the entire 736 bytes is a Go gob-encoded struct?
            # Or a protobuf message?
            # Go gob starts with a type descriptor
            # Protobuf has tag-length-value structure

            # Or maybe it's just the JSON with additional binary fields
            # Let's look at the ORIGINAL encoded body to understand the pipeline

            # Original body: 984 chars of custom-alphabet encoding
            # After decoding: 736 bytes
            # 984 * 6 = 5904 bits = 738 bytes
            # But we only get 736 bytes (skipping 2 $ chars)
            # 984 - 2 = 982 valid chars * 6 = 5892 bits
            # 5892 / 8 = 736.5 → 736 bytes (4 bits leftover)

            # The 4 leftover bits might be important
            print("\n=== Bit-level analysis ===")
            bits = []
            dollar_positions = []
            for i, ch in enumerate(body):
                if ch == '$':
                    dollar_positions.append(i)
                if ch in alpha_index:
                    idx = alpha_index[ch]
                    for j in range(5, -1, -1):
                        bits.append((idx >> j) & 1)

            print(f"Total bits from valid chars: {len(bits)}")
            print(f"Leftover bits: {len(bits) % 8}")
            print(f"$ positions in body: {dollar_positions[:5]}...")

            # The leftover bits are 4 bits (5892 % 8 = 4)
            # These 4 bits might encode additional data or be padding

            # Print the last 8 bytes and the leftover bits
            leftover = bits[-4:]
            print(f"Leftover 4 bits: {''.join(str(b) for b in leftover)} = 0x{int(''.join(str(b) for b in leftover), 2):x}")

            # Now the key question: what IS the 492-byte binary region?
            # Let's compare with another API body to find patterns

            print("\n=== Comparing with tracking body ===")
            with open('D:/Project/lingma/capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f2:
                for line2 in f2:
                    obj2 = json.loads(line2)
                    if 'tracking' in obj2.get('path', '') and obj2.get('body_utf8'):
                        body2 = obj2['body_utf8']
                        decoded2 = bitstream_decode(body2)
                        print(f"Tracking body: {len(decoded2)} bytes")
                        printable2 = sum(1 for b in decoded2 if 32 <= b < 127)
                        print(f"Printable: {printable2}/{len(decoded2)} ({printable2/len(decoded2)*100:.0f}%)")

                        # First 16 bytes
                        print(f"First 16: {decoded2[:16].hex()}")
                        print(f"ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded2[:16])}")
                        break

            break
