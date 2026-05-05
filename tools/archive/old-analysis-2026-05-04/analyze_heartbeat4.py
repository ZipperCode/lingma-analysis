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

            # Let's examine the FULL decoded text more carefully
            # The text ends with '"}}' followed by 492 bytes

            # Check: is the JSON COMPLETE? Let's see what the last clean chars are
            # before the non-printable region
            last_printable = None
            for i in range(244, len(decoded)):
                if 32 <= decoded[i] < 127:
                    last_printable = i

            print(f"Last printable byte after offset 244: {last_printable}")
            if last_printable:
                print(f"  Value: 0x{decoded[last_printable]:02x} = {chr(decoded[last_printable])}")

            # Show all printable bytes from 244 onward
            print("\nPrintable bytes from offset 244:")
            for i in range(244, len(decoded)):
                if 32 <= decoded[i] < 127:
                    context = decoded[max(244,i-3):i+4]
                    ctx_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
                    print(f"  Offset {i}: 0x{decoded[i]:02x} = '{chr(decoded[i])}' context: {ctx_str}")

            # The heartbeat body is 736 bytes
            # If the JSON is 244 bytes, remaining = 492 bytes
            # What if the remaining bytes are a different data structure?
            # Maybe a protobuf message or binary format?

            # Let's also check: what if the body is TWO concatenated JSON objects?
            # {"heartbeat":...}{"auth":...}

            # Or what if the body is: JSON + AES-CBC(auth_data)?
            # Where the auth_data is encrypted separately

            # Let's check the LAST 16 bytes for PKCS5 padding
            last16 = decoded[-16:]
            print(f"\nLast 16 bytes: {last16.hex()}")

            # Count high-value bytes (>0x80) which suggest encryption
            high_bytes = sum(1 for b in decoded[244:] if b > 0x7F)
            total = len(decoded) - 244
            print(f"High bytes (>0x7F) in region 244+: {high_bytes}/{total} ({high_bytes/total*100:.0f}%)")

            # AES-encrypted data should have ~50% high bytes (random distribution)
            # If it's much lower, it might not be encrypted

            # Byte distribution in the "ciphertext" region
            print("\nByte value distribution (region 244+):")
            ranges = [(0x00, 0x1F, "Control"), (0x20, 0x7F, "Printable"),
                     (0x80, 0x9F, "High-low"), (0xA0, 0xBF, "High-mid"),
                     (0xC0, 0xDF, "High-high"), (0xE0, 0xFF, "Highest")]
            for lo, hi, label in ranges:
                count = sum(1 for b in decoded[244:] if lo <= b <= hi)
                print(f"  {label} (0x{lo:02x}-0x{hi:02x}): {count} ({count/total*100:.0f}%)")

            break
