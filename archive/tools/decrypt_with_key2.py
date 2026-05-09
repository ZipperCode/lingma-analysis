import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad

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

AES_KEY = b'QbgzpWzN7tfe43gf'

with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', ''):
            body = obj['body_utf8']
            print(f"Raw body length: {len(body)} chars")
            print(f"Raw body (first 200 chars): {body[:200]}")
            print(f"Raw body (chars 200-400): {body[200:400]}")
            print(f"Raw body (chars 400-600): {body[400:600]}")
            print(f"Raw body (chars 600-800): {body[600:800]}")
            print(f"Raw body (last 200 chars): {body[800:]}")

            # Count characters in the custom alphabet vs other chars
            in_alpha = sum(1 for ch in body if ch in alpha_index)
            dollar_count = body.count('$')
            other = sum(1 for ch in body if ch not in alpha_index and ch != '$')

            print(f"\nIn alphabet: {in_alpha}/{len(body)} ({in_alpha/len(body)*100:.1f}%)")
            print(f"$ count: {dollar_count}")
            print(f"Other chars: {other}")
            if other > 0:
                for i, ch in enumerate(body):
                    if ch not in alpha_index and ch != '$':
                        print(f"  Other char at pos {i}: {repr(ch)} (0x{ord(ch):02x})")

            # Decode and show full content
            decoded = bitstream_decode(body)
            print(f"\nDecoded length: {len(decoded)} bytes")

            # Show as hex dump with ASCII
            for i in range(0, len(decoded), 16):
                chunk = decoded[i:i+16]
                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                print(f"  {i:04d}: {hex_str:<48} {ascii_str}")

            # Try: the entire decoded content might be JSON if we pad and decrypt
            # But first, let's check if offset 244+ data is actually JSON continuation
            text = decoded.decode('latin-1')

            # Look at the transition point
            print(f"\n=== Around offset 240-250 ===")
            for i in range(240, min(260, len(decoded))):
                b = decoded[i]
                print(f"  {i}: 0x{b:02x} = {chr(b) if 32 <= b < 127 else '.'}")

            break

# Now let's check: is the tracking body FIRST 9 bytes actually encrypted too?
print("\n\n=== Full tracking body analysis ===")
with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'tracking' in obj.get('path', '') and obj.get('body_utf8'):
            body = obj['body_utf8']
            decoded = bitstream_decode(body)

            # Show first 20 bytes as hex
            print(f"Tracking first 20 bytes hex: {decoded[:20].hex()}")
            print(f"Tracking first 20 bytes: {decoded[:20]}")

            # The tracking body might be: encrypted JSON (1344 bytes = 84 blocks)
            # Or it might be: header (9 bytes) + encrypted data (1344 bytes)

            # If the first 9 bytes are a header, what format?
            # Could be: nonce (8 bytes) + length (1 byte)
            # Or: version (1 byte) + nonce/IV (8 bytes)

            # Try decrypting with IV = bytes 1-9 + padding
            iv = decoded[1:9] + b'\x00' * 8  # Use bytes 1-8 as partial IV
            ciphertext = decoded[9:]
            try:
                cipher = AES.new(AES_KEY, AES.MODE_CBC, b'\x00' * 16)
                decrypted = cipher.decrypt(ciphertext)
                try:
                    decrypted_unpadded = unpad(decrypted, 16)
                except:
                    decrypted_unpadded = decrypted
                printable = sum(1 for b in decrypted_unpadded if 32 <= b < 127)
                print(f"\nZero IV decrypt (unpadded): {printable}/{len(decrypted_unpadded)} printable")
                print(f"  ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted_unpadded[:128])}")
            except Exception as e:
                print(f"Error: {e}")

            # Try CTR mode (unlikely but worth checking)
            # CTR needs a nonce, not IV
            try:
                nonce = decoded[:8]
                cipher = AES.new(AES_KEY, AES.MODE_CTR, nonce=nonce)
                decrypted = cipher.decrypt(ciphertext)
                printable = sum(1 for b in decrypted if 32 <= b < 127)
                print(f"\nCTR (nonce=first 8 bytes): {printable}/{len(decrypted)} printable")
                print(f"  ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted[:128])}")
            except Exception as e:
                print(f"CTR error: {e}")

            break
