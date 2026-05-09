import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

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
print(f"AES Key: {AES_KEY.decode('ascii')}")
print(f"Key hex: {AES_KEY.hex()}")

# Load heartbeat body
with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', ''):
            body = obj['body_utf8']
            decoded = bitstream_decode(body)
            print(f"\nHeartbeat decoded length: {len(decoded)} bytes")

            # The plaintext JSON is the first 244 bytes
            plaintext_json = decoded[:244]
            ciphertext = decoded[244:]
            print(f"Plaintext JSON: {plaintext_json.decode('latin-1')}")
            print(f"Ciphertext length: {len(ciphertext)} bytes")
            print(f"Ciphertext hex: {ciphertext[:32].hex()}...")

            # The ciphertext should be a multiple of 16 (AES block size)
            print(f"Ciphertext length mod 16: {len(ciphertext) % 16}")

            # Try decrypting with different IV strategies
            # Strategy 1: IV = all zeros (common default)
            # Strategy 2: IV prepended to ciphertext (first 16 bytes)
            # Strategy 3: IV derived from key
            # Strategy 4: IV = some constant

            # Since the plaintext is 244 bytes and the body starts with that JSON,
            # the encryption likely only covers the data AFTER the JSON prefix.
            # Or perhaps the entire body is encrypted but we're seeing a partial decryption.

            # Actually wait - the disassembly shows:
            # 1. Convert plaintext to []byte
            # 2. Convert key to []byte
            # 3. Create AES cipher with key
            # 4. Call cipher's encrypt method
            # 5. PKCS5 pad
            # 6. Base64 encode

            # But the heartbeat body has a plaintext JSON prefix followed by ciphertext.
            # This is unusual. Let me think about this differently.

            # Maybe the plaintext JSON is NOT part of the encrypted data.
            # Maybe the POST body is: JSON_header + encrypted_payload
            # Where only the encrypted_payload goes through AES+custom_base64

            # But our capture shows the entire body encoded in the custom alphabet.
            # So either:
            # a) The server expects the body to be partially plaintext, partially encrypted
            # b) The "plaintext" prefix is actually part of a different encoding layer

            # Let me try: decrypt the ciphertext portion with different IVs

            strategies = {
                "IV=zeros": b'\x00' * 16,
                "IV=key": AES_KEY[:16],
            }

            for name, iv in strategies.items():
                try:
                    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
                    decrypted = cipher.decrypt(ciphertext)
                    # Try to unpad
                    try:
                        decrypted = unpad(decrypted, 16)
                    except:
                        pass
                    printable = sum(1 for b in decrypted if 32 <= b < 127)
                    print(f"\n{name} ({iv.hex()}):")
                    print(f"  Decrypted length: {len(decrypted)}")
                    print(f"  Printable: {printable}/{len(decrypted)} ({printable/len(decrypted)*100:.0f}%)")
                    print(f"  First 32 bytes hex: {decrypted[:32].hex()}")
                    print(f"  ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted[:64])}")
                except Exception as e:
                    print(f"\n{name}: Error - {e}")

            break

# Now let's also try with the tracking body
print("\n\n=== Tracking body analysis ===")
with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'tracking' in obj.get('path', '') and obj.get('body_utf8'):
            body = obj['body_utf8']
            decoded = bitstream_decode(body)
            print(f"Tracking decoded length: {len(decoded)} bytes")
            print(f"First 9 bytes hex: {decoded[:9].hex()}")
            print(f"First 9 bytes ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded[:9])}")

            # The tracking body might be encrypted differently
            # Let's try decrypting the entire tracking body (minus 9-byte header)
            ciphertext = decoded[9:]
            print(f"Ciphertext length (minus 9): {len(ciphertext)} bytes")
            print(f"Length mod 16: {len(ciphertext) % 16}")

            # If it's 1344 bytes, that's exactly 84 AES blocks
            if len(ciphertext) % 16 == 0:
                print("  -> Ciphertext length is a multiple of 16!")
                iv = b'\x00' * 16
                try:
                    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
                    decrypted = cipher.decrypt(ciphertext)
                    printable = sum(1 for b in decrypted if 32 <= b < 127)
                    print(f"\n  Decrypted length: {len(decrypted)}")
                    print(f"  Printable: {printable}/{len(decrypted)} ({printable/len(decrypted)*100:.0f}%)")
                    print(f"  First 64 bytes hex: {decrypted[:64].hex()}")
                    print(f"  ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted[:128])}")
                except Exception as e:
                    print(f"  Error: {e}")
            break
