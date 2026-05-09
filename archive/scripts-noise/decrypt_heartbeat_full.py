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
            decoded = bitstream_decode(body)
            print(f"Heartbeat decoded: {len(decoded)} bytes = {len(decoded)//16} AES blocks")
            print(f"mod 16 = {len(decoded) % 16}")

            # CRITICAL: The decoded data IS exactly 46 AES blocks
            # This means the ENTIRE 736 bytes is encrypted data
            # The "plaintext JSON" we see is just what happens when we
            # interpret the decrypted data incorrectly

            # Try decrypting with zero IV (most common default)
            iv = b'\x00' * 16
            try:
                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(decoded)
                print(f"\nCBC with zero IV:")
                printable = sum(1 for b in decrypted if 32 <= b < 127)
                print(f"  Printable: {printable}/{len(decrypted)} ({printable/len(decrypted)*100:.0f}%)")
                print(f"  First 64 bytes hex: {decrypted[:64].hex()}")
                print(f"  First 64 bytes ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted[:64])}")

                # Try to unpad
                try:
                    decrypted_unpadded = unpad(decrypted, 16)
                    print(f"\n  After unpadding: {len(decrypted_unpadded)} bytes")
                    print(f"  Unpadded printable: {sum(1 for b in decrypted_unpadded if 32 <= b < 127)}/{len(decrypted_unpadded)}")
                    print(f"  Unpadded content: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted_unpadded[:200])}")
                except Exception as e:
                    print(f"  Unpad failed: {e}")
            except Exception as e:
                print(f"CBC decrypt error: {e}")

            # Try with IV = key
            try:
                cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_KEY)
                decrypted = cipher.decrypt(decoded)
                printable = sum(1 for b in decrypted if 32 <= b < 127)
                print(f"\nCBC with IV=KEY:")
                print(f"  Printable: {printable}/{len(decrypted)} ({printable/len(decrypted)*100:.0f}%)")
                print(f"  First 64 bytes ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted[:64])}")
                try:
                    decrypted_unpadded = unpad(decrypted, 16)
                    print(f"  After unpadding: {len(decrypted_unpadded)} bytes")
                except:
                    pass
            except Exception as e:
                print(f"CBC with IV=KEY error: {e}")

            # Try with IV = reversed key
            try:
                cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_KEY[::-1])
                decrypted = cipher.decrypt(decoded)
                printable = sum(1 for b in decrypted if 32 <= b < 127)
                print(f"\nCBC with IV=reversed KEY:")
                print(f"  Printable: {printable}/{len(decrypted)} ({printable/len(decrypted)*100:.0f}%)")
                print(f"  First 64 bytes ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted[:64])}")
                try:
                    decrypted_unpadded = unpad(decrypted, 16)
                    print(f"  After unpadding: {len(decrypted_unpadded)} bytes")
                except:
                    pass
            except Exception as e:
                print(f"CBC with IV=reversed key error: {e}")

            # Try CTR mode with various nonces
            for nonce in [b'\x00'*8, AES_KEY[:8], decoded[:8]]:
                try:
                    cipher = AES.new(AES_KEY, AES.MODE_CTR, nonce=nonce)
                    decrypted = cipher.decrypt(decoded)
                    printable = sum(1 for b in decrypted if 32 <= b < 127)
                    if printable > len(decrypted) * 0.6:  # Only show if mostly printable
                        print(f"\nCTR with nonce={nonce.hex()}:")
                        print(f"  Printable: {printable}/{len(decrypted)} ({printable/len(decrypted)*100:.0f}%)")
                        print(f"  Content: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted[:200])}")
                except Exception as e:
                    pass

            # Maybe the key is different for the heartbeat!
            # Let's try: what if the key is MD5 of the machine ID?
            import hashlib
            machine_id = "35346164-3866-492d-a339-30773a32652d"
            md5_key = hashlib.md5(machine_id.encode()).digest()
            print(f"\nTrying MD5 of machine ID as key: {md5_key.hex()}")
            try:
                cipher = AES.new(md5_key, AES.MODE_CBC, b'\x00' * 16)
                decrypted = cipher.decrypt(decoded)
                printable = sum(1 for b in decrypted if 32 <= b < 127)
                print(f"  Printable: {printable}/{len(decrypted)} ({printable/len(decrypted)*100:.0f}%)")
                print(f"  First 64 bytes ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted[:64])}")
                try:
                    decrypted_unpadded = unpad(decrypted, 16)
                    print(f"  After unpadding: {len(decrypted_unpadded)} bytes")
                    print(f"  Content: {decrypted_unpadded[:200]}")
                except:
                    pass
            except Exception as e:
                print(f"  Error: {e}")

            # Try MD5 of key string
            md5_of_key = hashlib.md5(AES_KEY).digest()
            print(f"\nTrying MD5 of key string as key: {md5_of_key.hex()}")
            try:
                cipher = AES.new(md5_of_key, AES.MODE_CBC, b'\x00' * 16)
                decrypted = cipher.decrypt(decoded)
                printable = sum(1 for b in decrypted if 32 <= b < 127)
                print(f"  Printable: {printable}/{len(decrypted)} ({printable/len(decrypted)*100:.0f}%)")
                print(f"  First 64 bytes ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted[:64])}")
                try:
                    decrypted_unpadded = unpad(decrypted, 16)
                    print(f"  After unpadding: {len(decrypted_unpadded)} bytes")
                except:
                    pass
            except Exception as e:
                print(f"  Error: {e}")

            break
