"""
Final brute-force attempt with correct decoding.

Structure hypothesis:
- 1 byte header + 176 bytes ciphertext (11 AES blocks)
- Or: no header, entire 177 bytes is AES-CTR ciphertext

Machine ID: 35346164-3866-492d-a339-30773a32652d
"""

import hashlib
import json
import base64

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    HAS_CRYPTO = True
except ImportError:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        HAS_CRYPTOGRAPHY = True
    except ImportError:
        HAS_CRYPTO = False
        HAS_CRYPTOGRAPHY = False

CUSTOM_ALPHABET = "!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
ALPHABET_INDEX = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}
STANDARD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

MACHINE_ID = "35346164-3866-492d-a339-30773a32652d"

def decode_body(text):
    bits = []
    for ch in text:
        if ch in ALPHABET_INDEX and ALPHABET_INDEX[ch] < 64:
            idx = ALPHABET_INDEX[ch]
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

USER_STATUS_BODY = "uOFLDgKLDEKLN(iNBM)O#S%^D,%NBOg.JHiKuODbxoBymk.WB*f*DSQMu(CLFOFYN(Lbu*ByBMT*ep$$xoByxoKNB*%NBEjL#kFYPxCQ@(g.JHiau(tLuLf*lLf*xoBrxoKYDSDYDxjnFHWUDSQNBM)NBLf*Ggf*mYKf#xLru(gzBMn*m.f*JxjLNzLzxoByxoB.l@VfjMN(l@TflRzIVRBkxoBrxoKfDxK^u(QiugCbP(Fh"

decoded = decode(USER_STATUS_BODY)
print(f"Decoded: {len(decoded)} bytes")
print(f"First 16: {decoded[:16].hex()}")
print(f"Last 16: {decoded[-16:].hex()}")

# Generate key candidates
def generate_keys():
    keys = {}
    mid = MACHINE_ID.encode()
    mid_no_dash = MACHINE_ID.replace("-", "").encode()

    # Hex decode machine ID
    try:
        hex_decoded = bytes.fromhex(MACHINE_ID.replace("-", ""))
    except:
        hex_decoded = b""

    # Direct bytes
    keys['mid_16'] = mid[:16]
    keys['mid_32'] = mid[:32]
    keys['mid_nodash_16'] = mid_no_dash[:16]
    keys['mid_nodash_32'] = mid_no_dash[:32]
    keys['hex_16'] = hex_decoded[:16] if hex_decoded else b'\x00' * 16

    # Hash-based
    keys['md5_mid_16'] = hashlib.md5(mid).digest()
    keys['md5_mid_32'] = hashlib.md5(mid + mid).digest()[:32]
    keys['md5_nodash_16'] = hashlib.md5(mid_no_dash).digest()
    keys['sha256_mid_16'] = hashlib.sha256(mid).digest()[:16]
    keys['sha256_mid_32'] = hashlib.sha256(mid).digest()
    keys['sha256_nodash_16'] = hashlib.sha256(mid_no_dash).digest()[:16]
    keys['sha256_nodash_32'] = hashlib.sha256(mid_no_dash).digest()
    keys['sha1_mid_16'] = hashlib.sha1(mid).digest()[:16]

    # Hex decoded based
    if hex_decoded:
        keys['md5_hex_16'] = hashlib.md5(hex_decoded).digest()
        keys['sha256_hex_16'] = hashlib.sha256(hex_decoded).digest()[:16]
        keys['sha256_hex_32'] = hashlib.sha256(hex_decoded).digest()

    # Common strings
    for s in ['lingma', 'Lingma', 'LINGMA', 'cosy', 'Cosy', 'COSY',
              'alibaba', 'Alibaba', 'aliyun', 'Aliyun', 'aes', 'encrypt',
              'machine', 'key', 'secret']:
        keys[f'md5_{s}_16'] = hashlib.md5(s.encode()).digest()
        keys[f'sha256_{s}_32'] = hashlib.sha256(s.encode()).digest()

    # Combined
    for s in ['lingma', 'cosy', 'encrypt', 'aes']:
        salted = (s + MACHINE_ID).encode()
        keys[f'md5_{s}+mid_16'] = hashlib.md5(salted).digest()
        keys[f'sha256_{s}+mid_32'] = hashlib.sha256(salted).digest()

        salted2 = (MACHINE_ID + s).encode()
        keys[f'md5_mid+{s}_16'] = hashlib.md5(salted2).digest()
        keys[f'sha256_mid+{s}_32'] = hashlib.sha256(salted2).digest()

    # Zero keys
    keys['zero_16'] = b'\x00' * 16
    keys['zero_32'] = b'\x00' * 32

    return keys

# Generate IV candidates
def generate_ivs():
    ivs = {}
    mid = MACHINE_ID.encode()
    mid_no_dash = MACHINE_ID.replace("-", "").encode()
    try:
        hex_decoded = bytes.fromhex(MACHINE_ID.replace("-", ""))
    except:
        hex_decoded = b'\x00' * 16

    ivs['zero'] = b'\x00' * 16
    ivs['md5_mid'] = hashlib.md5(mid).digest()
    ivs['sha256_mid_16'] = hashlib.sha256(mid).digest()[:16]
    ivs['mid_16'] = mid[:16]
    ivs['mid_nodash_16'] = mid_no_dash[:16]
    ivs['hex_decoded'] = hex_decoded
    ivs['hex_padded'] = hex_decoded + b'\x00' * (16 - len(hex_decoded))
    ivs['ones'] = b'\x01' * 16
    ivs['ff'] = b'\xff' * 16

    # IV from encoded body itself (first 16 bytes of decoded)
    # This would be if IV is prepended to ciphertext
    ivs['from_body_first16'] = decoded[:16]

    return ivs

keys = generate_keys()
ivs = generate_ivs()

print(f"\nKey candidates: {len(keys)}")
print(f"IV candidates: {len(ivs)}")

results = []
total_tests = 0

# Test CBC mode with 1-byte header
print("\n=== Testing CBC mode (1-byte header + 176 bytes ciphertext) ===")
header_byte = decoded[0]
ciphertext = decoded[1:]  # 176 bytes

print(f"Header byte: 0x{header_byte:02x}")
print(f"Ciphertext length: {len(ciphertext)} bytes ({len(ciphertext) // 16} blocks)")
print(f"First block: {ciphertext[:16].hex()}")
print(f"Last block: {ciphertext[-16:].hex()}")

for key_name, key in keys.items():
    if len(key) not in (16, 24, 32):
        continue

    for iv_name, iv in ivs.items():
        if len(iv) != 16:
            continue

        total_tests += 1

        try:
            if HAS_CRYPTO:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                pt = cipher.decrypt(ciphertext)

                # Check PKCS5 padding
                pad_len = pt[-1]
                if 1 <= pad_len <= 16 and all(b == pad_len for b in pt[-pad_len:]):
                    pt_unpadded = pt[:-pad_len]
                else:
                    continue

                # Check if valid JSON
                try:
                    obj = json.loads(pt_unpadded)
                    print(f"\n*** JSON MATCH! ***")
                    print(f"Key: {key_name} ({key.hex()})")
                    print(f"IV: {iv_name} ({iv.hex()})")
                    print(f"Plaintext: {json.dumps(obj, indent=2)[:300]}")
                    results.append(('CBC', key_name, iv_name, obj))
                except:
                    # Check if printable
                    printable = sum(1 for b in pt_unpadded if 32 <= b < 127)
                    if printable / len(pt_unpadded) > 0.8:
                        text = pt_unpadded.decode('utf-8', errors='replace')
                        if '{' in text and '}' in text:
                            print(f"\n*** POSSIBLE MATCH (not JSON but printable with braces) ***")
                            print(f"Key: {key_name}")
                            print(f"IV: {iv_name}")
                            print(f"Text: {text[:200]}")
                            results.append(('CBC-printable', key_name, iv_name, text))
        except Exception as e:
            pass

print(f"\n\nTested {total_tests} CBC combinations")
print(f"Found {len(results)} potential matches")

if not results:
    print("\n\nNo CBC match found. Trying AES-CTR mode...")

    # Test CTR mode (no padding needed)
    total_tests = 0
    for key_name, key in keys.items():
        if len(key) not in (16, 24, 32):
            continue

        for iv_name, iv in ivs.items():
            if len(iv) != 16:
                continue

            total_tests += 1

            try:
                if HAS_CRYPTO:
                    # Try with no counter (just IV as nonce)
                    from Crypto.Cipher import AES
                    # CTR with 8-byte nonce + 8-byte counter
                    try:
                        cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
                        pt = cipher.decrypt(decoded)  # Full 177 bytes

                        printable = sum(1 for b in pt if 32 <= b < 127)
                        if printable / len(pt) > 0.7:
                            text = pt.decode('utf-8', errors='replace')
                            try:
                                obj = json.loads(text)
                                print(f"\n*** CTR JSON MATCH! ***")
                                print(f"Key: {key_name}")
                                print(f"IV/nonce: {iv_name}")
                                print(f"Plaintext: {json.dumps(obj, indent=2)[:300]}")
                                results.append(('CTR', key_name, iv_name, obj))
                            except:
                                if '{' in text:
                                    print(f"\n*** CTR POSSIBLE MATCH ***")
                                    print(f"Key: {key_name}")
                                    print(f"IV/nonce: {iv_name}")
                                    print(f"Text: {text[:200]}")
                    except:
                        pass
            except:
                pass

    print(f"\n\nTested {total_tests} CTR combinations")
    print(f"Found {len(results)} CTR matches")

if not results:
    print("\n\nNo matches with any standard mode.")
    print("\nNext steps:")
    print("1. Run Lingma and use Frida to capture the actual key")
    print("2. The alphabet might be different from what we assume")
    print("3. The key derivation might use a non-standard algorithm")
