"""
Brute-force decryption of Lingma encoded bodies.

Known:
- user/status body (240 chars) decodes to 180 bytes of AES ciphertext
- Ciphertext is identical across captures (deterministic encryption)
- Machine ID: 35346164-3866-492d-a339-30773a32652d
- Encryption: AES with PKCS5 padding, custom base64 encoding

Strategy: Try all plausible key derivations and IV values.
For each, decrypt and check if the result is valid JSON.

The JSON should contain fields like:
- requestId (UUID string)
- version (string)
- machineId or deviceId
- platform info

Total key derivations to try: ~20
Total IV derivations to try: ~10
Total combinations: ~200 (very feasible)
"""

import hashlib
import struct
import json
import base64
from typing import Optional

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    HAS_PYCRYPTO = True
except ImportError:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
        HAS_CRYPTOGRAPHY = True
    except ImportError:
        HAS_PYCRYPTO = False
        HAS_CRYPTOGRAPHY = False

# Known values
MACHINE_ID = "35346164-3866-492d-a339-30773a32652d"
ALPHABET = "!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
ALPHABET_INDEX = {c: i for i, c in enumerate(ALPHABET)}
STANDARD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# The user/status encoded body (240 chars)
USER_STATUS_BODY = "uOFLDgKLDEKLN(iNBM)O#S%^D,%NBOg.JHiKuODbxoBymk.WB*f*DSQMu(CLFOFYN(Lbu*ByBMT*ep$$xoByxoKNB*%NBEjL#kFYPxCQ@(g.JHiau(tLuLf*lLf*xoBrxoKYDSDYDxjnFHWUDSQNBM)NBLf*Ggf*mYKf#xLru(gzBMn*m.f*JxjLNzLzxoByxoB.l@VfjMN(l@TflRzIVRBkxoBrxoKfDxK^u(QiugCbP(Fh"


def decode_custom_base64(text: str) -> bytes:
    """Decode the custom base64-like encoding."""
    mapped = []
    for ch in text:
        if ch in ALPHABET_INDEX:
            idx = ALPHABET_INDEX[ch]
            # Map to standard base64
            if idx < 64:
                mapped.append(STANDARD_B64[idx])
            else:
                # 65th character maps to standard base64 padding or +/
                # Since we have 65 chars but base64 uses 64, the 65th
                # is likely unused or maps to padding
                pass
        # Skip characters not in alphabet
    mapped_str = "".join(mapped)
    # Add padding
    while len(mapped_str) % 4 != 0:
        mapped_str += "="
    return base64.b64decode(mapped_str)


def aes_decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> Optional[bytes]:
    """Decrypt AES-CBC with PKCS5 unpadding."""
    key_len = len(key)
    if key_len not in (16, 24, 32):
        return None

    try:
        if HAS_PYCRYPTO:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            try:
                return unpad(decrypted, AES.block_size)
            except ValueError:
                return None
        elif HAS_CRYPTOGRAPHY:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            # Manual PKCS5 unpadding
            pad_len = decrypted[-1]
            if 1 <= pad_len <= 16 and all(b == pad_len for b in decrypted[-pad_len:]):
                return decrypted[:-pad_len]
            return None
        else:
            print("  No crypto library available. Install pycryptodome or cryptography.")
            return None
    except Exception as e:
        return None


def aes_decrypt_ecb(key: bytes, ciphertext: bytes) -> Optional[bytes]:
    """Decrypt AES-ECB with PKCS5 unpadding."""
    key_len = len(key)
    if key_len not in (16, 24, 32):
        return None

    try:
        if HAS_PYCRYPTO:
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted = cipher.decrypt(ciphertext)
            try:
                return unpad(decrypted, AES.block_size)
            except ValueError:
                return None
        elif HAS_CRYPTOGRAPHY:
            cipher = Cipher(algorithms.AES(key), modes.ECB())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            pad_len = decrypted[-1]
            if 1 <= pad_len <= 16 and all(b == pad_len for b in decrypted[-pad_len:]):
                return decrypted[:-pad_len]
            return None
        else:
            return None
    except Exception:
        return None


def try_all_keys():
    """Try all plausible key derivations."""
    machine_id = MACHINE_ID
    machine_id_bytes = machine_id.encode('utf-8')

    # Key derivation methods
    keys = {}

    # 1. Direct bytes (first 16/32 bytes of machine ID)
    keys['direct_16'] = machine_id_bytes[:16]
    keys['direct_32'] = machine_id_bytes[:32]

    # 2. MD5 of machine ID
    keys['md5'] = hashlib.md5(machine_id_bytes).digest()  # 16 bytes

    # 3. SHA256 of machine ID (truncated to 16/32)
    sha256 = hashlib.sha256(machine_id_bytes).digest()
    keys['sha256_16'] = sha256[:16]
    keys['sha256_32'] = sha256  # 32 bytes

    # 4. SHA1 truncated
    sha1 = hashlib.sha1(machine_id_bytes).digest()
    keys['sha1_16'] = sha1[:16]

    # 5. Machine ID without dashes
    no_dashes = machine_id.replace("-", "")
    no_dash_bytes = no_dashes.encode('utf-8')
    keys['no_dash_16'] = no_dash_bytes[:16]
    keys['no_dash_32'] = no_dash_bytes[:32]

    # 6. MD5 of machine ID without dashes
    keys['md5_no_dash_16'] = hashlib.md5(no_dash_bytes).digest()
    keys['md5_no_dash_32'] = hashlib.md5(no_dash_bytes + no_dash_bytes).digest()[:32]

    # 7. Hex decode of machine ID parts
    # 35346164-3866-492d-a339-30773a32652d -> decode hex pairs
    try:
        hex_decoded = bytes.fromhex(machine_id.replace("-", ""))
        keys['hex_decode_16'] = hex_decoded[:16]
        keys['hex_decode_32'] = hex_decoded  # 16 bytes (UUID)
        print(f"  Hex decoded machine ID: {hex_decoded.hex()}")
        print(f"  Hex decoded as text: {hex_decoded.decode('ascii', errors='replace')}")
    except ValueError:
        print("  Hex decode failed")

    # 8. MD5 of hex-decoded ID
    try:
        hex_decoded = bytes.fromhex(machine_id.replace("-", ""))
        keys['md5_hex_16'] = hashlib.md5(hex_decoded).digest()
        keys['md5_hex_32'] = hashlib.md5(hex_decoded + hex_decoded).digest()
    except:
        pass

    # 9. SHA256 of hex-decoded ID
    try:
        hex_decoded = bytes.fromhex(machine_id.replace("-", ""))
        sha_hex = hashlib.sha256(hex_decoded).digest()
        keys['sha256_hex_16'] = sha_hex[:16]
        keys['sha256_hex_32'] = sha_hex
    except:
        pass

    # 10. Common hardcoded keys (unlikely but worth trying)
    keys['zero_16'] = b'\\x00' * 16
    keys['zero_32'] = b'\\x00' * 32

    # 11. Lingma-related hardcoded strings
    for s in ['lingma', 'Lingma', 'LINGMA', 'cosy', 'Cosy', 'COSY',
              'alibaba', 'Alibaba', 'aliyun', 'Aliyun']:
        h = hashlib.md5(s.encode()).digest()
        keys[f'md5_{s}_16'] = h
        keys[f'sha256_{s}_32'] = hashlib.sha256(s.encode()).digest()

    # 12. Machine ID with common salt
    for salt in ['lingma', 'cosy', 'encrypt', 'aes', 'key', 'machine']:
        salted = (salt + machine_id).encode()
        keys[f'md5_{salt}_machine_16'] = hashlib.md5(salted).digest()
        keys[f'sha256_{salt}_machine_32'] = hashlib.sha256(salted).digest()

        salted2 = (machine_id + salt).encode()
        keys[f'md5_machine_{salt}_16'] = hashlib.md5(salted2).digest()
        keys[f'sha256_machine_{salt}_32'] = hashlib.sha256(salted2).digest()

    return keys


def try_all_ivs() -> dict[str, bytes]:
    """Try all plausible IV values."""
    ivs = {}

    # 1. Zero IV (most likely for deterministic encryption)
    ivs['zero_16'] = b'\\x00' * 16

    # 2. IV derived from machine ID
    machine_id = MACHINE_ID.encode()
    ivs['md5_machine'] = hashlib.md5(machine_id).digest()
    ivs['sha256_machine'] = hashlib.sha256(machine_id).digest()[:16]

    # 3. IV = first 16 bytes of machine ID
    ivs['machine_id_16'] = machine_id[:16]

    # 4. IV = machine ID without dashes
    no_dashes = MACHINE_ID.replace("-", "").encode()
    ivs['no_dashes_16'] = no_dashes[:16]

    # 5. Hex-decoded machine ID as IV
    try:
        hex_decoded = bytes.fromhex(MACHINE_ID.replace("-", ""))
        ivs['hex_decoded'] = hex_decoded
        ivs['hex_decoded_padded'] = hex_decoded + b'\\x00' * (16 - len(hex_decoded))
    except:
        pass

    # 6. Fixed IV from binary
    # Try common fixed IVs
    for fixed in [b'\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f\\x10',
                  b'abcdefghijklmnop',
                  b'0123456789abcdef',
                  b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01']:
        ivs[f'fixed_{fixed[:8].hex()}'] = fixed

    return ivs


def is_valid_json(data: bytes) -> bool:
    """Check if data is valid JSON."""
    try:
        obj = json.loads(data)
        return isinstance(obj, (dict, list))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False


def analyze_plaintext(data: bytes) -> dict:
    """Analyze decrypted plaintext for JSON-like patterns."""
    result = {
        'is_json': False,
        'json_obj': None,
        'has_braces': False,
        'has_request_id': False,
        'has_version': False,
        'printable_ratio': 0,
        'preview': '',
    }

    try:
        text = data.decode('utf-8', errors='replace')
        result['printable_ratio'] = sum(1 for c in text if 32 <= ord(c) < 127) / len(text)
        result['preview'] = text[:100]
        result['has_braces'] = '{' in text and '}' in text
        result['has_request_id'] = 'requestId' in text or 'request_id' in text
        result['has_version'] = 'version' in text

        if is_valid_json(data):
            result['is_json'] = True
            result['json_obj'] = json.loads(data)
    except:
        pass

    return result


def main():
    print("=" * 60)
    print("Lingma Body Decryption Brute-Force")
    print("=" * 60)

    # Step 1: Decode the custom base64
    print(f"\\n1. Decoding custom base64 ({len(USER_STATUS_BODY)} chars)...")
    ciphertext = decode_custom_base64(USER_STATUS_BODY)
    print(f"   Decoded: {len(ciphertext)} bytes")
    print(f"   First 32 bytes (hex): {ciphertext[:32].hex()}")

    # Check if length is a multiple of 16 (AES block size)
    if len(ciphertext) % 16 != 0:
        print(f"   WARNING: Length is NOT a multiple of 16!")
        print(f"   This might not be AES-CBC, or there's a header/MAC prepended")
    else:
        print(f"   Length is {len(ciphertext) // 16} AES blocks")

    # Step 2: Generate all possible keys
    print(f"\\n2. Generating key candidates...")
    keys = try_all_keys()
    print(f"   Generated {len(keys)} key candidates")

    # Step 3: Generate all possible IVs
    print(f"\\n3. Generating IV candidates...")
    ivs = try_all_ivs()
    print(f"   Generated {len(ivs)} IV candidates")

    # Step 4: Try all combinations
    print(f"\\n4. Trying {len(keys)} x {len(ivs)} = {len(keys) * len(ivs)} combinations...")
    print("=" * 60)

    results = []
    total = 0
    for key_name, key in keys.items():
        for iv_name, iv in ivs.items():
            if len(key) not in (16, 24, 32):
                continue
            if len(iv) != 16:
                continue

            total += 1

            # Try CBC mode
            plaintext = aes_decrypt_cbc(key, iv, ciphertext)
            if plaintext:
                analysis = analyze_plaintext(plaintext)
                if analysis['is_json'] or analysis['printable_ratio'] > 0.7:
                    results.append({
                        'key': key_name,
                        'iv': iv_name,
                        'mode': 'CBC',
                        'plaintext': plaintext,
                        'analysis': analysis,
                    })
                    print(f"\\n  *** POSSIBLE MATCH ***")
                    print(f"  Key: {key_name} ({key.hex()})")
                    print(f"  IV: {iv_name} ({iv.hex()})")
                    print(f"  Mode: CBC")
                    print(f"  Plaintext: {analysis['preview'][:100]}")
                    print(f"  Is JSON: {analysis['is_json']}")
                    if analysis['is_json']:
                        print(f"  JSON: {json.dumps(analysis['json_obj'], indent=2)[:200]}")

            # Try ECB mode (less likely but possible)
            plaintext_ecb = aes_decrypt_ecb(key, ciphertext)
            if plaintext_ecb:
                analysis = analyze_plaintext(plaintext_ecb)
                if analysis['is_json'] or analysis['printable_ratio'] > 0.7:
                    results.append({
                        'key': key_name,
                        'iv': iv_name,
                        'mode': 'ECB',
                        'plaintext': plaintext_ecb,
                        'analysis': analysis,
                    })
                    print(f"\\n  *** POSSIBLE MATCH (ECB) ***")
                    print(f"  Key: {key_name} ({key.hex()})")
                    print(f"  Mode: ECB")
                    print(f"  Plaintext: {analysis['preview'][:100]}")

    print(f"\\n{'=' * 60}")
    print(f"Tested {total} combinations")
    print(f"Found {len(results)} potential matches")

    if not results:
        print(f"\\nNo valid decryption found with standard key derivations.")
        print(f"\\nPossible reasons:")
        print(f"1. The key is derived using a non-standard algorithm")
        print(f"2. The IV is not a standard derivation (maybe hardcoded)")
        print(f"3. The encoding is NOT AES (maybe a different cipher)")
        print(f"4. The alphabet mapping is different from what we assumed")
        print(f"\\nNext steps:")
        print(f"1. Run Frida on a live process to capture the key")
        print(f"2. Extract the encoding alphabet from the binary")
        print(f"3. Analyze the encrypt.init function more carefully")

    return results


if __name__ == "__main__":
    main()
