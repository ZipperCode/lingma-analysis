"""
Comprehensive analysis of the Encode=1 body encoding.

Goals:
1. Confirm it's a base64-like encoding with custom alphabet
2. Determine if there's encryption layer (AES, XOR, etc.)
3. Find patterns between different encoded bodies
4. Try to reverse the encoding from binary analysis data
"""

import base64
import json
import struct
import zlib
from collections import Counter, defaultdict
from pathlib import Path

ALPHABET = "!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
ALPHABET_INDEX = {c: i for i, c in enumerate(ALPHABET)}
STANDARD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def load_capture(path: str) -> list[dict]:
    entries = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def decode_custom_base64(text: str) -> bytes:
    """Decode custom base64 alphabet to bytes using standard base64 decoder."""
    # Map custom alphabet to standard base64 by position
    mapped = []
    for ch in text:
        if ch in ALPHABET_INDEX:
            idx = ALPHABET_INDEX[ch]
            if idx < 64:
                mapped.append(STANDARD_B64[idx])
            else:
                # Index 64: map to '+' (we'll try different mappings)
                mapped.append('+')
        else:
            mapped.append(ch)

    mapped_str = "".join(mapped)
    # Fix padding
    while len(mapped_str) % 4 != 0:
        mapped_str += "="

    return base64.b64decode(mapped_str)


def decode_6bit_stream(text: str) -> bytes:
    """Decode by treating each char as a 6-bit index and concatenating."""
    indices = [ALPHABET_INDEX.get(c, 0) for c in text]
    bit_stream = "".join(f"{idx:06b}" for idx in indices)
    byte_count = len(bit_stream) // 8
    result = []
    for i in range(byte_count):
        byte_bits = bit_stream[i * 8 : (i + 1) * 8]
        result.append(int(byte_bits, 2))
    return bytes(result)


def xor_bruteforce(data: bytes, target_prefix: bytes):
    """Try single-byte XOR to match a known prefix."""
    key = data[0] ^ target_prefix[0]
    result = bytes([b ^ key for b in data])
    if result[: len(target_prefix)] == target_prefix:
        return key, result
    return None, None


def try_multi_byte_xor(data: bytes, max_key_len: int = 4):
    """Try multi-byte XOR assuming the plaintext is JSON."""
    # JSON objects typically start with '{' and end with '}'
    # Common patterns: '{"', '":', ',"', ': "'
    # For a 2-byte XOR key: data[0]^k0 = '{', data[1]^k1 = '"'
    # So k0 = data[0] ^ 0x7b, k1 = data[1] ^ 0x22

    for key_len in range(1, max_key_len + 1):
        # Derive key from known plaintext prefix '{"' + common chars
        known_prefixes = [
            b'{"',
            b'{"r',
            b'{"re',
            b'{"requestId',
            b'{}',
            b'{"data',
            b'{"version',
        ]

        for prefix in known_prefixes:
            if len(prefix) < key_len:
                continue
            key = bytes([data[i] ^ prefix[i] for i in range(key_len)])

            # Apply key
            decrypted = bytearray()
            for i, b in enumerate(data):
                decrypted.append(b ^ key[i % key_len])

            # Check if it looks like valid JSON/UTF-8
            try:
                text = bytes(decrypted).decode("utf-8", errors="strict")
                if text.startswith("{") and text.rstrip("\x00\x01\x02 ").endswith("}"):
                    # Verify: count braces
                    if text.count("{") == text.count("}") and text.count("[") == text.count("]"):
                        return key, text
            except:
                pass

    return None, None


def analyze_entropy(data: bytes, block_size: int = 16):
    """Analyze byte distribution in blocks to detect encryption patterns."""
    if len(data) < block_size:
        return []

    entropies = []
    for i in range(0, len(data) - block_size + 1, block_size):
        block = data[i : i + block_size]
        unique = len(set(block))
        entropies.append((i, unique))

    return entropies


def compare_same_endpoint_bodies():
    """Compare bodies from the same endpoint across different captures."""
    print("=" * 60)
    print("Comparing same-endpoint bodies")
    print("=" * 60)

    # Load multiple captures
    files = [
        "capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl",
        "capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl",
    ]

    endpoint_bodies = defaultdict(list)
    for fpath in files:
        try:
            entries = load_capture(fpath)
            for entry in entries:
                if entry.get("body_len", 0) > 0:
                    path = entry.get("path", "").split("?")[0]
                    body = entry.get("body_utf8", "")
                    if body:
                        endpoint_bodies[path].append(body)
        except FileNotFoundError:
            continue

    for path, bodies in endpoint_bodies.items():
        if len(bodies) >= 2:
            print(f"\n{path}:")
            for i, body in enumerate(bodies):
                if i == 0:
                    print(f"  [{i}] len={len(body)}: {body[:80]}...")
                else:
                    same = body == bodies[0]
                    print(f"  [{i}] len={len(body)}: {'SAME' if same else 'DIFFERENT'} from [0]")
                    if not same:
                        # Find first difference
                        for j in range(min(len(body), len(bodies[0]))):
                            if body[j] != bodies[0][j]:
                                print(f"    First diff at pos {j}: '{bodies[0][j]}' vs '{body[j]}'")
                                break


def analyze_user_status():
    """Deep analysis of user/status encoded body."""
    print("\n" + "=" * 60)
    print("Deep analysis: user/status body")
    print("=" * 60)

    body = "uOFLDgKLDEKLN(iNBM)O#S%^D,%NBOg.JHiKuODbxoBymk.WB*f*DSQMu(CLFOFYN(Lbu*ByBMT*ep$$xoByxoKNB*%NBEjL#kFYPxCQ@(g.JHiau(tLuLf*lLf*xoBrxoKYDSDYDxjnFHWUDSQNBM)NBLf*Ggf*mYKf#xLru(gzBMn*m.f*JxjLNzLzxoByxoB.l@VfjMN(l@TflRzIVRBkxoBrxoKfDxK^u(QiugCbP(Fh"
    print(f"Body length: {len(body)} chars")
    print(f"Expected decoded size: {len(body) * 3 // 4} bytes (base64 ratio)")

    # Decode
    decoded = decode_custom_base64(body)
    print(f"Decoded: {len(decoded)} bytes")
    print(f"Hex: {decoded.hex()}")

    # Analyze entropy
    entropies = analyze_entropy(decoded)
    print(f"\nByte distribution per 16-byte block:")
    for offset, unique in entropies[:12]:
        print(f"  [{offset:3d}-{offset+15:3d}]: {unique} unique bytes")

    # The byte distribution should help identify if it's encrypted
    # Encrypted data typically has ~12-14 unique bytes per 16-byte block
    # Compressed data might have fewer
    # Plaintext JSON would have ~8-12 unique bytes

    # Try XOR attacks
    print("\nTrying single-byte XOR:")
    for target in [b"{", b'{"', b"{\n"]:
        key, result = xor_bruteforce(decoded, target)
        if key is not None:
            print(f"  Key 0x{key:02x}: {result[:200]}")

    print("\nTrying multi-byte XOR:")
    key, text = try_multi_byte_xor(decoded, max_key_len=4)
    if key:
        print(f"  Found key: {key.hex()}")
        print(f"  Decrypted: {text[:300]}")
    else:
        print("  No XOR key found")

    # Check for AES block patterns
    print("\nChecking for AES block patterns:")
    blocks = [decoded[i : i + 16] for i in range(0, len(decoded), 16)]
    unique_blocks = set(blocks)
    print(f"  Total 16-byte blocks: {len(blocks)}")
    print(f"  Unique blocks: {len(unique_blocks)}")

    if len(blocks) > len(unique_blocks):
        print("  -> Duplicate blocks found! This suggests ECB mode or deterministic encryption")
        # Find duplicates
        block_map = defaultdict(list)
        for i, block in enumerate(blocks):
            block_map[block].append(i)
        for block, indices in block_map.items():
            if len(indices) > 1:
                print(f"    Block {block.hex()[:32]}... appears at blocks {indices}")


def analyze_chat_body():
    """Analyze the larger chat generation body."""
    print("\n" + "=" * 60)
    print("Analysis: agent_chat_generation body")
    print("=" * 60)

    entries = load_capture("capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl")
    for entry in entries:
        if "agent_chat_generation" in entry.get("path", "") and entry.get("body_len", 0) > 0:
            body = entry.get("body_utf8", "")
            print(f"Body length: {len(body)} chars")
            print(f"Expected decoded size: {len(body) * 3 // 4} bytes")

            decoded = decode_custom_base64(body)
            print(f"Decoded: {len(decoded)} bytes")
            print(f"Hex first 64: {decoded[:64].hex()}")
            print(f"Hex last 32: {decoded[-32:].hex()}")

            # Check if it's the same encoding as user/status
            user_status = "uOFLDgKLDEKLN(iNBM)O#S%^D,%NBOg.JHiKuODbxoBymk.WB*f*DSQMu(CLFOFYN(Lbu*ByBMT*ep$$xoByxoKNB*%NBEjL#kFYPxCQ@(g.JHiau(tLuLf*lLf*xoBrxoKYDSDYDxjnFHWUDSQNBM)NBLf*Ggf*mYKf#xLru(gzBMn*m.f*JxjLNzLzxoByxoB.l@VfjMN(l@TflRzIVRBkxoBrxoKfDxK^u(QiugCbP(Fh"
            us_decoded = decode_custom_base64(user_status)

            # Compare first bytes
            print(f"\nuser/status decoded first 16: {us_decoded[:16].hex()}")
            print(f"chat decoded first 16:        {decoded[:16].hex()}")

            # Check if they share any common prefix or pattern
            common = 0
            for i in range(min(len(us_decoded), len(decoded))):
                if us_decoded[i] == decoded[i]:
                    common += 1
                else:
                    break
            print(f"Common prefix bytes: {common}")

            # Check byte distribution
            entropies = analyze_entropy(decoded)
            print(f"\nByte distribution per 16-byte block:")
            for offset, unique in entropies[:8]:
                block = decoded[offset : offset + 16]
                print(f"  [{offset:4d}-{offset+15:4d}]: {unique} unique bytes | {block.hex()}")

            # Try multi-byte XOR
            print("\nTrying multi-byte XOR:")
            key, text = try_multi_byte_xor(decoded, max_key_len=8)
            if key:
                print(f"  Found key: {key.hex()}")
                print(f"  Decrypted: {text[:300]}")
            else:
                print("  No XOR key found")

            break


def try_known_plaintext_recovery():
    """
    Try to recover the plaintext by assuming certain structure in the JSON.

    For user/status, the request is likely:
    - POST with Encode=1
    - Small JSON object

    If the encoding is: JSON -> custom_base64 -> AES -> custom_base64
    Then we need to figure out the AES key.

    If it's just: JSON -> custom_base64
    Then our direct decode should work.

    Let's check if the decoded bytes could be any known format.
    """
    print("\n" + "=" * 60)
    print("Known plaintext recovery attempt")
    print("=" * 60)

    body = "uOFLDgKLDEKLN(iNBM)O#S%^D,%NBOg.JHiKuODbxoBymk.WB*f*DSQMu(CLFOFYN(Lbu*ByBMT*ep$$xoByxoKNB*%NBEjL#kFYPxCQ@(g.JHiau(tLuLf*lLf*xoBrxoKYDSDYDxjnFHWUDSQNBM)NBLf*Ggf*mYKf#xLru(gzBMn*m.f*JxjLNzLzxoByxoB.l@VfjMN(l@TflRzIVRBkxoBrxoKfDxK^u(QiugCbP(Fh"
    decoded = decode_custom_base64(body)

    # Check various formats
    print("\n1. Is it UTF-16 encoded JSON?")
    try:
        text = decoded.decode("utf-16-le")
        if text.startswith("{"):
            print(f"  YES (LE): {text[:200]}")
    except:
        print("  No")

    try:
        text = decoded.decode("utf-16-be")
        if text.startswith("{"):
            print(f"  YES (BE): {text[:200]}")
    except:
        print("  No")

    print("\n2. Is it GBK/GB2312 encoded?")
    try:
        text = decoded.decode("gbk")
        if text.startswith("{") or text.isascii():
            print(f"  Maybe: {text[:200]}")
    except:
        print("  No")

    print("\n3. Is it protobuf?")
    # Simple protobuf check: repeated varint + field patterns
    if decoded[0] & 0x07 in [0, 1, 2, 3, 5]:  # Valid wire type
        print(f"  Possible: first byte wire type = {decoded[0] & 0x07}")

    print("\n4. Is it MessagePack?")
    # MessagePack fixmap: 0x80-0x8f
    if 0x80 <= decoded[0] <= 0x8F:
        print(f"  Possible: fixmap with {decoded[0] - 0x80} fields")

    print("\n5. Is it BSON?")
    # BSON starts with 4-byte length (little endian)
    if len(decoded) >= 4:
        bson_len = struct.unpack("<I", decoded[:4])[0]
        print(f"  BSON length: {bson_len} (actual: {len(decoded)})")
        if bson_len == len(decoded):
            print(f"  -> MATCHES!")

    print("\n6. Is it CBOR?")
    # CBOR major type 5 (map): 0xa0-0xbf
    if 0xA0 <= decoded[0] <= 0xBF:
        print(f"  Possible: map with encoded size")

    print("\n7. Raw hex analysis:")
    # Look for recognizable patterns
    for offset in range(len(decoded)):
        # UUID pattern: 8-4-4-4-12 hex chars
        window = decoded[offset : offset + 16]
        try:
            text = window.decode("ascii")
            import re

            if re.match(r"[0-9a-f]{8}-[0-9a-f]{4}-", text):
                print(f"  UUID-like at offset {offset}: {text}")
        except:
            pass

    print("\n8. Checking byte value distribution:")
    counter = Counter(decoded)
    print(f"  Total unique bytes: {len(counter)}")
    print(f"  Most common bytes:")
    for byte, count in counter.most_common(10):
        print(f"    0x{byte:02x} ({chr(byte) if 32 <= byte < 127 else '.'}): {count}")

    # Check if it could be AES-encrypted
    # AES encryption produces uniformly distributed bytes
    avg_unique = sum(len(set(decoded[i : i + 16])) for i in range(0, len(decoded) - 15, 16)) / (
        len(decoded) // 16
    )
    print(f"\n  Average unique bytes per 16-byte block: {avg_unique:.1f}")
    if avg_unique > 12:
        print("  -> High entropy, consistent with encryption")
    elif avg_unique > 8:
        print("  -> Medium entropy, could be compressed data")
    else:
        print("  -> Low entropy, likely plaintext or simple encoding")


def build_alphabet_mapping():
    """
    Build a complete mapping between the custom alphabet and standard base64.

    Custom: !#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz
    Standard: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/

    Let's try all possible 1-to-1 mappings and see which one produces valid output.
    """
    print("\n" + "=" * 60)
    print("Alphabet mapping analysis")
    print("=" * 60)

    # The custom alphabet has 65 characters (indices 0-64)
    # Standard base64 has 64 characters (indices 0-63)
    # The 65th character might be padding or have special meaning

    print(f"Custom alphabet ({len(ALPHABET)} chars):")
    print(f"  {ALPHABET}")
    print(f"  Index: {''.join(f'{i % 10}' for i in range(len(ALPHABET)))}")

    print(f"\nStandard base64 ({len(STANDARD_B64)} chars):")
    print(f"  {STANDARD_B64}")

    # Known: in standard base64:
    # A-Z (26) -> 0-25
    # a-z (26) -> 26-51
    # 0-9 (10) -> 52-61
    # +/ (2)  -> 62-63
    # = (1)   -> padding

    # In custom alphabet:
    # ! (0)  # (1)  $ (2)  % (3)  & (4)  ( (5)  ) (6)  * (7)  , (8)  . (9)
    # @ (10)
    # A-Z (11-36)
    # ^ (37) _ (38)
    # a-z (39-64)

    # If this is a simple base64 variant where A-Z,a-z keep their standard positions,
    # then we'd need digits and +/ somewhere.
    # But the custom alphabet has symbols in positions 0-10 and 37-38.

    # Let's check if the decoded output matches expected byte patterns
    # for a known JSON structure.

    # For a JSON like {"requestId":"..."}, the first few bytes would be:
    # 0x7b 0x22 0x72 0x65 0x71 0x75 0x65 0x73 0x74 0x49 0x64 0x22 0x3a 0x22
    # In base64, these would encode to specific characters.

    # Let's encode {"requestId":""} with standard base64:
    json_sample = b'{"requestId":""}'
    std_b64 = base64.b64encode(json_sample).decode()
    print(f"\nSample JSON: {json_sample}")
    print(f"Standard base64: {std_b64}")

    # Now, what would it be with our custom alphabet?
    # If we map: A->A, B->B, etc. (keep uppercase), then a->a, etc. (keep lowercase)
    # But 0-9 would need to map to the symbols.

    # Position mapping hypothesis:
    # Custom[0-9] = symbols -> maps to base64[0-9] = A-J... wait that doesn't work

    # Let me try a different approach:
    # What if the alphabet is just reordered, but still represents a standard
    # base64 encoding with a different character set?

    # For the user/status body starting with "uOFL":
    # In standard base64, "uOFL" decodes to bytes [0xba, 0x3d, 0xcb]
    # Wait, that's not right. Let me recalculate.

    # "uOFL" in standard base64:
    # u=46, O=14, F=5, L=11
    # 46*64^3 + 14*64^2 + 5*64 + 11 = ...
    # Actually, base64 decodes 4 chars to 3 bytes:
    # (46<<18)|(14<<12)|(5<<6)|11 = 0x2e<<18 | 0xe<<12 | 0x5<<6 | 0xb
    # = 0x0b8e150b -> bytes [0x2e, 0x38, 0x50, ...] wait that's not right either

    # Let me just use Python:
    try:
        decoded = base64.b64decode("uOFL")
        print(f"Standard base64 decode of 'uOFL': {decoded.hex()}")
    except:
        pass

    # Now with custom alphabet positions:
    # u=59, O=25, F=16, L=22
    # Map to standard: these would be at indices 59, 25, 16, 22 in standard base64
    std_chars = STANDARD_B64[59] + STANDARD_B64[25] + STANDARD_B64[16] + STANDARD_B64[22]
    print(f"Mapped to standard base64: '{std_chars}'")
    decoded = base64.b64decode(std_chars + "==")
    print(f"Decoded: {decoded.hex()}")
    # This gives the same result as our position-based decode

    # So the decoded bytes are what they are. The question is:
    # Are these bytes the original JSON, or are they encrypted?

    # Since we know AesEncryptWithBase64 exists, let's assume:
    # JSON -> AES -> custom_base64
    # And we need to find the AES key.


def try_aes_key_derivation():
    """
    Try to derive the AES key from known data.

    The encrypt package has AesEncryptWithBase64 and AesDecryptWithBase64.
    The key might come from:
    - machineKey (derived from cache/id)
    - A hardcoded key in the binary
    - A key derived from the session/token

    Let's try the machineKey we already know from the cache/user analysis.
    """
    from Crypto.Cipher import AES

    body = "uOFLDgKLDEKLN(iNBM)O#S%^D,%NBOg.JHiKuODbxoBymk.WB*f*DSQMu(CLFOFYN(Lbu*ByBMT*ep$$xoByxoKNB*%NBEjL#kFYPxCQ@(g.JHiau(tLuLf*lLf*xoBrxoKYDSDYDxjnFHWUDSQNBM)NBLf*Ggf*mYKf#xLru(gzBMn*m.f*JxjLNzLzxoByxoB.l@VfjMN(l@TflRzIVRBkxoBrxoKfDxK^u(QiugCbP(Fh"
    decoded = decode_custom_base64(body)

    print("\n" + "=" * 60)
    print("AES key derivation attempt")
    print("=" * 60)
    print(f"Encoded body decoded: {len(decoded)} bytes")

    # We know from the token flow analysis that:
    # - cache/id contains the machine ID
    # - cache/user is encrypted with AES-128-CBC using machineKey

    # The machine ID from the capture:
    machine_id = "35346164-3866-492d-a339-30773a32652d"

    # Try various key derivation methods
    print(f"\nMachine ID: {machine_id}")

    # Try machine_id as AES key (truncated/padded to 16 bytes)
    for key_source in [
        machine_id.encode(),
        machine_id.encode()[:16],
        machine_id.encode()[:32],
        bytes(range(16)),  # All zeros
        b"\x00" * 16,
        b"\x00" * 32,
        b"cosy" * 4,  # "cosy" padding
        b"lingma" * 3,  # "lingma" padding
    ]:
        if len(key_source) not in [16, 24, 32]:
            continue

        for iv_source in [
            b"\x00" * 16,  # Zero IV
            key_source[:16],  # Key as IV
            machine_id.encode()[:16],  # Machine ID as IV
        ]:
            try:
                cipher = AES.new(key_source, AES.MODE_CBC, iv_source[:16])
                decrypted = cipher.decrypt(decoded)

                # Try to decode as UTF-8
                try:
                    text = decrypted.decode("utf-8")
                    if text.startswith("{") and "requestId" in text[:50]:
                        print(f"\n  SUCCESS! Key: {key_source.hex()} IV: {iv_source[:16].hex()}")
                        print(f"  Decrypted: {text}")
                        return
                    elif text.startswith("{") and text.endswith("}\x00") or text.endswith("}"):
                        print(f"\n  Possible match! Key: {key_source.hex()} IV: {iv_source[:16].hex()}")
                        print(f"  Decrypted: {text[:200]}")
                except:
                    pass
            except Exception as e:
                pass

    print("\n  No AES key found with common derivations")


def main():
    compare_same_endpoint_bodies()
    analyze_user_status()
    analyze_chat_body()
    try_known_plaintext_recovery()
    build_alphabet_mapping()

    try:
        try_aes_key_derivation()
    except ImportError:
        print("\n  pycryptodome not available, skipping AES attempts")


if __name__ == "__main__":
    main()
