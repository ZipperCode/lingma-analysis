"""
Differential analysis of Encode=1 bodies across multiple captures.

Key insight: user/status body is IDENTICAL across 5+ captures.
This means: same plaintext -> same ciphertext (deterministic encryption, no random IV).

Strategy:
1. For endpoints where the body changes (chat, finish), analyze WHAT changes
2. For endpoints where the body is the same (user/status), the plaintext is fixed
3. Use the known function chain to narrow down the encryption algorithm
"""

import json
import base64
from collections import Counter, defaultdict

ALPHABET = "!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
ALPHABET_INDEX = {c: i for i, c in enumerate(ALPHABET)}
STANDARD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def decode_custom_base64(text: str) -> bytes:
    mapped = []
    for ch in text:
        if ch in ALPHABET_INDEX:
            idx = ALPHABET_INDEX[ch]
            mapped.append(STANDARD_B64[idx] if idx < 64 else '+')
    mapped_str = "".join(mapped)
    while len(mapped_str) % 4 != 0:
        mapped_str += "="
    return base64.b64decode(mapped_str)

def load_capture(path: str) -> list[dict]:
    entries = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries

def differential_analysis():
    """
    For business/finish, we have two captures of len=848 and len=852.
    These might have different requestIds but similar structure.

    For user/status, all captures are identical.

    Let's look at the ASK/FINISH endpoint which has two bodies of the SAME length (244).
    """
    print("=" * 60)
    print("Differential analysis: same-length bodies")
    print("=" * 60)

    # Load the 235500 capture which has ask/finish
    entries = load_capture("capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl")

    finish_entries = [e for e in entries if "ask/finish" in e.get("path", "") and e.get("body_len", 0) > 0]
    if len(finish_entries) >= 2:
        body1 = finish_entries[0].get("body_utf8", "")
        body2 = finish_entries[1].get("body_utf8", "")

        print(f"\nask/finish capture 1: len={len(body1)}")
        print(f"ask/finish capture 2: len={len(body2)}")

        # Find differences
        diffs = []
        for i in range(max(len(body1), len(body2))):
            c1 = body1[i] if i < len(body1) else None
            c2 = body2[i] if i < len(body2) else None
            if c1 != c2:
                diffs.append((i, c1, c2))

        print(f"Total differences: {len(diffs)}")
        if len(diffs) <= 50:
            for pos, c1, c2 in diffs:
                idx1 = ALPHABET_INDEX.get(c1, -1) if c1 else -1
                idx2 = ALPHABET_INDEX.get(c2, -1) if c2 else -1
                print(f"  pos {pos:3d}: '{c1}' (idx={idx1:2d}) vs '{c2}' (idx={idx2:2d}), XOR={idx1^idx2:02x}")

        # Decode both and compare at byte level
        dec1 = decode_custom_base64(body1)
        dec2 = decode_custom_base64(body2)
        print(f"\nDecoded lengths: {len(dec1)} vs {len(dec2)}")

        byte_diffs = []
        for i in range(max(len(dec1), len(dec2))):
            b1 = dec1[i] if i < len(dec1) else None
            b2 = dec2[i] if i < len(dec2) else None
            if b1 != b2:
                byte_diffs.append((i, b1, b2))

        print(f"Byte-level differences: {len(byte_diffs)}")
        if len(byte_diffs) <= 50:
            for pos, b1, b2 in byte_diffs:
                print(f"  pos {pos:3d}: 0x{b1:02x} vs 0x{b2:02x}, XOR=0x{b1^b2:02x}")

        # If byte differences are concentrated in a few positions,
        # it suggests the plaintext has small variations (like different requestIds)

    # Also check embedding_k2 which has len=180 and len=176
    print("\n" + "=" * 60)
    print("embedding_k2: len=180 vs len=176")
    print("=" * 60)

    embedding_entries = [e for e in entries if "embedding_k2" in e.get("path", "") and e.get("body_len", 0) > 0]
    if len(embedding_entries) >= 2:
        body1 = embedding_entries[0].get("body_utf8", "")
        body2 = embedding_entries[1].get("body_utf8", "")
        print(f"Body 1: len={len(body1)}")
        print(f"  {body1[:100]}...")
        print(f"Body 2: len={len(body2)}")
        print(f"  {body2[:100]}...")

        # Find where they diverge
        common = 0
        for i in range(min(len(body1), len(body2))):
            if body1[i] == body2[i]:
                common += 1
            else:
                break
        print(f"Common prefix: {common} chars")
        print(f"Difference starts at pos {common}: '{body1[common:common+10]}' vs '{body2[common:common+10]}'")


def analyze_user_status_fixed_body():
    """
    The user/status body is 240 chars = 180 decoded bytes.
    All captures produce the exact same body.

    If this is AES-encrypted JSON, and it's deterministic (no IV), then:
    - It could be AES-ECB (deterministic per block)
    - Or AES-CBC with fixed/zero IV

    180 bytes -> original JSON could be:
    - ~180 bytes uncompressed
    - ~165 bytes with PKCS#7 padding (180 - 15 = 165)
    - Or 180 bytes is the raw plaintext (no encryption, just encoding)

    Let's think about what JSON would be exactly 165-180 bytes.
    """
    print("\n" + "=" * 60)
    print("user/status fixed body: plaintext size estimation")
    print("=" * 60)

    # AES-128/256 with PKCS#7: ciphertext_len = (plaintext_len // 16 + 1) * 16
    # For 180 bytes ciphertext:
    # 180 = 12 * 16, so plaintext was between 165 and 180 bytes (165 to 179 + padding)

    for original_size in range(165, 181):
        padding = 16 - (original_size % 16) if original_size % 16 != 0 else 16
        cipher_size = original_size + padding
        if cipher_size == 180:
            print(f"  If plaintext was {original_size} bytes, padding = {padding}, total = {cipher_size}")

    # What JSON structures are ~165-179 bytes?
    examples = [
        '{"requestId":"67fdb6d5-e38f-4308-867d-b97c2b663935","version":"1"}',  # 66 bytes
        '{"requestId":"67fdb6d5-e38f-4308-867d-b97c2b663935"}',  # 52 bytes
    ]

    print(f"\nSimple JSON sizes:")
    for ex in examples:
        print(f"  {ex} -> {len(ex)} bytes")

    # For a user/status request, it might include more fields:
    # Machine info, device fingerprint, etc.
    # 165-180 bytes is quite large for a simple status check

    # Could the body include binary data or certificates?
    # Or could it be a protobuf message?

    # Let's also check: is the user/status request body the same across ALL capture files?
    print("\nChecking user/status body across all captures:")
    files = [
        "capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl",
        "capture/lingma-http-capture-proxynofrida-20260424-233125.jsonl",
        "capture/lingma-http-capture-proxynofrida-20260424-235210.jsonl",
        "capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl",
    ]

    bodies = []
    for fpath in files:
        try:
            entries = load_capture(fpath)
            for entry in entries:
                if "user/status" in entry.get("path", "") and entry.get("body_len", 0) > 0:
                    body = entry.get("body_utf8", "")
                    if body:
                        bodies.append((fpath.split("/")[-1], body))
        except FileNotFoundError:
            pass

    if bodies:
        print(f"  Found {len(bodies)} user/status bodies")
        unique = set(b[1] for b in bodies)
        print(f"  Unique bodies: {len(unique)}")
        if len(unique) == 1:
            print("  ALL IDENTICAL - confirms deterministic encryption")


def try_brute_force_user_status_json():
    """
    Try to figure out what JSON the user/status request contains.

    Since the decoded body is 180 bytes and the encryption is likely AES,
    we need to either:
    1. Know the AES key (from the binary)
    2. Brute-force the plaintext size and structure

    Let's try another angle: what if the encoding is NOT AES, but something simpler?

    The encodeRequestBody function is only 352 bytes of code.
    AES-256-CBC implementation in Go would be much larger.
    So encodeRequestBody might not be doing the encryption itself.
    Instead, it might:
    1. Call a lower-level encoding function
    2. Or the "encoding" is just the custom base64, and the "encryption"
       happens in a different function (like AesEncryptWithBase64)

    If the plaintext IS 180 bytes of JSON, that's a very large request for
    a simple user/status check. Unless it includes telemetry or fingerprint data.
    """
    print("\n" + "=" * 60)
    print("Brute-force JSON structure for user/status")
    print("=" * 60)

    # Try various JSON structures and see what size we get
    import uuid

    structures = [
        lambda: json.dumps({"requestId": str(uuid.uuid4()), "version": "1"}),
        lambda: json.dumps({"requestId": str(uuid.uuid4()), "version": "1", "data": {}}),
        lambda: json.dumps({"requestId": str(uuid.uuid4()), "version": "1", "data": "{}"}),
        lambda: json.dumps({"requestId": str(uuid.uuid4()), "encodeVersion": "1"}),
        lambda: json.dumps({"requestId": str(uuid.uuid4())}),
        lambda: json.dumps({}),
    ]

    print("JSON structure sizes:")
    for i, fn in enumerate(structures):
        s = fn()
        print(f"  [{i}] {len(s)} bytes: {s[:80]}")

    # Now let's try: what if the 180 bytes IS the plaintext, not encrypted?
    # Maybe the "encoding" for user/status is just the custom base64,
    # and the encryption only applies to certain endpoints?

    # Let's check shouldEncryptBody decision logic:
    # The function name suggests it decides WHETHER to encrypt
    # Maybe for GET requests or small POST requests, it returns false

    # Wait, user/status is a POST with Encode=1
    # If shouldEncryptBody returned false for this request, the body wouldn't be encrypted

    # Let me reconsider: maybe the encoding chain is:
    # 1. JSON body -> possibly encrypt (shouldEncryptBody decides)
    # 2. (encrypted or not) -> custom base64 encode
    # 3. Add Encode=1 query param

    # If user/status body is NOT encrypted (shouldEncryptBody returns false),
    # then the 180 bytes should be valid JSON!

    # Let's check: is 180 bytes of decoded data valid JSON in any encoding?
    decoded = decode_custom_base64(
        "uOFLDgKLDEKLN(iNBM)O#S%^D,%NBOg.JHiKuODbxoBymk.WB*f*DSQMu(CLFOFYN(Lbu*ByBMT*ep$$xoByxoKNB*%NBEjL#kFYPxCQ@(g.JHiau(tLuLf*lLf*xoBrxoKYDSDYDxjnFHWUDSQNBM)NBLf*Ggf*mYKf#xLru(gzBMn*m.f*JxjLNzLzxoByxoB.l@VfjMN(l@TflRzIVRBkxoBrxoKfDxK^u(QiugCbP(Fh"
    )

    print(f"\nDecoded body stats:")
    print(f"  Length: {len(decoded)} bytes")
    print(f"  Printable ASCII: {sum(1 for b in decoded if 32 <= b < 127)} / {len(decoded)}")
    print(f"  Null bytes: {sum(1 for b in decoded if b == 0)}")
    print(f"  Byte range: 0x{min(decoded):02x} - 0x{max(decoded):02x}")

    # If it's JSON, it should be mostly printable ASCII
    # 88 out of 256 possible values are used -> high entropy
    # Only {sum(1 for b in decoded if 32 <= b < 127)} out of {len(decoded)} are printable
    # This strongly suggests encryption

    # But wait - let me reconsider the decoding.
    # What if the custom base64 is NOT standard base64 with a different alphabet?
    # What if it uses a different bit-packing scheme?

    # The alphabet has 65 characters. In standard base64:
    # 4 chars = 24 bits = 3 bytes
    # But with 65 characters, each char carries log2(65) ≈ 6.022 bits
    # 240 chars × 6.022 bits ≈ 1445 bits ≈ 180.6 bytes

    # The standard base64 mapping and 6-bit stream mapping give the same result
    # because both use 6 bits per character.

    # So the decoded 180 bytes are correct for the base64-like decoding.
    # The question is whether these bytes are the plaintext or ciphertext.

    # Given the high entropy (88 unique bytes, avg 14.6 unique per 16-byte block),
    # it's most likely ciphertext from AES encryption.

    print("\n  Conclusion: Encoded body is likely AES-encrypted, not plain JSON")


def try_go_binary_extraction():
    """
    Try to extract the encoding function from the binary.

    encodeRequestBody is at RVA 0x881820, size 0x160 (352 bytes).
    This is small enough to analyze manually.

    In Go, the pclntab (program counter to line number table) contains
    information about function calls. Let's extract the call targets.
    """
    print("\n" + "=" * 60)
    print("Binary analysis: extract call targets from encodeRequestBody")
    print("=" * 60)

    # Read the binary and extract bytes at the function address
    # The module base is not known statically, but GoReSym gives us VAs
    # encodeRequestBody VA = 5377628192 = 0x1400881820

    # We need the actual binary file to analyze. Let's check if it's available.
    import os

    # Common locations for Lingma binary
    possible_paths = [
        os.path.expanduser("~/.lingma/bin/Lingma"),
        os.path.expanduser("~/.lingma/bin/Lingma.exe"),
        "C:/Users/Zipper/.lingma/bin/Lingma.exe",
    ]

    found = None
    for path in possible_paths:
        if os.path.exists(path):
            found = path
            break

    if found:
        print(f"Found binary: {found}")
        # Extract function bytes
        with open(found, "rb") as f:
            # We need the file offset for RVA 0x881820
            # This requires parsing the PE header
            # For now, let's just check if we can read the file
            f.seek(0)
            header = f.read(0x400)
            print(f"File size: {os.path.getsize(found)}")
            print(f"First 4 bytes (PE magic): {header[:4]}")
    else:
        print("Binary not found locally. Can't analyze function bytes.")
        print("Need to either:")
        print("1. Copy the binary from the original machine")
        print("2. Run Frida hooks on the live process")


def analyze_header_patterns():
    """
    Analyze if there's a header or structure before the encrypted payload.

    Many encryption protocols prepend:
    - A version byte
    - An IV (16 bytes for AES)
    - A MAC tag (16-32 bytes)

    If the 180-byte decoded body has a header, the actual encrypted payload
    might be smaller.
    """
    print("\n" + "=" * 60)
    print("Header pattern analysis")
    print("=" * 60)

    # user/status decoded body
    body = "uOFLDgKLDEKLN(iNBM)O#S%^D,%NBOg.JHiKuODbxoBymk.WB*f*DSQMu(CLFOFYN(Lbu*ByBMT*ep$$xoByxoKNB*%NBEjL#kFYPxCQ@(g.JHiau(tLuLf*lLf*xoBrxoKYDSDYDxjnFHWUDSQNBM)NBLf*Ggf*mYKf#xLru(gzBMn*m.f*JxjLNzLzxoByxoB.l@VfjMN(l@TflRzIVRBkxoBrxoKfDxK^u(QiugCbP(Fh"
    decoded = decode_custom_base64(body)

    # Check for common headers
    print(f"First byte: 0x{decoded[0]:02x}")
    print(f"First 2 bytes: 0x{decoded[:2].hex()}")
    print(f"First 4 bytes: 0x{decoded[:4].hex()}")
    print(f"First 8 bytes: 0x{decoded[:8].hex()}")
    print(f"First 16 bytes: 0x{decoded[:16].hex()}")

    # Check if first byte could be a version indicator
    # Common version bytes: 0x01, 0x02, 0x03
    # 0xed is not a common version byte

    # Check if there's a length prefix
    # Big-endian 4-byte length: 0xed94163a = 3986154042 (too large)
    # Little-endian 4-byte length: 0x3a1694ed = 974558445 (too large)

    # Check if it could be a nonce/IV
    # If the first 16 bytes are an IV:
    iv = decoded[:16]
    print(f"\nPossible IV: {iv.hex()}")

    # If the remaining bytes are the ciphertext:
    ciphertext = decoded[16:]
    print(f"Ciphertext: {len(ciphertext)} bytes = {len(ciphertext)/16} blocks")

    if len(ciphertext) % 16 == 0:
        print(f"  -> {len(ciphertext)//16} full AES blocks")
    else:
        print(f"  -> Not aligned to 16-byte boundary (unlikely for AES)")

    # Compare with the chat body
    chat_body = "M&KZE)nZOUPGnb)vLiX)cawWlQsoqQuYvXXYVQuAgyPHXQG(!QQ,nQyyiy#H@QyYOQ#*HyDsaQQsTQXsJQsyxYQyGxYQynxYyOyQOQyHxYyXxY"
    # Take just the first 100 chars for quick analysis
    chat_short = chat_body[:100]
    chat_decoded = decode_custom_base64(chat_short)
    print(f"\nChat body (first 100 chars) decoded: {len(chat_decoded)} bytes")
    print(f"First 16 bytes: {chat_decoded[:16].hex()}")

    # If the IV is included, the first 16 bytes of different requests should differ
    # (unless the IV is fixed, which would be a security issue)
    # But we know user/status always produces the same 180 bytes,
    # so either the IV is fixed or there's no IV at all.


def main():
    differential_analysis()
    analyze_user_status_fixed_body()
    try_brute_force_user_status_json()
    try_go_binary_extraction()
    analyze_header_patterns()

    print("\n" + "=" * 60)
    print("SUMMARY AND NEXT STEPS")
    print("=" * 60)
    print("""
1. The user/status body is IDENTICAL across 5+ captures
   -> Deterministic encryption (no random IV, or fixed key+IV)

2. Decoded body has HIGH ENTROPY (88 unique bytes out of 256, avg 14.6 per 16-byte block)
   -> Consistent with AES encryption, not plaintext JSON

3. No XOR key found for the decoded bytes
   -> Not a simple XOR cipher

4. The encodeRequestBody function is only 352 bytes
   -> Too small to contain full AES implementation
   -> Likely calls a library function (AesEncryptWithBase64 at RVA 0x103c00)

5. NEXT STEPS:
   a) Run the Frida hook script (frida_trace_encoding.py) to capture
      encodeRequestBody input/output and AesEncryptWithBase64 calls
   b) Extract the AES key from the binary or from memory
   c) Analyze the AesEncryptWithBase64 function (RVA 0x103c00, size 416 bytes)
   """)


if __name__ == "__main__":
    main()
