"""Deep dive into the encoding - try base64 position mapping on various bodies."""

import base64
import json
import zlib
from collections import Counter
from pathlib import Path

ALPHABET = "!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
ALPHABET_INDEX = {c: i for i, c in enumerate(ALPHABET)}
STANDARD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def custom_to_standard(text: str) -> str:
    """Map custom alphabet chars to standard base64 by position.
    Char at index 64 ('z') maps to nothing special, we'll use '/' as fallback.
    """
    result = []
    for ch in text:
        if ch in ALPHABET_INDEX:
            idx = ALPHABET_INDEX[ch]
            if idx < 64:
                result.append(STANDARD_B64[idx])
            else:
                # Index 64 maps beyond standard base64, use '+' as placeholder
                result.append('+')
        else:
            result.append(ch)
    return "".join(result)

def reconstruct_from_6bit(text: str) -> bytes:
    """Reconstruct bytes by treating each char as a 6-bit index."""
    indices = [ALPHABET_INDEX.get(c, 0) for c in text]
    bit_stream = ''.join(f'{idx:06b}' for idx in indices)
    byte_count = len(bit_stream) // 8
    raw_bytes = []
    for i in range(byte_count):
        byte_bits = bit_stream[i*8:(i+1)*8]
        raw_bytes.append(int(byte_bits, 2))
    return bytes(raw_bytes)

def load_capture(path: str) -> list[dict]:
    entries = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries

def try_decode_all(body: str, label: str):
    """Try multiple decode strategies on a body."""
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"  Body length: {len(body)}")
    print(f"{'='*60}")

    # Strategy A: Reconstruct from 6-bit stream
    raw_6bit = reconstruct_from_6bit(body)
    print(f"\n  [6-bit stream] -> {len(raw_6bit)} bytes")
    print(f"  Hex first 64: {raw_6bit[:64].hex()}")

    # Try single-byte XOR on 6-bit stream result
    for key in range(256):
        xored = bytes([b ^ key for b in raw_6bit])
        try:
            text = xored.decode('utf-8')
            if text.startswith('{') and len(text) > 10:
                print(f"  XOR 0x{key:02x}: {text[:200]}")
        except:
            pass

    # Try zlib
    for wbits in [15, -15, 8, 31, 47, 0]:
        try:
            decompressed = zlib.decompress(raw_6bit, wbits)
            print(f"  zlib(wbits={wbits}): {decompressed[:300]}")
        except:
            pass

    # Strategy B: Position-mapped base64
    mapped = custom_to_standard(body)
    for pad in ["", "=", "==", "==="]:
        test = mapped + pad
        while len(test) % 4 != 0:
            test += "="
        try:
            raw = base64.b64decode(test)
            print(f"\n  [base64-mapped + pad '{pad}'] -> {len(raw)} bytes")
            print(f"  Hex first 64: {raw[:64].hex()}")

            # Try UTF-8
            try:
                text = raw.decode('utf-8')
                if len(text) > 10:
                    print(f"  UTF-8: {text[:300]}")
            except:
                pass

            # Try single-byte XOR
            for key in range(256):
                xored = bytes([b ^ key for b in raw])
                try:
                    text = xored.decode('utf-8')
                    if text.startswith('{') and len(text) > 10:
                        print(f"  XOR 0x{key:02x}: {text[:200]}")
                except:
                    pass

            # Try zlib
            for wbits in [15, -15, 8, 31, 47, 0]:
                try:
                    decompressed = zlib.decompress(raw, wbits)
                    print(f"  zlib(wbits={wbits}): {decompressed[:300]}")
                except:
                    pass
        except:
            pass

def analyze_first_4_chars():
    """Analyze the first 4 chars of the user/status body more carefully."""
    print("=== First 4 chars analysis ===")
    encoded = "uOFL"
    indices = [ALPHABET_INDEX[c] for c in encoded]
    print(f"Chars: {encoded}")
    print(f"Indices: {indices}")

    # Method 1: 6-bit concatenation -> bytes
    bits = ''.join(f'{idx:06b}' for idx in indices)
    print(f"Bits: {bits}")
    b0 = int(bits[0:8], 2)
    b1 = int(bits[8:16], 2)
    b2 = int(bits[16:24], 2)
    print(f"Bytes: 0x{b0:02x} 0x{b1:02x} 0x{b2:02x}")

    # Method 2: base64 position mapping
    std = "".join(STANDARD_B64[i] for i in indices)
    print(f"Mapped to standard: {std}")
    try:
        decoded = base64.b64decode(std)
        print(f"Base64 decoded: {decoded.hex()}")
        print(f"As bytes: {[hex(b) for b in decoded]}")
    except Exception as e:
        print(f"Base64 decode failed: {e}")

    # What would JSON '{"requestId":"' look like?
    json_start = '{"'
    json_bytes = json_start.encode()
    print(f"\nTarget JSON start bytes: {[hex(b) for b in json_bytes]}")

    # What 6-bit indices would produce these bytes?
    # For '{"' = 0x7b 0x22 = 01111011 00100010
    # 16 bits -> need 3 6-bit values = 18 bits (first 16 match)
    target_bits = '0111101100100010'
    # Pad to multiple of 6
    target_bits_18 = target_bits + '00'  # 18 bits
    idx0 = int(target_bits_18[0:6], 2)
    idx1 = int(target_bits_18[6:12], 2)
    idx2 = int(target_bits_18[12:18], 2)
    print(f"To get '{{\"', we'd need indices: {idx0}, {idx1}, {idx2}")
    print(f"Chars at those indices: '{ALPHABET[idx0]}', '{ALPHABET[idx1]}', '{ALPHABET[idx2]}'")
    print(f"Actual first 3 chars: '{encoded[0]}', '{encoded[1]}', '{encoded[2]}'")
    print(f"Actual indices: {indices[0]}, {indices[1]}, {indices[2]}")

    # So it's NOT directly encoding JSON. There must be an intermediate step.
    # Maybe: JSON -> some transformation -> base64-like encoding

    # What about JSON -> zlib/deflate -> base64-like encoding?
    # Let's try: what if the decoded bytes ARE compressed?

def check_user_status_compression():
    """Check if the user/status body could be a compressed known JSON."""
    print("\n=== user/status compression check ===")

    # First decode the 6-bit stream
    encoded_body = "uOFLDgKLDEKLN(iNBM)O#S%^D,%NBOg.JHiKuODbxoBymk.WB*f*DSQMu(CLFOFYN(Lbu*ByBMT*ep$$xoByxoKNB*%NBEjL#kFYPxCQ@(g.JHiau(tLuLf*lLf*xoBrxoKYDSDYDxjnFHWUDSQNBM)NBLf*Ggf*mYKf#xLru(gzBMn*m.f*JxjLNzLzxoByxoB.l@VfjMN(l@TflRzIVRBkxoBrxoKfDxK^u(QiugCbP(Fh"

    raw = reconstruct_from_6bit(encoded_body)
    print(f"Decoded 180 bytes: {raw.hex()}")

    # Try common compressed JSON patterns
    sample_requests = [
        b'{"requestId":""}',
        b'{}',
        b'{"data":{}}',
        b'{"Encode":1}',
        b'{}',
    ]

    for sample in sample_requests:
        print(f"\n  Sample: {sample}")
        for level in range(10):
            try:
                compressed = zlib.compress(sample, level)
                if len(compressed) <= 180:
                    print(f"    zlib(level={level}): {len(compressed)} bytes")
            except:
                pass
            try:
                compressed = zlib.compress(sample, level)[2:-4]  # raw deflate
                if len(compressed) <= 180:
                    print(f"    raw deflate(level={level}): {len(compressed)} bytes")
            except:
                pass

        # Try with various UUIDs
        import uuid
        for _ in range(3):
            test = json.dumps({"requestId": str(uuid.uuid4())}).encode()
            for level in [9]:
                try:
                    compressed = zlib.compress(test, level)
                    print(f"    With UUID, zlib(9): {len(compressed)} bytes")
                except:
                    pass

def try_encoding_samples():
    """Encode known JSON samples with various methods and compare lengths."""
    print("\n=== Encoding length comparison ===")

    samples = [
        (b'{}', "empty object"),
        (b'{"requestId":""}', "with empty uuid"),
        (b'{"requestId":"00000000-0000-0000-0000-000000000000"}', "with full uuid"),
        (b'{"requestId":"67fdb6d5-e38f-4308-867d-b97c2b663935","version":"1"}', "with uuid+version"),
    ]

    for sample, desc in samples:
        print(f"\n  {desc}: {len(sample)} bytes raw")
        print(f"    JSON: {sample.decode()}")

        # Base64
        b64 = base64.b64encode(sample).decode()
        print(f"    base64: {len(b64)} chars")

        # Custom base64-like encoding
        custom_chars = len(sample) * 4 // 3 + (4 if len(sample) % 3 else 0)
        print(f"    custom (4:3 ratio): ~{custom_chars} chars")

        # zlib compressed + base64
        for level in [1, 6, 9]:
            compressed = zlib.compress(sample, level)
            b64_comp = base64.b64encode(compressed).decode()
            print(f"    zlib({level})+base64: {len(compressed)}+{len(b64_comp)} chars")

def main():
    # Detailed analysis of first 4 chars
    analyze_first_4_chars()

    # Check if user/status could be compressed
    check_user_status_compression()

    # Compare encoding lengths
    try_encoding_samples()

    # Try decode all unique POST bodies
    entries = load_capture("capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl")
    post_entries = [e for e in entries if e.get("body_len", 0) > 0]

    seen = set()
    for entry in post_entries:
        body = entry.get("body_utf8", "")
        if body and body not in seen:
            seen.add(body)
            path = entry.get("path", "")
            label = f"{entry['method']} {path} (len={len(body)})"
            try_decode_all(body, label)
            # Only process the first few to avoid overwhelming output
            if len(seen) >= 5:
                break

if __name__ == "__main__":
    main()
