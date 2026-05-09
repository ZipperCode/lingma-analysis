"""Analyze the custom 65-char body encoding to reconstruct the algorithm."""

import base64
import json
import re
from collections import Counter
from pathlib import Path

# Known alphabet from binary analysis
ALPHABET = "!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
ALPHABET_SET = set(ALPHABET)
ALPHABET_INDEX = {c: i for i, c in enumerate(ALPHABET)}

def load_capture(path: str) -> list[dict]:
    entries = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries

def analyze_body(body: str, label: str):
    """Analyze a single encoded body for patterns."""
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(f"Length: {len(body)} (mod 4 = {len(body) % 4})")

    # Character distribution
    counter = Counter(body)
    unique_chars = set(body)
    print(f"Unique chars: {len(unique_chars)} / 65")
    missing = ALPHABET_SET - unique_chars
    if missing:
        print(f"Missing chars: {''.join(sorted(missing))}")

    # Check for padding chars
    if '=' in body:
        print(f"Contains '=' padding: YES")
    if '+' in body or '/' in body:
        print(f"Contains standard base64 chars +/")

    # Frequency analysis
    print(f"\nTop 15 most frequent chars:")
    for ch, cnt in counter.most_common(15):
        idx = ALPHABET_INDEX.get(ch, -1)
        print(f"  '{ch}' (idx={idx:2d}): {cnt:5d} ({cnt/len(body)*100:.1f}%)")

    # Bigram analysis
    bigrams = Counter(body[i:i+2] for i in range(len(body)-1))
    print(f"\nTop 10 bigrams:")
    for bg, cnt in bigrams.most_common(10):
        print(f"  '{bg}': {cnt}")

    # Check if it maps directly to standard base64
    try:
        decoded = base64.b64decode(body, validate=False)
        print(f"\nIf decoded as standard base64: {len(decoded)} bytes")
        # Check if it looks like valid UTF-8
        try:
            text = decoded.decode('utf-8')
            if all(c.isprintable() or c in '\n\r\t' for c in text):
                print(f"  Looks like valid UTF-8: {text[:200]}")
        except:
            pass
        # Check if it looks like compressed/zlib data
        print(f"  Hex preview: {decoded[:32].hex()}")
    except Exception as e:
        print(f"\nCannot decode as standard base64: {e}")

    # Try character frequency comparison with base64
    print(f"\n  Character index histogram (first 50 chars):")
    for i, ch in enumerate(body[:50]):
        idx = ALPHABET_INDEX.get(ch, -1)
        print(f"    [{i:2d}] '{ch}' -> idx={idx:2d} (binary: {idx:06b})")

    return body

def try_base64_substitution(body: str):
    """Try mapping custom alphabet to standard base64 alphabet."""
    std_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    # Method 1: position-based substitution
    # Each char in custom alphabet maps to the char at the same position in std base64
    mapped = ""
    for ch in body:
        if ch in ALPHABET_INDEX:
            mapped += std_alphabet[ALPHABET_INDEX[ch]]
        else:
            mapped += ch

    try:
        decoded = base64.b64decode(mapped + "==")  # add padding just in case
        print(f"\n  Position-mapped base64 decode: {len(decoded)} bytes")
        print(f"  Hex: {decoded[:64].hex()}")
        try:
            text = decoded.decode('utf-8')
            if all(c.isprintable() or c in '\n\r\t{}[]":, ' for c in text[:100]):
                print(f"  UTF-8: {text[:200]}")
        except:
            pass

        # Try zlib decompression
        import zlib
        try:
            decompressed = zlib.decompress(decoded)
            print(f"  Zlib decompressed: {decompressed[:200]}")
        except:
            pass
        try:
            decompressed = zlib.decompress(decoded, -15)
            print(f"  Raw deflate: {decompressed[:200]}")
        except:
            pass
        try:
            decompressed = zlib.decompress(decoded, 8)
            print(f"  Deflate: {decompressed[:200]}")
        except:
            pass

    except Exception as e:
        print(f"\n  Position-mapped base64 decode failed: {e}")

    # Try with different padding
    for pad in ["", "=", "==", "==="]:
        try:
            test = mapped + pad
            # Ensure length is multiple of 4
            while len(test) % 4 != 0:
                test += "="
            decoded = base64.b64decode(test)
            print(f"\n  With padding '{pad}': {len(decoded)} bytes")
            print(f"  Hex: {decoded[:64].hex()}")
        except:
            pass

    # Method 2: try the reverse mapping (std base64 -> custom)
    # This doesn't make sense for decoding, skip

def xor_analysis(body1: str, body2: str, label1: str, label2: str):
    """XOR analysis between two encoded bodies of same length."""
    if len(body1) != len(body2):
        print(f"\n  Cannot XOR: lengths differ ({len(body1)} vs {len(body2)})")
        return

    print(f"\n{'='*60}")
    print(f"  XOR analysis: {label1} vs {label2}")
    print(f"{'='*60}")

    idx1 = [ALPHABET_INDEX.get(c, 0) for c in body1]
    idx2 = [ALPHABET_INDEX.get(c, 0) for c in body2]

    xored = [a ^ b for a, b in zip(idx1, idx2)]

    print(f"  XOR values (first 50): {[f'{v:02x}' for v in xored[:50]]}")
    print(f"  Unique XOR values: {Counter(xored)}")

    # Check if XOR is constant (would indicate simple XOR cipher)
    if len(set(xored)) == 1:
        print(f"  CONSTANT XOR: 0x{xored[0]:02x} -> Simple XOR cipher!")

def main():
    capture_file = "capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl"
    entries = load_capture(capture_file)

    post_entries = [e for e in entries if e.get("body_len", 0) > 0]
    print(f"Found {len(post_entries)} POST requests with bodies")

    results = []
    for i, entry in enumerate(post_entries):
        body = entry.get("body_utf8", "")
        if body:
            path = entry.get("path", "")
            label = f"[{i}] {entry['method']} {path} (len={len(body)})"
            analyze_body(body, label)
            results.append((body, label))

    # Try base64 substitution on each
    for body, label in results:
        print(f"\n{'='*60}")
        print(f"  Base64 substitution attempt: {label}")
        print(f"{'='*60}")
        try_base64_substitution(body)

    # XOR analysis between same-length bodies
    for i, (body1, label1) in enumerate(results):
        for j, (body2, label2) in enumerate(results):
            if i < j and len(body1) == len(body2):
                xor_analysis(body1, body2, label1, label2)

    # Analyze length patterns
    print(f"\n{'='*60}")
    print("  Length analysis of all encoded bodies")
    print(f"{'='*60}")
    for body, label in results:
        print(f"  {label}: len={len(body)}, mod4={len(body)%4}")
        # Original JSON size estimation
        # Base64 expands by 4/3, so original ≈ len * 3/4
        est_original = len(body) * 3 // 4
        print(f"    Estimated original size: ~{est_original} bytes")

if __name__ == "__main__":
    main()
