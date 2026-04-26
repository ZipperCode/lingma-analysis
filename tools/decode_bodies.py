"""
Precisely decode the custom base64-like body to determine ciphertext length.
"""

CUSTOM_ALPHABET = "!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
ALPHABET_INDEX = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}
STANDARD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# User/status body (240 chars)
USER_STATUS_BODY = "uOFLDgKLDEKLN(iNBM)O#S%^D,%NBOg.JHiKuODbxoBymk.WB*f*DSQMu(CLFOFYN(Lbu*ByBMT*ep$$xoByxoKNB*%NBEjL#kFYPxCQ@(g.JHiau(tLuLf*lLf*xoBrxoKYDSDYDxjnFHWUDSQNBM)NBLf*Ggf*mYKf#xLru(gzBMn*m.f*JxjLNzLzxoByxoB.l@VfjMN(l@TflRzIVRBkxoBrxoKfDxK^u(QiugCbP(Fh"

print(f"Body length: {len(USER_STATUS_BODY)} chars")
print(f"Alphabet size: {len(CUSTOM_ALPHABET)}")

# Method 1: Map each char to 6 bits, then pack into bytes
def decode_method1(text):
    """Each alphabet character maps to 6 bits, pack tightly into bytes."""
    bits = []
    for ch in text:
        if ch in ALPHABET_INDEX:
            idx = ALPHABET_INDEX[ch]
            if idx < 64:
                for i in range(5, -1, -1):
                    bits.append((idx >> i) & 1)

    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result), len(bits)

# Method 2: Standard base64-style (4 chars = 3 bytes)
def decode_method2(text):
    """Map to standard base64 alphabet, then decode as base64."""
    import base64
    mapped = []
    for ch in text:
        if ch in ALPHABET_INDEX:
            idx = ALPHABET_INDEX[ch]
            if idx < 64:
                mapped.append(STANDARD_B64[idx])
    mapped_str = "".join(mapped)
    while len(mapped_str) % 4 != 0:
        mapped_str += "="
    return base64.b64decode(mapped_str)

r1, nbits = decode_method1(USER_STATUS_BODY)
r2 = decode_method2(USER_STATUS_BODY)

print(f"\nMethod 1 (bitstream): {len(r1)} bytes from {nbits} bits")
print(f"  {nbits / 8:.1f} bytes theoretical")
print(f"  {nbits % 8} leftover bits")
print(f"  First 32 bytes: {r1[:32].hex()}")
print(f"  Last 32 bytes: {r1[-32:].hex()}")

print(f"\nMethod 2 (base64-style): {len(r2)} bytes")
print(f"  First 32 bytes: {r2[:32].hex()}")
print(f"  Last 32 bytes: {r2[-32:].hex()}")

print(f"\nAre they the same? {r1 == r2}")
if r1 != r2:
    # Find first difference
    for i in range(min(len(r1), len(r2))):
        if r1[i] != r2[i]:
            print(f"  First diff at byte {i}: {r1[i]:02x} vs {r2[i]:02x}")
            break

# Check if the decoded length is a multiple of 16
print(f"\nMethod 1: {len(r1)} % 16 = {len(r1) % 16}")
print(f"Method 2: {len(r2)} % 16 = {len(r2) % 16}")

# Now decode ALL captured bodies
print("\n" + "=" * 60)
print("Decoding all captured bodies:")
print("=" * 60)

bodies = {
    'user/status': "uOFLDgKLDEKLN(iNBM)O#S%^D,%NBOg.JHiKuODbxoBymk.WB*f*DSQMu(CLFOFYN(Lbu*ByBMT*ep$$xoByxoKNB*%NBEjL#kFYPxCQ@(g.JHiau(tLuLf*lLf*xoBrxoKYDSDYDxjnFHWUDSQNBM)NBLf*Ggf*mYKf#xLru(gzBMn*m.f*JxjLNzLzxoByxoB.l@VfjMN(l@TflRzIVRBkxoBrxoKfDxK^u(QiugCbP(Fh",
}

# Let's also look at the JSONL capture for more bodies
import json
import os

capture_files = [f for f in os.listdir('capture') if f.endswith('.jsonl')]
print(f"\nCapture files found: {capture_files}")

for cf in capture_files:
    filepath = os.path.join('capture', cf)
    with open(filepath, 'r') as f:
        lines = f.readlines()

    bodies_found = 0
    for line in lines:
        try:
            entry = json.loads(line)
            if 'body' in entry:
                body = entry['body']
                if len(body) > 50 and all(ch in ALPHABET_INDEX or ch not in ALPHABET_INDEX for ch in body):
                    decoded, nbits = decode_method1(body)
                    decoded2 = decode_method2(body)
                    key = entry.get('endpoint', entry.get('path', 'unknown'))

                    if bodies_found < 5:
                        print(f"\n  [{cf}] {key} ({len(body)} chars):")
                        print(f"    Method1: {len(decoded)} bytes ({nbits} bits, {nbits%8} leftover)")
                        print(f"    Method2: {len(decoded2)} bytes")
                        print(f"    M1 % 16 = {len(decoded) % 16}")
                        print(f"    M2 % 16 = {len(decoded2) % 16}")
                    bodies_found += 1
        except:
            pass

    print(f"  {cf}: {bodies_found} encoded bodies found")
