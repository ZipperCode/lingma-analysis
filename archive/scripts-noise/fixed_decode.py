import json

CUSTOM_ALPHABET = "!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
ALPHABET_INDEX = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}

def decode_fixed(text):
    """Decode custom base64-like encoding.
    Each char -> 6 bits. Pack tightly into bytes.
    """
    bits = []
    for ch in text:
        if ch in ALPHABET_INDEX:
            idx = ALPHABET_INDEX[ch]
            if idx < 64:
                for i in range(5, -1, -1):
                    bits.append((idx >> i) & 1)

    # Pack into bytes
    n_bytes = len(bits) // 8
    result = bytearray(n_bytes)
    for i in range(n_bytes):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i * 8 + j]
        result[i] = byte
    return bytes(result)

USER_STATUS_BODY = "uOFLDgKLDEKLN(iNBM)O#S%^D,%NBOg.JHiKuODbxoBymk.WB*f*DSQMu(CLFOFYN(Lbu*ByBMT*ep$$xoByxoKNB*%NBEjL#kFYPxCQ@(g.JHiau(tLuLf*lLf*xoBrxoKYDSDYDxjnFHWUDSQNBM)NBLf*Ggf*mYKf#xLru(gzBMn*m.f*JxjLNzLzxoByxoB.l@VfjMN(l@TflRzIVRBkxoBrxoKfDxK^u(QiugCbP(Fh"

decoded = decode_fixed(USER_STATUS_BODY)
n_chars = sum(1 for ch in USER_STATUS_BODY if ch in ALPHABET_INDEX)
print(f"User/status body: {n_chars} chars -> {len(decoded)} bytes")
print(f"Expected: {n_chars * 6 // 8} bytes")
print(f"First 32 bytes: {decoded[:32].hex()}")
print(f"Last 32 bytes: {decoded[-32:].hex()}")
print(f"180 % 16 = {len(decoded) % 16}")

# Decode all bodies
print("\n" + "=" * 60)
print("All bodies:")
print("=" * 60)

all_bodies = []
with open('capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl') as f:
    for line in f:
        d = json.loads(line)
        path = d.get('path', '?')
        body_b64 = d.get('body_base64_preview', '')
        if body_b64 and len(body_b64) > 50:
            decoded = decode_fixed(body_b64)
            short_path = path.split('?')[0].split('/')[-1]
            all_bodies.append((short_path, decoded))
            print(f"\n{short_path}: {len(decoded)} bytes ({len(decoded)} % 16 = {len(decoded) % 16})")
            print(f"  First 16: {decoded[:16].hex()}")
            print(f"  Last 16:  {decoded[-16:].hex()}")

# Check for header+ciphertext split
print("\n" + "=" * 60)
print("Possible header/ciphertext splits:")
print("=" * 60)

for short_path, decoded in all_bodies:
    n = len(decoded)
    found = False
    for header_size in [0, 1, 2, 4, 8, 12, 16, 24, 32]:
        remaining = n - header_size
        if remaining > 0 and remaining % 16 == 0:
            print(f"\n{short_path}: {header_size} byte header + {remaining} byte ciphertext ({remaining//16} blocks)")
            if header_size > 0:
                print(f"  Header: {decoded[:header_size].hex()}")
            print(f"  First block: {decoded[header_size:header_size+16].hex()}")
            print(f"  Last block:  {decoded[-16:].hex()}")
            found = True
            break
    if not found:
        print(f"\n{short_path}: {n} bytes - no clean split")
