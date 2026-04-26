import json

CUSTOM_ALPHABET = "!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
ALPHABET_INDEX = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}

def decode_v2(text):
    """Proper decoder: each char -> 6 bits, pack into bytes."""
    bits = []
    for ch in text:
        if ch in ALPHABET_INDEX:
            idx = ALPHABET_INDEX[ch]
            if idx < 64:
                for i in range(5, -1, -1):
                    bits.append((idx >> i) & 1)

    n_bytes = len(bits) // 8
    result = bytearray()
    for byte_idx in range(n_bytes):
        byte = 0
        for bit_idx in range(8):
            byte = (byte << 1) | bits[byte_idx * 8 + bit_idx]
        result.append(byte)
    return bytes(result)

# Check user/status body from capture vs hardcoded
HARDCODED = "uOFLDgKLDEKLN(iNBM)O#S%^D,%NBOg.JHiKuODbxoBymk.WB*f*DSQMu(CLFOFYN(Lbu*ByBMT*ep$$xoByxoKNB*%NBEjL#kFYPxCQ@(g.JHiau(tLuLf*lLf*xoBrxoKYDSDYDxjnFHWUDSQNBM)NBLf*Ggf*mYKf#xLru(gzBMn*m.f*JxjLNzLzxoByxoB.l@VfjMN(l@TflRzIVRBkxoBrxoKfDxK^u(QiugCbP(Fh"

print(f"Hardcoded body: {len(HARDCODED)} chars")
decoded_h = decode_v2(HARDCODED)
print(f"Decoded: {len(decoded_h)} bytes")
print(f"First 32: {decoded_h[:32].hex()}")

# Now check capture file
with open('capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl') as f:
    for line in f:
        d = json.loads(line)
        path = d.get('path', '')
        if 'user/status' in path:
            body = d.get('body_base64_preview', '')
            print(f"\nCapture body (user/status): {len(body)} chars")

            # Check which chars are NOT in alphabet
            not_in_alpha = [ch for ch in body if ch not in ALPHABET_INDEX]
            print(f"Chars not in alphabet: {len(not_in_alpha)}")
            if not_in_alpha:
                print(f"  Sample: {set(not_in_alpha)}")

            # Count valid chars
            valid = sum(1 for ch in body if ch in ALPHABET_INDEX and ALPHABET_INDEX[ch] < 64)
            total_valid = sum(1 for ch in body if ch in ALPHABET_INDEX)
            print(f"Valid chars (idx < 64): {valid}")
            print(f"Total in alphabet (including idx 64): {total_valid}")

            # Decode
            decoded_c = decode_v2(body)
            print(f"Decoded: {len(decoded_c)} bytes")
            print(f"First 32: {decoded_c[:32].hex()}")

            # Compare first bytes
            if len(decoded_h) > 0 and len(decoded_c) > 0:
                print(f"\nComparison:")
                print(f"  Hardcoded first 16: {decoded_h[:16].hex()}")
                print(f"  Capture first 16:   {decoded_c[:16].hex()}")
                print(f"  Same? {decoded_h[:16] == decoded_c[:16]}")

            break
