"""Check if user/status body has all chars in alphabet."""

CUSTOM_ALPHABET = "!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
ALPHABET_SET = set(CUSTOM_ALPHABET)

USER_STATUS_BODY = "uOFLDgKLDEKLN(iNBM)O#S%^D,%NBOg.JHiKuODbxoBymk.WB*f*DSQMu(CLFOFYN(Lbu*ByBMT*ep$$xoByxoKNB*%NBEjL#kFYPxCQ@(g.JHiau(tLuLf*lLf*xoBrxoKYDSDYDxjnFHWUDSQNBM)NBLf*Ggf*mYKf#xLru(gzBMn*m.f*JxjLNzLzxoByxoB.l@VfjMN(l@TflRzIVRBkxoBrxoKfDxK^u(QiugCbP(Fh"

print(f"Body length: {len(USER_STATUS_BODY)}")

# Count chars in vs out of alphabet
in_alpha = 0
out_alpha = 0
out_chars = []
for ch in USER_STATUS_BODY:
    if ch in ALPHABET_SET:
        in_alpha += 1
    else:
        out_alpha += 1
        out_chars.append(ch)

print(f"In alphabet: {in_alpha}")
print(f"Out of alphabet: {out_alpha}")
if out_chars:
    print(f"Out chars: {out_chars}")

# Calculate bits
bits = in_alpha * 6
bytes_decoded = bits // 8
leftover = bits % 8
print(f"\nBits: {bits}")
print(f"Bytes: {bytes_decoded}")
print(f"Leftover bits: {leftover}")

# The user/status body has ALL chars in alphabet, so 240 * 6 = 1440 bits = 180 bytes
# But our decoder output 177 bytes
# Let's check the decoder more carefully

# 240 chars * 6 bits = 1440 bits
# 1440 / 8 = 180 bytes exactly!
# So the bitstream decoder might have a bug

# Let's decode more carefully
bits = []
for ch in USER_STATUS_BODY:
    if ch in ALPHABET_SET:
        idx = ALPHABET_SET.__hash__(ch)  # No, this is wrong
        idx = CUSTOM_ALPHABET.index(ch)
        if idx < 64:
            for i in range(5, -1, -1):
                bits.append((idx >> i) & 1)

print(f"\nTotal bits from decoder: {len(bits)}")
print(f"Total bytes: {len(bits) // 8}")
print(f"Leftover: {len(bits) % 8}")

# Check: are there any chars with index >= 64?
max_idx = max(CUSTOM_ALPHABET.index(ch) for ch in USER_STATUS_BODY)
print(f"\nMax index in body: {max_idx}")

# The 65th char (index 64) is the last char 'z' which has index 64
# Wait, let me check the alphabet order
print(f"\nAlphabet (65 chars): {CUSTOM_ALPHABET}")
print(f"Char at index 64: {CUSTOM_ALPHABET[64]}")

# So index 64 = 'z' but we skip it (idx < 64)
# Let's count how many chars have idx < 64
valid_chars = sum(1 for ch in USER_STATUS_BODY if CUSTOM_ALPHABET.index(ch) < 64)
skipped = sum(1 for ch in USER_STATUS_BODY if CUSTOM_ALPHABET.index(ch) >= 64)
print(f"\nValid chars (idx < 64): {valid_chars}")
print(f"Skipped chars (idx >= 64): {skipped}")
