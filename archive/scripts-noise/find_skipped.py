"""
Find which characters have index >= 64 (and are thus skipped by the decoder).
"""

CUSTOM_ALPHABET = "!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
ALPHABET_INDEX = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}

# Check the last character of the alphabet
print(f"Alphabet: {CUSTOM_ALPHABET}")
print(f"Alphabet length: {len(CUSTOM_ALPHABET)}")
print(f"Last char: '{CUSTOM_ALPHABET[-1]}' at index {len(CUSTOM_ALPHABET) - 1}")

# Now check the body
body = "uOFLDgKLDEKLN(iNBM)O#S%^D,%NBOg.JHiKuODbxoBymk.WB*f*DSQMu(CLFOFYN(Lbu*ByBMT*ep$$xoByxoKNB*%NBEjL#kFYPxCQ@(g.JHiau(tLuLf*lLf*xoBrxoKYDSDYDxjnFHWUDSQNBM)NBLf*Ggf*mYKf#xLru(gzBMn*m.f*JxjLNzLzxoByxoB.l@VfjMN(l@TflRzIVRBkxoBrxoKfDxK^u(QiugCbP(Fh"

print(f"\nBody: {len(body)} chars")

# Find chars with index >= 64
skipped = []
for i, ch in enumerate(body):
    if ch in ALPHABET_INDEX and ALPHABET_INDEX[ch] >= 64:
        skipped.append((i, ch, ALPHABET_INDEX[ch]))

print(f"Characters with index >= 64 (skipped): {len(skipped)}")
for pos, ch, idx in skipped:
    context = body[max(0,pos-3):pos+4]
    print(f"  Position {pos}: '{ch}' (index {idx}), context: ...{context}...")

valid_count = sum(1 for ch in body if ch in ALPHABET_INDEX and ALPHABET_INDEX[ch] < 64)
total_in_alpha = sum(1 for ch in body if ch in ALPHABET_INDEX)
not_in_alpha = sum(1 for ch in body if ch not in ALPHABET_INDEX)

print(f"\nTotal chars: {len(body)}")
print(f"In alphabet (any index): {total_in_alpha}")
print(f"Valid (index < 64): {valid_count}")
print(f"Skipped (index >= 64): {total_in_alpha - valid_count}")
print(f"Not in alphabet: {not_in_alpha}")
print(f"\nExpected bits: {valid_count * 6}")
print(f"Expected bytes: {valid_count * 6 // 8}")
print(f"Leftover bits: {valid_count * 6 % 8}")

# Key insight: if 'z' (index 64) is used, it's being skipped
# 240 - 4 = 236 valid chars
# 236 * 6 = 1416 bits = 177 bytes

# BUT: what if the encoding uses ALL 65 chars differently?
# What if 'z' is padding or some special marker?

# Let's think about this differently:
# If 240 chars encode 180 bytes (with PKCS5 padding), the ciphertext is 180 bytes
# But 180 is not a multiple of 16 either (180 = 11*16 + 4)
# So even with 240 chars, we can't get AES-CBC output

# UNLESS the ciphertext is actually shorter and some chars are overhead

# Alternative: maybe it's NOT AES-CBC but AES-CTR
# AES-CTR output = input length (any length)
# If plaintext JSON is ~165 bytes, + PKCS5 padding = 176 bytes (11 blocks)
# But we'd still need to encode 176 bytes into the custom alphabet
# 176 * 8 / 6 = 234.67 chars, rounded up = 235 chars
# But we have 240 chars

# Or maybe the encoding includes some header bytes
# Let's check: what if first N chars encode a header and the rest encode ciphertext?

# 240 chars total, 4 skipped (z chars)
# 236 chars * 6 bits = 1416 bits = 177 bytes

# If first 2 bytes (16 bits) are a header/version:
# Remaining: 175 bytes (not multiple of 16)
# If first 1 byte:
# Remaining: 176 bytes = 11 * 16!

print("\n" + "=" * 60)
print("Possible structure:")
print("=" * 60)
print(f"Total decoded: 177 bytes")
print(f"If 1-byte header: 176 bytes ciphertext (11 AES blocks)")
print(f"If 2-byte header: 175 bytes (NOT multiple of 16)")
print(f"If 3-byte header: 174 bytes (NOT multiple of 16)")
print(f"If 4-byte header: 173 bytes (NOT multiple of 16)")
print(f"If 5-byte header: 172 bytes (NOT multiple of 16)")
print(f"If 16-byte header: 161 bytes (NOT multiple of 16)")
print(f"If 17-byte header: 160 bytes (10 AES blocks)")

# The most likely splits:
print(f"\nMost likely: 1 byte header + 176 bytes ciphertext (11 blocks)")
print(f"Or: 17 bytes header + 160 bytes ciphertext (10 blocks)")
