import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import struct

CUSTOM_ALPHABET = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
alpha_index = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}

def bitstream_decode(text):
    bits = []
    for ch in text:
        if ch not in alpha_index:
            continue
        idx = alpha_index[ch]
        for i in range(5, -1, -1):
            bits.append((idx >> i) & 1)
    n_bytes = len(bits) // 8
    result = bytearray()
    for i in range(n_bytes):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i * 8 + j]
        result.append(byte)
    return bytes(result)

AES_KEY = b'QbgzpWzN7tfe43gf'

# Load the capture file
with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    captures = [json.loads(line) for line in f]

# List all entries with POST methods and their body sizes
print("=== All POST entries in capture ===")
for i, obj in enumerate(captures):
    path = obj.get('path', '')
    method = obj.get('method', '')
    body_len = obj.get('body_len', 0)
    body_utf8_len = len(obj.get('body_utf8', ''))
    if method == 'POST':
        print(f"  [{i}] {method} {path}")
        print(f"      body_len: {body_len}, body_utf8: {body_utf8_len} chars")

# Focus on the tracking body
print("\n\n=== Tracking body deep analysis ===")
for obj in captures:
    if 'tracking' in obj.get('path', '') and obj.get('body_utf8'):
        body = obj['body_utf8']
        decoded = bitstream_decode(body)
        print(f"Decoded length: {len(decoded)} bytes")

        # Check if this could be a complete encrypted JSON
        # 1353 bytes = not a multiple of 16
        # 1353 - 9 = 1344 = 84 * 16 ✓

        # What if the entire thing is encrypted, including the "header"?
        # 1353 / 16 = 84.56... → not aligned
        # But maybe the encoding added padding

        # Let's check: is the FIRST byte actually part of the encoding?
        # Or is there a protocol header?

        # Show full hex dump of first 50 bytes
        print("First 50 bytes:")
        for i in range(0, min(50, len(decoded)), 16):
            chunk = decoded[i:i+16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f"  {i:04d}: {hex_str:<48} {ascii_str}")

        # Let's try: what if we decrypt the entire decoded data with CTR mode?
        # CTR doesn't need padding, so any length works

        # Try with first 16 bytes as IV (nonce)
        iv = decoded[:16]
        ciphertext = decoded[16:]
        print(f"\nTrying CTR with IV = first 16 bytes: {iv.hex()}")
        try:
            cipher = AES.new(AES_KEY, AES.MODE_CTR, nonce=iv[:8])
            decrypted = cipher.decrypt(ciphertext)
            printable = sum(1 for b in decrypted if 32 <= b < 127)
            print(f"  Printable: {printable}/{len(decrypted)} ({printable/len(decrypted)*100:.0f}%)")
            if printable > len(decrypted) * 0.5:
                print(f"  ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted[:200])}")
        except Exception as e:
            print(f"  Error: {e}")

        # Also try: what if the tracking body uses a DIFFERENT key?
        # Let's check if there are other 16-byte string constants

        # For now, let's try to understand the tracking body's first 9 bytes
        first9 = decoded[:9]
        print(f"\nFirst 9 bytes analysis:")
        print(f"  Hex: {first9.hex()}")
        print(f"  As uint64: {struct.unpack('<Q', first9[:8])[0]}")
        print(f"  As uint64 BE: {struct.unpack('>Q', first9[:8])[0]}")
        print(f"  Byte 0: 0x{first9[0]:02x} = {first9[0]}")
        print(f"  Bytes 1-8 as int64: {struct.unpack('<q', first9[1:9])[0]}")

        # Could be:
        # - Version byte (0x7d = 125)
        # - Or a field count
        # - Or part of a protobuf message

        # Try protobuf-style interpretation:
        # byte 0 = field tag (field_number << 3 | wire_type)
        tag = first9[0]
        field_num = tag >> 3
        wire_type = tag & 0x7
        print(f"\nAs protobuf field tag:")
        print(f"  Tag byte: 0x{tag:02x}")
        print(f"  Field number: {field_num}")
        print(f"  Wire type: {wire_type}")

        # Wire type 7 is unusual (valid types are 0-5)
        # So probably not protobuf

        break

# Let's also look at ALL the different encoded bodies in the capture
print("\n\n=== All body sizes in capture ===")
for obj in captures:
    body_utf8 = obj.get('body_utf8', '')
    path = obj.get('path', '')
    if body_utf8:
        decoded = bitstream_decode(body_utf8)
        print(f"  {path}: encoded={len(body_utf8)} chars, decoded={len(decoded)} bytes, mod16={len(decoded)%16}")
