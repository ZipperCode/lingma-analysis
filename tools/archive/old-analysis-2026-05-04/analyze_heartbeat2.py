import json

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

with open('D:/Project/lingma/capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for line in f:
        obj = json.loads(line)
        if 'heartbeat' in obj.get('path', ''):
            body = obj['body_utf8']
            decoded = bitstream_decode(body)
            text = decoded.decode('latin-1')

            # Check character distribution at byte 244 onward
            print("=== Byte frequency analysis (bytes 244-300) ===")
            region = decoded[244:300]
            freq = {}
            for b in region:
                freq[b] = freq.get(b, 0) + 1
            sorted_freq = sorted(freq.items(), key=lambda x: -x[1])
            for val, count in sorted_freq[:15]:
                char = chr(val) if 32 <= val < 127 else '.'
                print(f"  0x{val:02x} ({char}): {count} times")

            # The most common byte in the ciphertext region
            most_common = sorted_freq[0][0]
            print(f"\nMost common byte: 0x{most_common:02x}")

            # XOR entire region with most common byte
            xored = bytes(b ^ most_common for b in decoded[244:300])
            print(f"XOR with 0x{most_common:02x}: {xored.hex()}")
            print(f"As text: {''.join(chr(b) if 32 <= b < 127 else '.' for b in xored)}")

            # Check if this could be AES-CBC with a constant IV
            # by looking at the relationship between consecutive blocks
            print()
            print("=== XOR between consecutive 16-byte blocks ===")
            for i in range(244, 308, 16):
                if i + 32 <= len(decoded):
                    block1 = decoded[i:i+16]
                    block2 = decoded[i+16:i+32]
                    xor_result = bytes(a ^ b for a, b in zip(block1, block2))
                    match_count = sum(1 for b in xor_result if b == 0)
                    print(f"  XOR blocks at {i}: {match_count} matching bytes, result: {xor_result[:8].hex()}...")

            # The ENTIRE body as potential ciphertext
            # Let's check if there's a structure marker
            # For AES-CBC: IV prepended (16 bytes), then ciphertext
            # So actual ciphertext starts at offset 16
            # Let's see what's at offset 16
            print()
            print("=== Bytes at various offsets ===")
            for offset in [0, 16, 32, 240, 244, 256]:
                block = decoded[offset:offset+16]
                printable = sum(1 for b in block if 32 <= b < 127)
                print(f"  Offset {offset}: {block.hex()} ({printable}/16 printable)")

            break
