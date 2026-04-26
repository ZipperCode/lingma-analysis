"""
Analyze decoded body bytes for patterns.
Check if there's a header/IV/MAC structure.
"""
import json

CUSTOM_ALPHABET = "!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
ALPHABET_INDEX = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}

def decode_method1(text):
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
    return bytes(result)

bodies = {}
with open('capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl') as f:
    for line in f:
        d = json.loads(line)
        path = d.get('path', '?')
        body_b64 = d.get('body_base64_preview', '')
        if body_b64 and len(body_b64) > 50:
            decoded = decode_method1(body_b64)
            bodies[path] = bodies.get(path, [])
            bodies[path].append(decoded)

print("=== Pattern Analysis ===\n")

for path, decodeds in bodies.items():
    short_path = path.split('?')[0].split('/')[-1]
    for i, decoded in enumerate(decodeds):
        print(f"{short_path} (len={len(decoded)}):")

        # Check first bytes
        first8 = decoded[:8]
        last8 = decoded[-8:]

        # Check for common suffix
        print(f"  First 16: {decoded[:16].hex()}")
        print(f"  Last 16:  {decoded[-16:].hex()}")

        # Check if last bytes follow a pattern
        # Look at bytes from position -16 to end
        tail = decoded[-16:]
        print(f"  Tail analysis: {' '.join(f'{b:02x}' for b in tail)}")

        # Check byte distribution
        non_zero = sum(1 for b in decoded if b != 0)
        high_entropy = sum(1 for b in decoded if b > 127)
        printable = sum(1 for b in decoded if 32 <= b < 127)

        print(f"  Non-zero: {non_zero}/{len(decoded)}, High bits: {high_entropy}, Printable: {printable}")

    if len(decodeds) > 1:
        # Compare duplicates
        print(f"  [Comparing {len(decodeds)} instances]")
        for i in range(1, len(decodeds)):
            same = decodeds[0] == decodeds[i]
            print(f"  Instance 0 vs {i}: {'IDENTICAL' if same else 'DIFFERENT'}")
    print()

# Now check for common patterns across ALL bodies
print("\n=== Cross-body suffix analysis ===")
all_decodeds = []
with open('capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl') as f:
    for line in f:
        d = json.loads(line)
        body_b64 = d.get('body_base64_preview', '')
        path = d.get('path', '?')
        if body_b64 and len(body_b64) > 50:
            decoded = decode_method1(body_b64)
            all_decodeds.append((path, decoded))

# Check if any bodies share a common suffix (possibly HMAC or padding)
print("\nComparing last 16 bytes across all bodies:")
suffixes = {}
for path, decoded in all_decodeds:
    suffix = decoded[-16:].hex()
    short_path = path.split('?')[0].split('/')[-1]
    if suffix not in suffixes:
        suffixes[suffix] = []
    suffixes[suffix].append(short_path)

for suffix, paths in suffixes.items():
    if len(paths) > 1:
        print(f"  SHARED suffix {suffix}: {', '.join(paths)}")
    else:
        print(f"  Unique suffix {suffix}: {paths[0]}")

# Check if bodies from same API share a suffix pattern
print("\n=== Bodies from same API ===")
api_groups = {}
for path, decoded in all_decodeds:
    api = path.split('?')[0].rsplit('/', 1)[-1]
    if api not in api_groups:
        api_groups[api] = []
    api_groups[api].append(decoded)

for api, decodeds in api_groups.items():
    if len(decodeds) > 1:
        print(f"\n{api} ({len(decodeds)} instances):")
        for i, d in enumerate(decodeds):
            print(f"  [{i}] last 16: {d[-16:].hex()}")
        # Compare
        if all(d[-16:] == decodeds[0][-16:] for d in decodeds[1:]):
            print(f"  => ALL SHARE SAME LAST 16 BYTES")
        elif all(d[-15:] == decodeds[0][-15:] for d in decodeds[1:]):
            print(f"  => ALL SHARE SAME LAST 15 BYTES (first of tail differs)")
