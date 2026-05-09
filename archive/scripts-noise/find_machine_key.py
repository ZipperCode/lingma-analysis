"""
Find the machineKey and encryption pipeline details.

Key findings:
- "Using machineKey: %s" at offset 0x253a6a8
- encrypt.newEncoding and encrypt.shuffle exist
- CustomDecryptV1 and CustomDecryptParts exist

Strategy:
1. Find the machineKey value from cache/id
2. Analyze how machineKey is used for body encryption
3. Check if the alphabet is shuffled based on a key
"""

import struct
import re
import json
import hashlib
import os
from pathlib import Path

BINARY_PATH = "C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe"

def find_machine_key_strings():
    """Find strings around 'machineKey' references."""
    with open(BINARY_PATH, "rb") as f:
        data = f.read()

    print("=" * 60)
    print("1. machineKey related strings and code")
    print("=" * 60)

    # Find all references to machineKey
    pattern = b'machineKey'
    pos = 0
    while True:
        pos = data.find(pattern, pos)
        if pos < 0:
            break

        # Get surrounding context (200 bytes before, 200 after)
        start = max(0, pos - 200)
        end = min(len(data), pos + 200)
        context = data[start:end]

        # Find string boundaries (null-terminated)
        null_before = context.rfind(b'\x00', 0, 200)
        if null_before >= 0:
            context = context[null_before + 1:]
        null_after = context.find(b'\x00')
        if null_after >= 0:
            context = context[:null_after]

        try:
            text = context.decode('ascii', errors='replace')
            print(f"\n  0x{pos:08x}: {text[:200]}")
        except:
            pass
        pos += 1

    # Also search for MachineKey (capitalized)
    print("\n\n  MachineKey (capitalized):")
    pattern = b'MachineKey'
    pos = 0
    count = 0
    while True:
        pos = data.find(pattern, pos)
        if pos < 0:
            break
        start = max(0, pos - 100)
        end = min(len(data), pos + 100)
        context = data[start:end]
        null_before = context.rfind(b'\x00', 0, 100)
        if null_before >= 0:
            context = context[null_before + 1:]
        null_after = context.find(b'\x00')
        if null_after >= 0:
            context = context[:null_after]
        try:
            text = context.decode('ascii', errors='replace')
            if len(text) > 5 and count < 5:
                print(f"  0x{pos:08x}: {text[:150]}")
            count += 1
        except:
            pass
        pos += 1
    print(f"  Total: {count} occurrences")

def find_cache_files():
    """Read cache/id and cache/user from ~/.lingma."""
    print("\n" + "=" * 60)
    print("2. Cache files analysis")
    print("=" * 60)

    base_dir = Path.home() / ".lingma"
    cache_dir = base_dir / "cache"

    # Find all cache directories
    for cache_path in cache_dir.rglob("*"):
        if cache_path.is_dir():
            continue

        file_data = cache_path.read_bytes()
        print(f"\n  {cache_path}")
        print(f"    Size: {len(file_data)} bytes")
        print(f"    First 32 bytes (hex): {file_data[:32].hex()}")

        # Try to read as text
        try:
            text = file_data.decode('utf-8', errors='replace')
            print(f"    Text: {text[:200]}")
        except:
            pass

def try_decrypt_cache_user():
    """
    Try to decrypt cache/user using machineKey.

    From the token flow analysis:
    - cache/id contains the machine ID
    - cache/user is encrypted with AES-128-CBC
    - machineKey is derived from cache/id
    """
    print("\n" + "=" * 60)
    print("3. Decrypt cache/user attempt")
    print("=" * 60)

    base_dir = Path.home() / ".lingma"

    # Read cache/id
    id_path = base_dir / "cache" / "id"
    if not id_path.exists():
        print(f"  cache/id not found at {id_path}")
        return

    machine_id = id_path.read_text().strip()
    print(f"  Machine ID: {machine_id}")

    # Read cache/user
    user_path = base_dir / "cache" / "user"
    if not user_path.exists():
        print(f"  cache/user not found at {user_path}")
        return

    user_data = user_path.read_bytes()
    print(f"  cache/user size: {len(user_data)} bytes")
    print(f"  First 32 bytes (hex): {user_data[:32].hex()}")

    # Try different machineKey derivation methods
    # Method 1: machine_id itself
    # Method 2: MD5 of machine_id
    # Method 3: SHA256 of machine_id (truncated to 16/32 bytes)
    # Method 4: machine_id bytes directly (padded/truncated)

    machine_id_bytes = machine_id.encode('utf-8')
    md5_key = hashlib.md5(machine_id_bytes).digest()
    sha256_key = hashlib.sha256(machine_id_bytes).digest()

    print(f"\n  Possible keys:")
    print(f"    machine_id bytes: {machine_id_bytes[:16].hex()} (len={len(machine_id_bytes)})")
    print(f"    MD5(machine_id):  {md5_key.hex()}")
    print(f"    SHA256(machine_id): {sha256_key.hex()}")

    # Try to find the encrypt_user_info structure
    # From the token flow analysis, cache/user contains:
    # A JSON structure with "encrypt_user_info" field
    # which is base64-encoded encrypted data

    try:
        user_json = json.loads(user_data)
        print(f"\n  cache/user JSON keys: {list(user_json.keys())}")
        if 'encrypt_user_info' in user_json:
            print(f"    encrypt_user_info length: {len(user_json['encrypt_user_info'])}")
            print(f"    encrypt_user_info preview: {user_json['encrypt_user_info'][:100]}")
        if 'security_oauth_token' in user_json:
            print(f"    security_oauth_token: {user_json['security_oauth_token'][:50]}...")
    except json.JSONDecodeError:
        # Maybe it's binary encrypted data
        print(f"  cache/user is not JSON, likely binary")

def analyze_shuffle_function():
    """
    Analyze the encrypt.shuffle function to understand how the alphabet is generated.

    If the alphabet is shuffled based on a key, we need to understand the shuffle algorithm.
    """
    print("\n" + "=" * 60)
    print("4. Shuffle function analysis")
    print("=" * 60)

    # Find the shuffle function in GoReSym output
    goresym_path = "capture/goresym-lingma.json"
    if os.path.exists(goresym_path):
        with open(goresym_path, "r") as f:
            goresym = json.load(f)

        # Find shuffle function
        for func in goresym.get('Funcs', []):
            if 'shuffle' in func.get('FullName', '').lower():
                print(f"  Function: {func['FullName']}")
                print(f"    Start: 0x{func['Start']:x}")
                print(f"    End: 0x{func['End']:x}")
                print(f"    Size: 0x{func['End'] - func['Start']:x} = {func['End'] - func['Start']} bytes")

    # Also try to extract the shuffle function bytes
    # From GoReSym: shuffle is in cosy/encrypt package
    # The package starts around VA 0x140101000

    # Let's search for the shuffle function's string reference
    with open(BINARY_PATH, "rb") as f:
        data = f.read()

    # Find "shuffle" string
    pos = data.find(b'encrypt.shuffle')
    if pos >= 0:
        print(f"\n  'encrypt.shuffle' string at 0x{pos:x}")
        # Show context
        context = data[max(0, pos-50):pos+100]
        print(f"  Context: {context[:150]}")

def try_known_key_derivation():
    """
    Try to derive the encryption key using the known machine ID.

    The machine ID from captures: 35346164-3866-492d-a339-30773a32652d
    This looks like a UUID: 54646164-3866-492d-a339-30773a32652d

    Wait, let me check: 35346164-3866-492d-a339-30773a32652d
    In hex: 35 34 61 64 - 38 66 49 2d - a339 - 30773a32652d
    As ASCII: '54ad'-'8fI-'... that doesn't look right.

    Actually, the machine ID in the captures is:
    Cosy-Machineid: 35346164-3866-492d-a339-30773a32652d

    Let me decode: 35346164 in hex = '5' '4' 'a' 'd' in ASCII? No...
    0x35 = '5', 0x34 = '4', 0x61 = 'a', 0x64 = 'd'
    So "54ad" or reading as: 35 34 61 64 = "54ad"

    Actually: 35 34 61 64 38 66 49 2d a339 30773a32652d
    As ASCII: "54ad8fI-"... hmm

    Wait, the format 35346164-3866-492d-a339-30773a32652d looks like
    a UUID but with a non-standard format. Let me just use it as-is.
    """
    print("\n" + "=" * 60)
    print("5. Key derivation test")
    print("=" * 60)

    machine_id = "35346164-3866-492d-a339-30773a32652d"

    # Various possible key derivations
    import hashlib

    # 1. Direct bytes (first 16)
    key1 = machine_id.encode()[:16]
    print(f"  Direct 16 bytes: {key1.hex()}")
    print(f"    As text: {key1}")

    # 2. MD5
    key2 = hashlib.md5(machine_id.encode()).digest()
    print(f"  MD5: {key2.hex()}")

    # 3. SHA256 truncated to 16
    key3 = hashlib.sha256(machine_id.encode()).digest()[:16]
    print(f"  SHA256[:16]: {key3.hex()}")

    # 4. SHA256 truncated to 32 (AES-256)
    key4 = hashlib.sha256(machine_id.encode()).digest()
    print(f"  SHA256: {key4.hex()}")

    # 5. machine ID without dashes
    no_dashes = machine_id.replace("-", "")
    key5 = no_dashes.encode()[:16]
    print(f"  No dashes (16): {key5.hex()}")

    # 6. Hex-decoded machine ID
    try:
        # 35346164 -> decode as hex
        hex_decoded = bytes.fromhex(machine_id.replace("-", ""))
        print(f"  Hex decoded: {hex_decoded.hex()}")
        print(f"  As text: {hex_decoded}")
    except:
        print(f"  Hex decode failed")

def main():
    find_machine_key_strings()
    find_cache_files()
    try_decrypt_cache_user()
    analyze_shuffle_function()
    try_known_key_derivation()

if __name__ == "__main__":
    main()
