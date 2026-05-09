"""
Extract the AES key and encryption pipeline from the binary.

Key findings so far:
- AES S-Box at file offset 0x5c4ae80
- aes128-cbc, aes192-cbc, aes256-cbc strings present
- pkcs5UnPadding at 0x3b07078 (code.alibaba-inc.com/cosy/encrypt.pkcs5UnPadding)
- AesEncryptWithBase64 at RVA 0x103c00 (file offset 0x103000)
- encodeRequestBody at RVA 0x881820 (file offset 0x880c20)

Strategy: Extract strings from the cosy/encrypt package area to find:
1. The encryption key derivation
2. The IV generation method
3. The full encodeRequestBody -> encryption chain
"""

import struct
import re

BINARY_PATH = "C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe"

def find_ascii_strings(data: bytes, min_len: int = 4) -> list[tuple[int, str]]:
    """Find all ASCII strings in binary data."""
    strings = []
    pattern = rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
    for match in re.finditer(pattern, data):
        offset = match.start()
        text = match.group().decode('ascii', errors='replace')
        strings.append((offset, text))
    return strings

def find_utf8_strings(data: bytes, min_len: int = 4) -> list[tuple[int, str]]:
    """Find UTF-8 strings (including Go's length-prefixed strings)."""
    strings = []
    # Also look for non-ASCII printable chars
    pattern = rb'[\x20-\x7e\x80-\xff]{' + str(min_len).encode() + rb',}'
    for match in re.finditer(pattern, data):
        offset = match.start()
        try:
            text = match.group().decode('utf-8', errors='replace')
            if any(0x20 <= ord(c) < 0x7f or 0x80 <= ord(c) for c in text):
                strings.append((offset, text))
        except:
            pass
    return strings

def rva_to_file_offset(rva: int) -> int:
    """Convert RVA to file offset."""
    # .text section starts at VA 0x1000, file offset 0x400
    # For .text: file_offset = rva - 0x1000 + 0x400 = rva - 0xC00
    # But we need to handle all sections

    sections = [
        ('.text',   0x00001000, 0x01f3f246, 0x00000400),
        ('.rdata',  0x01f41000, 0x03cfc250, 0x01f3f800),
        ('.data',   0x05c3e000, 0x00518d80, 0x05c3bc00),
        ('.pdata',  0x06157000, 0x000973ec, 0x060a6400),
        ('.reloc',  0x061f0000, 0x00087e30, 0x0613da00),
    ]

    for name, va, size, raw_offset in sections:
        if va <= rva < va + size:
            return raw_offset + (rva - va)
    return rva  # fallback

def main():
    with open(BINARY_PATH, "rb") as f:
        data = f.read()

    # === 1. Find all cosy/encrypt related strings ===
    print("=" * 60)
    print("1. cosy/encrypt package strings")
    print("=" * 60)

    encrypt_strings = []
    for pattern in [b'cosy/encrypt', b'encrypt.pkcs5', b'encrypt.Aes', b'encrypt.Rsa',
                    b'encrypt.Md5', b'encrypt.XxHash', b'encrypt.Custom',
                    b'encrypt.init', b'encrypt.Corrupt', b'encrypt.encod',
                    b'encrypt.decod']:
        pos = 0
        while True:
            pos = data.find(pattern, pos)
            if pos < 0:
                break
            # Get the full string around this position
            start = max(0, pos - 40)
            end = min(len(data), pos + 80)
            context = data[start:end]
            # Find string boundaries
            str_start = context.find(b'\x00')
            if str_start >= 0:
                context = context[str_start+1:]
            str_end = context.find(b'\x00')
            if str_end >= 0:
                context = context[:str_end]

            try:
                text = context.decode('ascii', errors='replace')
                encrypt_strings.append((pos, text))
            except:
                pass
            pos += 1

    for offset, text in sorted(encrypt_strings)[:30]:
        print(f"  0x{offset:08x}: {text[:100]}")

    # === 2. Search for key-related strings ===
    print("\n" + "=" * 60)
    print("2. Key/password/secret related strings")
    print("=" * 60)

    key_patterns = [
        b'key', b'Key', b'KEY',
        b'secret', b'Secret', b'SECRET',
        b'password', b'Password', b'PASSWORD',
        b'token', b'Token', b'TOKEN',
        b'machineKey', b'MachineKey',
        b'encryptionKey', b'EncryptionKey',
        b'aesKey', b'AesKey',
        b'masterKey', b'MasterKey',
    ]

    for pat in key_patterns:
        pos = 0
        found = 0
        while True:
            pos = data.find(pat, pos)
            if pos < 0:
                break
            # Get context
            start = max(0, pos - 20)
            end = min(len(data), pos + 60)
            context = data[start:end]
            # Find string boundaries
            null_before = context.rfind(b'\x00')
            if null_before >= 0:
                context = context[null_before+1:]
            null_after = context.find(b'\x00')
            if null_after >= 0:
                context = context[:null_after]

            try:
                text = context.decode('ascii', errors='replace')
                if len(text) > 3 and found < 3:
                    print(f"  0x{pos:08x}: {text[:100]}")
                found += 1
            except:
                pass
            pos += 1

    # === 3. Search for IV-related strings ===
    print("\n" + "=" * 60)
    print("3. IV-related strings")
    print("=" * 60)

    for pat in [b'iv', b'Iv', b'IV', b'initializationVector', b'InitializationVector',
                b'nonce', b'Nonce', b'NONCE', b'ivSeed', b'iv_bytes']:
        pos = 0
        found = 0
        while True:
            pos = data.find(pat, pos)
            if pos < 0:
                break
            start = max(0, pos - 20)
            end = min(len(data), pos + 60)
            context = data[start:end]
            null_before = context.rfind(b'\x00')
            if null_before >= 0:
                context = context[null_before+1:]
            null_after = context.find(b'\x00')
            if null_after >= 0:
                context = context[:null_after]
            try:
                text = context.decode('ascii', errors='replace')
                if len(text) > 3 and found < 3:
                    print(f"  0x{pos:08x}: {text[:100]}")
                found += 1
            except:
                pass
            pos += 1

    # === 4. Extract strings from the encrypt package area ===
    print("\n" + "=" * 60)
    print("4. Strings near encrypt package (VA 0x14010xxxx)")
    print("=" * 60)

    # encrypt package is around VA 0x140101000 to 0x140104000
    # File offset: 0x103000 - 0x104000 (approximately)
    encrypt_area_start = rva_to_file_offset(0x100000)
    encrypt_area_end = rva_to_file_offset(0x110000)

    area_data = data[encrypt_area_start:encrypt_area_end]
    strings = find_ascii_strings(area_data, min_len=6)

    print(f"  Found {len(strings)} strings in encrypt package area:")
    for offset, text in strings[:100]:
        abs_offset = encrypt_area_start + offset
        print(f"  0x{abs_offset:08x}: {text}")

    # === 5. Search for the actual encodeRequestBody implementation ===
    print("\n" + "=" * 60)
    print("5. encodeRequestBody implementation analysis")
    print("=" * 60)

    func_rva = 0x881820
    func_offset = rva_to_file_offset(func_rva)
    func_data = data[func_offset:func_offset + 0x160]

    print(f"  Function at RVA 0x{func_rva:x} (file offset 0x{func_offset:x})")
    print(f"  Function size: 0x160 bytes")
    print(f"  First 32 bytes (hex): {func_data[:32].hex()}")

    # Extract strings within the function
    func_strings = find_ascii_strings(func_data, min_len=4)
    if func_strings:
        print(f"  Strings found in function:")
        for offset, text in func_strings:
            print(f"    offset+{offset:04x}: {text}")

    # Look for CALL instructions in the function
    # x86-64 CALL relative: E8 xx xx xx xx
    print(f"\n  CALL instructions:")
    for i in range(len(func_data) - 4):
        if func_data[i] == 0xE8:  # CALL rel32
            rel = struct.unpack_from('<i', func_data, i+1)[0]
            target = func_rva + i + 5 + rel
            target_offset = rva_to_file_offset(target)
            print(f"    0x{func_rva + i:x}: CALL 0x{target:x} (rel={rel:#x})")

            # Try to find a symbol name near the target
            # Search for Go function name near the target
            search_start = max(0, target_offset - 200)
            search_end = min(len(data), target_offset + 100)
            search_data = data[search_start:search_end]
            target_strings = find_ascii_strings(search_data, min_len=10)
            for _, text in target_strings[:3]:
                if 'cosy' in text or 'encrypt' in text or 'encode' in text:
                    print(f"      -> likely: {text}")

    # Look for JMP instructions too
    print(f"\n  JMP instructions:")
    for i in range(len(func_data) - 4):
        if func_data[i] == 0xE9:  # JMP rel32
            rel = struct.unpack_from('<i', func_data, i+1)[0]
            target = func_rva + i + 5 + rel
            print(f"    0x{func_rva + i:x}: JMP 0x{target:x} (rel={rel:#x})")

    # === 6. Search for encodeRequestBody's caller chain ===
    # The buildRequest function calls encodeRequestBody
    # Let's find what calls encodeRequestBody
    print("\n" + "=" * 60)
    print("6. Functions that call encodeRequestBody")
    print("=" * 60)

    # encodeRequestBody's address in VA
    target_va = 0x1400000000 + func_rva  # base + rva

    # Search for CALL instructions targeting this address
    # In a 98MB binary, this would be very slow. Let's skip for now.
    print("  (skipping - would need to scan entire binary)")

    # === 7. Summary ===
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"""
Key findings:
1. AES S-Box confirmed at file offset 0x5c4ae80
2. CBC mode strings found (aes128-cbc, aes192-cbc, aes256-cbc)
3. pkcs5UnPadding confirmed in cosy/encrypt package
4. The encodeRequestBody function has {len(func_data)} bytes

The encoding pipeline is likely:
JSON -> AES-128-CBC (or AES-256-CBC) with PKCS5 padding -> custom base64

The remaining question is:
- What key is used for AES?
- Is the IV fixed or derived?

Since user/status always produces the same ciphertext,
the IV must be fixed (or zero).

NEXT: Run Frida to capture the actual AES key from memory
when AesEncryptWithBase64 is called.
""")


if __name__ == "__main__":
    main()
