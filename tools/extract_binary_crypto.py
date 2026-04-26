"""
Extract and analyze encryption-related data from Lingma.exe binary.

Goals:
1. Find AES keys or key derivation patterns
2. Extract strings near encryption functions
3. Analyze the encodeRequestBody function calls
4. Find hardcoded encryption parameters
"""

import struct
import re
import sys

BINARY_PATH = "C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe"

def find_strings_in_range(data: bytes, start: int, end: int, min_len: int = 4) -> list[tuple[int, str]]:
    """Find ASCII strings in a range of the binary."""
    strings = []
    pattern = rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
    for match in re.finditer(pattern, data[start:end]):
        offset = start + match.start()
        text = match.group().decode('ascii', errors='replace')
        strings.append((offset, text))
    return strings

def extract_function_bytes(data: bytes, rva: int, size: int) -> bytes:
    """Extract function bytes from binary given RVA and size."""
    # We need to convert RVA to file offset
    # Parse PE header to find section containing this RVA
    return data[rva:rva+size]  # This won't work directly, need PE parsing

def parse_pe_sections(data: bytes) -> list[dict]:
    """Parse PE file to get section information."""
    # Check DOS header
    if data[:2] != b'MZ':
        print("Not a valid PE file")
        return []

    # Get PE header offset
    pe_offset = struct.unpack_from('<I', data, 0x3c)[0]
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        print(f"Not a valid PE file at offset {pe_offset}")
        return []

    # Optional header
    opt_header_offset = pe_offset + 24
    magic = struct.unpack_from('<H', data, opt_header_offset)[0]

    if magic == 0x20b:  # PE32+
        num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
        opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
        section_offset = opt_header_offset + opt_header_size

        sections = []
        for i in range(num_sections):
            sec_start = section_offset + i * 40
            name = data[sec_start:sec_start+8].rstrip(b'\x00').decode('ascii', errors='replace')
            virt_size = struct.unpack_from('<I', data, sec_start + 8)[0]
            virt_addr = struct.unpack_from('<I', data, sec_start + 12)[0]
            raw_size = struct.unpack_from('<I', data, sec_start + 16)[0]
            raw_offset = struct.unpack_from('<I', data, sec_start + 20)[0]

            sections.append({
                'name': name,
                'virt_size': virt_size,
                'virt_addr': virt_addr,
                'raw_size': raw_size,
                'raw_offset': raw_offset,
            })

        return sections

    return []

def rva_to_file_offset(sections: list[dict], rva: int) -> int:
    """Convert RVA to file offset."""
    for sec in sections:
        if sec['virt_addr'] <= rva < sec['virt_addr'] + sec['virt_size']:
            return sec['raw_offset'] + (rva - sec['virt_addr'])
    return rva  # Fallback

def main():
    print(f"Reading binary: {BINARY_PATH}")
    with open(BINARY_PATH, "rb") as f:
        data = f.read()

    print(f"Binary size: {len(data)} bytes ({len(data)/1024/1024:.1f} MB)")

    # Parse PE sections
    sections = parse_pe_sections(data)
    if not sections:
        print("Failed to parse PE sections")
        return

    print(f"\nPE Sections:")
    for sec in sections[:10]:
        print(f"  {sec['name']:8s} VA=0x{sec['virt_addr']:08x} size=0x{sec['virt_size']:08x} "
              f"raw=0x{sec['raw_offset']:08x}/{sec['raw_size']}")

    # Extract strings near encryption functions
    # cosy/encrypt functions are around VA 0x140100xxx
    # Let's search in the .text section

    text_section = None
    for sec in sections:
        if sec['name'] == '.text':
            text_section = sec
            break

    if text_section:
        print(f"\n.text section: VA=0x{text_section['virt_addr']:x} size=0x{text_section['virt_size']:x}")

        # Extract the .text section data
        text_start = text_section['raw_offset']
        text_size = text_section['raw_size']
        text_data = data[text_start:text_start + text_size]

        # Search for encryption-related strings
        print("\nSearching for encryption-related strings in .text:")
        patterns = [
            rb'AES', rb'aes', rb'Aes', rb'encrypt', rb'decrypt',
            rb'Encrypt', rb'Decrypt', rb'cipher', rb'Cipher',
            rb'pkcs5', rb'pkcs7', rb'PKCS',
            rb'AES-', rb'aes-', rb'cbc', r'CBC', r'ecb', r'ECB',
            rb'ctr', r'CTR', rb'gcm', r'GCM',
            rb'\x00key\x00', rb'\x00Key\x00', rb'\x00KEY\x00',
        ]

        for pat in patterns[:5]:  # Start with a few patterns
            for match in re.finditer(pat, text_data, re.IGNORECASE):
                offset = text_section['virt_addr'] + match.start()
                context = text_data[max(0, match.start()-20):match.end()+20]
                print(f"  0x{offset:08x}: {context[:40]}")

    # Find strings near AesEncryptWithBase64 (RVA 0x103c00)
    print(f"\nSearching near AesEncryptWithBase64 (RVA 0x103c00):")
    # Get a range around the function
    func_rva = 0x103c00
    file_offset = rva_to_file_offset(sections, func_rva)
    print(f"  RVA 0x{func_rva:x} -> file offset 0x{file_offset:x}")

    if file_offset < len(data):
        # Extract surrounding strings
        search_start = max(0, file_offset - 0x1000)
        search_end = min(len(data), file_offset + 0x1000)

        strings = find_strings_in_range(data, search_start, search_end, min_len=4)
        print(f"  Found {len(strings)} strings in +/- 4KB range:")
        for offset, text in strings[:50]:
            rel_offset = offset - file_offset
            print(f"    0x{offset:08x} (rel+{rel_offset:+#06x}): {text}")

    # Find strings near encodeRequestBody (RVA 0x881820)
    print(f"\nSearching near encodeRequestBody (RVA 0x881820):")
    func_rva = 0x881820
    file_offset = rva_to_file_offset(sections, func_rva)
    print(f"  RVA 0x{func_rva:x} -> file offset 0x{file_offset:x}")

    if file_offset < len(data):
        search_start = max(0, file_offset - 0x1000)
        search_end = min(len(data), file_offset + 0x1000)

        strings = find_strings_in_range(data, search_start, search_end, min_len=4)
        print(f"  Found {len(strings)} strings in +/- 4KB range:")
        for offset, text in strings[:50]:
            rel_offset = offset - file_offset
            print(f"    0x{offset:08x} (rel+{rel_offset:+#06x}): {text}")

    # Search for common AES-related constants in the binary
    print(f"\nSearching for AES S-Box (first 16 bytes):")
    aes_sbox_start = bytes([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    ])
    pos = 0
    found_count = 0
    while True:
        pos = data.find(aes_sbox_start, pos)
        if pos < 0:
            break
        print(f"  Found at file offset 0x{pos:x}")
        pos += 1
        found_count += 1
        if found_count > 5:
            break

    if found_count == 0:
        print("  Not found")

    # Search for "aes-128-cbc", "aes-256-cbc", etc.
    print(f"\nSearching for cipher mode strings:")
    cipher_strings = [
        b'aes-128-cbc', b'aes-256-cbc', b'aes-128-ecb', b'aes-256-ecb',
        b'aes-128-ctr', b'aes-256-ctr', b'aes-128-gcm', b'aes-256-gcm',
        b'AES-128-CBC', b'AES-256-CBC',
        b'cbc', b'CBC', b'ecb', b'ECB', b'ctr', b'CTR',
    ]
    for cs in cipher_strings:
        pos = 0
        found = 0
        while True:
            pos = data.find(cs, pos)
            if pos < 0:
                break
            if found == 0:
                print(f"  '{cs.decode()}': found at 0x{pos:x}")
            found += 1
            pos += 1
            if found > 3:
                print(f"    ... and {found-3} more")
                break

    # Search for the alphabet string itself
    print(f"\nSearching for custom alphabet string:")
    alphabet_bytes = b"!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
    pos = data.find(alphabet_bytes)
    if pos >= 0:
        print(f"  Found at file offset 0x{pos:x}")
        # Show context
        context = data[max(0,pos-20):pos+len(alphabet_bytes)+20]
        print(f"  Context: {context}")
    else:
        # Try to find partial alphabet
        print("  Full alphabet not found as contiguous string")
        for partial in [b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz"]:
            pos = data.find(partial)
            if pos >= 0:
                print(f"  Partial match '{partial[:10]}...' at 0x{pos:x}")

    # Search for pkcs5 padding implementation
    print(f"\nSearching for pkcs5-related strings:")
    pkcs_strings = [
        b'pkcs5', b'pkcs7', b'PKCS5', b'PKCS7',
        b'padding', b'Padding',
        b'blockSize', b'block_size',
        b'16', b'pad',
    ]
    for cs in pkcs_strings[:5]:
        pos = data.find(cs)
        if pos >= 0:
            context = data[max(0,pos-20):pos+40]
            print(f"  '{cs.decode()}' at 0x{pos:x}: context={context[:60]}")

    print(f"\n=== Summary ===")
    print(f"Binary analyzed: {BINARY_PATH}")
    print(f"Size: {len(data)} bytes")
    print(f"PE sections: {len(sections)}")


if __name__ == "__main__":
    main()
