import struct

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def parse_pe(pe_data):
    """Properly parse PE file to get section headers"""
    # DOS Header
    dos_sig = struct.unpack('<H', pe_data[0:2])[0]
    assert dos_sig == 0x5A4D, "Not a PE file"

    e_lfanew = struct.unpack('<I', pe_data[60:64])[0]
    print(f"e_lfanew: 0x{e_lfanew:x}")

    # NT Signature
    nt_sig = struct.unpack('<I', pe_data[e_lfanew:e_lfanew+4])[0]
    print(f"NT signature: 0x{nt_sig:x} (PE\\0\\0 = 0x00004550)")

    # COFF File Header (20 bytes)
    coff_offset = e_lfanew + 4
    machine = struct.unpack('<H', pe_data[coff_offset:coff_offset+2])[0]
    num_sections = struct.unpack('<H', pe_data[coff_offset+2:coff_offset+4])[0]
    opt_header_size = struct.unpack('<H', pe_data[coff_offset+16:coff_offset+18])[0]

    print(f"Machine: 0x{machine:x} ({'x86_64' if machine == 0x8664 else 'x86'})")
    print(f"Number of sections: {num_sections}")
    print(f"Optional header size: {opt_header_size} (0x{opt_header_size:x})")

    # Optional Header
    opt_offset = coff_offset + 20
    magic = struct.unpack('<H', pe_data[opt_offset:opt_offset+2])[0]
    print(f"Magic: 0x{magic:x} ({'PE32+' if magic == 0x20B else 'PE32' if magic == 0x10B else 'unknown'})")

    # Section headers start after optional header
    section_offset = opt_offset + opt_header_size
    print(f"Section headers start at: 0x{section_offset:x}")

    sections = []
    for i in range(num_sections):
        sec = pe_data[section_offset + i*40 : section_offset + (i+1)*40]
        name = sec[0:8].rstrip(b'\x00').decode('ascii', errors='replace')
        virtual_size = struct.unpack('<I', sec[8:12])[0]
        virtual_address = struct.unpack('<I', sec[12:16])[0]
        raw_size = struct.unpack('<I', sec[16:20])[0]
        raw_offset = struct.unpack('<I', sec[20:24])[0]

        sections.append({
            'name': name,
            'virtual_address': virtual_address,
            'virtual_size': virtual_size,
            'raw_offset': raw_offset,
            'raw_size': raw_size,
        })
        print(f"  Section {i}: {name:8s} VA=0x{virtual_address:08x} VS=0x{virtual_size:06x} RA=0x{raw_offset:08x} RS=0x{raw_size:06x}")

    return sections

with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

sections = parse_pe(pe_data)

# Now find file offset for a given RVA
def rva_to_file_offset(sections, rva):
    for sec in sections:
        va = sec['virtual_address']
        vs = sec['virtual_size']
        if va <= rva < va + max(vs, sec['raw_size']):
            return sec['raw_offset'] + (rva - va)
    return None

# Test with the alphabet RVA (0x5c48b40 from previous analysis)
alphabet_rva = 0x5c48b40
offset = rva_to_file_offset(sections, alphabet_rva)
print(f"\nAlphabet RVA 0x{alphabet_rva:x} -> file offset 0x{offset:x}")
if offset:
    data = pe_data[offset:offset+70]
    print(f"Data at offset: {data[:70]}")

# Test with AesEncryptWithBase64 RVA
aes_rva = 0x455da0
offset = rva_to_file_offset(sections, aes_rva)
print(f"\nAesEncryptWithBase64 RVA 0x{aes_rva:x} -> file offset 0x{offset:x}")
if offset:
    data = pe_data[offset:offset+64]
    print(f"First 64 bytes: {data.hex()}")

# Test with shuffle RVA
shuffle_rva = 0x454a40
offset = rva_to_file_offset(sections, shuffle_rva)
print(f"\nshuffle RVA 0x{shuffle_rva:x} -> file offset 0x{offset:x}")
if offset:
    data = pe_data[offset:offset+64]
    print(f"First 64 bytes: {data.hex()}")
