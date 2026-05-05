import struct

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def rva_to_offset(pe_data, rva):
    """Convert RVA to file offset"""
    dos_sig = struct.unpack('<H', pe_data[0:2])[0]
    if dos_sig != 0x5A4D:
        raise ValueError("Not a PE file")

    e_lfanew = struct.unpack('<I', pe_data[60:64])[0]

    # Optional Header offset
    opt_header_offset = e_lfanew + 24
    magic = struct.unpack('<H', pe_data[opt_header_offset:opt_header_offset+2])[0]

    if magic == 0x20B:  # PE32+
        opt_size = struct.unpack('<H', pe_data[opt_header_offset+16:opt_header_offset+18])[0]
    else:
        opt_size = struct.unpack('<H', pe_data[opt_header_offset+20:opt_header_offset+22])[0]

    section_offset = e_lfanew + 24 + opt_size

    # Parse section count from FileHeader
    num_sections = struct.unpack('<H', pe_data[e_lfanew+6:e_lfanew+8])[0]

    print(f"  e_lfanew=0x{e_lfanew:x}, opt_size={opt_size}, section_offset=0x{section_offset:x}")
    print(f"  num_sections={num_sections}")

    for i in range(num_sections):
        sec = pe_data[section_offset + i*40 : section_offset + (i+1)*40]
        sec_name = sec[0:8].rstrip(b'\x00').decode('ascii', errors='replace')
        sec_rva = struct.unpack('<I', sec[12:16])[0]
        sec_size = struct.unpack('<I', sec[16:20])[0]
        sec_offset = struct.unpack('<I', sec[20:24])[0]

        if sec_rva <= rva < sec_rva + sec_size:
            file_offset = sec_offset + (rva - sec_rva)
            print(f"  Found section: {sec_name}, RVA range [0x{sec_rva:x}-0x{sec_rva+sec_size:x}), file offset=0x{file_offset:x}")
            return file_offset

    print(f"  No section found for RVA 0x{rva:x}")
    return None

with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

# Test with known functions
for name, rva in [('AesEncryptWithBase64', 0x455da0), ('shuffle', 0x454a40), ('newEncoding', 0x5be20)]:
    print(f"\nLooking up {name} (RVA 0x{rva:x}):")
    offset = rva_to_offset(pe_data, rva)
    if offset is not None:
        # Show first 64 bytes
        data = pe_data[offset:offset+64]
        print(f"  First 64 bytes: {data.hex()}")
