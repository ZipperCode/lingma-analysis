# Analyze AesEncryptWithBase64 disassembly to understand key/IV derivation
# RVA 0x455da0 - AesEncryptWithBase64
# RVA 0x455800 - CustomEncryptV1
# RVA 0x456280 - pkcs5Padding
# RVA 0x454a40 - shuffle
# RVA 0x5be20  - newEncoding

import struct

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

def rva_to_offset(pe_data, rva):
    """Convert RVA to file offset"""
    # Parse PE headers
    dos_sig = struct.unpack('<H', pe_data[0:2])[0]
    if dos_sig != 0x5A4D:  # MZ
        raise ValueError("Not a PE file")

    e_lfanew = struct.unpack('<I', pe_data[60:64])[0]

    # NT Header
    nt_sig = struct.unpack('<I', pe_data[e_lfanew:e_lfanew+4])[0]
    if nt_sig != 0x00004550:  # PE\0\0
        raise ValueError("Invalid PE signature")

    # Optional Header
    opt_header_offset = e_lfanew + 24
    opt_header = pe_data[opt_header_offset:opt_header_offset+224]
    magic = struct.unpack('<H', opt_header[0:2])[0]

    if magic == 0x20B:  # PE32+
        num_sections = struct.unpack('<H', opt_header[2:4])[0]
        opt_size = struct.unpack('<H', opt_header[16:18])[0]
        section_offset = e_lfanew + 24 + opt_size
    else:  # PE32
        num_sections = struct.unpack('<H', pe_data[opt_header_offset+6:opt_header_offset+8])[0]
        opt_size = struct.unpack('<H', pe_data[opt_header_offset+20:opt_header_offset+22])[0]
        section_offset = e_lfanew + 24 + opt_size

    # Section headers
    for i in range(num_sections):
        sec = pe_data[section_offset + i*40 : section_offset + (i+1)*40]
        sec_rva = struct.unpack('<I', sec[12:16])[0]
        sec_size = struct.unpack('<I', sec[16:20])[0]
        sec_offset = struct.unpack('<I', sec[20:24])[0]

        if sec_rva <= rva < sec_rva + sec_size:
            return sec_offset + (rva - sec_rva)

    return None

with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

def rva_to_bytes(rva, length):
    offset = rva_to_offset(pe_data, rva)
    if offset is None:
        return None
    return pe_data[offset:offset+length]

# List of functions to disassemble
functions = {
    'AesEncryptWithBase64': 0x455da0,
    'CustomEncryptV1': 0x455800,
    'pkcs5Padding': 0x456280,
    'shuffle': 0x454a40,
    'newEncoding': 0x5be20,
}

for name, rva in functions.items():
    print(f"\n{'='*80}")
    print(f"Function: {name} (RVA 0x{rva:x})")
    print(f"{'='*80}")

    # Get first 2000 bytes of function
    data = rva_to_bytes(rva, 2000)
    if data is None:
        print(f"  Could not find RVA 0x{rva:x}")
        continue

    # Simple x86-64 disassembly using capstone
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        # Go functions end with RET (0xC3)
        # Disassemble until we hit RET and the next instruction isn't padding
        instructions = []
        address = rva
        i = 0
        found_ret = False

        for insn in md.disasm(data, rva):
            instructions.append(f"  {insn.address:#010x}:  {insn.mnemonic:<8} {insn.op_str}")
            i += 1
            if insn.mnemonic == 'ret' and not found_ret:
                found_ret = True
                # Take a bit more to see if there's more code
                if i > 50:  # Reasonable function length
                    break
            if found_ret and i > 20:
                break
            if i > 500:  # Safety limit
                break

        print(f"\n  Total instructions: {len(instructions)}")
        print(f"\n  First 100 instructions:")
        for insn in instructions[:100]:
            print(insn)

        if len(instructions) > 100:
            print(f"\n  ... ({len(instructions) - 100} more instructions)")
            # Show the last 20 instructions (likely the RET)
            print(f"\n  Last 20 instructions:")
            for insn in instructions[-20:]:
                print(insn)

    except ImportError:
        print("  capstone not available, using raw bytes")
        # Show raw hex dump
        for i in range(0, min(500, len(data)), 16):
            hex_str = ' '.join(f'{b:02x}' for b in data[i:i+16])
            print(f"  {rva+i:#010x}: {hex_str}")
