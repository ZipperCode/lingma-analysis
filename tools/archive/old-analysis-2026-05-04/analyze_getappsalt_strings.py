"""
静态分析 getAppSalt 函数内部引用的字符串。
通过分析函数代码中对 .rdata 区域的引用来提取 salt 值。
"""
import struct
import os

LINGMA_EXE = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def rva_to_file_offset(rva, sections):
    """Convert RVA to file offset using section headers."""
    for name, vaddr, raw_size, raw_ptr, _, _ in sections:
        if vaddr <= rva < vaddr + raw_size:
            return raw_ptr + (rva - vaddr)
    return None

def read_rva(rva, size, sections, data):
    """Read data at a given RVA."""
    offset = rva_to_file_offset(rva, sections)
    if offset is None:
        return None
    return data[offset:offset + size]

def parse_sections(pe_data):
    """Parse PE section headers."""
    dos_header = struct.unpack('<H', pe_data[:2])[0]
    if dos_header != 0x5A4D:
        raise ValueError("Not a PE file")

    nt_header_offset = struct.unpack('<I', pe_data[0x3C:0x40])[0]
    # COFF header starts at nt_header_offset + 4 (skip signature)
    coff_offset = nt_header_offset + 4
    num_sections = struct.unpack('<H', pe_data[coff_offset + 2:coff_offset + 4])[0]
    size_of_optional_header = struct.unpack('<H', pe_data[coff_offset + 16:coff_offset + 18])[0]
    sections_offset = coff_offset + 20 + size_of_optional_header
    sections = []
    for i in range(num_sections):
        sec = sections_offset + i * 40
        name = pe_data[sec:sec + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        vaddr = struct.unpack('<I', pe_data[sec + 12:sec + 16])[0]
        raw_size = struct.unpack('<I', pe_data[sec + 16:sec + 20])[0]
        raw_ptr = struct.unpack('<I', pe_data[sec + 20:sec + 24])[0]
        sections.append((name, vaddr, raw_size, raw_ptr, sec, i))
    return sections

def find_string_references_in_function(sections, data, func_rva, func_size):
    """Find all string references in a function by looking for MOV reg, imm64 patterns
    that point to .rdata or .rodata sections."""

    func_offset = rva_to_file_offset(func_rva, sections)
    if func_offset is None:
        print(f"Cannot find file offset for RVA {hex(func_rva)}")
        return []

    code = data[func_offset:func_offset + func_size]

    # Find .rdata section range
    rdata_ranges = []
    for name, vaddr, raw_size, raw_ptr, _, _ in sections:
        if name in ('.rdata', '.rodata'):
            rdata_ranges.append((vaddr, vaddr + raw_size))

    print(f"Function at RVA {hex(func_rva)}, size {func_size}")
    print(f"File offset: {hex(func_offset)}")
    print(f"Looking for references to: {rdata_ranges}")

    strings_found = []

    # Disassemble manually looking for LEA/MOV with immediate values pointing to .rdata
    # x86-64 instructions that load addresses:
    # LEA reg, [rip + disp32] -> 48 8D xx xx xx xx xx
    # MOV reg, imm64 -> 48 B8 xx xx xx xx xx xx xx xx
    # CMP reg, imm32 -> 48 3D xx xx xx xx
    # etc.

    i = 0
    while i < len(code) - 4:
        # Look for LEA with RIP-relative addressing: 48 8D xx [disp32]
        if code[i] == 0x48 and code[i + 1] == 0x8D:
            modrm = code[i + 2]
            # modrm: mod=00, reg=r/m=05 means [rip + disp32]
            if (modrm & 0xC7) == 0x05:  # mod=00, r/m=101
                disp = struct.unpack('<i', code[i + 3:i + 7])[0]
                # RIP-relative: address = rip + disp (rip = next instruction)
                rip = func_rva + i + 7
                target = rip + disp
                # Check if target is in .rdata
                for start, end in rdata_ranges:
                    if start <= target < end:
                        # Try to read string at target
                        offset = rva_to_file_offset(target, sections)
                        if offset is not None:
                            try:
                                end_idx = data.index(b'\x00', offset, offset + 256)
                                s = data[offset:end_idx].decode('utf-8', errors='replace')
                                if len(s) > 1 and s.isprintable():
                                    strings_found.append((i, hex(func_rva + i), hex(target), s))
                            except:
                                pass
                        break
            i += 1
            continue

        # Look for MOV r64, imm64: 48 B8/B9/BA/BB/BC/BD/BE/BF
        if code[i] == 0x48 and 0xB8 <= code[i + 1] <= 0xBF:
            imm64 = struct.unpack('<Q', code[i + 2:i + 10])[0]
            target = imm64 & 0xFFFFFFFF  # Could be full 64-bit address
            if target > 0x10000:  # Likely an address
                for start, end in rdata_ranges:
                    if start <= target < end:
                        offset = rva_to_file_offset(target, sections)
                        if offset is not None:
                            try:
                                end_idx = data.index(b'\x00', offset, offset + 256)
                                s = data[offset:end_idx].decode('utf-8', errors='replace')
                                if len(s) > 1 and s.isprintable():
                                    strings_found.append((i, hex(func_rva + i), hex(target), s))
                            except:
                                pass
                        break
                # Also try as 64-bit address
                if imm64 > 0x140000000:
                    for start, end in rdata_ranges:
                        if start <= imm64 < end:
                            offset = rva_to_file_offset(imm64, sections)
                            if offset is not None:
                                try:
                                    end_idx = data.index(b'\x00', offset, offset + 256)
                                    s = data[offset:end_idx].decode('utf-8', errors='replace')
                                    if len(s) > 1 and s.isprintable():
                                        strings_found.append((i, hex(func_rva + i), hex(imm64), s))
                                except:
                                    pass
                            break
            i += 10
            continue

        # Look for CALL with RIP-relative: E8 disp32
        if code[i] == 0xE8:
            disp = struct.unpack('<i', code[i + 1:i + 5])[0]
            rip = func_rva + i + 5
            target = rip + disp
            # Don't resolve call targets for now, just note them
            i += 5
            continue

        i += 1

    return strings_found

def main():
    with open(LINGMA_EXE, 'rb') as f:
        data = f.read()

    sections = parse_sections(data)
    print("Sections:")
    for name, vaddr, raw_size, raw_ptr, _, _ in sections:
        print(f"  {name:12s} VA={hex(vaddr):12s} size={hex(raw_size):8s} raw={hex(raw_ptr):8s}")

    # getAppSalt info
    getAppSalt_rva = 0x882760
    getAppSalt_size = 1087

    print(f"\n=== Analyzing getAppSalt at RVA {hex(getAppSalt_rva)} ===\n")

    strings = find_string_references_in_function(sections, data, getAppSalt_rva, getAppSalt_size)

    print(f"\nFound {len(strings)} string references in getAppSalt:")
    for offset, rva, target, s in strings:
        print(f"  +{offset:4d} ({rva}): -> {target} = \"{s}\"")

    # Also analyze related functions
    related = [
        (0x882680, 203, "addBigModelSignatureHeaders"),
        (0x882ba0, 207, "addBigModelAuthorizationHeaders"),
        (0x882c80, 442, "trimQueryPath"),
    ]

    for rva, size, name in related:
        print(f"\n=== Analyzing {name} at RVA {hex(rva)} ===\n")
        strings = find_string_references_in_function(sections, data, rva, size)
        print(f"Found {len(strings)} string references:")
        for offset, addr_rva, target, s in strings:
            print(f"  +{offset:4d} ({addr_rva}): -> {target} = \"{s}\"")

if __name__ == '__main__':
    main()
