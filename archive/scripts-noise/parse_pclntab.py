"""
解析 pclntab 来找到 getAppSalt 的代码地址
使用已知的 pclntab magic 位置 (0x88961) 作为起点
"""
import struct
import mmap

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def main():
    with open(BINARY_PATH, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    # Known pclntab magic at 0x88961
    magic_offset = 0x88961

    # Read the magic and header
    header_data = mm[magic_offset:magic_offset+50]
    print(f"pclntab header at file offset 0x{magic_offset:x}:")
    print(f"  Magic bytes: {header_data[:4].hex()}")
    print(f"  Full 50 bytes: {header_data.hex()}")

    # Parse Go pclntab header
    # For Go 1.16+:
    #   magic: 4 bytes (0xFFFFFFF1 for little-endian)
    #   pad: 1 byte (0x00)
    #   ptrsize: 1 byte (4 or 8)
    #   nfunc: 4 bytes (little-endian, number of functions)
    #   nfiles: 4 bytes (number of source files)
    magic = struct.unpack('<I', header_data[:4])[0]
    print(f"\nParsed header:")
    print(f"  magic: 0x{magic:x}")

    if magic in [0xFFFFFFF1, 0xFFFFFFFA, 0xFFFFFFFF]:
        print(f"  Valid Go pclntab magic!")
        ptrsize = header_data[5]
        nfunc = struct.unpack('<I', header_data[6:10])[0]
        nfiles = struct.unpack('<I', header_data[10:14])[0]
        print(f"  ptrsize: {ptrsize}")
        print(f"  nfunc: {nfunc}")
        print(f"  nfiles: {nfiles}")

        if ptrsize in [4, 8] and nfunc > 0 and nfunc < 200000:
            print(f"  *** VALID pclntab! ***")

            # The pclntab is at this offset
            pclntab_base = magic_offset
            funcname_offset = pclntab_base + 14  # After header

            # Function names table starts after the header
            # Format: [funcnameoff (4 bytes)][funcnameoff (4 bytes)]...
            # The actual names are at offsets from the pclntab base

            # Search for getAppSalt name offset
            # We found getAppSalt name at file offset 0x3b9dbba
            # But this is the absolute file offset, we need to find
            # what the pclntab offset to this is

            # Actually, the funcnametab is a separate table
            # Let's find all function entries

            # For now, let's just search for all function names
            # that are in the cosy/remoting package

            print(f"\n\nSearching for cosy/remoting function names...")
            # Search for the string "cosy/remoting" followed by a function name
            search = b'cosy/remoting'
            pos = 0
            count = 0
            while count < 100:
                idx = mm.find(search, pos)
                if idx < 0:
                    break
                # Get the full function name
                end = idx
                while end < len(mm) and mm[end] != 0:
                    end += 1
                func_name = mm[idx:end].decode('ascii', errors='replace')
                print(f"  0x{idx:x}: {func_name}")
                pos = idx + 1
                count += 1

            # Now let's find the pclntab function table
            # The function table (funcdata) is right after the header
            # Each entry is:
            #   entry (8 bytes for 64-bit): function entry point offset
            #   nameOff (4 bytes): offset to function name in funcnametab
            #   ... more fields

            # This is getting complex. Let's try a simpler approach:
            # Find the moduledata which has a pointer to pclntab

    else:
        print(f"  Not a standard Go pclntab magic")

        # Let's check what this really is
        # It might be inside a function, not the pclntab header
        print(f"\nLet's search more carefully...")

    # ===== Alternative: Search for moduledata =====
    # moduledata is in the .data section and contains pclntab pointer
    # Let's find .data section first
    print("\n\n===== Searching for moduledata =====")

    # We know from previous analysis that moduledata is at .data offset 0x162e0
    # with pclntab pointer at 0x143a57ae8

    # Let's verify by reading .data
    # First, parse PE headers to find .data section
    dos_header = mm[0:2]
    if dos_header != b'MZ':
        print("Not a valid PE file")
        return

    e_lfanew = struct.unpack('<I', mm[60:64])[0]
    print(f"PE header at 0x{e_lfanew:x}")

    # Optional header
    optional_header = e_lfanew + 24
    image_base = struct.unpack('<Q', mm[optional_header+24:optional_header+32])[0]
    print(f"Image base: 0x{image_base:x}")

    # Section headers start after optional header
    num_sections = struct.unpack('<H', mm[e_lfanew + 6:e_lfanew + 8])[0]
    optional_header_size = struct.unpack('<H', mm[e_lfanew + 20:e_lfanew + 22])[0]
    section_header_start = e_lfanew + 24 + optional_header_size

    print(f"Number of sections: {num_sections}")

    sections = {}
    for i in range(num_sections):
        offset = section_header_start + i * 40
        name = mm[offset:offset+8].decode('ascii', errors='replace').rstrip('\x00')
        virt_size = struct.unpack('<I', mm[offset+8:offset+12])[0]
        virt_addr = struct.unpack('<I', mm[offset+12:offset+16])[0]
        raw_size = struct.unpack('<I', mm[offset+16:offset+20])[0]
        raw_addr = struct.unpack('<I', mm[offset+20:offset+24])[0]
        sections[name] = {
            'virt_size': virt_size,
            'virt_addr': virt_addr,
            'raw_size': raw_size,
            'raw_addr': raw_addr,
        }
        print(f"  {name}: VA=0x{virt_addr:x}, size=0x{virt_size:x}, raw=0x{raw_addr:x}")

    # moduledata should be in .data section
    if '.data' in sections:
        data_section = sections['.data']
        data_start = data_section['raw_addr']
        data_size = data_section['raw_size']

        print(f"\n.data section: file offset 0x{data_start:x}, size 0x{data_size:x}")

        # Previous analysis found moduledata at .data + 0x162e0
        moduledata_offset = data_start + 0x162e0
        print(f"Known moduledata at file offset 0x{moduledata_offset:x}")

        # Read surrounding pointers
        data = mm[moduledata_offset - 0x10:moduledata_offset + 0x200]
        print(f"\nModuledata context:")
        for i in range(0, len(data), 8):
            val = struct.unpack('<Q', data[i:i+8])[0]
            if val > 0x140000000 and val < 0x144000000:
                file_offset = val - image_base  # Rough RVA
                print(f"  +0x{i:3x}: 0x{val:x} (RVA ~0x{file_offset:x}) <-- pointer")

        # The pclntab pointer should be at a known offset in moduledata
        # moduledata structure (Go 1.23):
        #   pclntab: *moduledata
        #   ftab:    funcTab
        #   ...

        # Let's just search the entire .data section for pointers to .rdata
        # (function names are in .rdata)
        rdata = sections.get('.rdata', {})
        rdata_va = rdata.get('virt_addr', 0)
        rdata_end = rdata_va + rdata.get('virt_size', 0)

        print(f"\n.rdata VA range: 0x{rdata_va:x} - 0x{rdata_end:x}")

    # ===== Direct approach: find function by name string =====
    # We know getAppSalt name is at 0x3b9dbba
    # Let's find what code references this
    print(f"\n\n===== Finding code that references getAppSalt name =====")
    getAppSalt_name_offset = 0x3b9dbba

    # In Go's pclntab, the function name offset is stored relative to
    # the funcnametab base. The funcnametab itself is referenced from
    # the pclntab header or moduledata.

    # Let's try to find all pclntab-like structures
    # that point to getAppSalt's name string

    # Actually, let's try the simplest approach:
    # Brute force search for all references to getAppSalt name offset
    text = sections.get('.text', {})
    text_va = text.get('virt_addr', 0)
    text_raw = text.get('raw_addr', 0)
    text_size = text.get('virt_size', 0)

    # The getAppSalt name is at .rdata RVA 0x3b9dbba
    # But wait, 0x3b9dbba is a file offset, not an RVA
    # Let me convert it to an RVA
    # We need to find which section contains 0x3b9dbba

    print(f"\nFile offset 0x{getAppSalt_name_offset:x} is in which section?")
    for name, info in sections.items():
        raw_start = info['raw_addr']
        raw_end = raw_start + info['raw_size']
        if raw_start <= getAppSalt_name_offset < raw_end:
            rva = info['virt_addr'] + (getAppSalt_name_offset - raw_start)
            va = image_base + rva
            print(f"  In section {name}")
            print(f"  RVA: 0x{rva:x}")
            print(f"  VA: 0x{va:x}")
            break

    mm.close()

if __name__ == '__main__':
    main()
