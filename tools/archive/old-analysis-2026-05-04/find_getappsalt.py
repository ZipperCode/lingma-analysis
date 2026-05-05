"""
使用 moduledata 的 pclntab 指针 (RVA 0x3a57ac0) 来解析 Go 函数表
并找到 getAppSalt 的代码地址
"""
import struct
import mmap

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

# Section info from parse_pclntab.py
SECTIONS = {
    '.text': {'va': 0x1000, 'size': 0x1f3f246, 'raw': 0x400},
    '.rdata': {'va': 0x1f41000, 'size': 0x3cfc250, 'raw': 0x1f3f800},
    '.data': {'va': 0x5c3e000, 'size': 0x518d80, 'raw': 0x5c3bc00},
    '.pdata': {'va': 0x6157000, 'size': 0x973ec, 'raw': 0x60a6400},
}

def rva_to_file(rva):
    """Convert RVA to file offset"""
    for name, sec in SECTIONS.items():
        if sec['va'] <= rva < sec['va'] + sec['size']:
            return sec['raw'] + (rva - sec['va']), name
    return None, None

def file_to_rva(file_offset):
    """Convert file offset to RVA"""
    for name, sec in SECTIONS.items():
        if sec['raw'] <= file_offset < sec['raw'] + sec['size']:
            return sec['va'] + (file_offset - sec['raw'])
    return None

def read_ptr(mm, offset):
    """Read 8-byte pointer"""
    return struct.unpack('<Q', mm[offset:offset+8])[0]

def main():
    with open(BINARY_PATH, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    # pclntab pointer from moduledata: RVA 0x3a57ac0
    pclntab_rva = 0x3a57ac0
    pclntab_file, pclntab_section = rva_to_file(pclntab_rva)
    print(f"pclntab pointer: RVA 0x{pclntab_rva:x}, file offset 0x{pclntab_file:x}, section {pclntab_section}")

    # Read the pclntab header
    # For Go 1.18+, the header starts at the _FuncTab struct:
    #   entry: pointer to function table (array of funcInfo)
    #   ...

    # Actually, Go's runtime.pclntab is accessed via moduledata.pclntab
    # which points to a struct with:
    #   magic uint32
    #   pad byte
    #   ptrsize byte
    #   nfunc uint
    #   functions []funcInfo

    # The magic should be at the pclntab pointer location
    header = mm[pclntab_file:pclntab_file+20]
    magic = struct.unpack('<I', header[:4])[0]
    print(f"Magic at pclntab: 0x{magic:x}")

    if magic == 0xFFFFFFF1:
        print("  -> Go 1.20+ pclntab (little-endian)")
    elif magic == 0xFFFFFFFB:
        print("  -> Go 1.2- pclntab")
    elif magic == 0xFFFFFFFA:
        print("  -> Go 1.16 pclntab")
    elif magic == 0xFFFFFFFF:
        print("  -> Go 1.15- pclntab")
    else:
        print(f"  -> Unknown magic 0x{magic:x}")
        print(f"  First 20 bytes: {header.hex()}")

        # Maybe the pclntab pointer doesn't point to the magic directly
        # In newer Go versions, the structure might be different
        # Let's look at what the pointer actually references

        # The pclntab might be a pointer to the moduledata's internal pclntab struct
        # which is different from the _FuncTab

        # Let's try to find the actual pclntab by searching for magic bytes
        print("\nSearching for pclntab magic bytes in entire binary...")
        for magic_val, name in [(0xFFFFFFF1, "Go 1.20+"), (0xFFFFFFFB, "Go 1.2-"),
                                 (0xFFFFFFFA, "Go 1.16"), (0xFFFFFFFF, "Go 1.15-")]:
            magic_bytes = struct.pack('<I', magic_val)
            pos = 0
            while True:
                idx = mm.find(magic_bytes, pos)
                if idx < 0:
                    break
                # Verify it's a real pclntab header
                if idx + 14 < len(mm):
                    ptrsize = mm[idx+5]
                    nfunc = struct.unpack('<I', mm[idx+6:idx+10])[0]
                    if ptrsize in [4, 8] and 0 < nfunc < 200000:
                        print(f"  Found {name} magic at file offset 0x{idx:x}")
                        print(f"    ptrsize={ptrsize}, nfunc={nfunc}")
                        pos = idx + 4
                    else:
                        pos = idx + 4
                else:
                    break

    # ===== Alternative approach: parse .pdata (Windows function table) =====
    print("\n\n===== Parsing .pdata (RUNTIME_FUNCTION entries) =====")
    pdata = SECTIONS['.pdata']
    pdata_raw = pdata['raw']
    pdata_size = pdata['size']

    num_funcs = pdata_size // 12  # Each RUNTIME_FUNCTION is 12 bytes
    print(f".pdata: {num_funcs} RUNTIME_FUNCTION entries")

    # Get all function addresses
    func_list = []
    for i in range(num_funcs):
        offset = pdata_raw + i * 12
        begin = struct.unpack('<I', mm[offset:offset+4])[0]
        end = struct.unpack('<I', mm[offset+4:offset+8])[0]
        if begin != 0 and end > begin:
            # Verify it's in .text
            if SECTIONS['.text']['va'] <= begin < SECTIONS['.text']['va'] + SECTIONS['.text']['size']:
                func_list.append((begin, end))

    print(f"Valid functions in .text: {len(func_list)}")

    # Now we need to find which of these functions is getAppSalt
    # getAppSalt is a small function that likely returns a string
    # It's in the cosy/remoting package

    # Let's find small functions (1-32 bytes)
    small_funcs = [(begin, end) for begin, end in func_list if end - begin <= 32]
    print(f"Small functions (<=32 bytes): {len(small_funcs)}")

    # getAppSalt is likely called by addBigModelSignatureHeaders
    # Both are in cosy/remoting, so they should be near each other

    # Let's search for functions near trimQueryPath (0x882c80)
    # trimQueryPath is at RVA 0x882c80 (within .text)
    trim_rva = 0x882c80

    nearby = [(begin, end) for begin, end in small_funcs
              if abs(begin - trim_rva) < 0x100000]
    print(f"Small functions near trimQueryPath (within 1MB): {len(nearby)}")

    nearby.sort(key=lambda x: abs(x[0] - trim_rva))
    for begin, end in nearby[:30]:
        size = end - begin
        func_code = mm[SECTIONS['.text']['raw'] + (begin - SECTIONS['.text']['va']):
                        SECTIONS['.text']['raw'] + (begin - SECTIONS['.text']['va']) + size]
        # Check if it returns a string (has RET and references .rdata)
        has_ret = 0xC3 in func_code
        refs_rdata = False
        for j in range(len(func_code) - 4):
            val = struct.unpack('<I', func_code[j:j+4])[0]
            # Check if any immediate value could be an .rdata reference
            if SECTIONS['.rdata']['va'] <= val < SECTIONS['.rdata']['va'] + SECTIONS['.rdata']['size']:
                refs_rdata = True
                break

        if has_ret:
            code_hex = func_code[:32].hex()
            print(f"  RVA 0x{begin:x} (size={size}) RET={has_ret} rdata_ref={refs_rdata}: {code_hex}")

    # ===== Search for getAppSalt in function names =====
    # We know getAppSalt name is at file offset 0x3b9dbba (RVA 0x3b9f3ba)
    # In Go's pclntab, function names are stored in a name table
    # The funcInfo structure has a nameOff field that's an offset into this table

    # Let's search for the name table and map function addresses to names
    print(f"\n\n===== Searching for function name mapping =====")

    # The funcnametab is a table of name offsets
    # It's typically stored near the pclntab or in .rdata
    # Let's find all references to getAppSalt's name string

    getAppSalt_name_file = 0x3b9dbba
    getAppSalt_name_rva = 0x3b9f3ba

    print(f"getAppSalt name at: file 0x{getAppSalt_name_file:x}, RVA 0x{getAppSalt_name_rva:x}")

    # Search .text for references to this name string
    text = SECTIONS['.text']
    text_data = mm[text['raw']:text['raw'] + text['size']]

    # Search for LEA instructions that reference this .rdata address
    # LEA RAX, [RIP + disp32] where target = RIP + disp32 = getAppSalt_name_rva
    # disp32 = getAppSalt_name_rva - RIP

    ref_count = 0
    for i in range(0, min(len(text_data) - 7, 0x2000000), 1):  # Search first 32MB of .text
        # Check for LEA with RIP-relative addressing
        # 48 8D 05 [disp32] = LEA RAX, [RIP+disp32]
        if text_data[i] == 0x48 and text_data[i+1] == 0x8D and text_data[i+2] == 0x05:
            disp = struct.unpack('<i', text_data[i+3:i+7])[0]
            rip = text['va'] + i + 7  # RIP points to next instruction
            target = rip + disp
            if target == getAppSalt_name_rva:
                func_rva = text['va'] + i
                print(f"  Found reference at RVA 0x{func_rva:x} (file 0x{text['raw'] + i:x})")
                print(f"    LEA RAX, [RIP+0x{disp:x}] -> target 0x{target:x}")
                ref_count += 1
        elif text_data[i] == 0x48 and text_data[i+1] == 0x8D:
            # 48 8D XX [disp32] where XX is any register
            if text_data[i+2] < 0x40:  # Valid ModR/M
                disp = struct.unpack('<i', text_data[i+3:i+7])[0]
                rip = text['va'] + i + 7
                target = rip + disp
                if target == getAppSalt_name_rva:
                    reg = text_data[i+2]
                    func_rva = text['va'] + i
                    print(f"  Found reference at RVA 0x{func_rva:x}: LEA REG{reg}, [RIP+0x{disp:x}]")
                    ref_count += 1

    if ref_count == 0:
        print(f"  No direct references found to getAppSalt name string")
        print(f"  This suggests the name is only in pclntab, not in code")

    mm.close()

if __name__ == '__main__':
    main()
