"""
终极方案: 通过 .pdata 和函数名字表交叉引用找到 getAppSalt
1. 解析 .pdata 获取所有函数入口
2. 在函数体中搜索对函数名字符串的引用
3. 确定哪些函数属于 cosy/remoting
"""
import struct
import capstone

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def main():
    with open(LINGMA, 'rb') as f:
        data = f.read()

    # Parse PE headers
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    f = lambda o, s: data[o:o+s]

    num_sections = struct.unpack('<H', f(pe_offset + 4, 2))[0]
    opt_size = struct.unpack('<H', f(pe_offset + 20, 2))[0]

    sections = []
    sec_off = pe_offset + 24
    for i in range(num_sections):
        name = data[sec_off + i*40:sec_off + i*40 + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize = struct.unpack('<I', data[sec_off + i*40 + 8:sec_off + i*40 + 12])[0]
        vaddr = struct.unpack('<I', data[sec_off + i*40 + 12:sec_off + i*40 + 16])[0]
        raw_size = struct.unpack('<I', data[sec_off + i*40 + 16:sec_off + i*40 + 20])[0]
        raw_addr = struct.unpack('<I', data[sec_off + i*40 + 20:sec_off + i*40 + 24])[0]
        sections.append((name, vaddr, vsize, raw_addr, raw_size))

    text_sec = next(s for s in sections if s[0] == '.text')
    rdata_sec = next(s for s in sections if s[0] == '.rdata')
    pdata_sec = next(s for s in sections if s[0] == '.pdata')

    text_base, text_vsize, text_raw, _ = text_sec[1], text_sec[2], text_sec[3], text_sec[4]
    rdata_base, rdata_vsize, rdata_raw = rdata_sec[1], rdata_sec[2], rdata_sec[3]

    # Parse .pdata (RUNTIME_FUNCTION entries, 12 bytes each)
    pdata_raw_off = pdata_sec[3]
    pdata_raw_size = pdata_sec[4]
    num_rtf = pdata_raw_size // 12

    print(f".pdata: {num_rtf} RUNTIME_FUNCTION entries")

    # Parse all .pdata entries
    rtf_entries = []
    for i in range(num_rtf):
        off = pdata_raw_off + i * 12
        begin_addr = struct.unpack('<I', data[off:off+4])[0]
        end_addr = struct.unpack('<I', data[off+4:off+8])[0]
        unwind_data = struct.unpack('<I', data[off+8:off+12])[0]
        rtf_entries.append((begin_addr, end_addr, unwind_data))

    print(f"Parsed {len(rtf_entries)} entries")

    # Get all function name offsets from pclntab
    # Function names are at known positions
    func_names = []
    idx = 0
    search_region = data
    while True:
        idx = search_region.find(b'cosy/remoting.', idx)
        if idx < 0 or idx > 6*1024*1024:
            break
        end = search_region.find(b'\x00', idx)
        if end > 0:
            name = search_region[idx:end].decode('utf-8', errors='replace')
            if all(c.isprintable() for c in name) and '(' not in name.split('.')[-1]:
                func_names.append((idx, name))
            idx = end + 1
        else:
            break

    print(f"\nFound {len(func_names)} cosy/remoting function names")

    # Show them sorted
    for off, name in sorted(func_names, key=lambda x: x[1]):
        print(f"  name_off=0x{off:08x}  {name}")

    # Now we need to find which .pdata entries correspond to these functions
    # The challenge: function NAME is in .rdata but CODE is in .text
    # There's no direct pointer from name to code

    # Approach: For each function name, search nearby names to see if their
    # .pdata entries are adjacent, suggesting they're in the same package

    # Get the known code addresses
    known_funcs = {
        'trimQueryPath': 0x882c80,
        'getAuthSignature': 0x890140,
        'getAuthPayload': 0x890380,
    }

    print("\n=== Functions with known code addresses ===")
    for name, rva in known_funcs.items():
        # Find this name in the name table
        name_off = None
        for off, n in func_names:
            if n.endswith(name) or name in n:
                name_off = off
                break
        if name_off:
            print(f"  {name}: code_rva=0x{rva:x}, name_off=0x{name_off:x}")

    # Get the .pdata entry for trimQueryPath (known at 0x882c80)
    print("\n=== .pdata entry for trimQueryPath (0x882c80) ===")
    trim_rva = 0x882c80
    for i, (begin, end, uw) in enumerate(rtf_entries):
        if begin == trim_rva:
            print(f"  Entry #{i}: begin=0x{begin:x}, end=0x{end:x}, size={end-begin}")
            # Show adjacent entries
            for j in range(max(0, i-5), min(len(rtf_entries), i+5)):
                b, e, u = rtf_entries[j]
                print(f"  Entry #{j}: begin=0x{b:x}, end=0x{e:x}, size={e-b}")
            break
    else:
        print("  Not found!")

    # Now let's find functions adjacent to trimQueryPath
    # getAppSalt should be one of the nearby functions
    print("\n=== Functions near trimQueryPath ===")
    trim_idx = None
    for i, (begin, end, uw) in enumerate(rtf_entries):
        if begin == 0x882c80:
            trim_idx = i
            break

    if trim_idx:
        # Show 20 entries before and after
        for j in range(max(0, trim_idx - 20), min(len(rtf_entries), trim_idx + 20)):
            b, e, u = rtf_entries[j]
            # Disassemble first few bytes to see if it looks like a Go function
            file_off = 0x400 + b - 0x1000
            code = data[file_off:file_off + 16]
            hex_str = code.hex()
            # Check for Go prologue
            is_go = code[:3] == bytes([0x49, 0x3b, 0x66]) or code[:3] == bytes([0x4c, 0x8d, 0x64])
            marker = " <-- trimQueryPath" if j == trim_idx else ""
            print(f"  #{j:5d} 0x{b:07x}-0x{e:07x} ({e-b:5d}B) {'GO' if is_go else '??'} {hex_str[:24]}{marker}")

    # The strategy now: search for code that references the getAppSalt name string
    # In the remoting package, some function might reference getAppSalt's name
    # for logging or error messages

    print("\n=== Searching for code references to getAppSalt name ===")
    # The getAppSalt name string is at 0x3b9dba6
    # In Go code, this string would be referenced via a LEA instruction
    # LEA reg, [RIP + disp32] where disp32 points to the string

    # The string VA is: string_file_off - rdata_raw + rdata_base + ImageBase
    # = 0x3b9dba6 - 0x1f3f800 + 0x1f41000 + 0x140000000
    # = 0x143b9f3a6

    string_rva = 0x3b9dba6 - rdata_raw + rdata_base
    string_va = 0x140000000 + string_rva
    print(f"getAppSalt string VA: 0x{string_va:x}")
    print(f"getAppSalt string RVA: 0x{string_rva:x}")

    # Search ALL code for LEA instructions that reference this VA
    # LEA with RIP-relative: 48 8d XX YY YY YY YY
    # target = RIP + 7 + disp32

    # This is slow for the whole binary, so let's narrow the search
    # to the remoting package region (around trimQueryPath)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    # Search within +/- 0x20000 of trimQueryPath
    search_start = max(0x1000, 0x882c80 - 0x30000)
    search_end = 0x882c80 + 0x30000

    text_data = data[0x400 + search_start - 0x1000:0x400 + search_end - 0x1000]

    found_refs = []
    for i in range(len(text_data) - 7):
        # LEA r64, [RIP + disp32]: 48 8d XX [disp32]
        if text_data[i] == 0x48 and text_data[i+1] == 0x8d:
            disp32 = struct.unpack('<i', text_data[i+3:i+7])[0]
            target_rva = (search_start + i + 7 + disp32)
            # Check if this points to the getAppSalt string
            if target_rva == string_rva:
                found_refs.append(search_start + i)

    print(f"Found {len(found_refs)} code references to getAppSalt string")
    for ref in found_refs:
        print(f"  Code at 0x{ref:x}")
        # Disassemble the function containing this reference
        # Find the function start by looking for the function prologue
        func_start = ref
        while func_start > search_start:
            file_off = 0x400 + func_start - 0x1000
            code = data[file_off:file_off+3]
            if code == bytes([0x49, 0x3b, 0x66]) or code == bytes([0x4c, 0x8d, 0x64]):
                break
            func_start -= 1
        print(f"  Function starts at: 0x{func_start:x}")

        # Disassemble
        func_data = data[0x400 + func_start - 0x1000:0x400 + func_start - 0x1000 + 200]
        for (addr, size, mnemonic, op_str) in md.disasm_lite(func_data, func_start):
            if size == 0:
                break
            print(f"    0x{addr:x}: {mnemonic} {op_str}")
            if addr > func_start + 200:
                break

    if not found_refs:
        print("No direct code references found. The function name may only be in pclntab.")

if __name__ == '__main__':
    main()
