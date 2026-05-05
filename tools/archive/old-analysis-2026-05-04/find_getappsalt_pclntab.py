"""
简化版: 直接搜索二进制文件中的函数名和代码引用
"""
import struct

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def main():
    with open(LINGMA, 'rb') as f:
        data = f.read(100 * 1024 * 1024)

    # Step 1: Find all cosy/remoting function names
    print("=== cosy/remoting functions ===")
    idx = 0
    found_funcs = []
    while True:
        idx = data.find(b'cosy/remoting.', idx)
        if idx < 0 or idx > 100 * 1024 * 1024:
            break
        end = data.find(b'\x00', idx)
        if end >= 0:
            name = data[idx:end].decode('utf-8', errors='replace')
            # Verify it looks like a function name
            if any(c.isalpha() for c in name) and '(' not in name:
                found_funcs.append((idx, name))
                print(f"  file_offset=0x{idx:08x}  name={name}")
            idx = end + 1
        else:
            break

    print(f"\nTotal cosy/remoting functions: {len(found_funcs)}")

    # Step 2: For getAppSalt specifically
    print("\n=== getAppSalt analysis ===")
    appsalt_names = [(off, name) for off, name in found_funcs if 'getAppSalt' in name]
    if appsalt_names:
        off, name = appsalt_names[0]
        print(f"getAppSalt name at file offset: 0x{off:x}")

        # In Go pclntab, the name offset is: off - funcnametable_base
        # And the funcInfo has both nameOff and entryOff (relative offsets)

        # Let's look at the context around this name string
        # Go pclntab name table: null-terminated strings packed together
        # Show surrounding function names
        print("\nSurrounding function names:")
        start = max(0, off - 200)
        end = min(len(data), off + 200)
        region = data[start:end]
        parts = region.split(b'\x00')
        for p in parts:
            if b'cosy/remoting' in p and len(p) > 10:
                pos = start + region.find(p)
                print(f"  0x{pos:08x}: {p.decode('utf-8', errors='replace')}")
    else:
        print("getAppSalt not found!")

    # Step 3: Find the pclntab funcnametable offset and search for getAppSalt's entry
    print("\n=== Pclntab approach ===")
    # We know from Go source that funcInfo structure contains:
    # - entryOff (int32): offset of function entry from text start
    # - nameOff (int32): offset of function name from funcnametable
    # These are in the _func table in pclntab

    # Search for the pattern: near the getAppSalt name, there should be a _func entry
    # containing the offset to the function code

    # Alternative: search for int32 values near getAppSalt name offset
    # that could be entryOff values

    # Let's try a different approach: find the .gopclntab section
    gopclntab_markers = [
        b'\xf0\xff\xff\xff',  # magic 0xFFFFFFF0 (Go 1.16+)
        b'\xf1\xff\xff\xff',  # magic 0xFFFFFFF1
        b'\xfb\xff\xff\xff',  # magic 0xFFFFFFFB
        b'\xfa\xff\xff\xff',  # magic 0xFFFFFFFA
    ]

    for marker in gopclntab_markers:
        idx = data.find(marker)
        if idx >= 0:
            # Check if this looks like pclntab (followed by valid quantum/ptr_size)
            quantum = data[idx + 6]
            ptr_size = data[idx + 7]
            if quantum in (1, 2, 4) and ptr_size in (4, 8):
                print(f"pclntab header at file offset 0x{idx:x}")
                print(f"  magic: 0x{int.from_bytes(data[idx:idx+4], 'little'):08x}")
                print(f"  quantum: {quantum}, ptr_size: {ptr_size}")

                # Read nfunc
                nfunc = struct.unpack('<I', data[idx+8:idx+12])[0]
                print(f"  nfunc: {nfunc}")

                # In Go 1.18+:
                # +16: functions offset (ptr_size)
                # +16+ptr_size: funcNameOffset (ptr_size)
                if ptr_size == 8:
                    func_off = struct.unpack('<Q', data[idx+16:idx+24])[0]
                    name_off = struct.unpack('<Q', data[idx+24:idx+32])[0]
                else:
                    func_off = struct.unpack('<I', data[idx+16:idx+20])[0]
                    name_off = struct.unpack('<I', data[idx+20:idx+24])[0]

                print(f"  functions offset: 0x{func_off:x}")
                print(f"  funcNameOffset: 0x{name_off:x}")

                # The funcNameOffset is relative to pclntab base
                # So the name table is at: idx + name_off
                name_table_pos = idx + name_off
                print(f"  name table at file offset: 0x{name_table_pos:x}")

                # Search for getAppSalt in the name table
                # Read from name table to find getAppSalt name offset
                if name_table_pos < len(data):
                    name_table = data[name_table_pos:name_table_pos + 5000000]
                    gs_idx = name_table.find(b'cosy/remoting.getAppSalt')
                    if gs_idx >= 0:
                        # The offset of getAppSalt name relative to name table start
                        name_rel_offset = gs_idx
                        print(f"\n  getAppSalt in name table at relative offset: 0x{name_rel_offset:x}")

                        # Now we need to find the _func table entry that corresponds to this
                        # In Go 1.18+, _func entries are indexed by function index
                        # The nameOff is: name_table_start + name_relative_offset

                        # But actually, in newer Go, nameOff is the offset within the funcnametable
                        # So nameOff = name_relative_offset

                        # The func table stores _func structures sequentially
                        # Each _func has: entryOff (int32), nameOff (int32)

                        # Let's find the func table
                        func_table_pos = idx + func_off
                        print(f"  func table at file offset: 0x{func_table_pos:x}")

                        # Search for entries that reference getAppSalt's name offset
                        # This is tricky because we need to match nameOff to getAppSalt's position
                        # Let's dump some entries
                        print("\n  First 10 _func entries:")
                        fpos = func_table_pos
                        for i in range(10):
                            if fpos + 8 > len(data):
                                break
                            entry_off = struct.unpack('<i', data[fpos:fpos+4])[0]
                            name_off_entry = struct.unpack('<i', data[fpos+4:fpos+8])[0]
                            # Try to read the name
                            name_pos = idx + name_off_entry
                            if 0 <= name_pos < len(data):
                                name_end = data.find(b'\x00', name_pos)
                                if name_end > 0:
                                    name_str = data[name_pos:name_end].decode('utf-8', errors='replace')[:80]
                                    print(f"    [{i}] entryOff=0x{entry_off:x} nameOff=0x{name_off_entry:x} name={name_str}")
                            fpos += 8

                        # Now search ALL func entries for getAppSalt
                        print("\n  Searching for getAppSalt in func table...")
                        fpos = func_table_pos
                        for i in range(nfunc):
                            if fpos + 8 > len(data):
                                break
                            entry_off = struct.unpack('<i', data[fpos:fpos+4])[0]
                            name_off_entry = struct.unpack('<i', data[fpos+4:fpos+8])[0]

                            if name_off_entry == name_rel_offset:
                                entry_va = 0x140001000 + entry_off  # text base + entryOff
                                print(f"    FOUND! [{i}] entryOff=0x{entry_off:x} (file=0x{entry_off + 0x400:x})")
                                print(f"    Entry VA: 0x{entry_va:x}")
                                print(f"    Entry RVA from base: 0x{entry_va - 0x140000000:x}")
                                break

                            fpos += 8
                        else:
                            print("  Not found in func table - Go version format may differ")

                break

if __name__ == '__main__':
    main()
