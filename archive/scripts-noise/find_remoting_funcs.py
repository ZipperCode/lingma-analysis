"""
系统性地查找所有 cosy/remoting 函数的代码地址
方法: 从 pclntab 中提取函数名到 entryOff 的映射
"""
import struct

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def main():
    with open(LINGMA, 'rb') as f:
        data = f.read(100*1024*1024)

    pclntab_off = 0x3a8fd20

    # Go 1.20+ pcHeader layout:
    # +0: magic (4)
    # +4: pad (2)
    # +6: quantum (1)
    # +7: ptr_size (1)
    # +8: nfunc (4)
    # +12: nfiles (4)
    # +16: textStart (4) - offset of first func text
    # +20: funcnameOffset (4) - offset to func name table
    # +24: cuOffset (4) - offset to compilation unit table
    # +28: funcInfoOffset (4) - offset to funcInfo (_func) table
    # +32: datapOffset (4) - offset to moduledata

    nfunc = struct.unpack('<I', data[pclntab_off+8:pclntab_off+12])[0]
    textStart = struct.unpack('<I', data[pclntab_off+16:pclntab_off+20])[0]
    funcnameOffset = struct.unpack('<I', data[pclntab_off+20:pclntab_off+24])[0]
    cuOffset = struct.unpack('<I', data[pclntab_off+24:pclntab_off+28])[0]
    funcInfoOffset = struct.unpack('<I', data[pclntab_off+28:pclntab_off+32])[0]
    datapOffset = struct.unpack('<I', data[pclntab_off+32:pclntab_off+36])[0]

    print(f'nfunc: {nfunc}')
    print(f'textStart: 0x{textStart:x}')
    print(f'funcnameOffset: 0x{funcnameOffset:x}')
    print(f'cuOffset: 0x{cuOffset:x}')
    print(f'funcInfoOffset: 0x{funcInfoOffset:x}')
    print(f'datapOffset: 0x{datapOffset:x}')

    # These are offsets FROM pclntab base
    funcname_table = pclntab_off + funcnameOffset
    funcInfo_table = pclntab_off + funcInfoOffset

    print(f'\nfuncname table at file offset: 0x{funcname_table:x}')
    print(f'funcInfo table at file offset: 0x{funcInfo_table:x}')

    # Verify funcname table
    sample = data[funcname_table:funcname_table+200]
    null_end = sample.find(b'\x00')
    print(f'funcname sample: {sample[:null_end] if null_end > 0 else sample[:30]}')

    # Find funcname table START by searching for first valid func name
    # The funcname table is at funcnameOffset from pclntab
    # All function names are packed here
    # Let's find getAppSalt's nameOff (relative offset within funcname table)
    gs_off = 0x3b9dba6
    gs_nameOff = gs_off - funcname_table
    print(f'\ngetAppSalt nameOff: 0x{gs_nameOff:x} ({gs_nameOff})')

    # Now parse the funcInfo (_func) table
    # In Go 1.20+, _func entries might not be simple sequential int32 pairs
    # Let's check the first few entries

    print(f'\n=== funcInfo table entries ===')
    pos = funcInfo_table

    # Try different entry sizes
    for entry_size in [8, 12, 16, 20, 24]:
        print(f'\nTrying entry size {entry_size}:')
        pos = funcInfo_table
        found_gs = False
        for i in range(min(nfunc, 200)):
            if pos + entry_size > len(data):
                break

            # For 8-byte entries: entryOff(4) + nameOff(4)
            if entry_size == 8:
                eOff = struct.unpack('<I', data[pos:pos+4])[0]
                nOff = struct.unpack('<I', data[pos+4:pos+8])[0]
            elif entry_size == 12:
                eOff = struct.unpack('<I', data[pos:pos+4])[0]
                nOff = struct.unpack('<I', data[pos+4:pos+8])[0]
            elif entry_size == 16:
                eOff = struct.unpack('<I', data[pos:pos+4])[0]
                nOff = struct.unpack('<I', data[pos+4:pos+8])[0]
            else:
                eOff = struct.unpack('<I', data[pos:pos+4])[0]
                nOff = struct.unpack('<I', data[pos+4:pos+8])[0]

            # Check if entryOff looks valid
            if eOff > 0x1000 and eOff < 0x2000000:
                # Resolve name
                name_pos = funcname_table + nOff
                if 0 <= name_pos < len(data):
                    name_end = data.find(b'\x00', name_pos)
                    if name_end > name_pos:
                        name = data[name_pos:name_end].decode('utf-8', errors='replace')
                        if 'getAppSalt' in name:
                            print(f'  *** FOUND getAppSalt at entry {i}! ***')
                            print(f'  pos: 0x{pos:x}, entryOff: 0x{eOff:x}, nameOff: 0x{nOff:x}')
                            entry_va = 0x140001000 + eOff
                            print(f'  Entry VA: 0x{entry_va:x}')
                            print(f'  Entry file offset: 0x{0x400 + eOff:x}')
                            found_gs = True

                        if i < 5:
                            print(f'  [{i}] entryOff=0x{eOff:x} nameOff=0x{nOff:x} -> {name[:80]}')

            pos += entry_size

        if not found_gs:
            if entry_size == 8:
                print(f'  (no getAppSalt found in first 200 entries)')

    # If none of the above work, let's try a completely different approach:
    # Search for int32 pairs (entryOff, nameOff) across the entire pclntab area
    print(f'\n=== Brute force search for getAppSalt _func entry ===')
    # nameOff should be gs_nameOff = getAppSalt_file_off - funcname_table
    target_nameOff = gs_nameOff
    print(f'Target nameOff: 0x{target_nameOff:x}')

    found = False
    for pos in range(pclntab_off, pclntab_off + 0x800000, 4):
        try:
            nameOff_val = struct.unpack('<I', data[pos+4:pos+8])[0]
            if nameOff_val == target_nameOff:
                entryOff = struct.unpack('<I', data[pos:pos+4])[0]
                if entryOff > 0x1000 and entryOff < 0x2000000:
                    print(f'FOUND at pos=0x{pos:x}: entryOff=0x{entryOff:x}')
                    entry_va = 0x140001000 + entryOff
                    print(f'  Entry VA: 0x{entry_va:x}')
                    entry_file = 0x400 + entryOff
                    print(f'  Entry file: 0x{entry_file:x}')
                    # Show code
                    code = data[entry_file:entry_file+16]
                    print(f'  Code: {code.hex()}')
                    found = True
                    break
        except:
            pass

    if not found:
        print('Not found with brute force either')
        # Try with signed int32
        print('Trying signed int32...')
        for pos in range(pclntab_off, pclntab_off + 0x800000, 4):
            try:
                nameOff_val = struct.unpack('<i', data[pos+4:pos+8])[0]
                if nameOff_val == target_nameOff:
                    entryOff = struct.unpack('<i', data[pos:pos+4])[0]
                    if entryOff > 0x1000 and entryOff < 0x2000000:
                        print(f'FOUND at pos=0x{pos:x}: entryOff=0x{entryOff:x}')
                        entry_va = 0x140001000 + entryOff
                        print(f'  Entry VA: 0x{entry_va:x}')
                        found = True
                        break
            except:
                pass

        if not found:
            print('Still not found. The pclntab format may be different.')
            # Let's dump some info about the funcInfo table area
            print(f'\nfuncInfo table content (first 128 bytes):')
            content = data[funcInfo_table:funcInfo_table+128]
            for i in range(0, 128, 16):
                hex_str = content[i:i+16].hex()
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in content[i:i+16])
                print(f'  +{i:04x}: {hex_str}  {ascii_str}')

if __name__ == '__main__':
    main()
