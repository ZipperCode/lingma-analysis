"""
直接定位 getAppSalt - 使用已知 pclntab 地址 0x3a8fd20
"""
import struct
import capstone

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

def rva_to_file(rva):
    return 0x400 + rva - 0x1000

def resolve_string(data, file_off):
    if 0 < file_off < len(data):
        end = data.find(b'\x00', file_off)
        if end > file_off and end - file_off < 500:
            return data[file_off:end].decode('utf-8', errors='replace')
    return None

def main():
    with open(LINGMA, 'rb') as f:
        data = f.read()

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    # Parse PE sections
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    num_sections = struct.unpack('<H', data[pe_offset + 4:pe_offset + 6])[0]
    sec_off = pe_offset + 24
    sections = {}
    for i in range(num_sections):
        name = data[sec_off + i*40:sec_off + i*40 + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        vaddr = struct.unpack('<I', data[sec_off + i*40 + 12:sec_off + i*40 + 16])[0]
        raw_addr = struct.unpack('<I', data[sec_off + i*40 + 20:sec_off + i*40 + 24])[0]
        raw_size = struct.unpack('<I', data[sec_off + i*40 + 16:sec_off + i*40 + 20])[0]
        sections[name] = (vaddr, raw_addr, raw_size)

    pdata_raw, pdata_size = sections['.pdata'][1], sections['.pdata'][2]

    # Known pclntab location
    PCLNTAB = 0x3a8fd20

    print(f"pclntab at 0x{PCLNTAB:x}")

    magic = struct.unpack('<I', data[PCLNTAB:PCLNTAB+4])[0]
    quantum = data[PCLNTAB + 6]
    ptr_size = data[PCLNTAB + 7]
    nfunc = struct.unpack('<I', data[PCLNTAB+8:PCLNTAB+12])[0]

    print(f"magic: 0x{magic:08x}, quantum: {quantum}, ptr_size: {ptr_size}")
    print(f"nfunc: {nfunc}")

    # Go 1.20+ pclntab header layout
    textStart = struct.unpack('<I', data[PCLNTAB+16:PCLNTAB+20])[0]
    funcnameOff = struct.unpack('<I', data[PCLNTAB+20:PCLNTAB+24])[0]
    cuOff = struct.unpack('<I', data[PCLNTAB+24:PCLNTAB+28])[0]
    funcInfoOff = struct.unpack('<I', data[PCLNTAB+28:PCLNTAB+32])[0]
    datapOff = struct.unpack('<I', data[PCLNTAB+32:PCLNTAB+36])[0]

    print(f"textStart: 0x{textStart:x}")
    print(f"funcnameOff: 0x{funcnameOff:x}")
    print(f"cuOff: 0x{cuOff:x}")
    print(f"funcInfoOff: 0x{funcInfoOff:x}")
    print(f"datapOff: 0x{datapOff:x}")

    funcname_table = PCLNTAB + funcnameOff
    funcInfo_table = PCLNTAB + funcInfoOff

    print(f"\nfuncname table at: 0x{funcname_table:x}")
    print(f"funcInfo table at: 0x{funcInfo_table:x}")

    # First, verify funcname_table by reading the first name
    first_name = resolve_string(data, funcname_table)
    print(f"First function name: {first_name[:80] if first_name else 'N/A'}")

    # Now search for getAppSalt in the funcInfo table
    print(f"\nSearching {nfunc} entries for getAppSalt...")
    fpos = funcInfo_table
    for i in range(nfunc):
        if fpos + 8 > len(data):
            break
        try:
            eOff = struct.unpack('<i', data[fpos:fpos+4])[0]
            nOff = struct.unpack('<i', data[fpos+4:fpos+8])[0]
        except:
            break

        # Validate entry
        if eOff < 0 or nOff < 0:
            fpos += 8
            continue

        name_pos = funcname_table + nOff
        if name_pos <= 0 or name_pos >= len(data):
            fpos += 8
            continue

        # Quick check without full decode
        if data[name_pos:name_pos+10].startswith(b'cosy/remot'):
            name = resolve_string(data, name_pos)
            if name and 'getAppSalt' in name:
                entry_rva = textStart + eOff
                print(f"\nFOUND! funcInfo entry {i}:")
                print(f"  name: {name}")
                print(f"  entryOff: 0x{eOff:x}")
                print(f"  RVA: 0x{entry_rva:x}")
                print(f"  VA: 0x{IMAGE_BASE + entry_rva:x}")

                # Disassemble
                code_file = 0x400 + entry_rva
                print(f"\nDisassembly:")
                for (addr, sz, mnemonic, op_str) in md.disasm_lite(data[code_file:code_file+300], IMAGE_BASE + entry_rva):
                    if sz == 0:
                        break
                    print(f"  0x{addr:010x}: {mnemonic:10s} {op_str}")
                break
        fpos += 8
    else:
        print("getAppSalt not found in funcInfo table!")

    # =========================================================
    # 方法2: 使用已知 trimQueryPath 地址反推
    # =========================================================
    print("\n\n=== 方法2: 从 trimQueryPath 反推 ===")

    trim_rva = 0x882c80  # Known trimQueryPath code address
    trim_entryOff = trim_rva - textStart
    print(f"trimQueryPath entryOff: 0x{trim_entryOff:x}")

    # Search funcInfo for trimQueryPath
    fpos = funcInfo_table
    for i in range(nfunc):
        if fpos + 8 > len(data):
            break
        try:
            eOff = struct.unpack('<i', data[fpos:fpos+4])[0]
            nOff = struct.unpack('<i', data[fpos+4:fpos+8])[0]
        except:
            break

        if eOff == trim_entryOff:
            name_pos = funcname_table + nOff
            name = resolve_string(data, name_pos)
            print(f"trimQueryPath found at funcInfo[{i}]: name='{name[:60]}'")

            # getAppSalt is at funcInfo[i-2] since it's 2 positions before trimQueryPath in name list
            # But we need to verify the ordering
            # Name list order: addBigModelSignatureHeaders[27], getAppSalt[28],
            #                  addBigModelAuthorizationHeaders[29], trimQueryPath[30]
            # funcInfo order might match name list order

            print(f"\nfuncInfo entries around [{i}]:")
            for j in range(max(0, i-5), min(nfunc, i+5)):
                jpos = funcInfo_table + j * 8
                jeOff = struct.unpack('<i', data[jpos:jpos+4])[0]
                jnOff = struct.unpack('<i', data[jpos+4:jpos+8])[0]
                jname_pos = funcname_table + jnOff
                jname = resolve_string(data, jname_pos) or "<invalid>"
                jrva = textStart + jeOff
                print(f"  [{j}] entryOff=0x{jeOff:x}(rva=0x{jrva:x}) -> {jname[:80]}")

            # The getAppSalt entry
            appsalt_idx = None
            # Check if funcInfo order matches name table order
            # i-2 should be getAppSalt if the ordering is consistent
            for offset in [-2, -1, -3, -4, -5]:
                test_idx = i + offset
                if test_idx < 0:
                    continue
                tpos = funcInfo_table + test_idx * 8
                teOff = struct.unpack('<i', data[tpos:tpos+4])[0]
                tnOff = struct.unpack('<i', data[tpos+4:tpos+8])[0]
                tname_pos = funcname_table + tnOff
                tname = resolve_string(data, tname_pos) or ""
                if 'getAppSalt' in tname:
                    appsalt_idx = test_idx
                    trva = textStart + teOff
                    print(f"\n*** getAppSalt at funcInfo[{appsalt_idx}] ***")
                    print(f"  entryOff=0x{teOff:x}, RVA=0x{trva:x}")
                    print(f"  VA=0x{IMAGE_BASE + trva:x}")

                    # Find .pdata entry for size
                    for pi in range(pdata_size // 12):
                        poff = pdata_raw + pi * 12
                        pbegin = struct.unpack('<I', data[poff:poff+4])[0]
                        pend = struct.unpack('<I', data[poff+4:poff+8])[0]
                        if pbegin == trva:
                            print(f"  .pdata#{pi}: size={pend - pbegin}")

                            # Full disassembly
                            code_file = 0x400 + trva
                            print(f"\n  Full disassembly:")
                            for (addr, sz, mnemonic, op_str) in md.disasm_lite(data[code_file:code_file + min(pend-pbegin, 500)], IMAGE_BASE + trva):
                                if sz == 0:
                                    break
                                print(f"    0x{addr:010x}: {mnemonic:10s} {op_str}")
                            break
                    break

            if appsalt_idx is None:
                print(f"\ngetAppSalt not found near funcInfo[{i}]")
                # Try a different approach - just show the name table order
                print("Trying name table matching approach...")

                # Collect ALL cosy/remoting names and their nameOffs
                func_names = []
                idx = 0
                while True:
                    idx = data.find(b'cosy/remoting.', idx)
                    if idx < 0 or idx > len(data) - 100:
                        break
                    end = data.find(b'\x00', idx)
                    if end > 0:
                        name = data[idx:end].decode('utf-8', errors='replace')
                        if all(c.isprintable() for c in name) and '(' not in name.split('.')[-1]:
                            nameOff = idx - funcname_table
                            func_names.append((nameOff, name, idx))
                        idx = end + 1
                    else:
                        break

                print(f"\nFound {len(func_names)} cosy/remoting function names")
                print(f"funcname_table at 0x{funcname_table:x}")

                # Get getAppSalt's nameOff
                appsalt_nameOff = None
                for noff, name, foff in func_names:
                    if 'getAppSalt' in name:
                        appsalt_nameOff = noff
                        print(f"getAppSalt nameOff: 0x{noff:x}")
                        break

                # Now search ALL funcInfo for this nameOff
                if appsalt_nameOff is not None:
                    print(f"\nSearching funcInfo for nameOff=0x{appsalt_nameOff:x}...")
                    fpos2 = funcInfo_table
                    for i2 in range(nfunc):
                        if fpos2 + 8 > len(data):
                            break
                        try:
                            eOff2 = struct.unpack('<i', data[fpos2:fpos2+4])[0]
                            nOff2 = struct.unpack('<i', data[fpos2+4:fpos2+8])[0]
                        except:
                            break

                        if nOff2 == appsalt_nameOff and eOff2 > 0:
                            entry_rva2 = textStart + eOff2
                            print(f"FOUND! funcInfo[{i2}]: entryOff=0x{eOff2:x}(rva=0x{entry_rva2:x})")
                            print(f"VA=0x{IMAGE_BASE + entry_rva2:x}")

                            # Disassemble
                            code_file = 0x400 + entry_rva2
                            print(f"\nDisassembly:")
                            for (addr, sz, mnemonic, op_str) in md.disasm_lite(data[code_file:code_file+300], IMAGE_BASE + entry_rva2):
                                if sz == 0:
                                    break
                                print(f"  0x{addr:010x}: {mnemonic:10s} {op_str}")
                            break
                        fpos2 += 8
                    else:
                        print("NOT FOUND - entry size may differ")
                        # Try with different entry sizes
                        for entry_size in [12, 16, 20, 24]:
                            print(f"\nTrying entry size {entry_size}...")
                            fpos3 = funcInfo_table
                            for i3 in range(min(nfunc, 1000)):
                                if fpos3 + entry_size > len(data):
                                    break
                                try:
                                    eOff3 = struct.unpack('<i', data[fpos3:fpos3+4])[0]
                                    nOff3 = struct.unpack('<i', data[fpos3+4:fpos3+8])[0]
                                except:
                                    break

                                if nOff3 == appsalt_nameOff and eOff3 > 0:
                                    entry_rva3 = textStart + eOff3
                                    print(f"FOUND with size {entry_size}! funcInfo[{i3}]: rva=0x{entry_rva3:x}")
                                    # Disassemble
                                    code_file = 0x400 + entry_rva3
                                    print(f"\nDisassembly:")
                                    for (addr, sz, mnemonic, op_str) in md.disasm_lite(data[code_file:code_file+300], IMAGE_BASE + entry_rva3):
                                        if sz == 0:
                                            break
                                        print(f"  0x{addr:010x}: {mnemonic:10s} {op_str}")
                                    break
                                fpos3 += entry_size
                            else:
                                continue
                            break

            break

        fpos += 8
    else:
        print("trimQueryPath not found in funcInfo table!")

if __name__ == '__main__':
    main()
