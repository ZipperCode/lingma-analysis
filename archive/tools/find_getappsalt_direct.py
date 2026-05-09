"""
直接方法: 找到引用 getAppSalt 名字的函数
方法: 在 .rdata 中 getAppSalt 字符串地址附近，查找哪些函数的代码引用了这个地址
"""
import struct
import capstone

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

def rva_to_file(rva):
    return 0x400 + rva - 0x1000

def file_to_rva(file_off):
    return file_off - 0x400 + 0x1000

def main():
    with open(LINGMA, 'rb') as f:
        data = f.read()

    # Parse PE
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

    rdata_base, rdata_raw, rdata_size = sections['.rdata']
    pdata_raw, pdata_size = sections['.pdata'][1:]

    # =========================================================
    # 方法1: 在 pclntab 名字表中找到 getAppSalt，然后在 funcInfo
    # 表中查找对应的 entry
    # =========================================================
    print("=== 方法1: 解析 pclntab funcInfo 表 ===")

    # 找到 pclntab
    for marker in [b'\xf1\xff\xff\xff', b'\xf0\xff\xff\xff']:
        pclntab = data.find(marker)
        if pclntab < 0:
            continue
        quantum = data[pclntab + 6]
        ptr_size = data[pclntab + 7]
        if quantum in (1, 2, 4) and ptr_size == 8:
            print(f"pclntab at 0x{pclntab:x}, quantum={quantum}, ptr_size={ptr_size}")

            nfunc = struct.unpack('<I', data[pclntab+8:pclntab+12])[0]
            print(f"nfunc: {nfunc}")

            # Go 1.20+ header (32 bytes for ptr_size=8):
            # +0: magic(4) + pad(2) + quantum(1) + ptrsize(1) = 8
            # +8: nfunc(4) + nfiles(4) = 8
            # +16: textStart(4)
            # +20: funcNameOffset(4) - offset to funcnametable from pclntab
            # +24: cuOffset(4)
            # +28: funcInfoOffset(4) - offset to _func table
            # +32: datapOffset(4)

            # Actually in newer Go, it might be different. Let's try offsets:
            textStart = struct.unpack('<I', data[pclntab+16:pclntab+20])[0]
            funcNameOff = struct.unpack('<I', data[pclntab+20:pclntab+24])[0]
            cuOff = struct.unpack('<I', data[pclntab+24:pclntab+28])[0]
            funcInfoOff = struct.unpack('<I', data[pclntab+28:pclntab+32])[0]

            print(f"textStart: 0x{textStart:x}")
            print(f"funcNameOff: 0x{funcNameOff:x}")
            print(f"cuOff: 0x{cuOff:x}")
            print(f"funcInfoOff: 0x{funcInfoOff:x}")

            # funcNameOff is offset from pclntab to the funcnametable
            # The funcnametable contains packed function names
            funcname_table = pclntab + funcNameOff

            # Find getAppSalt in the funcnametable
            gs_in_name_table = data.find(b'cosy/remoting.getAppSalt', funcname_table)
            if gs_in_name_table >= 0:
                print(f"\ngetAppSalt in funcnametable at 0x{gs_in_name_table:x}")
                name_relative_off = gs_in_name_table - funcname_table
                print(f"Name relative offset: 0x{name_relative_off:x}")

                # Now the funcInfo table has _func entries
                # In Go 1.20+, _func is stored differently
                # Let's try to find which entry has this nameOff

                funcInfo_table = pclntab + funcInfoOff
                print(f"funcInfo table at 0x{funcInfo_table:x}")

                # Try different entry formats
                for entry_size, desc in [(8, "entryOff(4)+nameOff(4)"),
                                          (12, "entryOff(4)+nameOff(4)+???"),
                                          (16, "entryOff(4)+nameOff(4)+???(8)")]:
                    print(f"\n  Trying {desc} (size {entry_size}):")
                    fpos = funcInfo_table
                    found = False
                    for i in range(min(nfunc, 10000)):
                        if fpos + 8 > len(data):
                            break
                        eOff = struct.unpack('<i', data[fpos:fpos+4])[0]
                        nOff = struct.unpack('<i', data[fpos+4:fpos+8])[0]

                        if nOff == name_relative_off and eOff > 0:
                            print(f"    FOUND at entry {i}: entryOff=0x{eOff:x}")
                            entry_rva = textStart + eOff
                            print(f"    Entry RVA (textStart + entryOff): 0x{entry_rva:x}")
                            print(f"    Entry VA: 0x{IMAGE_BASE + entry_rva:x}")
                            # Verify code
                            entry_file = rva_to_file(entry_rva)
                            code = data[entry_file:entry_file+16]
                            print(f"    Code: {code.hex()}")
                            found = True
                            break
                        fpos += entry_size
                    if not found:
                        print(f"    (not found in first 10000 entries)")

            break

    # =========================================================
    # 方法2: 在 addBigModelSignatureHeaders 和
    # addBigModelAuthorizationHeaders 中搜索对 getAppSalt 的调用
    # =========================================================
    print("\n\n=== 方法2: 查找签名/授权函数的调用者 ===")

    # 这两个函数的名字在名字表中相邻:
    # [27] addBigModelSignatureHeaders
    # [28] getAppSalt
    # [29] addBigModelAuthorizationHeaders
    #
    # addBigModelSignatureHeaders 应该调用 getAppSalt

    # 我们已经知道 trimQueryPath 在 0x882c80
    # trimQueryPath 在名字表中是 [30]
    # 所以 [29] addBigModelAuthorizationHeaders 应该在 0x882c80 之前
    # [27] addBigModelSignatureHeaders 应该在 [29] 之前

    # 从之前的分析，0x880000-0x891000 有 156 个函数
    # cosy/remoting 有 116 个函数
    # 我们需要找出哪些 .pdata 条目对应哪些函数名

    # 更精确的方法: 利用已知函数来校准
    # trimQueryPath [30] = 0x882c80 (pdata#19182)
    # 所以如果名字表顺序 = 代码顺序:
    # [29] addBigModelAuthorizationHeaders ≈ pdata#19181 (0x882ba0)
    # [28] getAppSalt ≈ pdata#19180 (0x882760)
    # [27] addBigModelSignatureHeaders ≈ pdata#19179 (0x882680)

    # 但名字表不一定按字母序。让我们看看名字表中 [27]-[30] 的顺序:
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
                func_names.append((idx, name))
            idx = end + 1
        else:
            break

    print(f"Found {len(func_names)} cosy/remoting function names")

    # 显示名字表中的顺序
    print("\名字表中的顺序:")
    for i, (off, name) in enumerate(func_names):
        short = name.replace('cosy/remoting.', '')
        print(f"  [{i:3d}] 0x{off:08x} {short}")

    # 找到关键函数在名字表中的索引
    key_funcs = ['addBigModelSignatureHeaders', 'getAppSalt',
                 'addBigModelAuthorizationHeaders', 'trimQueryPath']
    indices = {}
    for i, (_, name) in enumerate(func_names):
        for kf in key_funcs:
            if kf in name:
                indices[kf] = i
                print(f"\n{kf}: index={i}")

    # 如果 trimQueryPath (名字表索引30) = pdata#19182
    # 那么 getAppSalt (名字表索引28) = pdata#19182 - (30-28) = pdata#19180
    if 'trimQueryPath' in indices and 'getAppSalt' in indices:
        trim_pdata = 19182  # known
        trim_name_idx = indices['trimQueryPath']
        appsalt_name_idx = indices['getAppSalt']

        # 假设名字表索引和 pdata 索引线性相关
        offset = trim_pdata - trim_name_idx
        appsalt_pdata = appsalt_name_idx + offset

        print(f"\n假设名字表→pdata线性映射:")
        print(f"  trimQueryPath: name_idx={trim_name_idx}, pdata=#{trim_pdata}")
        print(f"  offset = {trim_pdata} - {trim_name_idx} = {offset}")
        print(f"  getAppSalt: name_idx={appsalt_name_idx}, pdata=#{appsalt_pdata}")

        # 验证: 检查 pdata#19180 的代码
        pdata_entry = appsalt_pdata
        entry_off = pdata_raw + pdata_entry * 12
        begin = struct.unpack('<I', data[entry_off:entry_off+4])[0]
        end = struct.unpack('<I', data[entry_off+4:entry_off+8])[0]
        print(f"\n  pdata#{pdata_entry}: begin=0x{begin:x}, end=0x{end:x}, size={end-begin}")

        # 反汇编这个函数
        file_off = rva_to_file(begin)
        func_data = data[file_off:file_off + min(end - begin, 200)]
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        print(f"\n  Disassembly of candidate getAppSalt (0x{begin:x}):")
        for (addr, sz, mnemonic, op_str) in md.disasm_lite(func_data, IMAGE_BASE + begin):
            if sz == 0:
                break
            print(f"    0x{addr:010x}: {mnemonic:10s} {op_str}")

if __name__ == '__main__':
    main()
