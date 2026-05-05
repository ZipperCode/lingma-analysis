"""
精确定位 getAppSalt 代码地址
策略:
1. 提取 cosy/remoting 所有函数名及其在名字表中的相对偏移
2. 提取 .pdata 中 0x880000-0x891000 范围所有函数入口
3. 利用 Go 编译时函数名顺序 ≈ 代码顺序 的特性进行交叉引用
4. 对候选函数进行反汇编，寻找返回字符串常量的模式
"""
import struct
import capstone

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def main():
    with open(LINGMA, 'rb') as f:
        data = f.read()

    # Parse PE
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    f = lambda o, s: data[o:o+s]
    num_sections = struct.unpack('<H', f(pe_offset + 4, 2))[0]
    opt_size = struct.unpack('<H', f(pe_offset + 20, 2))[0]

    sections = []
    sec_off = pe_offset + 24
    for i in range(num_sections):
        name = data[sec_off + i*40:sec_off + i*40 + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        vaddr = struct.unpack('<I', data[sec_off + i*40 + 12:sec_off + i*40 + 16])[0]
        raw_addr = struct.unpack('<I', data[sec_off + i*40 + 20:sec_off + i*40 + 24])[0]
        raw_size = struct.unpack('<I', data[sec_off + i*40 + 16:sec_off + i*40 + 20])[0]
        sections.append((name, vaddr, raw_addr, raw_size))

    text_base, text_raw, _ = next(s for s in sections if s[0] == '.text')[1:]
    rdata_base, rdata_raw, rdata_size = next(s for s in sections if s[0] == '.rdata')[1:]
    pdata_raw, pdata_size = next(s for s in sections if s[0] == '.pdata')[2:]

    # Helper: RVA -> file offset
    def rva_to_file(rva):
        return 0x400 + rva - 0x1000

    def file_to_rva(file_off):
        return file_off - 0x400 + 0x1000

    # =========================================================
    # Step 1: 提取 cosy/remoting 所有函数名
    # =========================================================
    func_names = []
    idx = 0
    while True:
        idx = data.find(b'cosy/remoting.', idx)
        if idx < 0 or idx > 6*1024*1024:
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

    # 找到 getAppSalt 在名字表中的位置
    appsalt_idx = None
    for i, (off, name) in enumerate(func_names):
        if 'getAppSalt' in name:
            appsalt_idx = i
            print(f"getAppSalt at index {i}: file_off=0x{off:x}, name={name}")
            break

    # 显示 getAppSalt 前后各10个函数名
    if appsalt_idx is not None:
        print("\ngetAppSalt 附近的函数名:")
        for j in range(max(0, appsalt_idx - 10), min(len(func_names), appsalt_idx + 10)):
            off, name = func_names[j]
            marker = " <-- getAppSalt" if j == appsalt_idx else ""
            print(f"  [{j:3d}] 0x{off:08x}  {name}{marker}")

    # =========================================================
    # Step 2: 解析 .pdata 获取目标范围所有函数
    # =========================================================
    print(f"\n.pdata: {pdata_size // 12} total entries")

    target_funcs = []  # (rva, size, pdata_index)
    for i in range(pdata_size // 12):
        off = pdata_raw + i * 12
        begin = struct.unpack('<I', data[off:off+4])[0]
        end = struct.unpack('<I', data[off+4:off+8])[0]
        if 0x880000 <= begin < 0x891000:
            target_funcs.append((begin, end - begin, i))

    print(f"Functions in 0x880000-0x891000: {len(target_funcs)}")

    # =========================================================
    # Step 3: 对每个候选函数进行反汇编分析
    # =========================================================
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    # Go 函数返回字符串的模式:
    # 1. LEA RAX, [RIP+disp]  -> 字符串指针
    # 2. MOV RCX, imm        -> 字符串长度
    # 3. RET
    #
    # 对于 getAppSalt，预期会加载一个固定的 salt 字符串

    print("\n=== 分析每个候选函数 ===")

    for rva, size, pdata_idx in target_funcs:
        file_off = rva_to_file(rva)
        if file_off + min(size, 500) > len(data):
            continue

        func_data = data[file_off:file_off + min(size, 500)]

        # 查找是否有对 .rdata 中 cosy/remoting 字符串的引用
        # LEA reg, [RIP + disp32] 其中 RIP + 7 + disp32 指向 .rdata 区域
        has_string_ref = False
        refs = []

        for i in range(len(func_data) - 7):
            # 48 8d XX [disp32] - LEA with RIP-relative
            if func_data[i] == 0x48 and func_data[i+1] == 0x8d:
                disp32 = struct.unpack('<i', func_data[i+3:i+7])[0]
                # RIP 是下一条指令的地址
                rip = file_to_rva(file_off + i) + 7
                target_rva = rip + disp32

                # 检查是否指向 .rdata 中的 cosy/remoting 字符串
                if rdata_base <= target_rva < rdata_base + rdata_size:
                    target_file = rva_to_file(target_rva)
                    if 0 < target_file < len(data):
                        # 检查附近是否有 cosy/remoting 字符串
                        search_start = max(0, target_file - 50)
                        search_end = min(len(data), target_file + 200)
                        region = data[search_start:search_end]
                        if b'cosy/remoting' in region:
                            # 找到字符串内容
                            str_start = region.find(b'cosy/remoting')
                            if str_start >= 0:
                                abs_str_pos = search_start + str_start
                                str_end = data.find(b'\x00', abs_str_pos)
                                if str_end > abs_str_pos:
                                    name = data[abs_str_pos:str_end].decode('utf-8', errors='replace')
                                    refs.append((hex(rva + i), name))
                                    has_string_ref = True

        if has_string_ref:
            print(f"\n  0x{rva:x} (size={size}, pdata#{pdata_idx}) - references:")
            for addr, name in refs:
                print(f"    {addr}: {name[:80]}")

            # 如果引用了 getAppSalt 字符串，重点标记
            for _, name in refs:
                if 'getAppSalt' in name:
                    print(f"    *** POSSIBLE getAppSalt CODE at 0x{rva:x}! ***")

    # =========================================================
    # Step 4: 对重点候选函数进行完整反汇编
    # =========================================================
    print("\n\n=== 详细反汇编重点候选函数 ===")

    # 重点关注 0x882ba0 附近的函数
    focus_rvas = [0x882ba0, 0x882c80, 0x882e40, 0x882f80, 0x8830a0, 0x8831c0,
                  0x8832e0, 0x883400, 0x883520, 0x883640, 0x883760, 0x883880,
                  0x8839a0, 0x883a40, 0x883b60, 0x883d80, 0x883f40]

    for rva in focus_rvas:
        file_off = rva_to_file(rva)
        if file_off + 200 > len(data):
            continue

        # 找到 .pdata 中的 size
        size = 64
        for _, s, _ in target_funcs:
            pass
        for r, s, _ in target_funcs:
            if r == rva:
                size = s
                break

        func_data = data[file_off:file_off + min(size, 300)]

        print(f"\n--- Function at 0x{rva:x} (size={size}) ---")
        try:
            for (addr, sz, mnemonic, op_str) in md.disasm_lite(func_data, 0x140000000 + rva):
                if sz == 0:
                    break
                # 高亮 RIP-relative 寻址
                highlight = ""
                if '[rip' in op_str.lower() or '[rip' in mnemonic.lower():
                    # 解析目标地址
                    import re
                    m = re.search(r'0x([0-9a-f]+)', op_str)
                    if m:
                        highlight = f" -> points to 0x{int(m.group(1), 16):x}"
                print(f"  0x{addr:010x}: {mnemonic:10s} {op_str}{highlight}")
        except Exception as e:
            print(f"  Disassembly error: {e}")

        # 只反汇编前300字节或整个函数
        if size > 300:
            print(f"  ... ({size - 300} more bytes)")

if __name__ == '__main__':
    main()
