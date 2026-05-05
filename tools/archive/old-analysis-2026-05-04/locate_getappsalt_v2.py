"""
精确定位 getAppSalt 代码地址 - 修复版
1. 修复函数名搜索范围
2. 解析所有 RIP-relative 引用的字符串内容
3. 交叉引用函数名顺序和代码顺序
"""
import struct
import capstone

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def main():
    with open(LINGMA, 'rb') as f:
        data = f.read()

    print(f"Binary size: {len(data)} bytes ({len(data)/1024/1024:.1f} MB)")

    # Parse PE
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    f = lambda o, s: data[o:o+s]
    num_sections = struct.unpack('<H', f(pe_offset + 4, 2))[0]

    sections = []
    sec_off = pe_offset + 24
    for i in range(num_sections):
        name = data[sec_off + i*40:sec_off + i*40 + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        vaddr = struct.unpack('<I', data[sec_off + i*40 + 12:sec_off + i*40 + 16])[0]
        raw_addr = struct.unpack('<I', data[sec_off + i*40 + 20:sec_off + i*40 + 24])[0]
        raw_size = struct.unpack('<I', data[sec_off + i*40 + 16:sec_off + i*40 + 20])[0]
        sections.append((name, vaddr, raw_addr, raw_size))

    text_raw = next(s for s in sections if s[0] == '.text')[2]
    rdata_base, rdata_raw, rdata_size = next(s for s in sections if s[0] == '.rdata')[1:]
    pdata_raw, pdata_size = next(s for s in sections if s[0] == '.pdata')[2:]

    IMAGE_BASE = 0x140000000

    def rva_to_file(rva):
        return 0x400 + rva - 0x1000

    def file_to_rva(file_off):
        return file_off - 0x400 + 0x1000

    def resolve_rip_ref(file_off, instr_offset, disp32):
        """解析 RIP-relative 引用的目标地址和内容"""
        # RIP = RVA of next instruction
        instr_rva = file_to_rva(file_off) + instr_offset
        rip = instr_rva + 7  # after the 7-byte LEA instruction
        target_rva = rip + disp32
        target_file = rva_to_file(target_rva)
        if 0 < target_file < len(data):
            # Try to read as string
            end = data.find(b'\x00', target_file)
            if end > target_file and end - target_file < 500:
                return data[target_file:end].decode('utf-8', errors='replace')
            # Just return hex
            return f"<data at 0x{target_file:x}>"
        return f"<out of bounds: RVA 0x{target_rva:x}>"

    # =========================================================
    # Step 1: 提取所有 cosy/remoting 函数名（修复搜索范围）
    # =========================================================
    print("\n=== cosy/remoting function names ===")
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

    # 找到 getAppSalt
    appsalt_idx = None
    for i, (off, name) in enumerate(func_names):
        if 'getAppSalt' in name:
            appsalt_idx = i
            print(f"\ngetAppSalt: index={i}, file_off=0x{off:x}, name={name}")
            break

    # 显示 getAppSalt 附近的函数名顺序
    if appsalt_idx is not None:
        print("\n函数名顺序（getAppSalt 附近）:")
        for j in range(max(0, appsalt_idx - 5), min(len(func_names), appsalt_idx + 5)):
            off, name = func_names[j]
            marker = " <-- getAppSalt" if j == appsalt_idx else ""
            name_short = name.replace('cosy/remoting.', '')
            print(f"  [{j:3d}] 0x{off:08x}  {name_short}{marker}")

    # =========================================================
    # Step 2: 解析 .pdata 中 0x880000-0x891000 的所有函数
    # =========================================================
    target_funcs = []
    for i in range(pdata_size // 12):
        off = pdata_raw + i * 12
        begin = struct.unpack('<I', data[off:off+4])[0]
        end = struct.unpack('<I', data[off+4:off+8])[0]
        if 0x880000 <= begin < 0x891000:
            target_funcs.append((begin, end - begin, i))

    print(f"\n.pdata functions in 0x880000-0x891000: {len(target_funcs)}")

    # =========================================================
    # Step 3: 对每个函数，收集所有字符串引用
    # =========================================================
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    func_string_refs = {}  # rva -> list of (instr_rva, string_content)

    print("\n=== 扫描所有函数的字符串引用 ===")
    for rva, size, pdata_idx in target_funcs:
        file_off = rva_to_file(rva)
        if file_off + min(size, 500) > len(data):
            continue

        func_data = data[file_off:file_off + min(size, 500)]
        refs = []

        for i in range(len(func_data) - 7):
            # LEA reg, [RIP + disp32]: 48 8d XX [disp32]
            if func_data[i] == 0x48 and func_data[i+1] == 0x8d:
                disp32 = struct.unpack('<i', func_data[i+3:i+7])[0]
                target_file = rva_to_file(file_to_rva(file_off) + i + 7 + disp32)
                if 0 < target_file < len(data):
                    end = data.find(b'\x00', target_file)
                    if end > target_file and end - target_file < 500:
                        s = data[target_file:end].decode('utf-8', errors='replace')
                        if any(kw in s for kw in ['cosy/', 'remoting', 'algo', 'sign',
                                                   'salt', 'auth', 'header', 'endpoint',
                                                   'dashscope', 'key', 'secret']):
                            refs.append((file_to_rva(file_off) + i, s[:100]))

        if refs:
            func_string_refs[rva] = refs
            name_short = ''
            # Try to match with func_names
            if appsalt_idx is not None:
                # Check if any ref contains getAppSalt
                for _, s in refs:
                    if 'getAppSalt' in s:
                        print(f"  *** 0x{rva:x} (pdata#{pdata_idx}, size={size}) REFERENCES getAppSalt! ***")
                        for instr_off, s in refs:
                            print(f"      +0x{instr_off - rva:x}: {s[:80]}")

    # =========================================================
    # Step 4: 列出所有有字符串引用的函数
    # =========================================================
    print(f"\n=== {len(func_string_refs)} functions with relevant string references ===")
    for rva in sorted(func_string_refs.keys()):
        refs = func_string_refs[rva]
        _, size, pdata_idx = next((b, s, p) for b, s, p in target_funcs if b == rva)
        print(f"\n  0x{rva:x} (pdata#{pdata_idx}, size={size}):")
        for instr_off, s in refs:
            print(f"    +0x{instr_off - rva:x}: {s[:100]}")

    # =========================================================
    # Step 5: 关键 - 找到 getAppSalt 对应的代码
    # 利用函数名在名字表中的顺序 ≈ 代码顺序
    # =========================================================
    if appsalt_idx is not None and len(target_funcs) == len(func_names):
        print("\n=== 直接交叉映射 ===")
        print(f"名字表中有 {len(func_names)} 个 cosy/remoting 函数")
        print(f"代码区域有 {len(target_funcs)} 个函数")

        if len(func_names) == len(target_funcs):
            # 完美匹配!
            print("数量完全匹配! 直接映射:")
            for i, ((name_off, name), (code_rva, code_size, pdata_idx)) in \
                    enumerate(zip(func_names, target_funcs)):
                name_short = name.replace('cosy/remoting.', '')
                marker = " <-- getAppSalt!" if 'getAppSalt' in name else ""
                print(f"  [{i:3d}] name=0x{name_off:x} ({name_short}) -> code=0x{code_rva:x} (size={code_size}){marker}")

    # =========================================================
    # Step 6: 如果数量匹配，找到 getAppSalt 的代码地址
    # =========================================================
    if appsalt_idx is not None and appsalt_idx < len(target_funcs):
        code_rva, code_size, pdata_idx = target_funcs[appsalt_idx]
        name_off, name = func_names[appsalt_idx]
        print(f"\n{'='*60}")
        print(f"getAppSalt 代码地址: 0x{code_rva:x}")
        print(f"  pdata entry: #{pdata_idx}")
        print(f"  size: {code_size} bytes")
        print(f"  name: {name}")
        print(f"  name file offset: 0x{name_off:x}")
        print(f"{'='*60}")

        # 反汇编这个函数
        file_off = rva_to_file(code_rva)
        func_data = data[file_off:file_off + min(code_size, 300)]
        print(f"\n反汇编:")
        for (addr, sz, mnemonic, op_str) in md.disasm_lite(func_data, IMAGE_BASE + code_rva):
            if sz == 0:
                break
            # 解析 RIP-relative
            extra = ""
            if '[rip' in op_str.lower():
                import re
                m = re.search(r'0x([0-9a-f]+)', op_str)
                if m:
                    target = int(m.group(1), 16)
                    # This is the absolute address shown by capstone
                    extra = f" (absolute addr)"
            print(f"  0x{addr:010x}: {mnemonic:10s} {op_str}{extra}")

        if code_size > 300:
            print(f"  ... ({code_size - 300} more bytes)")

if __name__ == '__main__':
    main()
