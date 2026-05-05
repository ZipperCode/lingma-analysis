"""
最终方案: 通过分析函数调用链来定位 getAppSalt

关键已知信息:
1. trimQueryPath 代码在 0x882c80 (pdata#19182)
2. trimQueryPath 名字在名字表索引 30
3. getAppSalt 名字在名字表索引 28 (比 trimQueryPath 早 2 个)
4. addBigModelSignatureHeaders 在索引 27
5. addBigModelAuthorizationHeaders 在索引 29

策略: 从 pdata#19182 (trimQueryPath=0x882c80) 出发,
找到索引 27,28,29 对应的 pdata 条目
"""
import struct
import capstone

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

def rva_to_file(rva):
    return 0x400 + rva - 0x1000

def main():
    with open(LINGMA, 'rb') as f:
        data = f.read()

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

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

    pdata_raw, pdata_size = sections['.pdata'][1], sections['.pdata'][2]
    rdata_base = sections['.rdata'][0]

    def resolve_string_rva(rva):
        file_off = rva_to_file(rva)
        if 0 < file_off < len(data):
            end = data.find(b'\x00', file_off)
            if end > file_off and end - file_off < 500:
                return data[file_off:end].decode('utf-8', errors='replace')
        return None

    # =========================================================
    # 核心思路:
    # Go 编译器将同一包的函数编译到连续的代码区域
    # cosy/remoting 包的函数在 .pdata 中也是连续的
    #
    # 从 trimQueryPath (pdata#19182) 出发:
    # - addBigModelAuthorizationHeaders [29] 应该在它前面
    # - getAppSalt [28] 应该再前面
    # - addBigModelSignatureHeaders [27] 应该再前面
    #
    # 但名字表顺序 ≠ 编译顺序
    # 我们需要看名字表中的实际顺序来推断
    # =========================================================

    # 从名字表看, cosy/remoting 函数顺序是:
    # [27] addBigModelSignatureHeaders
    # [28] getAppSalt
    # [29] addBigModelAuthorizationHeaders
    # [30] trimQueryPath
    #
    # Go 编译器按源文件中声明的顺序排列函数
    # 所以源码中函数声明顺序就是:
    #   addBigModelSignatureHeaders
    #   getAppSalt
    #   addBigModelAuthorizationHeaders
    #   trimQueryPath

    # 但在 .pdata 中, trimQueryPath 是 #19182
    # 如果编译顺序 = pdata 顺序, 那么:
    #   trimQueryPath = #19182
    #   addBigModelAuthorizationHeaders = #19181
    #   getAppSalt = #19180
    #   addBigModelSignatureHeaders = #19179
    #
    # 但我们需要验证这个假设!

    # 方法: 检查 pdata#19181 (0x882ba0) 是否调用了 pdata#19182 (0x882c80=trimQueryPath)
    # 如果是, 说明 addBigModelAuthorizationHeaders 调用了 trimQueryPath

    # 从之前分析, 0x882ba0 确实调用了 0x882c80!
    # 这验证了 pdata#19181 确实是 addBigModelAuthorizationHeaders

    # 但等等, 名字表中 addBigModelAuthorizationHeaders 在 trimQueryPath 前面 [29 vs 30]
    # 所以如果源码顺序 = pdata 顺序, 那么 [29] 应该在 [30] 前面, 即:
    # addBigModelAuthorizationHeaders 的 pdata 条目应该在 trimQueryPath 之前

    # pdata#19181 (0x882ba0) 确实调用 pdata#19182 (0x882c80)
    # 这支持 pdata#19181 = addBigModelAuthorizationHeaders 的假设

    # 那 getAppSalt [28] = pdata#19180 = 0x882760
    # addBigModelSignatureHeaders [27] = pdata#19179 = 0x882680

    # 验证: getAppSalt 应该被 addBigModelSignatureHeaders 或
    # addBigModelAuthorizationHeaders 调用

    print("=== 验证假设 ===")
    print("假设: pdata#19180 (0x882760) = getAppSalt")
    print("假设: pdata#19179 (0x882680) = addBigModelSignatureHeaders")
    print("假设: pdata#19181 (0x882ba0) = addBigModelAuthorizationHeaders")
    print()

    # 检查 0x882680 (addBigModelSignatureHeaders) 是否调用 0x882760 (getAppSalt)
    print("检查 0x882680 是否调用 0x882760:")
    func_882680_start = 0x882680
    func_882680_end = 0x88274b  # from pdata#19179

    file_off = rva_to_file(func_882680_start)
    func_len = func_882680_end - func_882680_start
    func_data = data[file_off:file_off + func_len]

    found_calls = []
    for j in range(len(func_data) - 5):
        if func_data[j] == 0xE8:
            disp32 = struct.unpack('<i', func_data[j+1:j+5])[0]
            call_target = (func_882680_start + j + 5 + disp32) & 0xFFFFFFFF
            if call_target == 0x882760:
                found_calls.append(j)

    if found_calls:
        print(f"  YES! CALL at offset +{found_calls[0]:x}")
    else:
        print("  No direct CALL found")
        # 列出所有 CALL 目标
        print("  All CALL targets:")
        for j in range(len(func_data) - 5):
            if func_data[j] == 0xE8:
                disp32 = struct.unpack('<i', func_data[j+1:j+5])[0]
                call_target = (func_882680_start + j + 5 + disp32) & 0xFFFFFFFF
                if 0x880000 <= call_target < 0x891000:
                    print(f"    +0x{j:x}: CALL 0x{call_target:x}")

    # 检查 0x882ba0 (addBigModelAuthorizationHeaders) 是否调用 0x882760 (getAppSalt)
    print("\n检查 0x882ba0 是否调用 0x882760:")
    func_882ba0_start = 0x882ba0
    func_882ba0_end = 0x882c6f

    file_off = rva_to_file(func_882ba0_start)
    func_len = func_882ba0_end - func_882ba0_start
    func_data = data[file_off:file_off + func_len]

    found_calls = []
    for j in range(len(func_data) - 5):
        if func_data[j] == 0xE8:
            disp32 = struct.unpack('<i', func_data[j+1:j+5])[0]
            call_target = (func_882ba0_start + j + 5 + disp32) & 0xFFFFFFFF
            if call_target == 0x882760:
                found_calls.append(j)

    if found_calls:
        print(f"  YES! CALL at offset +{found_calls[0]:x}")
    else:
        print("  No direct CALL found")
        print("  All CALL targets in remoting range:")
        for j in range(len(func_data) - 5):
            if func_data[j] == 0xE8:
                disp32 = struct.unpack('<i', func_data[j+1:j+5])[0]
                call_target = (func_882ba0_start + j + 5 + disp32) & 0xFFFFFFFF
                if 0x880000 <= call_target < 0x891000:
                    print(f"    +0x{j:x}: CALL 0x{call_target:x}")

    # =========================================================
    # 方法3: 搜索所有引用 getAppSalt 名字串的函数
    # 在 Go 中, 函数名串通常在 panic、log、reflect 等场景被引用
    # 但 getAppSalt 更可能通过函数调用被引用
    # =========================================================
    print("\n\n=== 搜索 remoting 区域函数间的调用关系 ===")

    # 提取 pdata#19175 到 #19200 的所有函数
    target_range = range(19170, 19220)
    func_list = []
    for i in target_range:
        off = pdata_raw + i * 12
        begin = struct.unpack('<I', data[off:off+4])[0]
        end = struct.unpack('<I', data[off+4:off+8])[0]
        func_list.append((i, begin, end, end - begin))

    print(f"Functions pdata#19170-#19219:")
    for pdata_idx, begin, end, size in func_list:
        print(f"  #{pdata_idx} 0x{begin:07x}-0x{end:07x} ({size:5d}B)")

    # 构建调用图
    print("\nCall graph within this range:")
    for pdata_idx, begin, end, size in func_list:
        if size > 30000:
            continue
        file_off = rva_to_file(begin)
        if file_off + size > len(data):
            continue
        func_data = data[file_off:file_off + size]

        calls_to_remoting = []
        for j in range(len(func_data) - 5):
            if func_data[j] == 0xE8:
                disp32 = struct.unpack('<i', func_data[j+1:j+5])[0]
                call_target = (begin + j + 5 + disp32) & 0xFFFFFFFF
                # Check if target is in our function list
                for _, tb, te, _ in func_list:
                    if tb == call_target:
                        calls_to_remoting.append(call_target)
                        break

        if calls_to_remoting:
            for ct in calls_to_remoting:
                caller_idx = next(idx for idx, b, _, _ in func_list if b == begin)
                callee_idx = next(idx for idx, b, _, _ in func_list if b == ct)
                print(f"  0x{begin:07x}(#{caller_idx}) -> 0x{ct:07x}(#{callee_idx})")

    # =========================================================
    # 方法4: 搜索包含 "salt" 的字符串
    # =========================================================
    print("\n\n=== 搜索包含 'salt' 的字符串 ===")
    idx = 0
    while True:
        idx = data.find(b'salt', idx)
        if idx < 0 or idx > 50 * 1024 * 1024:
            break
        # Check if it's part of a longer string
        start = idx
        while start > 0 and data[start-1:start].isalpha():
            start -= 1
        end = data.find(b'\x00', idx)
        if end < 0:
            break
        s = data[start:end].decode('utf-8', errors='replace')
        if len(s) > 3 and any(c.isalpha() for c in s):
            print(f"  0x{start:08x}: {s[:100]}")
        idx = end + 1

    # Also search for "Salt"
    idx = 0
    while True:
        idx = data.find(b'Salt', idx)
        if idx < 0 or idx > 50 * 1024 * 1024:
            break
        start = idx
        while start > 0 and data[start-1:start].isalpha():
            start -= 1
        end = data.find(b'\x00', idx)
        if end < 0:
            break
        s = data[start:end].decode('utf-8', errors='replace')
        if len(s) > 3 and any(c.isalpha() for c in s):
            print(f"  0x{start:08x}: {s[:100]}")
        idx = end + 1

if __name__ == '__main__':
    main()
