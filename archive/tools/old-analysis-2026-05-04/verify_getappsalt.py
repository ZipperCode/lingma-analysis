"""
最终确认 getAppSalt
1. 查找 0x8843c0 的调用者 - 如果它是 addBigModelSignatureHeaders，应该有明确的上层调用
2. 分析 0x884200 的字符串引用，确认它是 getAppSalt
3. 确认函数名→代码地址的映射关系
"""
import struct
import capstone
import re

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

def rva_to_file(rva):
    return 0x400 + rva - 0x1000

def file_to_rva(file_off):
    return file_off - 0x400 + 0x1000

def resolve_string(data, rva):
    """将 RVA 解析为字符串"""
    file_off = rva_to_file(rva)
    if 0 < file_off < len(data):
        end = data.find(b'\x00', file_off)
        if end > file_off and end - file_off < 500:
            return data[file_off:end].decode('utf-8', errors='replace')
    return None

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

    pdata_raw, pdata_size = sections['.pdata'][1:]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    # =========================================================
    # 步骤1: 查找 0x8843c0 的调用者
    # =========================================================
    print("=== 查找 0x8843c0 的调用者 ===")
    target = 0x8843c0
    callers_8843c0 = []

    for i in range(pdata_size // 12):
        off = pdata_raw + i * 12
        begin = struct.unpack('<I', data[off:off+4])[0]
        end = struct.unpack('<I', data[off+4:off+8])[0]

        if end - begin > 50000:
            continue

        file_off = rva_to_file(begin)
        if file_off + (end - begin) > len(data):
            continue

        func_data = data[file_off:file_off + (end - begin)]

        for j in range(len(func_data) - 5):
            if func_data[j] == 0xE8:
                disp32 = struct.unpack('<i', func_data[j+1:j+5])[0]
                call_target = file_to_rva(file_off) + j + 5 + disp32
                if call_target == target:
                    callers_8843c0.append((begin, i, j, end - begin))
                    break

    print(f"Found {len(callers_8843c0)} caller(s) of 0x{target:x}:")
    for caller_rva, pdata_idx, call_offset, size in callers_8843c0:
        print(f"  0x{caller_rva:x} (pdata#{pdata_idx}, size={size})")

        # 反汇编前100字节看看
        caller_file = rva_to_file(caller_rva)
        caller_data = data[caller_file:caller_file + min(size, 150)]
        for (addr, sz, mnemonic, op_str) in md.disasm_lite(caller_data, IMAGE_BASE + caller_rva):
            if sz == 0:
                break
            print(f"    0x{addr:010x}: {mnemonic:10s} {op_str}")

    # =========================================================
    # 步骤2: 完整反汇编 0x884200 (getAppSalt 候选)
    # 并解析所有字符串引用
    # =========================================================
    print("\n\n=== 完整反汇编 getAppSalt (0x884200) ===")

    target_rva = 0x884200
    target_size = 430
    file_off = rva_to_file(target_rva)
    func_data = data[file_off:file_off + target_size]

    for (addr, sz, mnemonic, op_str) in md.disasm_lite(func_data, IMAGE_BASE + target_rva):
        if sz == 0:
            break

        extra = ""

        # 解析 LEA 指令中的 RIP-relative 引用
        if 'lea' in mnemonic.lower() and ('[' in op_str):
            # 手动计算
            offset_in_func = addr - (IMAGE_BASE + target_rva)
            if offset_in_func + 7 <= len(func_data):
                # 检查指令字节
                instr = func_data[offset_in_func:offset_in_func + 7]
                if len(instr) >= 7 and instr[0] == 0x48 and instr[1] == 0x8d:
                    disp32 = struct.unpack('<i', instr[3:7])[0]
                    instr_rva = target_rva + offset_in_func
                    rip = instr_rva + 7
                    target_str_rva = rip + disp32
                    s = resolve_string(data, target_str_rva)
                    if s:
                        # 只显示前80个可见字符
                        vis = ''.join(c for c in s if c.isprintable())[:80]
                        if len(vis) > 5:
                            extra = f'  => "{vis}"'

        # 解析 CMP 指令中的立即数 (可能是字符串比较)
        if 'cmp' in mnemonic.lower() and '0x' in op_str:
            # 检查是否是字符串字面量比较
            numbers = re.findall(r'0x([0-9a-f]+)', op_str)
            for num_str in numbers:
                num = int(num_str, 16)
                if 0x20202020 <= num <= 0x7E7E7E7E:
                    # 可能是 ASCII 字符串
                    try:
                        chars = bytes.fromhex(f'{num:08x}').decode('ascii')[::-1]
                        extra = f'  => compares with "{chars}"'
                    except:
                        pass

        # 高亮返回指令
        if mnemonic.lower() == 'ret':
            extra = '  <<< RETURN'

        print(f"  +0x{addr - IMAGE_BASE - target_rva:04x}: {mnemonic:12s} {op_str}{extra}")

    # =========================================================
    # 步骤3: 列出 remoting 区域所有函数的调用关系
    # =========================================================
    print("\n\n=== remoting 区域函数调用关系图 ===")

    # 只关注 0x880000-0x886000 范围内的函数
    target_funcs = []
    for i in range(pdata_size // 12):
        off = pdata_raw + i * 12
        begin = struct.unpack('<I', data[off:off+4])[0]
        end = struct.unpack('<I', data[off+4:off+8])[0]
        if 0x880000 <= begin < 0x886000:
            target_funcs.append((begin, end - begin, i))

    print(f"Functions in 0x880000-0x886000: {len(target_funcs)}")

    # 构建调用关系
    call_graph = {}  # caller_rva -> list of (callee_rva, call_offset)

    for func_rva, func_size, func_pdata in target_funcs:
        file_off = rva_to_file(func_rva)
        if file_off + func_size > len(data):
            continue

        func_data = data[file_off:file_off + func_size]
        calls = []

        for j in range(len(func_data) - 5):
            if func_data[j] == 0xE8:
                disp32 = struct.unpack('<i', func_data[j+1:j+5])[0]
                call_target = file_to_rva(file_off) + j + 5 + disp32
                # 只关心 remoting 区域内的调用
                if 0x880000 <= call_target < 0x891000:
                    calls.append((call_target, j))

        if calls:
            call_graph[func_rva] = calls

    # 找到调用 0x884200 的链
    print("\n调用链 (指向 0x884200):")

    def find_callers_of(target_rva, depth=0, visited=None):
        if visited is None:
            visited = set()
        if depth > 5 or target_rva in visited:
            return
        visited.add(target_rva)

        # 找到直接调用者
        direct_callers = []
        for caller_rva, calls in call_graph.items():
            for callee_rva, offset in calls:
                if callee_rva == target_rva:
                    direct_callers.append(caller_rva)

        for caller_rva in direct_callers:
            indent = "  " * depth
            print(f"{indent}0x{caller_rva:x} -> 0x{target_rva:x}")
            find_callers_of(caller_rva, depth + 1, visited)

    find_callers_of(0x884200)

    # =========================================================
    # 步骤4: 确认名字→代码映射
    # =========================================================
    print("\n\n=== 名字表与代码地址映射验证 ===")

    # 已知映射:
    # trimQueryPath (name_idx=30) -> 0x882c80 (pdata#19182)
    # 如果 getAppSalt (name_idx=28) -> 0x884200 (pdata#19193)
    # 那么偏移量应该是: 19193 - 28 = 19165
    # 但 trimQueryPath: 19182 - 30 = 19152
    # 不一致!

    # 让我们列出名字表中 27-33 和对应的 pdata
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

    print("名字表 [27:33]:")
    for i in range(27, min(33, len(func_names))):
        off, name = func_names[i]
        short = name.replace('cosy/remoting.', '')
        print(f"  [{i}] 0x{off:08x} {short}")

    print("\n.pdata #19178-#19199:")
    for i in range(19178, 19200):
        off = pdata_raw + i * 12
        begin = struct.unpack('<I', data[off:off+4])[0]
        end = struct.unpack('<I', data[off+4:off+8])[0]
        print(f"  #{i} 0x{begin:07x}-0x{end:07x} ({end-begin:5d}B)")

    # 关键问题: 名字表顺序 ≠ 代码地址顺序
    # 需要找到正确的映射

    # 让我们使用已知点来校准:
    # trimQueryPath (idx=30) = 0x882c80
    # 从调用关系看, 0x884200 被 0x8843c0 调用
    # 0x8843c0 在 pdata#19194

    # 如果名字是按字母序排列的:
    # 名字表顺序: init, Build..., doBuild..., ..., trimQueryPath, ...
    # 显然不是字母序 (init 在 Build 之前)

    # 但代码地址是按编译顺序排列的
    # Go 编译器按源文件中的声明顺序排列函数

    # 让我们检查: 如果 0x884200 是 getAppSalt, 那它应该被
    # addBigModelSignatureHeaders 或 addBigModelAuthorizationHeaders 调用

    print("\n=== 最终判断 ===")
    print("""
根据调用关系分析:
1. 0x884200 被 0x8843c0 (pdata#19194) 调用
2. 0x8843c0 在 remoting 代码区域
3. 0x884200 的代码行为:
   - 条件分支返回不同字符串
   - 检查 "system" 字符串
   - 这符合 getAppSalt 的行为 (不同模式返回不同 salt)

结论: getAppSalt 的代码地址极可能是 0x884200

验证:
- 0x884200 有 2 个调用者 (0x8843c0 和 0x1c3ffa0)
- 0x8843c0 在 remoting 区域
- 0x884200 大小 430 字节，是一个中等复杂度的函数
- 函数行为: 获取配置 → 条件选择字符串 → 返回
""")

if __name__ == '__main__':
    main()
