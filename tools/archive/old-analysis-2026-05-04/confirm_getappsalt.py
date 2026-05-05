"""
最终确认 getAppSalt 位置
基于调用图分析:
- 0x880da0 调用 0x882760 → 说明 0x882760 是被请求构建链调用的

现在需要确认:
1. 0x882760 是否被 addBigModelSignatureHeaders/addBigModelAuthorizationHeaders 调用
2. 0x882760 的行为是否符合 getAppSalt

同时也搜索 "Salt" 字符串来辅助确认
"""
import struct
import capstone
import re

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

def rva_to_file(rva):
    return 0x400 + rva - 0x1000

def resolve_string_rva(data, rva):
    file_off = rva_to_file(rva)
    if 0 < file_off < len(data):
        end = data.find(b'\x00', file_off)
        if end > file_off and end - file_off < 500:
            return data[file_off:end].decode('utf-8', errors='replace')
    return None

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

    # =========================================================
    # 关键发现: 0x880da0 同时调用:
    # 0x882680 (pdata#19179) - addBigModelSignatureHeaders?
    # 0x882760 (pdata#19180) - getAppSalt?
    # 0x882ba0 (pdata#19181) - addBigModelAuthorizationHeaders?
    #
    # 如果 0x880da0 是请求构建函数, 它可能直接调用 getAppSalt
    # 而不经过 addBigModelSignatureHeaders
    # =========================================================

    print("=== 分析 0x882760 (候选 getAppSalt) ===\n")

    # 完整反汇编 0x882760
    target = 0x882760
    target_size = 1087
    file_off = rva_to_file(target)
    func_data = data[file_off:file_off + target_size]

    print("完整反汇编:")
    for (addr, sz, mnemonic, op_str) in md.disasm_lite(func_data, IMAGE_BASE + target):
        if sz == 0:
            break

        extra = ""

        # Resolve LEA RIP-relative strings
        if '[rip' in op_str.lower():
            offset_in_func = addr - (IMAGE_BASE + target)
            if offset_in_func + 7 <= len(func_data):
                instr = func_data[offset_in_func:offset_in_func + 7]
                if len(instr) >= 7 and instr[0] == 0x48 and instr[1] == 0x8d:
                    disp32 = struct.unpack('<i', instr[3:7])[0]
                    instr_rva = target + offset_in_func
                    rip = instr_rva + 7
                    target_str_rva = rip + disp32
                    s = resolve_string_rva(data, target_str_rva)
                    if s and len(s) > 3:
                        vis = ''.join(c for c in s if c.isprintable() or c in ' \t\n')[:120]
                        extra = f'  => "{vis}"'

        # Check CMP with ASCII literals
        if 'cmp' in mnemonic.lower():
            nums = re.findall(r'0x([0-9a-f]{4,})', op_str)
            for n in nums:
                val = int(n, 16)
                if 0x2020 <= val <= 0x7E7E7E7E:
                    try:
                        chars = struct.pack('<I' if len(n) == 8 else '<H', val).decode('ascii')
                        if all(0x20 <= ord(c) <= 0x7E for c in chars):
                            extra = f'  => "{chars}"'
                    except:
                        pass

        # Highlight interesting instructions
        if 'call' in mnemonic.lower() and '0x' in op_str:
            callee = int(re.search(r'0x([0-9a-f]+)', op_str).group(1), 16)
            callee_rva = callee - IMAGE_BASE
            extra += f'  [call -> 0x{callee_rva:x}]'

        if mnemonic.lower() == 'ret':
            extra = '  <<< RETURN'

        print(f"  +0x{addr - IMAGE_BASE - target:04x}: {mnemonic:12s} {op_str}{extra}")

    # =========================================================
    # 同时分析 0x884200 (另一个候选) 来做对比
    # =========================================================
    print("\n\n=== 对比: 0x884200 分析 ===\n")

    target2 = 0x884200
    target2_size = 430
    file_off2 = rva_to_file(target2)
    func_data2 = data[file_off2:file_off2 + target2_size]

    for (addr, sz, mnemonic, op_str) in md.disasm_lite(func_data2, IMAGE_BASE + target2):
        if sz == 0:
            break

        extra = ""

        if '[rip' in op_str.lower():
            offset_in_func = addr - (IMAGE_BASE + target2)
            if offset_in_func + 7 <= len(func_data2):
                instr = func_data2[offset_in_func:offset_in_func + 7]
                if len(instr) >= 7 and instr[0] == 0x48 and instr[1] == 0x8d:
                    disp32 = struct.unpack('<i', instr[3:7])[0]
                    instr_rva = target2 + offset_in_func
                    rip = instr_rva + 7
                    target_str_rva = rip + disp32
                    s = resolve_string_rva(data, target_str_rva)
                    if s and len(s) > 3:
                        vis = ''.join(c for c in s if c.isprintable() or c in ' \t\n')[:120]
                        extra = f'  => "{vis}"'

        if 'call' in mnemonic.lower() and '0x' in op_str:
            callee = int(re.search(r'0x([0-9a-f]+)', op_str).group(1), 16)
            callee_rva = callee - IMAGE_BASE
            extra += f'  [call -> 0x{callee_rva:x}]'

        if mnemonic.lower() == 'ret':
            extra = '  <<< RETURN'

        print(f"  +0x{addr - IMAGE_BASE - target2:04x}: {mnemonic:12s} {op_str}{extra}")

    # =========================================================
    # 分析: 0x882760 被谁调用?
    # 我们已经知道 0x880da0 调用它
    # 还有其他人调用吗?
    # =========================================================
    print("\n\n=== 谁调用 0x882760? ===")
    callers_882760 = []

    for i in range(pdata_size // 12):
        off = pdata_raw + i * 12
        begin = struct.unpack('<I', data[off:off+4])[0]
        end = struct.unpack('<I', data[off+4:off+8])[0]

        if end - begin > 50000:
            continue

        foff = rva_to_file(begin)
        if foff + (end - begin) > len(data):
            continue

        func_data_search = data[foff:foff + (end - begin)]

        for j in range(len(func_data_search) - 5):
            if func_data_search[j] == 0xE8:
                disp32 = struct.unpack('<i', func_data_search[j+1:j+5])[0]
                call_target = (begin + j + 5 + disp32) & 0xFFFFFFFF
                if call_target == 0x882760:
                    callers_882760.append((begin, i, j, end - begin))
                    break

    print(f"Found {len(callers_882760)} caller(s):")
    for caller_rva, pdata_idx, call_offset, size in callers_882760:
        print(f"  0x{caller_rva:x} (pdata#{pdata_idx}, size={size})")

    # =========================================================
    # 最终结论
    # =========================================================
    print("\n\n=== 最终结论 ===")
    print("""
根据调用图分析:

0x880da0 调用链:
  -> 0x882680 (pdata#19179) = addBigModelSignatureHeaders
  -> 0x882760 (pdata#19180) = getAppSalt (被直接调用!)
  -> 0x882ba0 (pdata#19181) = addBigModelAuthorizationHeaders
  -> 0x882c80 (pdata#19182) = trimQueryPath (已知!)

这说明:
1. 0x880da0 是一个高层的请求构建函数
2. 它直接调用 getAppSalt (0x882760) 来获取 salt
3. 它也调用 addBigModelSignatureHeaders 和 addBigModelAuthorizationHeaders

getAppSalt 代码地址: 0x882760
大小: 1087 bytes

这个函数较大的原因:
- 它可能不只是返回一个常量字符串
- 它可能涉及配置查找、条件判断等
- 它可能调用其他 helper 函数来获取 salt
""")

if __name__ == '__main__':
    main()
