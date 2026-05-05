"""
搜索调用 getAppSalt 代码的函数
方法: 遍历所有 .pdata 条目，查找 CALL 指令指向候选地址的函数
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

    pdata_raw, pdata_size = sections['.pdata'][1:]

    # 从之前的交叉映射，我们有两个候选:
    # 1. 0x884200 (pdata#19193, size=430) - 来自直接索引映射
    # 2. 0x882760 (pdata#19180, size=1087) - 来自线性偏移映射
    #
    # 但这两种映射都不可靠。让我们用更直接的方法:
    # 搜索所有函数中是否有 CALL 0x884200 或 CALL 0x882760

    candidates = [0x884200, 0x882760]

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    for target in candidates:
        target_va = IMAGE_BASE + target
        print(f"\n=== 搜索调用 0x{target:x} 的函数 ===")

        callers = []
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

            # Search for CALL near instruction
            # E8 disp32 - direct call
            # FF /2 - indirect call through register/memory
            for j in range(len(func_data) - 5):
                if func_data[j] == 0xE8:
                    disp32 = struct.unpack('<i', func_data[j+1:j+5])[0]
                    call_target = file_to_rva(file_off) + j + 5 + disp32
                    if call_target == target:
                        callers.append((begin, i, j, end - begin))
                        break

        if callers:
            print(f"Found {len(callers)} caller(s):")
            for caller_rva, pdata_idx, call_offset, size in callers:
                print(f"  Function at 0x{caller_rva:x} (pdata#{pdata_idx}, size={size})")
                print(f"    CALL at +0x{call_offset:x}")

                # Disassemble the caller function
                caller_file = rva_to_file(caller_rva)
                caller_data = data[caller_file:caller_file + min(size, 300)]
                print(f"    Disassembly:")
                for (addr, sz, mnemonic, op_str) in md.disasm_lite(caller_data, IMAGE_BASE + caller_rva):
                    if sz == 0:
                        break
                    marker = " <-- CALL target" if addr == IMAGE_BASE + caller_rva + call_offset else ""
                    print(f"      0x{addr:010x}: {mnemonic:10s} {op_str}{marker}")
        else:
            print(f"No callers found for 0x{target:x}")

    # =========================================================
    # 方法3: 搜索 Go 字符串引用
    # 在 .rdata 中 getAppSalt 名字字符串附近，可能有对应的 Go 字符串字面量
    # (即 getAppSalt 返回的实际 salt 值)
    # =========================================================
    print("\n\n=== 方法3: 搜索 getAppSalt 名字周围的字符串 ===")

    # getAppSalt 名字在 .rdata 文件偏移 0x3b9dba6
    gs_name_off = 0x3b9dba6

    # 显示这个名字前后的字符串
    for direction, offset_range in [("before", range(gs_name_off - 200, gs_name_off)),
                                     ("after", range(gs_name_off + len(b'cosy/remoting.getAppSalt'),
                                                      gs_name_off + 200))]:
        if direction == "before":
            region = data[gs_name_off - 200:gs_name_off]
        else:
            region = data[gs_name_off + 27:gs_name_off + 200]

        print(f"\n  {direction} getAppSalt name:")
        # Find null-terminated strings
        pos = 0
        while pos < len(region):
            # Skip non-printable
            while pos < len(region) and not (32 <= region[pos] < 127):
                pos += 1
            if pos >= len(region):
                break
            end = pos
            while end < len(region) and 32 <= region[end] < 127:
                end += 1
            if end - pos > 3:
                abs_off = (gs_name_off - 200 if direction == "before" else gs_name_off + 27) + pos
                print(f"    0x{abs_off:08x}: {region[pos:end].decode('utf-8', errors='replace')}")
            pos = end + 1

    # =========================================================
    # 方法4: 在 remoting 代码区域搜索简单函数 (可能返回常量字符串)
    # =========================================================
    print("\n\n=== 方法4: 搜索简单的字符串返回函数 ===")

    # getAppSalt 很可能是一个小函数:
    # 1. 加载字符串指针到 RAX
    # 2. 加载字符串长度到 RCX/EDX
    # 3. RET

    # 搜索模式: LEA RAX, [RIP+disp] + MOV RCX, imm + RET
    # 或者: MOV RAX, imm + MOV ECX, imm + RET

    for i in range(pdata_size // 12):
        off = pdata_raw + i * 12
        begin = struct.unpack('<I', data[off:off+4])[0]
        end = struct.unpack('<I', data[off+4:off+8])[0]
        size = end - begin

        if size > 100 or size < 10:
            continue

        if not (0x880000 <= begin < 0x891000):
            continue

        file_off = rva_to_file(begin)
        if file_off + size > len(data):
            continue

        func_data = data[file_off:file_off + size]

        # Check for: LEA RAX, [RIP+disp] followed by MOV RCX/ECX, imm followed by RET
        has_lea_rax = False
        has_mov_len = False
        has_ret = False

        try:
            for (addr, sz, mnemonic, op_str) in md.disasm_lite(func_data, IMAGE_BASE + begin):
                if sz == 0:
                    break
                if 'lea' in mnemonic.lower() and 'rax' in op_str.lower() and 'rip' in op_str.lower():
                    has_lea_rax = True
                if ('mov' in mnemonic.lower() and
                    ('ecx' in op_str.lower() or 'rcx' in op_str.lower()) and
                    not '[' in op_str and
                    not 'rip' in op_str.lower()):
                    has_mov_len = True
                if mnemonic.lower() == 'ret':
                    has_ret = True
        except:
            continue

        if has_lea_rax and has_mov_len and has_ret:
            print(f"\n  Candidate: 0x{begin:x} (pdata#{i}, size={size})")
            # Disassemble
            for (addr, sz, mnemonic, op_str) in md.disasm_lite(func_data, IMAGE_BASE + begin):
                if sz == 0:
                    break
                print(f"    0x{addr:010x}: {mnemonic:10s} {op_str}")

if __name__ == '__main__':
    main()
