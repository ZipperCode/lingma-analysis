"""
精确搜索 getAppSalt 函数：基于机器码模式匹配
已知:
1. getAppSalt 函数名在 .rdata offset 0x3b9dbba
2. cosy/remoting 函数集中在 .text 的某个区域
3. trimQueryPath=0x882c80, getAuthSignature=0x890140
4. getAppSalt 返回字符串常量（Go string = ptr + len）

方案: 使用 frida-trace 方式 - 启动 Lingma 后用 websocket 连接触发签名
"""
import struct
import mmap
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

SECTIONS = {
    '.text': {'va': 0x1000, 'size': 0x1f3f246, 'raw': 0x400},
    '.rdata': {'va': 0x1f41000, 'size': 0x3cfc250, 'raw': 0x1f3f800},
    '.data': {'va': 0x5c3e000, 'size': 0x518d80, 'raw': 0x5c3bc00},
    '.pdata': {'va': 0x6157000, 'size': 0x973ec, 'raw': 0x60a6400},
}

def rva_to_file(rva):
    for name, sec in SECTIONS.items():
        if sec['va'] <= rva < sec['va'] + sec['size']:
            return sec['raw'] + (rva - sec['va']), name
    return None, None

def file_to_rva(file_offset):
    for name, sec in SECTIONS.items():
        if sec['raw'] <= file_offset < sec['raw'] + sec['size']:
            return sec['va'] + (file_offset - sec['raw'])
    return None

def main():
    with open(BINARY_PATH, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    text = SECTIONS['.text']
    rdata = SECTIONS['.rdata']
    pdata = SECTIONS['.pdata']

    # ===== Step 1: Parse .pdata to get all function addresses =====
    print("=== Step 1: Parsing .pdata ===")
    pdata_raw = pdata['raw']
    pdata_size = pdata['size']
    num_funcs = pdata_size // 12

    func_list = []
    for i in range(num_funcs):
        offset = pdata_raw + i * 12
        begin = struct.unpack('<I', mm[offset:offset+4])[0]
        end = struct.unpack('<I', mm[offset+4:offset+8])[0]
        if begin != 0 and end > begin:
            if text['va'] <= begin < text['va'] + text['size']:
                func_list.append((begin, end))

    print(f"Total functions: {len(func_list)}")

    # ===== Step 2: Find getAppSalt's name string and its surroundings =====
    print("\n=== Step 2: getAppSalt name location ===")
    getAppSalt_name_file = 0x3b9dbba
    getAppSalt_name_rva = file_to_rva(getAppSalt_name_file)
    print(f"getAppSalt name: file=0x{getAppSalt_name_file:x}, RVA=0x{getAppSalt_name_rva:x}")

    # Show surrounding function names (to understand the ordering)
    print("\nFunctions near getAppSalt in name table:")
    # Search for nearby strings in .rdata
    rdata_raw = rdata['raw']
    # Search around getAppSalt's name
    search_start = getAppSalt_name_file - 200
    search_end = getAppSalt_name_file + 200
    pos = search_start
    while pos < search_end:
        # Find start of string (look backwards for null)
        start = pos
        while start > 0 and mm[start-1] != 0:
            start -= 1
        # Find end of string
        end = start
        while end < len(mm) and mm[end] != 0 and mm[end] < 128:
            end += 1
        s = mm[start:end].decode('ascii', errors='replace')
        if '/' in s or '.' in s:  # Likely a function name
            rva = file_to_rva(start)
            print(f"  0x{start:x} (RVA 0x{rva:x}): {s}")
        pos = end + 1
        if pos > search_end:
            break

    # ===== Step 3: Find functions that return string constants =====
    print("\n=== Step 3: Finding string-returning functions ===")

    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # getAppSalt is likely a small function that:
    # 1. Returns a Go string (RAX=pointer, RCX/RDX=length)
    # 2. The pattern would be:
    #    LEA RAX, [rip + offset]  ; load string pointer from .rdata
    #    MOV RDX/RCX, length      ; load string length
    #    RET

    # Search for small functions near trimQueryPath that match this pattern
    trim_rva = 0x882c80
    auth_sig_rva = 0x890140

    # Get functions in a 2MB window around trimQueryPath
    nearby_funcs = [(b, e) for b, e in func_list
                    if 0x700000 <= b <= 0xa00000 and (e - b) <= 64]
    print(f"Small functions near trimQueryPath region: {len(nearby_funcs)}")

    # Filter to functions that:
    # 1. Have RET instruction
    # 2. Reference .rdata via LEA
    # 3. Move a constant into a register (likely string length)

    string_funcs = []
    for begin_rva, end_rva in nearby_funcs:
        size = end_rva - begin_rva
        func_file = text['raw'] + (begin_rva - text['va'])
        func_code = mm[func_file:func_file + size]

        instructions = list(md.disasm(func_code, begin_rva))
        has_ret = False
        rdata_refs = []
        const_moves = []

        for insn in instructions:
            if insn.mnemonic == 'ret':
                has_ret = True
            elif insn.mnemonic == 'lea':
                # Check RIP-relative to .rdata
                if 'rip' in insn.op_str:
                    try:
                        disp = insn.disp
                        next_addr = insn.address + insn.size
                        target = next_addr + disp
                        if rdata['va'] <= target < rdata['va'] + rdata['size']:
                            rdata_refs.append((insn.mnemonic, insn.op_str, target))
                    except:
                        pass
            elif insn.mnemonic in ('mov', 'movzx', 'movsx', 'movabs'):
                # Check for constant moves
                if '0x' in insn.op_str and not any(x in insn.op_str for x in ['[', 'rip']):
                    const_moves.append((insn.mnemonic, insn.op_str))

        if has_ret and rdata_refs:
            string_funcs.append((begin_rva, end_rva, size, rdata_refs, const_moves, func_code))

    print(f"Functions referencing .rdata: {len(string_funcs)}")

    # Show candidates
    for begin_rva, end_rva, size, rdata_refs, const_moves, func_code in string_funcs[:30]:
        rdata_str = ""
        for _, _, target in rdata_refs:
            target_rva = target
            target_file, _ = rva_to_file(target_rva)
            if target_file:
                data = mm[target_file:target_file+50]
                rdata_str = ''.join(chr(c) if 32 <= c < 127 else '.' for c in data)

        code_hex = func_code[:40].hex()

        # Calculate offset from trimQueryPath
        delta = begin_rva - trim_rva
        sign = "+" if delta >= 0 else ""

        print(f"  RVA 0x{begin_rva:x} (size={size}, delta={sign}0x{abs(delta):x}): {rdata_str[:60]}")

        # Show disassembly
        for insn in md.disasm(func_code, begin_rva):
            print(f"    {insn.address:x}: {insn.mnemonic} {insn.op_str}")
        print()

    mm.close()

if __name__ == '__main__':
    main()
