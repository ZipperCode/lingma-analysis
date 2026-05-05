"""
聚焦分析: getAppSalt 的具体行为
1. 它构建了什么数据结构
2. 它使用了哪些 map key 字符串
3. 追踪 0x9ea40 (string comparison) 的调用上下文
"""
import struct
import capstone
import re

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

def parse_sections(data):
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    coff = pe_offset + 4
    num_sections = struct.unpack('<H', data[coff + 2:coff + 4])[0]
    opt_size = struct.unpack('<H', data[coff + 16:coff + 18])[0]
    sec_off = coff + 20 + opt_size
    sections = []
    for i in range(num_sections):
        name = data[sec_off + i*40:sec_off + i*40 + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        vaddr = struct.unpack('<I', data[sec_off + i*40 + 12:sec_off + i*40 + 16])[0]
        raw_size = struct.unpack('<I', data[sec_off + i*40 + 16:sec_off + i*40 + 20])[0]
        raw_addr = struct.unpack('<I', data[sec_off + i*40 + 20:sec_off + i*40 + 24])[0]
        sections.append((name, vaddr, raw_addr, raw_size))
    return sections

def rva_to_file(rva, sections):
    for name, vaddr, raw_addr, raw_size in sections:
        if vaddr <= rva < vaddr + raw_size:
            return raw_addr + (rva - vaddr)
    return None

def resolve_string(data, sections, rva, max_len=300):
    off = rva_to_file(rva, sections)
    if off and 0 < off < len(data) - 1:
        end = data.find(b'\x00', off)
        if end > off and end - off < max_len:
            return data[off:end].decode('utf-8', errors='replace')
    return None

def main():
    with open(LINGMA, 'rb') as f:
        data = f.read()

    sections = parse_sections(data)
    rdata_name, rdata_vaddr, rdata_raw, rdata_size = [s for s in sections if s[0] == '.rdata'][0]

    # ========================================
    # Part 1: Analyze getAppSalt in detail
    # Focus on the map construction pattern
    # ========================================
    print("=== getAppSalt data flow analysis ===\n")

    off = rva_to_file(0x882760, sections)
    func_data = data[off:off + 1087]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    # Track the values loaded into registers before map operations
    print("Instructions before each mapassign (0x2dd360) call:\n")

    mapassign_count = 0
    buffer = []

    for insn in md.disasm(func_data, IMAGE_BASE + 0x882760):
        if insn.size == 0:
            break

        # Collect string refs
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                target = insn.address + insn.size + op.mem.disp
                target_rva = target - IMAGE_BASE
                s = resolve_string(data, sections, target_rva)
                if s and len(s) > 1:
                    buffer.append((insn.address, f"LEA string -> \"{s[:80]}\""))

        # Track MOV with immediate values
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                val = op.imm
                if val > 0x10000 and val < 0x6000000:  # Likely address
                    buffer.append((insn.address, f"MOV imm -> 0x{val:x}"))

        # Track constants
        if insn.mnemonic in ('mov', 'lea') and len(insn.op_str) > 0:
            # Check for small integer constants
            matches = re.findall(r'(?:0x)?([0-9a-f]+)', insn.op_str)
            for m in matches:
                try:
                    v = int(m, 16)
                    if v < 0x1000 and v > 0:
                        buffer.append((insn.address, f"const: {v}"))
                except:
                    pass

        # At mapassign call, dump the buffer
        if insn.mnemonic == 'call':
            if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
                callee = insn.operands[0].imm - IMAGE_BASE
                if callee == 0x2dd360:
                    mapassign_count += 1
                    print(f"\n--- mapassign #{mapassign_count} at {hex(insn.address)} ---")
                    for addr, desc in buffer[-15:]:
                        print(f"  0x{addr:010x}: {desc}")
                    buffer = []

        # Clear buffer on certain instructions
        if insn.mnemonic in ('ret', 'jmp') and not insn.op_str.startswith('0x140'):
            pass  # keep buffer

    # ========================================
    # Part 2: Analyze function 0x9ea40 (string comparison/lookup)
    # ========================================
    print("\n\n=== Function 0x9ea40 analysis ===\n")

    off = rva_to_file(0x9ea40, sections)
    if off:
        func_data = data[off:off + 300]
        for insn in md.disasm(func_data, IMAGE_BASE + 0x9ea40):
            if insn.size == 0:
                break
            extra = ""
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    target = insn.address + insn.size + op.mem.disp
                    target_rva = target - IMAGE_BASE
                    s = resolve_string(data, sections, target_rva)
                    if s and len(s) > 1:
                        extra = f'  => "{s[:80]}"'
            if insn.mnemonic == 'ret':
                extra = "  [RETURN]"
            print(f"  0x{insn.address:010x}: {insn.mnemonic:8s} {insn.op_str:40s}{extra}")

    # ========================================
    # Part 3: Search for API endpoint strings in .rdata
    # ========================================
    print("\n\n=== API endpoint strings ===\n")

    rdata_data = data[rdata_raw:rdata_raw + rdata_size]
    for pattern in [b'/algo', b'lingma.alibabacloud', b'tongyi.aliyun',
                    b'api-key', b'apiKey', b'api_key', b'AppSalt', b'appSalt', b'app_salt']:
        for match in re.finditer(pattern, rdata_data, re.IGNORECASE):
            off = match.start()
            rva = rdata_vaddr + off
            end = rdata_data.find(b'\x00', off)
            if end == -1:
                end = min(off + 200, len(rdata_data))
            s = rdata_data[off:end].decode('utf-8', errors='replace')
            print(f"  RVA 0x{rva:x}: \"{s[:150]}\"")

    # ========================================
    # Part 4: Look at 0x880da0 caller for context on getAppSalt return usage
    # ========================================
    print("\n\n=== Caller 0x880da0: getAppSalt call context ===\n")

    off = rva_to_file(0x880da0, sections)
    func_data = data[off:off + 1753]
    md2 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    lines = []
    for insn in md2.disasm(func_data, IMAGE_BASE + 0x880da0):
        if insn.size == 0:
            break
        lines.append((insn.address, insn.mnemonic, insn.op_str))

    # Find the getAppSalt call and surrounding context
    for i, (addr, mnem, ops) in enumerate(lines):
        if mnem == 'call' and '0x140882760' in ops:
            # Print 20 instructions before and after
            start = max(0, i - 10)
            end = min(len(lines), i + 20)
            for j in range(start, end):
                a, m, o = lines[j]
                marker = " <-- getAppSalt" if j == i else ""
                # Resolve string refs
                extra = ""
                if '[rip' in o.lower():
                    # Extract the displacement
                    m2 = re.search(r'\[rip \+ (0x[0-9a-f]+)\]', o, re.IGNORECASE)
                    if m2:
                        disp = int(m2.group(1), 16)
                        target_rva = (a + 7 + disp) - IMAGE_BASE
                        s = resolve_string(data, sections, target_rva)
                        if s:
                            extra = f'  => "{s[:60]}"'
                print(f"  0x{a:010x}: {m:8s} {o:40s}{extra}{marker}")
            break

if __name__ == '__main__':
    main()
