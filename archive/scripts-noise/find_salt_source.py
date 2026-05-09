"""
搜索 .rdata 中所有与 "salt" 相关的字符串，
并追踪 getAppSalt 中配置查找函数 0xa82c0 的行为。
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

def resolve_string(data, sections, rva, max_len=200):
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

    # ========================================
    # Step 1: Search all "salt" strings in .rdata
    # ========================================
    print("=== Step 1: Search 'salt' strings in .rdata ===\n")

    rdata_name, rdata_vaddr, rdata_raw, rdata_size = [s for s in sections if s[0] == '.rdata'][0]
    rdata_data = data[rdata_raw:rdata_raw + rdata_size]

    salt_locations = []
    for match in re.finditer(b'(?i)salt', rdata_data):
        off = match.start()
        rva = rdata_vaddr + off
        end = rdata_data.find(b'\x00', off)
        if end == -1:
            end = min(off + 200, len(rdata_data))
        s = rdata_data[off:end].decode('utf-8', errors='replace')
        if len(s) > 2:
            salt_locations.append((off, rva, s))
            print(f"  Off 0x{off:8x} RVA 0x{rva:x}: \"{s[:120]}\"")

    print(f"\nFound {len(salt_locations)} 'salt' string locations\n")

    # ========================================
    # Step 2: Analyze config lookup function 0xa82c0
    # ========================================
    print("=== Step 2: Analyze config function 0xa82c0 ===\n")

    off = rva_to_file(0xa82c0, sections)
    if off:
        # Read first 500 bytes and disassemble
        func_data = data[off:off + 500]
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True

        calls = []
        strings = []
        for insn in md.disasm(func_data, IMAGE_BASE + 0xa82c0):
            if insn.size == 0:
                break
            extra = ""

            # Check for string refs
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    target = insn.address + insn.size + op.mem.disp
                    target_rva = target - IMAGE_BASE
                    s = resolve_string(data, sections, target_rva)
                    if s and len(s) > 1:
                        extra = f'  => "{s[:100]}"'
                        strings.append((insn.address, target_rva, s[:100]))

            if insn.mnemonic == 'call':
                if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
                    callee_rva = insn.operands[0].imm - IMAGE_BASE
                    extra = f"  [CALL RVA: 0x{callee_rva:x}]"
                    calls.append(callee_rva)

            if insn.mnemonic == 'ret':
                extra = "  [RETURN]"

            print(f"  0x{insn.address:010x}: {insn.mnemonic:8s} {insn.op_str:40s}{extra}")

        print(f"\nString refs in 0xa82c0:")
        for addr, rva, s in strings:
            print(f"  0x{addr:010x}: -> RVA 0x{rva:x} \"{s}\"")

        print(f"\nCall targets from 0xa82c0:")
        for c in calls:
            print(f"  RVA 0x{c:x}")

    # ========================================
    # Step 3: Search for cosy-related config strings
    # ========================================
    print("\n\n=== Step 3: Search for cosy/app config strings ===\n")

    # Search for strings like "cosy.app", "app.salt", etc.
    patterns = [b'cosy', b'app\.salt', b'app_salt', b'app-salt',
                b'SaltLength', b'saltBytes', b'salt_value', b'getSalt']

    for pattern in patterns:
        for match in re.finditer(pattern, rdata_data):
            off = match.start()
            rva = rdata_vaddr + off
            end = rdata_data.find(b'\x00', off)
            if end == -1:
                end = min(off + 200, len(rdata_data))
            # Get a smaller context
            ctx_start = max(0, off - 20)
            ctx_end = min(len(rdata_data), end + 30)
            context = rdata_data[ctx_start:ctx_end]
            s = rdata_data[off:end].decode('utf-8', errors='replace')
            if len(s) > 3:
                print(f"  Pattern {pattern}: Off 0x{off:8x} RVA 0x{rva:x}: \"{s[:150]}\"")

    # ========================================
    # Step 4: Search for salt-related global variable references
    # ========================================
    print("\n\n=== Step 4: Find globals referenced by getAppSalt ===\n")

    # Look for LEA instructions in getAppSalt that point to .data section
    data_name, data_vaddr, data_raw, data_size = [s for s in sections if s[0] == '.data'][0]

    off = rva_to_file(0x882760, sections)
    func_data = data[off:off + 1087]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    data_refs = []
    for insn in md.disasm(func_data, IMAGE_BASE + 0x882760):
        if insn.size == 0:
            break
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                target = insn.address + insn.size + op.mem.disp
                target_rva = target - IMAGE_BASE
                # Check if it's in .data section
                if data_vaddr <= target_rva < data_vaddr + data_size:
                    print(f"  0x{insn.address:010x}: {insn.mnemonic} {insn.op_str}")
                    print(f"    -> .data RVA 0x{target_rva:x}")
                    # Try to read the value
                    data_off = rva_to_file(target_rva, sections)
                    if data_off:
                        val = data[data_off:data_off + 8]
                        print(f"    Value: {val.hex()}")
                    data_refs.append(target_rva)

    if not data_refs:
        print("  No .data references found in getAppSalt")

    # ========================================
    # Step 5: Look at the global vars referenced by 0x880da0 (the caller)
    # ========================================
    print("\n\n=== Step 5: Global var refs in caller 0x880da0 ===\n")

    off = rva_to_file(0x880da0, sections)
    func_data = data[off:off + 1753]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    data_refs2 = []
    for insn in md.disasm(func_data, IMAGE_BASE + 0x880da0):
        if insn.size == 0:
            break
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                target = insn.address + insn.size + op.mem.disp
                target_rva = target - IMAGE_BASE
                if data_vaddr <= target_rva < data_vaddr + data_size:
                    s = resolve_string(data, sections, target_rva)
                    data_off = rva_to_file(target_rva, sections)
                    if data_off:
                        val = data[data_off:data_off + 8]
                    print(f"  0x{insn.address:010x}: {insn.mnemonic:8s} {insn.op_str:35s} -> .data 0x{target_rva:x} val={val.hex() if data_off else 'N/A'}")
                    if s:
                        print(f"    => \"{s[:100]}\"")
                    data_refs2.append(target_rva)

if __name__ == '__main__':
    main()
