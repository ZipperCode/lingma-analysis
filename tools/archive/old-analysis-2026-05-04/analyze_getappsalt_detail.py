"""
详细分析 getAppSalt (0x882760) 的调用图和函数体。
使用 capstone 进行反汇编，追踪所有字符串引用和函数调用。
"""
import struct
import capstone
import re

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

def rva_to_file(rva, sections):
    for name, vaddr, raw_addr, raw_size in sections:
        if vaddr <= rva < vaddr + raw_size:
            return raw_addr + (rva - vaddr)
    return None

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

def resolve_string(data, sections, rva):
    """Resolve RVA to a null-terminated string."""
    off = rva_to_file(rva, sections)
    if off and 0 < off < len(data) - 1:
        end = data.find(b'\x00', off)
        if end > off and end - off < 500:
            return data[off:end].decode('utf-8', errors='replace')
    return None

def resolve_addr(data, sections, addr):
    """Resolve absolute VA to string."""
    return resolve_string(data, sections, addr - IMAGE_BASE)

def disassemble_function(data, sections, rva, size, name=""):
    """Full disassembly with string resolution."""
    off = rva_to_file(rva, sections)
    if off is None:
        print(f"  [Cannot find file offset for {hex(rva)}]")
        return []

    func_data = data[off:off + size]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    print(f"\n{'='*70}")
    print(f"Function: {name} RVA={hex(rva)} size={size}")
    print(f"{'='*70}")

    calls = []
    strings = []
    code_bytes = bytes(func_data)

    for insn in md.disasm(code_bytes, IMAGE_BASE + rva):
        if insn.size == 0:
            break

        extra = ""

        # Resolve string references
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                # RIP-relative: target = insn.address + insn.size + disp
                target = insn.address + insn.size + op.mem.disp
                target_rva = target - IMAGE_BASE
                s = resolve_string(data, sections, target_rva)
                if s and len(s) > 1:
                    extra = f"  => \"{s[:120]}\""
                    strings.append((insn.address, target_rva, s[:120]))

        # Highlight CALL instructions
        if insn.mnemonic == 'call':
            if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
                callee_rva = insn.operands[0].imm - IMAGE_BASE
                extra = f"  [CALL RVA: 0x{callee_rva:x}]"
                calls.append(callee_rva)
            elif insn.operands and insn.operands[0].type == capstone.x86.X86_OP_MEM:
                extra = "  [CALL indirect]"
                calls.append(None)

        if insn.mnemonic == 'ret':
            extra = "  [RETURN]"

        print(f"  0x{insn.address:010x}: {insn.mnemonic:8s} {insn.op_str:40s}{extra}")

    return calls, strings

def main():
    with open(LINGMA, 'rb') as f:
        data = f.read()

    sections = parse_sections(data)
    print(f"Found {len(sections)} sections")
    for name, vaddr, raw_addr, raw_size in sections:
        print(f"  {name:12s} VA={hex(vaddr):12s} size={hex(raw_size):8s} raw={hex(raw_addr):8s}")

    # Disassemble getAppSalt
    print("\n\n")
    getAppSalt_calls, getAppSalt_strings = disassemble_function(
        data, sections, 0x882760, 1087, "getAppSalt")

    # Print unique string refs
    print(f"\n\ngetAppSalt string references ({len(getAppSalt_strings)}):")
    for addr, target_rva, s in getAppSalt_strings:
        print(f"  0x{addr:010x}: -> RVA 0x{target_rva:x} \"{s}\"")

    # Print call targets
    print(f"\ngetAppSalt call targets ({len(getAppSalt_calls)}):")
    for i, c in enumerate(getAppSalt_calls):
        if c:
            print(f"  CALL #{i+1}: RVA 0x{c:x}")

    # Analyze the caller (0x880da0)
    print("\n\n")
    caller_calls, caller_strings = disassemble_function(
        data, sections, 0x880da0, 1753, "remoting_request_builder (caller)")

    print(f"\n\nCaller string references ({len(caller_strings)}):")
    for addr, target_rva, s in caller_strings:
        print(f"  0x{addr:010x}: -> RVA 0x{target_rva:x} \"{s}\"")

    # Look for salt-related strings in .rdata
    print("\n\n=== Searching .rdata for 'salt' strings ===")
    rdata_name, rdata_vaddr, rdata_raw, rdata_size = [s for s in sections if s[0] == '.rdata'][0]

    # Search for all occurrences of "salt" in .rdata
    rdata_data = data[rdata_raw:rdata_raw + rdata_size]
    for match in re.finditer(b'(?i)salt', rdata_data):
        off = match.start()
        rva = rdata_vaddr + off
        end = rdata_data.find(b'\x00', off)
        if end == -1:
            end = min(off + 200, len(rdata_data))
        s = rdata_data[off:end].decode('utf-8', errors='replace')
        # Show context
        context_start = max(0, off - 50)
        context_end = min(len(rdata_data), end + 50)
        context = rdata_data[context_start:context_end]
        print(f"  RVA 0x{rva:x} (off 0x{off:x}): \"{s[:100]}\"")

    # Also analyze key callees from getAppSalt
    key_callees = [c for c in getAppSalt_calls if c and 0x10000 < c < 0x2000000]
    print(f"\n\n=== Analyzing key callees from getAppSalt ===")
    for callee in key_callees[:10]:  # Only first 10
        try:
            off = rva_to_file(callee, sections)
            if off and off + 50 < len(data):
                # Read first 100 bytes
                callee_data = data[off:off + 100]
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                print(f"\n--- Function at RVA 0x{callee:x} ---")
                for insn in md.disasm(callee_data, IMAGE_BASE + callee):
                    if insn.size == 0:
                        break
                    print(f"  0x{insn.address:010x}: {insn.mnemonic:8s} {insn.op_str}")
        except Exception as e:
            print(f"\n--- RVA 0x{callee:x}: Error: {e} ---")

if __name__ == '__main__':
    main()
