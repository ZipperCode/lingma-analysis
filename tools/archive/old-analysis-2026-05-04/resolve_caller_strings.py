"""
解析 Caller 0x88eea6 和 0x892305 的字符串引用
确定这些调用者属于哪个函数
"""
import struct

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

def parse_sections(pe_data):
    e_lfanew = struct.unpack('<I', pe_data[60:64])[0]
    coff_offset = e_lfanew + 4
    num_sections = struct.unpack('<H', pe_data[coff_offset+2:coff_offset+4])[0]
    opt_header_size = struct.unpack('<H', pe_data[coff_offset+16:coff_offset+18])[0]
    section_offset = coff_offset + 20 + opt_header_size

    sections = []
    for i in range(num_sections):
        sec = pe_data[section_offset + i*40 : section_offset + (i+1)*40]
        sections.append({
            'name': sec[0:8].rstrip(b'\x00').decode('ascii', errors='replace'),
            'virtual_address': struct.unpack('<I', sec[12:16])[0],
            'virtual_size': struct.unpack('<I', sec[8:12])[0],
            'raw_offset': struct.unpack('<I', sec[20:24])[0],
            'raw_size': struct.unpack('<I', sec[16:20])[0],
        })
    return sections

def va_to_file_offset(sections, va):
    for sec in sections:
        va_start = sec['virtual_address']
        va_end = va_start + max(sec['virtual_size'], sec['raw_size'])
        if va_start <= va < va_end:
            return sec['raw_offset'] + (va - va_start)
    return None

sections = parse_sections(pe_data)

def resolve_rip_lea(data, offset, instruction_va, sections):
    """Resolve [rip + disp] reference"""
    # LEA with RIP-relative: the RIP value is the address of the next instruction
    # We need to find the displacement in the instruction encoding
    # LEA reg, [rip+disp32] = 48 8D modrm sib disp32
    # Find the disp32 in the bytes
    idx = None
    for i in range(max(0, len(data)-10), len(data)):
        if data[i:i+2] == b'\x48\x8d' or data[i:i+2] == b'\x8d':
            # Found LEA, look for disp32
            # The disp32 is after modrm and optional sib
            pass

    # Simpler: just take the last 4 bytes before the instruction as the displacement
    # Actually, let's parse the instruction properly

    # For now, use capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # Get a window around the offset
    window = data[max(0, offset-20):offset+20]
    va_start = instruction_va - 20

    for insn in md.disasm(window, va_start):
        if insn.address == instruction_va and insn.mnemonic == 'lea':
            op = insn.op_str
            if 'rip' in op:
                # Parse displacement
                if '+' in op:
                    parts = op.split('+')
                    disp_str = parts[1].strip().rstrip('h')
                    try:
                        disp = int(disp_str, 16)
                        target_va = insn.address + insn.size + disp
                        file_off = va_to_file_offset(sections, target_va)
                        if file_off and 0 < file_off < len(pe_data):
                            content = pe_data[file_off:file_off+100]
                            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in content)
                            return target_va, printable
                    except:
                        pass
    return None, None

# Now let's find ALL callers of AesEncryptWithBase64 and their string refs
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)

text_section = sections[0]
text_raw = pe_data[text_section['raw_offset']:text_section['raw_offset'] + text_section['raw_size']]

print("=== Finding ALL callers of AesEncryptWithBase64 (0x455da0) ===")
callers = []
i = 0
while i < len(text_raw) - 5:
    if text_raw[i] == 0xE8:
        rel32 = struct.unpack('<i', text_raw[i+1:i+5])[0]
        caller_va = text_section['virtual_address'] + i
        target = caller_va + 5 + rel32
        if target == 0x455da0:
            callers.append(caller_va)
            i += 5
            continue
    i += 1

print(f"Found {len(callers)} callers: {[f'0x{c:x}' for c in callers]}")

# For each caller, get the 500 bytes before and find string references
for caller_va in callers:
    offset = va_to_file_offset(sections, caller_va)
    if offset is None:
        continue

    print(f"\n\n{'='*60}")
    print(f"Caller at VA 0x{caller_va:x}")
    print(f"{'='*60}")

    context_data = pe_data[max(0, offset-500):offset + 50]
    context_va = caller_va - 500

    instructions = list(md.disasm(context_data, context_va))

    # Find LEA with RIP references
    for insn in instructions:
        if insn.mnemonic == 'lea' and 'rip' in insn.op_str:
            target_va, content = resolve_rip_lea(pe_data, va_to_file_offset(sections, insn.address), insn.address, sections)
            if target_va and content:
                print(f"  0x{insn.address:08x}: LEA -> VA 0x{target_va:x}")
                print(f"    Content: ...{content[:80]}...")

    # Also find any direct string references (MOV with immediate values that point to .rdata)
    for insn in instructions:
        if insn.mnemonic == 'mov':
            op = insn.op_str
            # Check if any operand is a large immediate (potential VA)
            parts = op.split(', ')
            for part in parts:
                part = part.strip().rstrip('h')
                try:
                    val = int(part, 16)
                    if val > 0x140000000 and val < 0x141000000:
                        # This is a VA
                        file_off = va_to_file_offset(sections, val)
                        if file_off and 0 < file_off < len(pe_data):
                            content = pe_data[file_off:file_off+80]
                            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in content)
                            print(f"  0x{insn.address:08x}: MOV immediate -> VA 0x{val:x}")
                            print(f"    Content: ...{printable}...")
                except:
                    pass
