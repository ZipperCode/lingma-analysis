import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

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

with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

sections = parse_sections(pe_data)
md = Cs(CS_ARCH_X86, CS_MODE_64)

# Analyze the callers in more detail - get 500 bytes before each call
callers_to_analyze = [
    (0x88eea6, "Caller 1 (0x88eea6)"),
    (0x892305, "Caller 2 (0x892305)"),
    (0x8926e2, "Caller 3 (0x8926e2)"),
    (0xaf33a6, "Caller 4 (0xaf33a6)"),
    (0xb96f68, "Caller 5 (0xb96f68)"),
]

for caller_va, name in callers_to_analyze:
    offset = va_to_file_offset(sections, caller_va)
    if not offset:
        continue

    # Get 500 bytes before the call
    context_start = max(0, offset - 500)
    context_data = pe_data[context_start:offset + 50]

    print(f"\n{'='*80}")
    print(f"{name}")
    print(f"{'='*80}")

    for insn in md.disasm(context_data, caller_va - 500):
        if insn.address >= caller_va - 500:
            # Highlight key instructions
            line = f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}"
            # Highlight LEA, MOV with RIP, and CALL
            if 'rip' in insn.op_str.lower() or insn.mnemonic == 'call' or insn.mnemonic == 'lea':
                line = f"  **0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}**"
            print(line)

    print()

# Also, let's examine the function at 0x88eea6 more carefully
# This appears to be a function that creates the encoding and calls AesEncryptWithBase64
# Let's find the start of this function

print("\n\n=== Finding function starts ===")
# Functions start with stack check or prologue
# Look backward from 0x88eea6 to find the function start
for target_va, name in [(0x88eea6, "function containing caller 1"),
                          (0x88f252, "function containing decrypt caller 1")]:
    offset = va_to_file_offset(sections, target_va)
    if not offset:
        continue

    # Look backward for function prologue
    # Typically: cmp rsp, [r14+0x10] / jbe / push rbp / mov rbp, rsp / sub rsp, N
    search_start = max(0, offset - 2000)
    search_data = pe_data[search_start:offset + 100]

    # Find the first "cmp rsp, qword ptr [r14 + 0x10]" pattern
    # This is: 4C 39 76 10 or 4C 39 64 24 XX
    func_start_offset = None
    func_start_va = None

    for i in range(len(search_data) - 8):
        # Look for the pattern: cmp rsp, [r14+0x10] (4C 39 76 10) followed by jbe
        if search_data[i:i+4] == b'\x4c\x39\x76\x10' or search_data[i:i+4] == b'\x4c\x39\xe4':
            # Found potential function start
            # Check if followed by jbe (0F 86)
            if i + 6 < len(search_data) and search_data[i+4:i+6] == b'\x0f\x86':
                func_start_offset = i
                func_start_va = target_va - 500 + (i - (offset - 500 - search_start))
                break

    if func_start_offset:
        print(f"\nFunction start for {name}: VA 0x{func_start_va:x}")
        # Disassemble the whole function
        func_data = pe_data[va_to_file_offset(sections, func_start_va):va_to_file_offset(sections, func_start_va) + 2000]
        func_end = False
        for insn in md.disasm(func_data, func_start_va):
            print(f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}")
            if insn.mnemonic == 'ret' and insn.address > func_start_va + 100:
                func_end = True
                break
