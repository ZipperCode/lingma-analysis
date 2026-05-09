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

# CustomEncryptV1 is at RVA 0x455800 (from symbol strings)
# Let's disassemble it to understand the encryption algorithm

print("=== CustomEncryptV1 disassembly ===")
# The function is very long, so let's get the first 200 instructions
offset = va_to_file_offset(sections, 0x455800)
func_data = pe_data[offset:offset + 8000]

instructions = []
for insn in md.disasm(func_data, 0x455800):
    instructions.append(insn)
    if insn.mnemonic == 'ret' and len(instructions) > 100:
        break
    if len(instructions) > 500:
        break

print(f"Total instructions: {len(instructions)}")
for insn in instructions[:200]:
    print(f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}")

if len(instructions) > 200:
    print(f"\n  ... ({len(instructions) - 200} more instructions) ...")
    print("\n  Last 30 instructions:")
    for insn in instructions[-30:]:
        print(f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}")

# Now search for callers of CustomEncryptV1
print("\n\n=== Searching for callers of CustomEncryptV1 ===")
text_section = sections[0]
text_raw = pe_data[text_section['raw_offset']:text_section['raw_offset'] + text_section['raw_size']]

target_va = 0x455800
callers = []

i = 0
while i < len(text_raw) - 5:
    if text_raw[i] == 0xE8:
        rel32 = struct.unpack('<i', text_raw[i+1:i+5])[0]
        caller_va = text_section['virtual_address'] + i
        target = caller_va + 5 + rel32
        if target == target_va:
            callers.append(caller_va)
            i += 5
            continue
    i += 1

print(f"Found {len(callers)} callers of CustomEncryptV1")
for caller_va in callers[:10]:
    offset = va_to_file_offset(sections, caller_va)
    if offset:
        context_data = pe_data[max(0, offset-150):offset + 30]
        print(f"\n  Caller at VA 0x{caller_va:x}:")
        for insn in md.disasm(context_data, caller_va - 150):
            if insn.address >= caller_va - 40:
                print(f"    0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}")

# Also look for the inner function at 0x454f80
# This is called from within CustomEncryptV1
print("\n\n=== Function at 0x454f80 (inner encoding function) ===")
offset = va_to_file_offset(sections, 0x454f80)
func_data = pe_data[offset:offset + 3000]

instructions = []
for insn in md.disasm(func_data, 0x454f80):
    instructions.append(insn)
    if insn.mnemonic == 'ret' and len(instructions) > 50:
        break
    if len(instructions) > 400:
        break

print(f"Total instructions: {len(instructions)}")
for insn in instructions[:100]:
    print(f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}")
