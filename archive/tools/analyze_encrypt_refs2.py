import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000

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
    """Convert virtual address (as shown by capstone) to file offset"""
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

print("=== Key references in AesEncryptWithBase64 ===")

# LEA at 0x455e9e: lea rax, [rip + 0x1c4f29b]
# RIP when executed = 0x455e9e + 7 = 0x455ea5
# Target VA = 0x455ea5 + 0x1c4f29b = 0x20a5140
ref1_rip = 0x455ea5
ref1_target_va = ref1_rip + 0x1c4f29b
ref1_offset = va_to_file_offset(sections, ref1_target_va)
print(f"\nLEA [rip + 0x1c4f29b] at 0x455e9e:")
print(f"  Target VA: 0x{ref1_target_va:x}")
if ref1_offset:
    data = pe_data[ref1_offset:ref1_offset+100]
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:100])
    print(f"  Data: {data[:100].hex()}")
    print(f"  ASCII: {printable}")

# MOV global at 0x455ee2: mov rax, qword ptr [rip + 0x5c52a57]
# RIP = 0x455ee9
ref2_rip = 0x455ee9
ref2_target_va = ref2_rip + 0x5c52a57
ref2_offset = va_to_file_offset(sections, ref2_target_va)
print(f"\nMOV [rip + 0x5c52a57] at 0x455ee2:")
print(f"  Target VA: 0x{ref2_target_va:x}")
if ref2_offset:
    data = pe_data[ref2_offset:ref2_offset+64]
    print(f"  Data: {data.hex()}")

# Same reference used by AesDecryptWithBase64
# At 0x455f6f: mov rdx, qword ptr [rip + 0x5c529ca]
ref3_rip = 0x455f76
ref3_target_va = ref3_rip + 0x5c529ca
ref3_offset = va_to_file_offset(sections, ref3_target_va)
print(f"\nMOV [rip + 0x5c529ca] at 0x455f6f:")
print(f"  Target VA: 0x{ref3_target_va:x}")

# Search for callers of AesEncryptWithBase64
print("\n=== Callers of AesEncryptWithBase64 ===")
text_section = sections[0]
text_raw = pe_data[text_section['raw_offset']:text_section['raw_offset'] + text_section['raw_size']]

callers = []
target_va = 0x455da0

i = 0
while i < len(text_raw) - 5:
    if text_raw[i] == 0xE8:
        rel32 = struct.unpack('<i', text_raw[i+1:i+5])[0]
        caller_va = text_section['virtual_address'] + i
        target = caller_va + 5 + rel32
        if target == target_va:
            callers.append(caller_va)
            i += 5  # Skip the call instruction
            continue
    i += 1

print(f"Found {len(callers)} callers")
for caller_va in callers[:15]:
    offset = va_to_file_offset(sections, caller_va)
    if offset:
        # Get 100 bytes before the call for context
        context_start = max(0, offset - 150)
        context_data = pe_data[context_start:offset + 30]
        print(f"\n  Caller at VA 0x{caller_va:x}:")
        for insn in md.disasm(context_data, caller_va - 150):
            if insn.address >= caller_va - 40:
                print(f"    0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}")

# Also search for callers of the decrypt function
print("\n=== Callers of AesDecryptWithBase64 ===")
decrypt_va = 0x455f40
decrypt_callers = []

i = 0
while i < len(text_raw) - 5:
    if text_raw[i] == 0xE8:
        rel32 = struct.unpack('<i', text_raw[i+1:i+5])[0]
        caller_va = text_section['virtual_address'] + i
        target = caller_va + 5 + rel32
        if target == decrypt_va:
            decrypt_callers.append(caller_va)
            i += 5
            continue
    i += 1

print(f"Found {len(decrypt_callers)} callers")
for caller_va in decrypt_callers[:15]:
    offset = va_to_file_offset(sections, caller_va)
    if offset:
        context_start = max(0, offset - 150)
        context_data = pe_data[context_start:offset + 30]
        print(f"\n  Caller at VA 0x{caller_va:x}:")
        for insn in md.disasm(context_data, caller_va - 150):
            if insn.address >= caller_va - 40:
                print(f"    0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}")
