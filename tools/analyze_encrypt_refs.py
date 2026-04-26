import struct

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

def rva_to_file_offset(sections, rva):
    for sec in sections:
        va = sec['virtual_address']
        if va <= rva < va + max(sec['virtual_size'], sec['raw_size']):
            return sec['raw_offset'] + (rva - va)
    return None

with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

sections = parse_sections(pe_data)

# Analyze key references in AesEncryptWithBase64
print("=== AesEncryptWithBase64 references ===")

# At 0x455e9e: lea rax, [rip + 0x1c4f29b]
# RIP at that point = 0x455e9e + 7 (instruction length) = 0x455ea5
ref1_addr = 0x455ea5
ref1_disp = 0x1c4f29b
ref1_target = ref1_addr + ref1_disp
ref1_rva = ref1_target - IMAGE_BASE
ref1_offset = rva_to_file_offset(sections, ref1_rva)
print(f"\nLEA at 0x455e9e: [rip + 0x{ref1_disp:x}]")
print(f"  Target address: 0x{ref1_target:x}")
print(f"  Target RVA: 0x{ref1_rva:x}")
if ref1_offset:
    data = pe_data[ref1_offset:ref1_offset+80]
    print(f"  Data: {data[:80]}")
    # Try to interpret as string
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:80])
    print(f"  ASCII: {printable}")

# At 0x455ee2: mov rax, qword ptr [rip + 0x5c52a57]
# RIP at that point = 0x455ee2 + 7 = 0x455ee9
ref2_addr = 0x455ee9
ref2_disp = 0x5c52a57
ref2_target = ref2_addr + ref2_disp
ref2_rva = ref2_target - IMAGE_BASE
ref2_offset = rva_to_file_offset(sections, ref2_rva)
print(f"\nMOV global at 0x455ee2: [rip + 0x{ref2_disp:x}]")
print(f"  Target address: 0x{ref2_target:x}")
print(f"  Target RVA: 0x{ref2_rva:x}")
if ref2_offset:
    data = pe_data[ref2_offset:ref2_offset+32]
    print(f"  Data (32 bytes): {data.hex()}")
    # Could be a pointer to an AES cipher object

# Also find the call targets
calls_in_aes = {
    'call 0x5bfe0': 0x5bfe0,     # likely string-to-bytes / makeSlice
    'call 0x1857e0': 0x1857e0,   # likely aes.NewCipher
    'call 0x456280': 0x456280,   # pkcs5Padding
    'call 0x180d60': 0x180d60,   # likely CBC encryption
    'call 0x57c20': 0x57c20,     # newEncoding
    'call 0x143c60': 0x143c60,   # encodeToString
}

print("\n=== Call targets in AesEncryptWithBase64 ===")
for name, rva in calls_in_aes.items():
    offset = rva_to_file_offset(sections, rva)
    print(f"  {name}: file offset 0x{offset:x}")

# Also check the second function starting at 0x455f40
# This appears to be AesDecryptWithBase64
print("\n=== AesDecryptWithBase64 references ===")
# At 0x455f6f: mov rdx, qword ptr [rip + 0x5c529ca]
# RIP = 0x455f76
ref3_addr = 0x455f76
ref3_disp = 0x5c529ca
ref3_target = ref3_addr + ref3_disp
ref3_rva = ref3_target - IMAGE_BASE
ref3_offset = rva_to_file_offset(sections, ref3_rva)
print(f"\nMOV global at 0x455f6f: [rip + 0x{ref3_disp:x}]")
print(f"  Target RVA: 0x{ref3_rva:x}")
if ref3_offset:
    data = pe_data[ref3_offset:ref3_offset+32]
    print(f"  Data (32 bytes): {data.hex()}")

# At 0x455ffa: lea rax, [rip + 0x1c4f13f]
ref4_addr = 0x456001
ref4_disp = 0x1c4f13f
ref4_target = ref4_addr + ref4_disp
ref4_rva = ref4_target - IMAGE_BASE
ref4_offset = rva_to_file_offset(sections, ref4_rva)
print(f"\nLEA at 0x455ffa: [rip + 0x{ref4_disp:x}]")
print(f"  Target RVA: 0x{ref4_rva:x}")
if ref4_offset:
    data = pe_data[ref4_offset:ref4_offset+80]
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:80])
    print(f"  ASCII: {printable}")

# Now let's find what calls AesEncryptWithBase64
# Search for calls to 0x455da0
print("\n=== Searching for callers of AesEncryptWithBase64 (0x455da0) ===")
# Look for E8 xx xx xx xx (CALL rel32) or FF /2 (CALL reg/mem)
# E8 = CALL rel32
call_pattern = struct.pack('<I', 0x455da0 - 0x140000000)  # No, calls use relative offsets
# Actually, Go code might call directly using the absolute address
# Let's search for the bytes that encode "call 0x455da0"
# The relative offset would be: 0x455da0 - (caller_addr + 5)
# We don't know the caller, so let's search in .text for E8 bytes

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)

def rva_from_file_offset(sections, file_offset):
    for sec in sections:
        ra = sec['raw_offset']
        if ra <= file_offset < ra + sec['raw_size']:
            return sec['virtual_address'] + (file_offset - ra)
    return None

# Search .text for calls to 0x455da0
text_section = sections[0]
text_data = pe_data[text_section['raw_offset']:text_section['raw_offset'] + min(text_section['raw_size'], 0x500000)]

# Check first 0x500000 bytes of .text
callers = []
for addr_offset in range(0, len(text_data) - 5, 1):
    # Check for E8 (CALL rel32)
    if text_data[addr_offset] == 0xE8:
        rel32 = struct.unpack('<i', text_data[addr_offset+1:addr_offset+5])[0]
        caller_rva = text_section['virtual_address'] + addr_offset
        target = caller_rva + 5 + rel32
        if target == 0x455da0:
            callers.append(caller_rva)

print(f"Found {len(callers)} direct calls to AesEncryptWithBase64")
for c in callers[:10]:
    # Show 100 bytes before the call to understand the context
    offset = rva_to_file_offset(sections, c)
    if offset:
        # Show 200 bytes before
        context_data = pe_data[max(0, offset-200):offset+30]
        # Disassemble
        caller_rva = c
        for insn in md.disasm(context_data, caller_rva - 200):
            if insn.address >= caller_rva - 50:
                print(f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}")
        print()
