import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import re

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

# Focus on the callers of AesEncryptWithBase64 and find where the KEY comes from
# AesEncryptWithBase64 takes two string arguments:
#   arg1 (RAX): plaintext string
#   arg2 (RDI): key string

# Let's analyze each caller and trace where the key (2nd argument) comes from

# Caller 4 at 0xaf33a6 is interesting - it loads from RIP-relative addresses
# 0x00af3398: mov rcx, [rip + 0x54b5e71]
# 0x00af339f: mov rdi, [rip + 0x54b5e72]
# 0x00af33a6: call 0x455da0

print("=== Analyzing Caller 4 (0xaf33a6) - key from global ===")
offset = va_to_file_offset(sections, 0xaf33a6)
context = pe_data[max(0, offset-100):offset+50]

for insn in md.disasm(context, 0xaf33a6 - 100):
    if insn.address >= 0xaf3350:
        # Highlight RIP-relative loads
        if 'rip' in insn.op_str.lower():
            # Resolve the reference
            parts = insn.op_str.split('+')
            if len(parts) == 2:
                try:
                    disp = int(parts[-1].strip(']'), 16)
                    target_va = insn.address + insn.size + disp
                    ref_offset = va_to_file_offset(sections, target_va)
                    if ref_offset:
                        ref_data = pe_data[ref_offset:ref_offset+40]
                        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ref_data[:40])
                        print(f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str} -> {printable}")
                    else:
                        print(f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}")
                except:
                    print(f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}")
        else:
            print(f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}")

# Caller 5 at 0xb96f68
# 0x00b96f5c: lea rcx, [rip + 0x1918395]
# 0x00b96f63: mov edi, 0x10
# 0x00b96f68: call 0x455da0
print("\n\n=== Analyzing Caller 5 (0xb96f68) ===")
offset = va_to_file_offset(sections, 0xb96f68)
context = pe_data[max(0, offset-200):offset+50]

for insn in md.disasm(context, 0xb96f68 - 200):
    if insn.address >= 0xb96f40:
        if 'rip' in insn.op_str.lower():
            parts = insn.op_str.split('+')
            if len(parts) == 2:
                try:
                    disp = int(parts[-1].strip(']'), 16)
                    target_va = insn.address + insn.size + disp
                    ref_offset = va_to_file_offset(sections, target_va)
                    if ref_offset:
                        ref_data = pe_data[ref_offset:ref_offset+40]
                        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ref_data[:40])
                        print(f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str} -> {printable}")
                    else:
                        print(f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}")
                except:
                    print(f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}")
        else:
            print(f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}")

# Now let's look at the encrypt package callers
# Functions at 0x88eea6 and 0x892305 are likely in the same package as AesEncryptWithBase64
# They're in the 0x88xxxx-0x89xxxx range

# Let's search for the Go package name by looking at the pclntab
print("\n\n=== Searching for function names in pclntab ===")
# The pclntab is in .rdata
# Let's look for function names near the encrypt package
rdata_section = sections[1]
rdata_raw = pe_data[rdata_section['raw_offset']:rdata_section['raw_offset'] + rdata_section['raw_size']]

# Search for "encrypt" in function names
for m in re.finditer(b'encrypt', rdata_raw):
    start = max(0, m.start() - 50)
    end = min(len(rdata_raw), m.end() + 100)
    context = rdata_raw[start:end]
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
    va = rdata_section['virtual_address'] + m.start()
    print(f"  0x{va:x}: ...{printable}...")

# Also search for "cosy" package references
print("\n\n=== cosy package references ===")
for m in re.finditer(b'cosy', rdata_raw):
    start = max(0, m.start() - 30)
    end = min(len(rdata_raw), m.end() + 100)
    context = rdata_raw[start:end]
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
    va = rdata_section['virtual_address'] + m.start()
    # Only show if it looks like a full package path
    if b'/' in context or b'.' in context:
        print(f"  0x{va:x}: ...{printable}...")
