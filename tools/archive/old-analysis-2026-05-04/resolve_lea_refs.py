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

# Collect all LEA references with RIP-relative addressing from Caller 1
# and resolve them to actual strings/data
print("=== Resolving LEA references from Caller 1 function ===")

# Key LEA references found:
# 0x88ed5e: lea eax, [rip + 0x1acf27c]
# 0x88ed64: lea rbx, [rip + 0x58211f5]
# 0x88ee0e: lea rax, [rip + 0x1c019f2]
# 0x88ee29: lea rax, [rip + 0x1c01e69]
# 0x88ee5a: lea rax, [rip + 0x1acf17f]
# 0x88ee70: lea rax, [rip + 0x1acf169]

refs = [
    (0x88ed61, 0x1acf27c, "LEA 1 (0x88ed5e)"),
    (0x88ed6b, 0x58211f5, "LEA 2 (0x88ed64) - key?"),
    (0x88ee15, 0x1c019f2, "LEA 3 (0x88ee0e)"),
    (0x88ee30, 0x1c01e69, "LEA 4 (0x88ee29)"),
    (0x88ee61, 0x1acf17f, "LEA 5 (0x88ee5a)"),
    (0x88ee77, 0x1acf169, "LEA 6 (0x88ee70)"),
]

for rip_val, disp, name in refs:
    target_va = rip_val + disp
    offset = va_to_file_offset(sections, target_va)
    print(f"\n{name}:")
    print(f"  RIP + disp = 0x{rip_val:x} + 0x{disp:x} = 0x{target_va:x}")
    print(f"  File offset: 0x{offset:x}")
    if offset:
        data = pe_data[offset:offset+80]
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:80])
        hex_str = data[:64].hex()
        print(f"  Hex (first 64): {hex_str}")
        print(f"  ASCII: {printable}")

        # If it looks like a Go string, also check the length prefix
        # Go string header: ptr + len
        ptr = struct.unpack('<Q', data[0:8])[0]
        if ptr < 0x10000000:  # Not a pointer, might be inline string data
            str_len = struct.unpack('<Q', data[8:16])[0]
            if 0 < str_len < 1000:
                str_data = pe_data[va_to_file_offset(sections, ptr):va_to_file_offset(sections, ptr)+str_len] if ptr > 0x1000 else b''
                if str_data:
                    print(f"  -> Go string: len={str_len}, data={str_data[:100]}")

# Now let's find ALL string constants near these references
# The strings are likely in .rodata or .data sections
print("\n\n=== Searching for string constants in .rdata ===")
rdata_section = sections[1]  # .rdata
rdata_offset = rdata_section['raw_offset']
rdata_va = rdata_section['virtual_address']

# Search for readable strings near the LEA targets
for rip_val, disp, name in refs:
    target_va = rip_val + disp
    if target_va >= rdata_va and target_va < rdata_va + rdata_section['virtual_size']:
        file_offset = rdata_offset + (target_va - rdata_va)
        # Search backward for the start of a string
        data = pe_data[max(rdata_offset, file_offset-50):file_offset+200]
        # Find the nearest null-terminated string
        # Look for the nearest string start (preceded by null byte)
        for i in range(len(data)):
            if data[i] == 0 and i + 1 < len(data):
                # Check if the rest is a printable string
                str_start = i + 1
                str_end = str_start
                while str_end < len(data) and data[str_end] != 0 and data[str_end] != 0:
                    str_end += 1
                if str_end - str_start > 5:
                    s = data[str_start:str_end].decode('ascii', errors='replace')
                    if all(32 <= c < 127 for c in s[:20]):
                        actual_offset = max(rdata_offset, file_offset-50) + str_start
                        actual_va = rdata_va + (actual_offset - rdata_offset)
                        print(f"  String at 0x{actual_va:x}: {s[:100]}")
                        break

# Also search for AES key patterns (16 or 32 byte constants)
print("\n\n=== Searching for potential AES keys (16-byte aligned constants) ===")
# Look in .rdata for 16-byte sequences that could be AES keys
# Also look for known patterns like "aes-key" or similar
import re
rdata_data = pe_data[rdata_offset:rdata_offset + rdata_section['raw_size']]

# Search for strings containing "key", "aes", "secret", "encrypt"
for keyword in [b'key', b'aes', b'secret', b'encrypt', b'cipher', b'token', b'password']:
    for m in re.finditer(keyword, rdata_data, re.IGNORECASE):
        context = rdata_data[max(0,m.start()-10):m.end()+50]
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
        va = rdata_va + m.start()
        print(f"  0x{va:x}: ...{printable}...")
