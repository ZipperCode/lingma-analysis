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

# Caller 4: loads RCX and RDI from global variables before calling AesEncryptWithBase64
# 0x00af3398: mov rcx, qword ptr [rip + 0x54b5e71]
# RIP at next instruction: 0xaf339f
# 0x00af339f: mov rdi, qword ptr [rip + 0x54b5e72]
# RIP at next instruction: 0xaf33a6

rcx_rip = 0xaf339f
rcx_disp = 0x54b5e71
rcx_target = rcx_rip + rcx_disp
rcx_offset = va_to_file_offset(sections, rcx_target)
print(f"RCX source (key pointer):")
print(f"  Target VA: 0x{rcx_target:x}")
print(f"  File offset: 0x{rcx_offset:x}")
if rcx_offset:
    data = pe_data[rcx_offset:rcx_offset+16]
    print(f"  Raw bytes: {data.hex()}")
    # This is a Go string header: ptr (8 bytes) + len (8 bytes)
    str_ptr = struct.unpack('<Q', data[0:8])[0]
    str_len = struct.unpack('<Q', data[8:16])[0]
    print(f"  String ptr: 0x{str_ptr:x}, len: {str_len}")
    if str_ptr > 0x1000 and str_len < 1000:
        str_offset = va_to_file_offset(sections, str_ptr)
        if str_offset:
            str_data = pe_data[str_offset:str_offset + str_len]
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in str_data)
            print(f"  String content: {str_data[:100]}")
            print(f"  ASCII: {printable[:100]}")

rdi_rip = 0xaf33a6
rdi_disp = 0x54b5e72
rdi_target = rdi_rip + rdi_disp
rdi_offset = va_to_file_offset(sections, rdi_target)
print(f"\nRDI source (plaintext pointer):")
print(f"  Target VA: 0x{rdi_target:x}")
print(f"  File offset: 0x{rdi_offset:x}")
if rdi_offset:
    data = pe_data[rdi_offset:rdi_offset+16]
    print(f"  Raw bytes: {data.hex()}")
    str_ptr = struct.unpack('<Q', data[0:8])[0]
    str_len = struct.unpack('<Q', data[8:16])[0]
    print(f"  String ptr: 0x{str_ptr:x}, len: {str_len}")
    if str_ptr > 0x1000 and str_len < 1000:
        str_offset = va_to_file_offset(sections, str_ptr)
        if str_offset:
            str_data = pe_data[str_offset:str_offset + str_len]
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in str_data)
            print(f"  String content: {str_data[:100]}")
            print(f"  ASCII: {printable[:100]}")

# Caller 5:
# 0x00b96f5c: lea rcx, [rip + 0x1918395]
# 0x00b96f63: mov edi, 0x10
# 0x00b96f68: call 0x455da0
# Here RCX is a pointer (LEA), not a loaded value. This might be a string header on the stack.

print(f"\n\n=== Caller 5 details ===")
rcx_rip5 = 0xb96f63
rcx_disp5 = 0x1918395
rcx_target5 = rcx_rip5 + rcx_disp5
rcx_offset5 = va_to_file_offset(sections, rcx_target5)
print(f"  RCX LEA target: VA 0x{rcx_target5:x}, offset 0x{rcx_offset5:x}")
if rcx_offset5:
    data = pe_data[rcx_offset5:rcx_offset5+16]
    print(f"  Data: {data.hex()}")
    str_ptr = struct.unpack('<Q', data[0:8])[0]
    str_len = struct.unpack('<Q', data[8:16])[0]
    print(f"  String ptr: 0x{str_ptr:x}, len: {str_len}")
    if str_ptr > 0x1000 and str_len < 1000:
        str_offset = va_to_file_offset(sections, str_ptr)
        if str_offset:
            str_data = pe_data[str_offset:str_offset + str_len]
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in str_data)
            print(f"  String: {str_data[:100]}")
            print(f"  ASCII: {printable[:100]}")

# Let's also look at what Caller 4's function does - find the function name
# by looking at the pclntab entry for 0xaf3380
print(f"\n\n=== Function name for caller at 0xaf3380 ===")
# Search for this VA in the pclntab
rdata_section = sections[1]
rdata_raw = pe_data[rdata_section['raw_offset']:rdata_section['raw_offset'] + rdata_section['raw_size']]

# Look for function name patterns near the encrypt package
# The function is in the cosy/encrypt package and handles encryption errors
import re
# Search for function names in the 0xafxxxx range
# These should appear in the pclntab with their module path
for pattern in [b'encrypt', b'AesEncrypt', b'AesDecrypt', b'encryptRecord', b'decryptRecord']:
    for m in re.finditer(pattern, rdata_raw):
        start = max(0, m.start() - 5)
        end = min(len(rdata_raw), m.end() + 200)
        context = rdata_raw[start:end]
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
        va = rdata_section['virtual_address'] + m.start()
        # Only show if it has package path indicators
        if b'cosy' in context.lower() or b'encrypt' in context.lower():
            print(f"  0x{va:x}: {printable[:200]}")

# Let's look at the cosy/storage/database package functions
print(f"\n\n=== cosy/storage/database functions ===")
for m in re.finditer(b'cosy/storage/database', rdata_raw):
    start = max(0, m.start() - 3)
    end = min(len(rdata_raw), m.end() + 200)
    context = rdata_raw[start:end]
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
    va = rdata_section['virtual_address'] + m.start()
    print(f"  0x{va:x}: {printable[:250]}")
