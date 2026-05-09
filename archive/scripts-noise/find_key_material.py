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

# Find the function start for Caller 1
# Search backwards from 0x88ed5e for the function prologue
print("=== Finding function start for Caller 1 ===")
search_start_va = 0x88ea00
target_va = 0x88ed5e

offset_start = va_to_file_offset(sections, search_start_va)
offset_end = va_to_file_offset(sections, target_va)

if offset_start and offset_end:
    func_data = pe_data[offset_start:offset_end + 50]
    for insn in md.disasm(func_data, search_start_va):
        print(f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}")
        # Stop at first meaningful instruction after garbage
        if insn.address > search_start_va + 50 and insn.mnemonic not in ('add', 'nop', 'int3'):
            if insn.mnemonic in ('push', 'mov', 'sub', 'lea', 'xor'):
                print(f"  ^^^ Likely function start ^^^")
                break

# Now let's trace the key through the AesEncryptWithBase64 function
# The function receives:
# - RAX: some string/slice (data to encrypt)
# - RBX: some string/slice (key? or encoding?)
# - RCX: some string/slice
# - RDI: 0x10 (block size?)
# Actually in Go's calling convention, arguments are passed in registers AND on the stack

# Let's focus on the call to 0x1857e0 (likely aes.NewCipher)
# This is the CRITICAL call - it creates the AES cipher from a key
print("\n\n=== Detailed analysis of AesEncryptWithBase64 ===")
aes_func_rva = 0x455da0
aes_func_offset = va_to_file_offset(sections, aes_func_rva)

if aes_func_offset:
    func_data = pe_data[aes_func_offset:aes_func_offset + 1000]
    for insn in md.disasm(func_data, aes_func_rva):
        line = f"  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}"

        # Highlight key calls
        if insn.mnemonic == 'call':
            target = insn.op_str
            line = f"  **0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}**"

        # Highlight moves of potential key material
        if insn.mnemonic == 'mov' and ('rip' in insn.op_str.lower() or 'rdx' in insn.op_str.lower()):
            if insn.address < 0x455e50:  # Only before the main encryption
                line = f"  **0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}**"

        print(line)

        if insn.address > aes_func_rva + 500:
            break

# Let's also look at what data is loaded into the key parameter for aes.NewCipher
# The call at 0x455e1a: call 0x1857e0 is likely aes.NewCipher(key)
# Before this call, the key should be in specific registers

print("\n\n=== Registers before call 0x1857e0 (aes.NewCipher) ===")
# Look at instructions 0x455de0 to 0x455e1a
print("""
  0x00455dd2:  mov      rdx, rax          # RDX = RAX (first arg - string header)
  0x00455dd5:  xor      eax, eax
  0x00455dd7:  mov      rsi, rbx          # RSI = RBX
  0x00455dda:  mov      rbx, rdx          # RBX = RDX (string data ptr)
  0x00455ddd:  mov      rcx, rsi          # RCX = RSI (string length)
  0x00455de0:  call     0x5bfe0           # string to []byte conversion?

  After call: RAX = []byte, RBX = data ptr, RCX = length

  0x00455df6:  mov      rbx, [rsp+0xb0]   # Restore RBX
  0x00455dfe:  mov      rcx, [rsp+0xb8]   # Restore RCX
  0x00455e06:  call     0x5bfe0           # Another string conversion

  After 2nd call: RAX = []byte (key?), RBX, RCX

  0x00455e1a:  call     0x1857e0          # aes.NewCipher(key_bytes)

  So the KEY is the SECOND string argument (from [rsp+0xb8] saved RDI)!
""")

# Let's also search for the Md5Encode function and its callers
# Md5Encode might be used to derive the AES key
print("\n\n=== Searching for Md5Encode and its callers ===")
# We know Md5Encode is in the encrypt package
# Let's find it by searching for references to MD5 constants or related strings
text_section = sections[0]
text_raw = pe_data[text_section['raw_offset']:text_section['raw_offset'] + text_section['raw_size']]

# Search for the md5 package import path or md5-related strings
import re
rdata_section = sections[1]
rdata_raw = pe_data[rdata_section['raw_offset']:rdata_section['raw_offset'] + rdata_section['raw_size']]

# Search for "crypto/md5" string
for m in re.finditer(b'crypto/md5', rdata_raw):
    va = rdata_section['virtual_address'] + m.start()
    offset = va_to_file_offset(sections, va)
    data = pe_data[offset:offset+50]
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
    print(f"  Found 'crypto/md5' at VA 0x{va:x}: {printable}")

# Search for "md5" in nearby context
for m in re.finditer(b'"md5"', rdata_raw):
    va = rdata_section['virtual_address'] + m.start()
    offset = va_to_file_offset(sections, va)
    data = pe_data[max(0,offset-20):offset+50]
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
    print(f"  Found '\"md5\"' at VA 0x{va:x}: ...{printable}...")

# Search for potential hardcoded key strings (common in malware/clients)
# Look for 16-byte or 32-byte printable strings that could be AES keys
print("\n\n=== Searching for potential hardcoded key strings ===")
# Find runs of 16+ printable ASCII characters that could be AES key material
for m in re.finditer(b'[\x20-\x7e]{16,}', rdata_raw):
    s = m.group()
    if 16 <= len(s) <= 64:
        va = rdata_section['virtual_address'] + m.start()
        # Check if nearby code references this string
        # (This would be very slow to do exhaustively, so just list them)
        print(f"  0x{va:x} ({len(s)} chars): {s[:60]}")
