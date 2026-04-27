#!/usr/bin/env python3
"""
Find all callers of Md5Encode (0x4563c0) using byte-level search.
"""
import struct
import pefile

LINGMA = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
MD5_ENCODE_RVA = 0x4563c0

pe = pefile.PE(LINGMA)
image_base = pe.OPTIONAL_HEADER.ImageBase

def rva_to_foffset(rva):
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
            return section.PointerToRawData + (rva - section.VirtualAddress)
    return None

def read_bytes(foffset, size):
    with open(LINGMA, 'rb') as f:
        f.seek(foffset)
        return f.read(size)

# Search in .text section
text_section = None
for s in pe.sections:
    if s.Name.decode('utf-8').strip('\x00') == '.text':
        text_section = s
        break

if not text_section:
    print(".text section not found")
    exit(1)

foff = text_section.PointerToRawData
code = read_bytes(foff, text_section.SizeOfRawData)
base_addr = image_base + text_section.VirtualAddress

call_sites = []
i = 0
while i < len(code) - 5:
    if code[i] == 0xe8:
        disp = struct.unpack('<i', code[i+1:i+5])[0]
        target = base_addr + i + 5 + disp
        target_rva = target - image_base
        if target_rva == MD5_ENCODE_RVA:
            call_rva = base_addr + i - image_base
            call_sites.append(call_rva)
    i += 1

print(f"Found {len(call_sites)} call sites to Md5Encode (0x{MD5_ENCODE_RVA:06x})")
for rva in call_sites:
    print(f"  0x{rva:06x}")
