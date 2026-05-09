#!/usr/bin/env python3
"""
Inspect the string passed to Md5Encode at call site 0x8902ef.
"""
import pefile

LINGMA = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"

pe = pefile.PE(LINGMA)
image_base = pe.OPTIONAL_HEADER.ImageBase

def rva_to_foffset(rva):
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
            return section.PointerToRawData + (rva - section.VirtualAddress)
    return None

def read_str_at_rva(rva, maxlen=256):
    off = rva_to_foffset(rva)
    if off is None:
        return None
    with open(LINGMA, 'rb') as f:
        f.seek(off)
        data = f.read(maxlen)
        end = data.find(b'\x00')
        if end >= 0:
            data = data[:end]
        try:
            return data.decode('utf-8')
        except:
            return data.hex()

# Call site 2: 0x8902ef
# lea rax, [rip + 0x1c18418] @ 0x8902b4
rip = 0x8902b4 + 7
str_rva = rip + 0x1c18418
print(f"Call site 2 string @ 0x{str_rva:08x}")
s = read_str_at_rva(str_rva, maxlen=128)
print(f"  = '{s}'")
print(f"  len = {len(s) if s else 0}")

# Also check 0x8902a4 which stores to [rsp+0x88]
# lea rcx, [rip + 0x1814e1c] @ 0x89029d
rip2 = 0x89029d + 7
str_rva2 = rip2 + 0x1814e1c
print(f"\nCall site 2 another string @ 0x{str_rva2:08x}")
s2 = read_str_at_rva(str_rva2, maxlen=128)
print(f"  = '{s2}'")
print(f"  len = {len(s2) if s2 else 0}")

# Call site 3: 0xc87f54
# lea rax, [rip + 0x13f3d1a] @ 0xc87f1f
rip3 = 0xc87f1f + 7
str_rva3 = rip3 + 0x13f3d1a
print(f"\nCall site 3 string @ 0x{str_rva3:08x}")
s3 = read_str_at_rva(str_rva3, maxlen=128)
print(f"  = '{s3}'")
print(f"  len = {len(s3) if s3 else 0}")
