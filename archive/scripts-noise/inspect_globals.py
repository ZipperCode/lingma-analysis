#!/usr/bin/env python3
"""
Read global variables referenced by addBigModelSignatureHeaders.
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

def read_qword(foffset):
    with open(LINGMA, 'rb') as f:
        f.seek(foffset)
        data = f.read(8)
        if len(data) < 8:
            return None
        return int.from_bytes(data, 'little')

def read_byte(foffset):
    with open(LINGMA, 'rb') as f:
        f.seek(foffset)
        data = f.read(1)
        if len(data) < 1:
            return None
        return data[0]

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

# Global string at .data (from 0x882946 / 0x88294d)
target1_rva = 0x88294d + 0x5725373  # = 0x05fa7cc0
target2_rva = 0x882954 + 0x5725374  # = 0x05fa7cc8

print("=" * 80)
print(f"Global string header @ RVA 0x{target1_rva:08x} / 0x{target2_rva:08x}")
print("=" * 80)

foff1 = rva_to_foffset(target1_rva)
foff2 = rva_to_foffset(target2_rva)
print(f"File offsets: 0x{foff1:x}, 0x{foff2:x}")

ptr = read_qword(foff1)
len_val = read_qword(foff2)
print(f"ptr  = 0x{ptr:016x} (RVA = 0x{ptr - image_base:08x})")
print(f"len  = {len_val}")

if ptr:
    s = read_str_at_rva(ptr - image_base, maxlen=256)
    print(f"string = '{s}'")

# Flag byte at 0x88290e
# Actually, let's read the raw bytes at 0x88290e to verify the instruction
print("\n" + "=" * 80)
print("Raw bytes at 0x88290e")
print("=" * 80)
foff = rva_to_foffset(0x88290e)
with open(LINGMA, 'rb') as f:
    f.seek(foff)
    raw = f.read(16)
    print(f"Raw bytes: {raw.hex()}")
    # Decode manually
    # 0F B6 35 ?? ?? ?? ?? = movzx esi, byte ptr [rip+disp32]
    if raw[:3] == b'\x0f\xb6\x35':
        disp = int.from_bytes(raw[3:7], 'little', signed=True)
        rip = 0x88290e + 7
        target = rip + disp
        print(f"Instruction: movzx esi, byte ptr [rip + {disp}] = [0x{target:08x}]")
        target_foff = rva_to_foffset(target)
        if target_foff:
            b = read_byte(target_foff)
            print(f"Flag byte value = 0x{b:02x} ({b})")

# Also check the strings loaded by lea at 0x882978 and 0x88297f
print("\n" + "=" * 80)
print("Key strings")
print("=" * 80)

# 0x882978: lea rdx, [rip+0x1c6ba4e]
rip = 0x882978 + 7
short_key_rva = rip + 0x1c6ba4e
print(f"Short key @ 0x{short_key_rva:08x}")
s = read_str_at_rva(short_key_rva, maxlen=128)
print(f"  = '{s}'")

# 0x88297f: lea rsi, [rip+0x1c6ba27]
rip = 0x88297f + 7
full_key_rva = rip + 0x1c6ba27
print(f"Full key @ 0x{full_key_rva:08x}")
s = read_str_at_rva(full_key_rva, maxlen=128)
print(f"  = '{s}'")
