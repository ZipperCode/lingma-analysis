import struct

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def rva_to_offset(rva):
    sections = [
        ('.text',   0x00001000, 0x01f3f246, 0x00000400),
        ('.rdata',  0x01f41000, 0x03cfc250, 0x01f3f800),
        ('.data',   0x05c3e000, 0x00518d80, 0x05c3bc00),
        ('.pdata',  0x06157000, 0x000973ec, 0x060a6400),
        ('.reloc',  0x061f0000, 0x00087e30, 0x0613da00),
    ]
    for name, va, size, raw in sections:
        if va <= rva < va + size:
            return raw + (rva - va)
    return rva

with open(BINARY_PATH, 'rb') as f:
    data = f.read()

known_alphabet = set("!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz")

# Search .rdata for contiguous printable chars that could be our alphabet
rdata_start = rva_to_offset(0x01f41000)
rdata_end = rdata_start + 0x03cfc250

print("Searching .rdata for 65-char alphabets...")

# Find contiguous ASCII sequences of length >= 60
i = rdata_start
sequences = []
while i < rdata_end:
    # Find start of contiguous printable ASCII (matching our alphabet)
    start = i
    while i < rdata_end and chr(data[i]) in known_alphabet:
        i += 1
    length = i - start
    if length >= 60:
        seq = data[start:i].decode('ascii')
        sequences.append((start, seq))
    # Skip to next potential start
    i += 1

print(f"Found {len(sequences)} candidate sequences:\n")
for offset, seq in sequences:
    va = 0x01f41000 + (offset - rdata_start)
    print(f"VA 0x{va:x} (offset 0x{offset:x}): '{seq[:70]}' (len={len(seq)})")

# Also search the entire binary for the alphabet
print("\n\nSearching entire binary for the 65-char alphabet...")

i = 0
while i < len(data):
    start = i
    while i < len(data) and chr(data[i]) in known_alphabet:
        i += 1
    length = i - start
    if length >= 60:
        seq = data[start:i].decode('ascii')
        print(f"Offset 0x{start:x} (len={length}): '{seq[:70]}'")
    i += 1

print("\n\nDone.")
