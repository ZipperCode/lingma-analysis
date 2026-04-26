"""
Patch Lingma.exe properly by adding a new PE section for shellcode.
This avoids overwriting existing code.
"""
import struct
import shutil
import os

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
OUTPUT = 'D:/Project/lingma/tools/Lingma_patched.exe'

IMAGE_BASE = 0x140000000
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200

def rva_to_file(rva, sections):
    for sec in sections:
        if sec['vaddr'] <= rva < sec['vaddr'] + sec['raw_size']:
            return sec['raw_addr'] + (rva - sec['vaddr'])
    return None

def main():
    with open(LINGMA, 'rb') as f:
        data = bytearray(f.read())

    # Parse PE header
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    coff = pe_offset + 4
    num_sections = struct.unpack('<H', data[coff + 2:coff + 4])[0]
    opt_size = struct.unpack('<H', data[coff + 16:coff + 18])[0]
    sec_off = coff + 20 + opt_size

    sections = []
    for i in range(num_sections):
        off = sec_off + i * 40
        name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vaddr = struct.unpack('<I', data[off+12:off+16])[0]
        vsize = struct.unpack('<I', data[off+8:off+12])[0]
        raw_size = struct.unpack('<I', data[off+16:off+20])[0]
        raw_addr = struct.unpack('<I', data[off+20:off+24])[0]
        chars = struct.unpack('<I', data[off+36:off+40])[0]
        sections.append({
            'name': name, 'vaddr': vaddr, 'vsize': vsize,
            'raw_size': raw_size, 'raw_addr': raw_addr,
            'chars': chars, 'off': off
        })

    # Find getAppSalt
    getAppSalt_off = rva_to_file(0x882760, sections)
    print(f"getAppSalt file offset: 0x{getAppSalt_off:x}")
    print(f"Original bytes: {data[getAppSalt_off:getAppSalt_off+10].hex(' ')}")

    # Calculate new section parameters
    last_sec = sections[-1]
    new_sec_vaddr = (last_sec['vaddr'] + max(last_sec['vsize'], last_sec['raw_size']) + SECTION_ALIGNMENT - 1) & ~(SECTION_ALIGNMENT - 1)
    new_sec_raw = 0x1000  # 4KB section
    new_sec_raw_addr = (last_sec['raw_addr'] + last_sec['raw_size'] + FILE_ALIGNMENT - 1) & ~(FILE_ALIGNMENT - 1)

    print(f"\nNew section: .salty")
    print(f"  Virtual address: 0x{new_sec_vaddr:x}")
    print(f"  Virtual size: 0x{new_sec_raw:x}")
    print(f"  Raw address: 0x{new_sec_raw_addr:x}")
    print(f"  Raw size: 0x{new_sec_raw:x}")

    # New section name (8 bytes max)
    new_sec_name = b'.salty\x00\x00'

    # Shellcode: trampoline that calls original getAppSalt then saves result
    # Place in the new section
    shellcode = bytearray()

    # Step 1: CALL original getAppSalt (skip our 5-byte JMP)
    original_func_rva = 0x882760 + 5  # After the JMP we'll insert
    shellcode_rva = new_sec_vaddr
    call_rel32 = original_func_rva - (shellcode_rva + 5)
    shellcode += b'\xe8' + struct.pack('<i', call_rel32)

    # Step 2: Save RAX, RCX, RDX to .data section using RIP-relative MOV
    # RAX -> .data + 0
    # RCX -> .data + 8
    # RDX -> .data + 16
    data_sec = [s for s in sections if s['name'] == '.data'][0]
    data_rva = data_sec['vaddr']

    for reg, disp in [('rax', 0), ('rcx', 8), ('rdx', 16)]:
        target_rva = data_rva + disp
        current_rva = shellcode_rva + len(shellcode)
        rip_disp = target_rva - (current_rva + 7)

        if reg == 'rax':
            shellcode += b'\x48\x89\x05'  # MOV [rip+disp], rax
        elif reg == 'rcx':
            shellcode += b'\x48\x89\x0d'  # MOV [rip+disp], rcx
        elif reg == 'rdx':
            shellcode += b'\x48\x89\x15'  # MOV [rip+disp], rdx

        shellcode += struct.pack('<i', rip_disp)

    # Step 3: RET
    shellcode += b'\xc3'

    # Pad to section size
    shellcode += b'\xcc' * (new_sec_raw - len(shellcode))

    print(f"\nShellcode ({len(shellcode)} bytes before padding):")
    print(f"  {bytes(shellcode[:50]).hex(' ')}")

    # Decode shellcode for verification
    pos = 0
    print("\nShellcode disassembly:")
    if shellcode[0] == 0xE8:
        rel = struct.unpack('<i', shellcode[1:5])[0]
        target = shellcode_rva + 5 + rel
        print(f"  0x{shellcode_rva:08x}: CALL 0x{target:08x}")
        pos = 5

    while pos < len(shellcode) - 7:
        if shellcode[pos:pos+3] == b'\x48\x89\x05':
            disp = struct.unpack('<i', shellcode[pos+3:pos+7])[0]
            target = shellcode_rva + pos + 7 + disp
            print(f"  0x{shellcode_rva+pos:08x}: MOV [rip+0x{disp:x}], rax -> 0x{target:08x}")
            pos += 7
        elif shellcode[pos:pos+3] == b'\x48\x89\x0d':
            disp = struct.unpack('<i', shellcode[pos+3:pos+7])[0]
            target = shellcode_rva + pos + 7 + disp
            print(f"  0x{shellcode_rva+pos:08x}: MOV [rip+0x{disp:x}], rcx -> 0x{target:08x}")
            pos += 7
        elif shellcode[pos:pos+3] == b'\x48\x89\x15':
            disp = struct.unpack('<i', shellcode[pos+3:pos+7])[0]
            target = shellcode_rva + pos + 7 + disp
            print(f"  0x{shellcode_rva+pos:08x}: MOV [rip+0x{disp:x}], rdx -> 0x{target:08x}")
            pos += 7
        elif shellcode[pos] == 0xC3:
            print(f"  0x{shellcode_rva+pos:08x}: RET")
            pos += 1
        else:
            pos += 1

    # Now modify the binary
    # 1. Append shellcode section to file
    new_data = bytearray(data)
    new_data += b'\x00' * (new_sec_raw_addr + new_sec_raw - len(data))
    new_data[new_sec_raw_addr:new_sec_raw_addr + new_sec_raw] = shellcode

    # 2. Insert JMP at getAppSalt entry
    shellcode_entry_rva = new_sec_vaddr
    jmp_rel32 = shellcode_entry_rva - (0x882760 + 5)
    new_data[getAppSalt_off] = 0xE9  # JMP rel32
    struct.pack_into('<i', new_data, getAppSalt_off + 1, jmp_rel32)

    print(f"\nJMP at getAppSalt:")
    print(f"  From RVA 0x882760 to shellcode RVA 0x{shellcode_entry_rva:x}")
    print(f"  JMP rel32 = 0x{jmp_rel32:x}")

    # 3. Add new section header
    num_sections += 1
    struct.pack_into('<H', new_data, coff + 2, num_sections)

    sec_hdr_off = sec_off + (num_sections - 1) * 40
    struct.pack_into('8s', new_data, sec_hdr_off, new_sec_name)
    struct.pack_into('<I', new_data, sec_hdr_off + 8, new_sec_raw)   # VirtualSize
    struct.pack_into('<I', new_data, sec_hdr_off + 12, new_sec_vaddr)  # VirtualAddress
    struct.pack_into('<I', new_data, sec_hdr_off + 16, new_sec_raw)    # SizeOfRawData
    struct.pack_into('<I', new_data, sec_hdr_off + 20, new_sec_raw_addr)  # PointerToRawData
    struct.pack_into('<I', new_data, sec_hdr_off + 24, 0)  # PointerToRelocations
    struct.pack_into('<I', new_data, sec_hdr_off + 28, 0)  # PointerToLinenumbers
    struct.pack_into('<H', new_data, sec_hdr_off + 32, 0)  # NumberOfRelocations
    struct.pack_into('<H', new_data, sec_hdr_off + 34, 0)  # NumberOfLinenumbers
    struct.pack_into('<I', new_data, sec_hdr_off + 36, 0xE0000020)  # Characteristics: CODE|EXECUTE|READ|WRITE

    # 4. Update SizeOfImage in optional header
    size_of_image_off = coff + 20 + 56  # SizeOfImage is at offset 56 in optional header
    new_size_of_image = (new_sec_vaddr + new_sec_raw + SECTION_ALIGNMENT - 1) & ~(SECTION_ALIGNMENT - 1)
    struct.pack_into('<I', new_data, size_of_image_off, new_size_of_image)

    print(f"Updated SizeOfImage: 0x{new_size_of_image:x}")
    print(f"New number of sections: {num_sections}")

    # Write output
    with open(OUTPUT, 'wb') as f:
        f.write(new_data)

    print(f"\nPatched binary written to: {OUTPUT}")
    print(f"Shellcode entry RVA: 0x{shellcode_entry_rva:x}")
    print(f"Result storage in .data at: 0x{data_rva:x}")

if __name__ == '__main__':
    main()
