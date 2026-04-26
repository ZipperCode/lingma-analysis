"""Verify the patched binary looks correct"""
import struct

LINGMA_ORIG = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
LINGMA_PATCHED = 'D:/Project/lingma/tools/Lingma_patched.exe'

def parse_sections(data):
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    coff = pe_offset + 4
    num_sections = struct.unpack('<H', data[coff + 2:coff + 4])[0]
    opt_size = struct.unpack('<H', data[coff + 16:coff + 18])[0]
    sec_off = coff + 20 + opt_size
    sections = []
    for i in range(num_sections):
        name = data[sec_off + i*40:sec_off + i*40 + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        vaddr = struct.unpack('<I', data[sec_off + i*40 + 12:sec_off + i*40 + 16])[0]
        raw_size = struct.unpack('<I', data[sec_off + i*40 + 16:sec_off + i*40 + 20])[0]
        raw_addr = struct.unpack('<I', data[sec_off + i*40 + 20:sec_off + i*40 + 24])[0]
        sections.append({'name': name, 'vaddr': vaddr, 'raw_size': raw_size, 'raw_addr': raw_addr})
    return sections

def rva_to_file(rva, sections):
    for sec in sections:
        if sec['vaddr'] <= rva < sec['vaddr'] + sec['raw_size']:
            return sec['raw_addr'] + (rva - sec['vaddr'])
    return None

def main():
    with open(LINGMA_ORIG, 'rb') as f:
        orig = f.read()
    with open(LINGMA_PATCHED, 'rb') as f:
        patched = f.read()

    sections = parse_sections(patched)

    # Check getAppSalt entry
    getAppSalt_off = rva_to_file(0x882760, sections)
    print(f"getAppSalt at file offset: 0x{getAppSalt_off:x}")
    print(f"\nORIGINAL bytes at getAppSalt entry:")
    print(f"  {orig[getAppSalt_off:getAppSalt_off+20].hex(' ')}")
    print(f"\nPATCHED bytes at getAppSalt entry:")
    print(f"  {patched[getAppSalt_off:getAppSalt_off+20].hex(' ')}")

    # Decode JMP
    if patched[getAppSalt_off] == 0xE9:
        rel32 = struct.unpack('<i', patched[getAppSalt_off+1:getAppSalt_off+5])[0]
        target = 0x882760 + 5 + rel32
        print(f"\nJMP rel32 = 0x{rel32:x}")
        print(f"JMP target RVA = 0x{target:x}")
        target_off = rva_to_file(target, sections)
        print(f"JMP target file offset = 0x{target_off:x}")

    # Check code cave content
    cave_off = rva_to_file(0x1090, sections)
    print(f"\nCode cave at file offset: 0x{cave_off:x}")
    print(f"ORIGINAL at cave:")
    print(f"  {orig[cave_off:cave_off+50].hex(' ')}")
    print(f"PATCHED at cave:")
    print(f"  {patched[cave_off:cave_off+50].hex(' ')}")

    # Decode trampoline
    offset = 0
    print(f"\nTrampoline disassembly:")
    if patched[cave_off] == 0xE8:
        call_rel32 = struct.unpack('<i', patched[cave_off+1:cave_off+5])[0]
        call_target = 0x1090 + 5 + call_rel32
        print(f"  CALL 0x{call_target:x}")
        offset = 5

    # Check for RIP-relative MOVs
    cave_data = patched[cave_off:cave_off+40]
    pos = 0
    while pos < len(cave_data) - 7:
        if cave_data[pos:pos+3] == b'\x48\x89\x05':
            disp32 = struct.unpack('<i', cave_data[pos+3:pos+7])[0]
            target = 0x1090 + pos + 7 + disp32
            print(f"  MOV [rip+0x{disp32:x}], rax -> 0x{target:x}")
            pos += 7
        elif cave_data[pos:pos+3] == b'\x48\x89\x0d':
            disp32 = struct.unpack('<i', cave_data[pos+3:pos+7])[0]
            target = 0x1090 + pos + 7 + disp32
            print(f"  MOV [rip+0x{disp32:x}], rcx -> 0x{target:x}")
            pos += 7
        elif cave_data[pos:pos+3] == b'\x48\x89\x15':
            disp32 = struct.unpack('<i', cave_data[pos+3:pos+7])[0]
            target = 0x1090 + pos + 7 + disp32
            print(f"  MOV [rip+0x{disp32:x}], rdx -> 0x{target:x}")
            pos += 7
        elif cave_data[pos] == 0xC3:
            print(f"  RET")
            pos += 1
        else:
            pos += 1

    # Also check: is the code cave area actually zeros in original?
    print(f"\n=== Code cave safety check ===")
    cave_orig = orig[cave_off:cave_off+30]
    print(f"Original bytes: {cave_orig.hex(' ')}")
    is_zero = all(b == 0 for b in cave_orig)
    print(f"Is all zeros: {is_zero}")
    if not is_zero:
        print(f"WARNING: Code cave is NOT empty! This might overwrite existing code!")

if __name__ == '__main__':
    main()
