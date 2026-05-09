"""
Patch Lingma.exe v3: Patch the CALLER instead of getAppSalt.
This is safer because we only modify code that calls getAppSalt, not getAppSalt itself.

Strategy:
1. In caller 0x880da0, find where it CALLs getAppSalt
2. After the CALL instruction, insert code to save RAX/RCX/RDX to .data
3. Then continue normal execution
"""
import struct
import capstone

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
OUTPUT = 'D:/Project/lingma/tools/Lingma_patched.exe'

IMAGE_BASE = 0x140000000

def parse_sections(data):
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
            'chars': chars
        })
    return sections

def rva_to_file(rva, sections):
    for sec in sections:
        if sec['vaddr'] <= rva < sec['vaddr'] + sec['raw_size']:
            return sec['raw_addr'] + (rva - sec['vaddr'])
    return None

def main():
    with open(LINGMA, 'rb') as f:
        data = bytearray(f.read())

    sections = parse_sections(data)

    # Disassemble caller to find getAppSalt call
    caller_off = rva_to_file(0x880da0, sections)
    caller_data = data[caller_off:caller_off + 2000]

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    getAppSalt_call = None
    getAppSalt_call_off = None

    for insn in md.disasm(caller_data, IMAGE_BASE + 0x880da0):
        if insn.mnemonic == 'call':
            if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
                callee = insn.operands[0].imm - IMAGE_BASE
                if callee == 0x882760:  # getAppSalt RVA
                    getAppSalt_call = insn
                    getAppSalt_call_off = insn.address - IMAGE_BASE
                    print(f"Found getAppSalt call at RVA 0x{getAppSalt_call_off:x}")
                    print(f"  Instruction: {insn.mnemonic} {insn.op_str}")
                    print(f"  Next instruction RVA: 0x{getAppSalt_call_off + insn.size:x}")
                    break

    if not getAppSalt_call:
        print("getAppSalt call not found in caller!")
        return

    # The instruction AFTER the call is where getAppSalt has returned
    # RAX/RCX/RDX have the return value
    # We need to save these registers to .data section

    # After the CALL, the next instruction starts at getAppSalt_call_off + call_size
    next_insn_rva = getAppSalt_call_off + getAppSalt_call.size
    next_insn_off = rva_to_file(next_insn_rva, sections)

    print(f"\nNext instruction after CALL:")
    print(f"  RVA: 0x{next_insn_rva:x}")
    print(f"  File offset: 0x{next_insn_off:x}")
    print(f"  Bytes: {data[next_insn_off:next_insn_off+20].hex(' ')}")

    # We need to insert our save code BEFORE the next instruction.
    # Since we can't insert (only replace), we'll:
    # 1. Replace the next instruction(s) with JMP to our shellcode
    # 2. Shellcode saves registers, then JMPs back after the saved instructions

    # Find how many instructions we need to overwrite (need at least 5 bytes for JMP)
    total_size = 0
    insns_to_replace = []
    for insn in md.disasm(data[next_insn_off:next_insn_off + 20], IMAGE_BASE + next_insn_rva):
        insns_to_replace.append(insn)
        total_size += insn.size
        if total_size >= 5:
            break

    print(f"\nInstructions to replace ({total_size} bytes):")
    for insn in insns_to_replace:
        print(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")

    # Check if we have enough space
    if total_size < 5:
        print("Not enough space for JMP! Need different approach.")
        # Use bigger region
        for insn in md.disasm(data[next_insn_off:next_insn_off + 30], IMAGE_BASE + next_insn_rva):
            total_size += insn.size
            insns_to_replace.append(insn)
            if total_size >= 10:
                break

    # Calculate shellcode location (new section)
    last_sec = sections[-1]
    new_sec_vaddr = (last_sec['vaddr'] + max(last_sec['vsize'], last_sec['raw_size']) + 0xFFF) & ~0xFFF
    new_sec_raw = 0x1000
    new_sec_raw_addr = (last_sec['raw_addr'] + last_sec['raw_size'] + 0x1FF) & ~0x1FF

    data_sec = [s for s in sections if s['name'] == '.data'][0]
    data_rva = data_sec['vaddr']

    shellcode_rva = new_sec_vaddr

    # Build shellcode
    shellcode = bytearray()

    # Save all registers we're going to use
    shellcode += b'\x50'  # push rax
    shellcode += b'\x51'  # push rcx
    shellcode += b'\x52'  # push rdx
    shellcode += b'\x41\x50'  # push r8
    shellcode += b'\x41\x51'  # push r9
    shellcode += b'\x41\x52'  # push r10
    shellcode += b'\x41\x53'  # push r11
    shellcode += b'\x9c'  # pushfq

    # Now save the ORIGINAL return values (which are on the stack from the pushes)
    # Actually, we need to save RAX/RCX/RDX BEFORE pushing them
    # Let me redo this...

    # RAX is the return value ptr, RCX is length, RDX is cap
    # Save them to .data BEFORE pushing
    current_rva = shellcode_rva

    # First, save RAX, RCX, RDX to .data (BEFORE pushing)
    # MOV [rip+disp], rax
    for reg_byte, disp in [(b'\x05', 0), (b'\x0d', 8), (b'\x15', 16)]:
        target_rva = data_rva + disp
        # RIP after this instruction = shellcode_rva + len(shellcode) + 7
        inst_rva = shellcode_rva + len(shellcode)
        rip_disp = target_rva - (inst_rva + 7)

        shellcode += b'\x48\x89' + reg_byte + struct.pack('<i', rip_disp)

    # Now also try to read the string content if it's a valid pointer
    # If RAX points to valid memory, try to save the first 64 bytes to .data + 0x20
    # This is more complex - skip for now, just save the pointers

    # Restore registers
    shellcode += b'\x9d'  # popfq
    shellcode += b'\x41\x5b'  # pop r11
    shellcode += b'\x41\x5a'  # pop r10
    shellcode += b'\x41\x59'  # pop r9
    shellcode += b'\x41\x58'  # pop r8
    shellcode += b'\x5a'  # pop rdx
    shellcode += b'\x59'  # pop rcx
    shellcode += b'\x58'  # pop rax

    # Execute the original replaced instructions
    # We need to copy the original bytes and execute them
    # The original instructions were at next_insn_off
    orig_bytes = bytes(data[next_insn_off:next_insn_off + total_size])
    # We need to adjust RIP-relative addresses in the copied instructions
    # For simplicity, let's just JMP back to after our JMP in the caller

    # JMP back to after the replaced instructions
    return_rva = next_insn_rva + total_size
    # Current position in shellcode
    current_rva = shellcode_rva + len(shellcode)
    jmp_back_rel32 = return_rva - (current_rva + 5)

    shellcode += b'\xe9' + struct.pack('<i', jmp_back_rel32)

    print(f"\nShellcode ({len(shellcode)} bytes):")
    print(f"  {bytes(shellcode[:60]).hex(' ')}")

    # Write JMP in caller to redirect to shellcode
    # The JMP goes at next_insn_off
    jmp_rel32 = shellcode_rva - (next_insn_rva + 5)
    data[next_insn_off] = 0xE9  # JMP rel32
    struct.pack_into('<i', data, next_insn_off + 1, jmp_rel32)

    # NOP out the remaining replaced bytes
    for i in range(total_size - 5):
        data[next_insn_off + 5 + i] = 0x90  # NOP

    print(f"\nJMP at caller RVA 0x{next_insn_rva:x} -> shellcode RVA 0x{shellcode_rva:x}")
    print(f"JMP rel32 = 0x{jmp_rel32:x}")

    # Now append new section
    new_data = bytearray(data)
    new_data += b'\x00' * (new_sec_raw_addr + new_sec_raw - len(data))
    new_data[new_sec_raw_addr:new_sec_raw_addr + new_sec_raw] = shellcode + b'\xcc' * (new_sec_raw - len(shellcode))

    # Add section header
    pe_offset = struct.unpack('<I', new_data[0x3C:0x40])[0]
    coff = pe_offset + 4
    num_sections = struct.unpack('<H', new_data[coff + 2:coff + 4])[0]
    opt_size = struct.unpack('<H', new_data[coff + 16:coff + 18])[0]
    sec_off = coff + 20 + opt_size

    num_sections += 1
    struct.pack_into('<H', new_data, coff + 2, num_sections)

    sec_hdr_off = sec_off + (num_sections - 1) * 40
    struct.pack_into('8s', new_data, sec_hdr_off, b'.salty\x00\x00')
    struct.pack_into('<I', new_data, sec_hdr_off + 8, new_sec_raw)  # VirtualSize
    struct.pack_into('<I', new_data, sec_hdr_off + 12, new_sec_vaddr)  # VirtualAddress
    struct.pack_into('<I', new_data, sec_hdr_off + 16, new_sec_raw)  # SizeOfRawData
    struct.pack_into('<I', new_data, sec_hdr_off + 20, new_sec_raw_addr)  # PointerToRawData
    struct.pack_into('<I', new_data, sec_hdr_off + 24, 0)
    struct.pack_into('<I', new_data, sec_hdr_off + 28, 0)
    struct.pack_into('<H', new_data, sec_hdr_off + 32, 0)
    struct.pack_into('<H', new_data, sec_hdr_off + 34, 0)
    struct.pack_into('<I', new_data, sec_hdr_off + 36, 0xE0000020)

    size_of_image_off = coff + 20 + 56
    new_size = (new_sec_vaddr + new_sec_raw + 0xFFF) & ~0xFFF
    struct.pack_into('<I', new_data, size_of_image_off, new_size)

    with open(OUTPUT, 'wb') as f:
        f.write(new_data)

    print(f"\nPatched binary written to: {OUTPUT}")
    print(f"Result storage in .data at RVA: 0x{data_rva:x}")
    print(f"  .data + 0x00 = RAX (return value ptr)")
    print(f"  .data + 0x08 = RCX (length)")
    print(f"  .data + 0x10 = RDX (cap)")

if __name__ == '__main__':
    main()
