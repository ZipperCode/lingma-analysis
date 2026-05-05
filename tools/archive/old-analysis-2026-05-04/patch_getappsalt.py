"""
Patch Lingma.exe to dump getAppSalt return value to a file.

Strategy:
1. Find a code cave (unused space) in the binary
2. Insert shellcode that:
   - Saves all registers
   - Calls Windows WriteFile to dump RAX content
   - Restores registers
   - Jumps back to original flow
3. Patch getAppSalt's return to call our dump code first
"""
import struct
import shutil
import os

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
OUTPUT = 'D:/Project/lingma/tools/Lingma_patched.exe'
DUMP_FILE = 'C:/Users/Zipper/.lingma/getappsalt_dump.txt'

IMAGE_BASE = 0x140000000

def parse_sections(data):
    pe_offset = struct.unpack('<H', data[0:2])[0]  # MZ header
    # Actually find PE header
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
        chars = struct.unpack('<I', data[sec_off + i*40 + 36:sec_off + i*40 + 40])[0]
        sections.append({
            'name': name, 'vaddr': vaddr, 'raw_size': raw_size,
            'raw_addr': raw_addr, 'chars': chars
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
    print("Sections:")
    for sec in sections:
        print(f"  {sec['name']:10s} VA=0x{sec['vaddr']:08x} Size=0x{sec['raw_size']:06x} Raw=0x{sec['raw_addr']:06x}")

    # getAppSalt function
    getAppSalt_rva = 0x882760
    getAppSalt_ret_off = rva_to_file(0x882b8a, sections)  # The return instruction
    print(f"\ngetAppSalt return instruction at file offset: 0x{getAppSalt_ret_off:x}")

    # Show current bytes around the return
    print(f"Current bytes at return: {data[getAppSalt_ret_off:getAppSalt_ret_off+10].hex(' ')}")

    # Find a code cave: look for a large region of zeros/0xCC in .text or padding
    text_sec = [s for s in sections if s['name'] == '.text'][0]
    code_cave = None
    min_size = 500  # Need at least 500 bytes for our shellcode

    # Search for zeros in .text section
    text_start = text_sec['raw_addr']
    text_end = text_start + text_sec['raw_size']

    # Look for runs of zeros
    zero_count = 0
    zero_start = 0
    for i in range(text_start, text_end):
        if data[i] == 0:
            if zero_count == 0:
                zero_start = i
            zero_count += 1
            if zero_count >= min_size:
                code_cave = zero_start
                break
        else:
            zero_count = 0

    if code_cave:
        cave_rva = code_cave - text_sec['raw_addr'] + text_sec['vaddr']
        print(f"Found code cave at file offset 0x{code_cave:x} (RVA 0x{cave_rva:x}), size >= {min_size}")
    else:
        print("No code cave found in .text section")
        # Try .rdata or other sections
        for sec in sections:
            sec_start = sec['raw_addr']
            sec_end = sec_start + sec['raw_size']
            zero_count = 0
            for i in range(sec_start, sec_end):
                if data[i] == 0:
                    if zero_count == 0:
                        zero_start = i
                    zero_count += 1
                    if zero_count >= min_size:
                        code_cave = zero_start
                        cave_rva = code_cave - sec['raw_addr'] + sec['vaddr']
                        print(f"Found code cave in {sec['name']} at offset 0x{code_cave:x} (RVA 0x{cave_rva:x})")
                        break
            if code_cave:
                break

    if not code_cave:
        print("ERROR: No code cave found!")
        return

    # Our strategy: Instead of complex shellcode, let's take a simpler approach.
    # We'll patch getAppSalt to save RAX to a known memory location in .data,
    # then our external tool reads that memory via Frida or another mechanism.

    # Actually, simpler approach: patch the return instruction to jump to our
    # code cave, which saves RAX/RCX to .data section, then returns normally.

    # Find .data section for storing the result
    data_sec = [s for s in sections if s['name'] == '.data'][0]
    result_ptr_rva = data_sec['vaddr']  # Use beginning of .data as storage
    result_ptr_off = data_sec['raw_addr']

    print(f"\nUsing .data section at RVA 0x{result_ptr_rva:x} for result storage")

    # Shellcode at code cave:
    # 1. Save registers (push all)
    # 2. Save RAX and RCX to .data
    # 3. Restore registers
    # 4. Execute original return instruction (add rsp, 0xf8; pop rbp; ret)
    #
    # Actually, the issue is we can't easily call Windows APIs from shellcode
    # without a valid PEB/TEB. Let's use a simpler approach:
    #
    # Just save RAX to .data and exit. Then use another tool to read the value.

    # Even simpler: Use DebugBreak + output debug string
    # Or: Write to a known memory location, signal via event

    # SIMPLEST APPROACH: Patch getAppSalt to write its result to .data,
    # then use a ReadProcessMemory tool to read it from the running process.

    # Shellcode (x86-64):
    # Save RAX to .data section (8 bytes)
    # Save RCX to .data section + 8 (8 bytes for length)
    # Try to write string to dump file... but this is complex without API calls

    # Let's use OutputDebugStringA approach:
    # 1. Find OutputDebugStringA in kernel32.dll via IAT
    # 2. Format the RAX value as hex string
    # 3. Call OutputDebugStringA

    # This is getting complex. Let me try a different tactic:
    # Use a memory-mapped file approach or simply write to .data and read externally.

    # For now, let's just save RAX to .data and read it with external tool
    shellcode = bytearray()

    # push rax; push rcx; push rdx; push r8; push r9; push r10; push r11; pushfq
    shellcode += b'\x50\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53\x9c'

    # mov [result_ptr], rax    - save return value ptr
    # mov result_ptr_rva first
    # We need the absolute address of .data
    # RIP-relative: lea rax, [rip + offset]; then mov [rax], original_rax
    # But we pushed rax... let's use r15
    shellcode += b'\x41\x5f'  # pop r15 (restore r15 for temp use)
    shellcode += b'\x53'       # push rbx (save rbx)

    # mov rbx, [rsp+8]  -- get saved rax value from stack
    # Actually this is getting too complex for inline shellcode.

    # Let me try the SIMPLEST possible approach:
    # Just patch to skip the function entirely and return a known value,
    # or insert an INT3 to break in debugger.

    print("\n=== Simpler approach: Return address patch ===")
    print("We'll patch the function epilogue to save RAX to .data before returning.")
    print("Then ReadProcessMemory can read the value from the running process.")

    # Actually, let me think about this differently.
    # The simplest patch that preserves Go compatibility:
    # Insert a single instruction before the return that copies RAX to .data
    # without disturbing the stack or calling any functions.

    # At getAppSalt return (0x882b8a):
    # Current: add rsp, 0xf8; pop rbp; ret
    # We want: [save rax to .data]; add rsp, 0xf8; pop rbp; ret

    # The function epilogue already does:
    # add rsp, 0xf8  (48 81 C4 F8 00 00 00)
    # pop rbp        (5d)
    # ret            (c3)

    # We need to insert our save before add rsp, 0xf8
    # But we can't insert - we can only replace bytes of same size.

    # Alternative: Replace the entire epilogue with:
    # 1. Save RAX to .data (RIP-relative mov)
    # 2. Execute original epilogue

    # The epilogue is at offset 0x882b8a - 0x882760 = 0x42a into the function
    # Let's find the exact position

    func_off = rva_to_file(0x882760, sections)
    epilogue_func_offset = 0x882b8a - 0x882760  # 0x42A
    epilogue_file_off = func_off + epilogue_func_offset

    print(f"Epilogue at file offset: 0x{epilogue_file_off:x}")
    print(f"Epilogue bytes: {data[epilogue_file_off:epilogue_file_off+10].hex(' ')}")

    # The epilogue starts at add rsp, 0xf8
    # We have room from the instruction before the epilogue to insert our code
    # Let's look at what's before

    print(f"\nInstructions before epilogue:")
    print(f"  Offset 0x{epilogue_file_off - 20:x}: {data[epilogue_file_off - 20:epilogue_file_off].hex(' ')}")

    # Actually, instead of inserting shellcode in the function,
    # let's replace the entire function body with our simpler version.
    # But that would break the function's actual behavior...

    # BETTER APPROACH:
    # Insert a JMP at the START of getAppSalt to our code cave.
    # In the code cave:
    #   1. JMP to the ORIGINAL getAppSalt (skip the JMP we inserted)
    #   2. After it returns, save RAX
    #   3. JMP back to original caller

    # This is essentially what Interceptor.replace does, but without Frida.
    # The difference is we do it at the binary level, which Go GC won't detect
    # as problematic (no injected JS runtime to conflict).

    jmp_target_rva = cave_rva
    jmp_from_rva = getAppSalt_rva

    # JMP rel32 at getAppSalt -> code cave
    # The JMP is 5 bytes: E9 <rel32>
    # rel32 = target - (source + 5)
    # But source and target are both RVAs
    # Actually, JMP rel32 is relative to the next instruction (RIP+5)
    # In file terms: cave_rva - (getAppSalt_rva + 5)
    # In absolute terms: same calculation since both are in same module

    cave_offset = code_cave
    getAppSalt_offset = rva_to_file(getAppSalt_rva, sections)

    # JMP rel32
    rel32 = (cave_offset + 0x140000000) - (getAppSalt_offset + 0x140000000 + 5)
    # Or just: rel32 = cave_rva - (getAppSalt_rva + 5)

    rel32 = cave_rva - (getAppSalt_rva + 5)
    print(f"\nPatching getAppSalt (RVA 0x{getAppSalt_rva:x}) to jump to cave (RVA 0x{cave_rva:x})")
    print(f"JMP rel32 = 0x{rel32:x}")

    # Write JMP at getAppSalt entry
    data[getAppSalt_offset] = 0xE9  # JMP rel32
    struct.pack_into('<i', data, getAppSalt_offset + 1, rel32)

    print(f"JMP instruction: {data[getAppSalt_offset:getAppSalt_offset+5].hex(' ')}")

    # At code cave: write our trampoline
    cave_data = bytearray(500)
    offset = 0

    # Step 1: Call original getAppSalt (skip our JMP)
    # The original getAppSalt code starts 5 bytes after the JMP
    original_func_rva = getAppSalt_rva + 5
    # We need to CALL the original
    call_rel32 = (original_func_rva + 0x140000000 + 5) - (cave_rva + 0x140000000 + 5)
    call_rel32 = original_func_rva - (cave_rva + 5)

    cave_data[offset] = 0xE8  # CALL rel32
    struct.pack_into('<i', cave_data, offset + 1, call_rel32)
    offset += 5

    # Step 2: After CALL, RAX has the return value
    # Save RAX and RCX to .data section
    # Use RIP-relative addressing from current position

    # Calculate RIP-relative offset to .data
    # Current RIP after the mov instruction = cave_rva + offset + 7
    # We want to store at result_ptr_rva (.data start)
    # RIP-relative: target = RIP + disp32 + 7 (for mov instruction)
    # disp32 = target - RIP - 7

    # mov [rip + disp32], rax
    # This stores RAX at result_ptr_rva
    data_rva = result_ptr_rva
    current_rva = cave_rva + offset
    disp32 = data_rva - current_rva - 7  # -7 for the mov instruction size

    cave_data[offset] = 0x48  # REX.W
    cave_data[offset+1] = 0x89  # MOV r/m64, r64
    cave_data[offset+2] = 0x05  # ModR/M: [rip + disp32], rax
    struct.pack_into('<i', cave_data, offset + 3, disp32)
    offset += 7

    # Also save RCX (length for Go strings)
    disp32_rcx = (data_rva + 8) - current_rva - 7  # Store 8 bytes after
    cave_data[offset] = 0x48
    cave_data[offset+1] = 0x89
    cave_data[offset+2] = 0x0D  # ModR/M for RCX
    struct.pack_into('<i', cave_data, offset + 3, disp32_rcx)
    offset += 7

    # Also save RDX (cap for Go slices)
    disp32_rdx = (data_rva + 16) - current_rva - 7
    cave_data[offset] = 0x48
    cave_data[offset+1] = 0x89
    cave_data[offset+2] = 0x15  # ModR/M for RDX
    struct.pack_into('<i', cave_data, offset + 3, disp32_rdx)
    offset += 7

    # Step 3: Now try to dump the string/slice content
    # This is more complex - we'd need to call Windows APIs
    # For now, just save the pointers and let external tool read the content

    # Step 4: RET - return to original caller
    cave_data[offset] = 0xC3  # RET
    offset += 1

    print(f"\nTrampoline shellcode ({offset} bytes):")
    print(f"  {bytes(cave_data[:offset]).hex(' ')}")

    # Write trampoline to code cave
    for i in range(len(cave_data)):
        data[cave_offset + i] = cave_data[i]

    # Write patched binary
    with open(OUTPUT, 'wb') as f:
        f.write(data)

    print(f"\nPatched binary written to: {OUTPUT}")
    print(f"Result will be saved to .data RVA 0x{result_ptr_rva:x}")
    print(f"Use ReadProcessMemory to read from running process!")
    print(f"\nTo test: run the patched binary and use read_dump.py to get results")

if __name__ == '__main__':
    main()
