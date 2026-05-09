"""
终极方案: 直接读取 getAppSalt 函数的机器码来找到它返回的值
如果 getAppSalt 返回一个硬编码字符串常量, 我们可以从函数代码中找到这个字符串的地址
"""
import pefile
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def main():
    pe = pefile.PE(BINARY_PATH, fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    sections = {}
    for section in pe.sections:
        name = section.Name.decode('ascii', errors='replace').rstrip('\x00')
        sections[name] = section

    rdata_data = sections['.rdata'].get_data()
    text_data = sections['.text'].get_data()

    # Step 1: Parse .pdata to find all function boundaries
    pdata_data = sections['.pdata'].get_data()
    num_pdata = len(pdata_data) // 12

    func_rvas = []
    for i in range(num_pdata):
        offset = i * 12
        begin_rva = struct.unpack('<I', pdata_data[offset:offset+4])[0]
        end_rva = struct.unpack('<I', pdata_data[offset+4:offset+8])[0]
        # Filter to .text range
        text_va = sections['.text'].VirtualAddress
        text_end = text_va + sections['.text'].Misc_VirtualSize
        if text_va <= begin_rva < text_end:
            func_rvas.append((begin_rva, end_rva))

    print(f'Functions in .text: {len(func_rvas)}')

    # Step 2: Find functions near getAppSalt's name position
    # getAppSalt name is at .rdata RVA 0x3b9f3a6
    # addBigModelSignatureHeaders name is at .rdata RVA 0x3b9f37c
    # They should be called together, so their code should be nearby

    # In Go, functions in the same package tend to be placed
    # near each other in .text (but not guaranteed due to linker optimization)

    # We know from the pclntab that functions are ordered:
    # ...addBigModelSignatureHeaders, getAppSalt, addBigModelAuthorizationHeaders...

    # Let's find a cluster of small functions that could be these

    # Alternative approach: search .text for patterns that match
    # getAppSalt's likely implementation

    # getAppSalt probably:
    # 1. Returns a string constant (Go string = pointer + length)
    # 2. The pattern would be:
    #    LEA RAX, [rip + offset]  ; load string pointer
    #    MOV RCX, length           ; load string length
    #    RET

    # Or it returns the result of getAppSalt() which is stored somewhere

    # Let's search for small functions that return strings
    # by looking for the pattern: LEA + MOV + RET

    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # The getAppSalt function should be in the middle of the cosy/remoting functions
    # Let's find functions in the typical remoting region

    # Based on the pclntab ordering, remoting functions span a certain RVA range
    # Let's find functions whose code references strings in the getAppSalt name region

    # Actually, let's try the simplest thing: disassemble the region around
    # where getAppSalt's code should be based on package ordering

    # From the pclntab name ordering:
    # BuildAlgoForRequestUrl -> ... -> getAppSalt -> ... -> trimQueryPath

    # These are all in cosy/remoting, so they're consecutive in the .text section
    # (approximately)

    # Let's find the first remoting function (BuildAlgoForRequestUrl)
    # by searching for its name reference in .text

    # BuildAlgoForRequestUrl name is at .rdata RVA 0x3b9f1bb
    # Let's find .text code that references this

    print('\nSearching for BuildAlgoForRequestUrl function code...')
    build_algo_name_rva = 0x3b9f1bb

    # In Go, the function name is referenced in the pclntab, not in the code itself
    # So we can't find the function by searching for name references

    # Let's try a different heuristic:
    # The remoting functions are grouped together. Let's find the region
    # by looking for LEA instructions that reference .rdata strings
    # near where the remoting function names are stored

    # .rdata region for remoting names: 0x3b9f000 - 0x3b9f600 (approx)
    # The corresponding .text region should have functions that reference these

    # Actually, let me just try to find functions by searching for the pattern
    # that getAppSalt would have:

    # getAppSalt() string - it probably returns a constant string
    # Go string return: RAX = string pointer, RCX (or RDX) = string length
    # Pattern:
    #   LEA RAX, [rip + salt_string_offset]
    #   MOV EDX, salt_length  (or MOV RCX, ...)
    #   RET

    # Or it might be even simpler:
    #   MOV EAX, salt_pointer_low32
    #   MOV ECX, salt_length
    #   RET

    # Let's search all small functions (2-20 bytes) for this pattern
    # First, get all function sizes
    func_sizes = [(end - begin, begin, end) for begin, end in func_rvas]
    small_funcs = [(size, begin, end) for size, begin, end in func_sizes if 4 <= size <= 64]

    print(f'Total small functions (4-64 bytes): {len(small_funcs)}')

    # Now filter to functions that reference .rdata
    text_va = sections['.text'].VirtualAddress
    text_file_offset = sections['.text'].PointerToRawData
    rdata_va = sections['.rdata'].VirtualAddress
    rdata_file_offset = sections['.rdata'].PointerToRawData
    rdata_end_va = rdata_va + sections['.rdata'].Misc_VirtualSize

    candidates = []
    for size, begin_rva, end_rva in small_funcs:
        # Get function code
        file_offset = text_file_offset + (begin_rva - text_va)
        func_code = text_data[begin_rva - text_va:begin_rva - text_va + size]

        # Disassemble
        instructions = list(md.disasm(func_code, begin_rva))

        # Check for LEA to .rdata
        has_rdata_ref = False
        ref_target = None
        for insn in instructions:
            if insn.mnemonic == 'lea':
                # Check if it references .rdata
                op_str = insn.op_str
                if 'rip' in op_str:
                    # Calculate target
                    # LEA uses RIP-relative addressing
                    # target = rip + disp (rip is next instruction address)
                    try:
                        disp = insn.disp
                        next_addr = insn.address + insn.size
                        target = next_addr + disp
                        if rdata_va <= target < rdata_end_va:
                            has_rdata_ref = True
                            ref_target = target
                            break
                    except:
                        pass

        if has_rdata_ref:
            candidates.append((size, begin_rva, end_rva, ref_target))

    print(f'Functions referencing .rdata via LEA: {len(candidates)}')

    # Now find candidates in the remoting package region
    # Remoting function names are at .rdata RVA 0x3b9f000 - 0x3b9f800
    # The corresponding code should be in a specific .text region

    # Let's check if any candidates are in the right region
    # by looking at the distribution of their RVAs

    if candidates:
        # Sort by RVA
        candidates.sort(key=lambda x: x[1])

        # Find the region where most candidates are
        rvas = [c[1] for c in candidates]
        min_rva = min(rvas)
        max_rva = max(rvas)
        print(f'Candidate RVA range: 0x{min_rva:x} - 0x{max_rva:x}')

        # Filter to remoting region (approximately 0x800000 - 0xd00000)
        # Based on the original Frida trace offsets
        remoting_candidates = [c for c in candidates if 0x700000 <= c[1] <= 0xe00000]
        print(f'Remoting region candidates: {len(remoting_candidates)}')

        for size, begin_rva, end_rva, ref_target in remoting_candidates[:20]:
            file_offset = text_file_offset + (begin_rva - text_va)
            func_code = text_data[begin_rva - text_va:begin_rva - text_va + size]

            # Show the function's code
            code_hex = func_code.hex()

            # Check if it references a specific .rdata region
            ref_rdata_offset = ref_target - rdata_va
            # Show what's at the referenced .rdata location
            ref_content = rdata_data[ref_rdata_offset:ref_rdata_offset+50]
            ref_str = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ref_content)

            print(f'  0x{begin_rva:x} (size={size}, ref_rdata=0x{ref_rdata_offset:x}): {ref_str[:60]}')

            # Show disassembly
            for insn in md.disasm(func_code, begin_rva):
                print(f'    {insn.mnemonic} {insn.op_str}')

    pe.close()

if __name__ == '__main__':
    main()
