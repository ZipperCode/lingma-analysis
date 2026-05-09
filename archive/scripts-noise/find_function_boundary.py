"""
找到包含 AesEncryptWithBase64 调用的函数
通过搜索函数序言 (PUSH RBP; MOV RBP, RSP) 来确定函数边界
"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

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

sections = parse_sections(pe_data)
md = Cs(CS_ARCH_X86, CS_MODE_64)
text_section = sections[0]

callers = [0x88eea6, 0x892305, 0x8926e2, 0xaf33a6, 0xb96f68]

print("=== Finding function boundaries for each caller ===")

for caller_va in callers:
    caller_offset = va_to_file_offset(sections, caller_va)
    if caller_offset is None:
        print(f"\nCaller 0x{caller_va:x}: offset not found")
        continue

    # Search backwards for function prologue
    # Go function prologue is often: PUSH RBP; MOV RBP, RSP; SUB RSP, N
    # Or in Go: MOV ...; SUB RSP, N

    search_start = max(0, caller_offset - 5000)
    search_data = pe_data[search_start:caller_offset + 100]
    search_va = caller_va - (caller_offset - search_start)

    instructions = list(md.disasm(search_data, search_va))

    # Find the call instruction closest to caller_va
    call_idx = None
    for i, insn in enumerate(instructions):
        if insn.address == caller_va:
            call_idx = i
            break

    if call_idx is None:
        print(f"\nCaller 0x{caller_va:x}: call instruction not found in disassembly")
        continue

    # Search backwards for function prologue patterns
    func_start = None
    for i in range(call_idx, max(0, call_idx - 200), -1):
        insn = instructions[i]
        # Look for function entry: typically SUB RSP, imm followed by MOV instructions
        if insn.mnemonic == 'sub' and 'rsp' in insn.op_str:
            # Check if previous instruction is a common prologue start
            if i > 0:
                prev = instructions[i-1]
                # In Go, functions often start with MOV to set up the frame
                # or with a direct SUB RSP
                # Or the function might just have NOPs at the start
                func_start = insn.address
                # Go further back to check for NOP padding (function boundary)
                for j in range(i-1, max(0, i-10), -1):
                    if instructions[j].mnemonic == 'nop' or instructions[j].mnemonic == 'int3':
                        func_start = instructions[j+1].address
                        break
                break

    if func_start is None:
        # Try looking for MOV R15, RSP or similar Go prologue
        for i in range(call_idx, max(0, call_idx - 200), -1):
            insn = instructions[i]
            if insn.mnemonic == 'mov' and ('r15' in insn.op_str or 'rbp' in insn.op_str) and 'rsp' in insn.op_str:
                func_start = insn.address
                break

    if func_start:
        print(f"\nCaller 0x{caller_va:x}: function starts around 0x{func_start:x}")

        # Now disassemble from func_start to find string references
        func_offset = va_to_file_offset(sections, func_start)
        if func_offset:
            func_data = pe_data[func_offset:func_offset + 2000]
            func_instructions = list(md.disasm(func_data, func_start))

            # Find string references (LEA with RIP pointing to .rdata/.data)
            string_refs = []
            for insn in func_instructions:
                if insn.address >= caller_va:
                    break  # Stop after the call
                if insn.mnemonic == 'lea' and 'rip' in insn.op_str:
                    op = insn.op_str
                    if '+' in op:
                        parts = op.split('+')
                        disp_str = parts[1].strip().rstrip('h')
                        try:
                            disp = int(disp_str, 16)
                            target_va = insn.address + insn.size + disp
                            target_off = va_to_file_offset(sections, target_va)
                            if target_off and 0 < target_off < len(pe_data):
                                content = pe_data[target_off:target_off+80]
                                printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in content)
                                string_refs.append((insn.address, target_va, printable[:60]))
                        except:
                            pass

            print(f"  String references before the call:")
            for addr, target, content in string_refs[:15]:
                print(f"    0x{addr:08x} -> 0x{target:x}: ...{content}...")

            # Also show what happens after the call
            for i, insn in enumerate(func_instructions):
                if insn.address == caller_va:
                    print(f"  After the call:")
                    for j in range(i+1, min(i+20, len(func_instructions))):
                        next_insn = func_instructions[j]
                        if next_insn.mnemonic == 'ret':
                            print(f"    0x{next_insn.address:08x}: ret")
                            break
                        print(f"    0x{next_insn.address:08x}: {next_insn.mnemonic:<10} {next_insn.op_str}")
                    break
    else:
        print(f"\nCaller 0x{caller_va:x}: could not find function start")
        # Just show some context
        print(f"  Showing context around call:")
        for i in range(max(0, call_idx-20), call_idx+5):
            insn = instructions[i]
            print(f"    0x{insn.address:08x}: {insn.mnemonic:<10} {insn.op_str}")
