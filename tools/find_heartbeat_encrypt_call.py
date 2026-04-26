"""
查找 heartbeat POST 的编码管道
关键: 找到调用 AesEncryptWithBase64 的 heartbeat 相关代码
"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

# Parse PE sections
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

# We know AesEncryptWithBase64 is at RVA 0x455da0
# And its callers are at: 0x88eea6, 0x892305, 0x8926e2, 0xaf33a6, 0xb96f68
# Let's find which of these callers is in the heartbeat/algo path

print("=== Analyzing AesEncryptWithBase64 callers ===")
callers = [0x88eea6, 0x892305, 0x8926e2, 0xaf33a6, 0xb96f68]

for caller_va in callers:
    offset = va_to_file_offset(sections, caller_va)
    if offset is None:
        print(f"\n  Caller 0x{caller_va:x}: offset not found")
        continue

    # Get larger context around the call
    context_data = pe_data[max(0, offset-300):offset + 50]

    print(f"\n  Caller at VA 0x{caller_va:x} (file offset 0x{offset:x}):")

    # Disassemble
    instructions = list(md.disasm(context_data, caller_va - 300))

    # Find the call to AesEncryptWithBase64
    for i, insn in enumerate(instructions):
        if insn.address >= caller_va - 5 and insn.mnemonic == 'call':
            # Show 30 instructions before the call
            print(f"  --- 30 instructions before call ---")
            for j in range(max(0, i-30), i):
                inst = instructions[j]
                print(f"    0x{inst.address:08x}: {inst.mnemonic:<10} {inst.op_str}")
            print(f"  >>> 0x{insn.address:08x}: {insn.mnemonic:<10} {insn.op_str}")

            # Show 10 instructions after
            for j in range(i+1, min(i+15, len(instructions))):
                inst = instructions[j]
                print(f"    0x{inst.address:08x}: {insn.mnemonic:<10} {inst.op_str}")
            break

# Also let's find which functions these callers belong to
# by searching the pclntab for nearby function names
print("\n\n=== Finding function names for callers ===")
text_section = sections[0]
text_raw = pe_data[text_section['raw_offset']:text_section['raw_offset'] + text_section['raw_size']]

# For each caller, search backwards for function prologue (or nearby function name in pclntab)
# The pclntab stores function names separately from code
# We can find the function by searching for the function's VA in the pclntab function table

# Alternative: search for function names that reference the caller's region
# by looking at the pclntab entries

# Let's try a different approach: find all function names and their VAs
# and match the callers to their enclosing functions

print("  Building function table from pclntab...")

# Find pclntab
# The pclntab starts with the magic number followed by version info
# Search near the beginning of .rdata

# Actually, let's use the known function name positions to estimate
# Function names in pclntab contain the package and function name

# For each caller VA, search for function names that might contain it
# by looking at cross-references

# Simpler approach: look for LEA instructions near the caller that load string constants
# These often reveal the function's purpose

for caller_va in callers:
    offset = va_to_file_offset(sections, caller_va)
    if offset is None:
        continue

    context_data = pe_data[max(0, offset-500):offset + 30]
    instructions = list(md.disasm(context_data, caller_va - 500))

    # Find LEA instructions that load addresses (these load string constants)
    print(f"\n  Caller 0x{caller_va:x} - string references:")
    for insn in instructions:
        if insn.address >= caller_va - 400 and insn.address < caller_va + 20:
            if insn.mnemonic == 'lea':
                # Try to resolve the address
                op = insn.op_str
                if 'rip' in op:
                    # Extract displacement
                    # Format: reg, [rip + disp] or [rip - disp]
                    parts = op.split('+')
                    if len(parts) == 2:
                        try:
                            disp = int(parts[1].strip().rstrip('h'), 16)
                            target = insn.address + insn.size + disp
                            file_off = va_to_file_offset(sections, target)
                            if file_off and 0 < file_off < len(pe_data):
                                data = pe_data[file_off:file_off+50]
                                printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in data)
                                print(f"    0x{insn.address:08x}: LEA -> 0x{target:x} = ...{printable}...")
                        except:
                            pass
