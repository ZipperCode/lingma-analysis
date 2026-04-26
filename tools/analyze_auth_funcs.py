"""Analyze GetAuthorizationHeader and API path registry."""
import struct
from capstone import *

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
IMAGE_BASE = 0x140000000
md = Cs(CS_ARCH_X86, CS_MODE_64)

with open(LINGMA, 'rb') as f:
    binary = f.read()

pe_off = struct.unpack('<I', binary[0x3c:0x40])[0]
opt_size = struct.unpack('<H', binary[pe_off + 20:pe_off + 22])[0]
sect_start = pe_off + 24 + opt_size
sections = {}
for i in range(6):
    off = sect_start + i * 40
    name = binary[off:off + 8].rstrip(b'\x00').decode()
    va = struct.unpack('<I', binary[off + 12:off + 16])[0]
    rp = struct.unpack('<I', binary[off + 20:off + 24])[0]
    vs = struct.unpack('<I', binary[off + 16:off + 20])[0]
    sections[name] = (va, rp, vs)

text_va, text_raw, text_vs = sections['.text']
rdata_va, rdata_raw, rdata_vs = sections['.rdata']
pdata_va, pdata_raw, pdata_vs = sections['.pdata']

def rva_to_offset(rva):
    for name, (va, rp, vs) in sections.items():
        if va <= rva < va + vs:
            return rp + (rva - va), name
    return None, 'unknown'

def read_at_rva(rva, size=0x200):
    off, sec = rva_to_offset(rva)
    if off is None:
        return None, sec
    return binary[off:off + size], sec

def get_func_bounds(func_rva):
    """Get function begin/end from .pdata."""
    pdata_end = pdata_raw + pdata_vs
    for poff in range(pdata_raw, pdata_end - 12, 12):
        begin = struct.unpack('<I', binary[poff:poff + 4])[0]
        end = struct.unpack('<I', binary[poff + 4:poff + 8])[0]
        if begin == func_rva:
            return begin, end
    return func_rva, func_rva + 0x200

def disasm_func(func_rva, max_insns=80):
    begin, end = get_func_bounds(func_rva)
    size = min(end - begin + 0x50, 0x500)
    code, sec = read_at_rva(begin, size)
    if code is None:
        print(f"  Cannot read at RVA 0x{begin:x}")
        return []

    insns = []
    count = 0
    calls = []
    rip_refs = []

    for insn in md.disasm(code, IMAGE_BASE + begin):
        rva = insn.address - IMAGE_BASE
        if rva > end + 0x50 or count > max_insns:
            break
        insns.append((rva, insn.mnemonic, insn.op_str, insn.size))

        if insn.mnemonic == 'call':
            # Calculate target
            if insn.op_str.startswith('0x'):
                target = int(insn.op_str, 16) - IMAGE_BASE
            elif insn.bytes[0] == 0xe8:
                disp = struct.unpack('<i', insn.bytes[1:5])[0]
                target = rva + insn.size + disp
            else:
                target = insn.op_str
            calls.append((rva, target))

        if 'rip' in insn.op_str and insn.mnemonic in ('lea', 'mov', 'cmp'):
            op = insn.op_str
            if 'rip +' in op:
                disp = int(op.split('rip + ')[1].split(']')[0].split(',')[0], 16)
            elif 'rip -' in op:
                disp = -int(op.split('rip - ')[1].split(']')[0].split(',')[0], 16)
            else:
                continue
            rip_next = insn.address + insn.size
            eff_addr = rip_next + disp - IMAGE_BASE
            if 0 < eff_addr < 0x6000000:
                rip_refs.append((rva, eff_addr))

        count += 1

    return insns, calls, rip_refs, begin, end

# Analyze GetAuthorizationHeader
print("=" * 70)
print("GetAuthorizationHeader function")
print("=" * 70)
# The string "GetAuthorizationHeader" is at 0x1fab37e in .rdata
# This is likely the name of a function. Find it via .gopclntab or by searching
# for function names. Go function names are in .rdata.

# Find functions that reference this string
def find_xrefs_to_string(str_rva):
    """Find functions that reference this string RVA."""
    str_va = str_rva + IMAGE_BASE
    results = []
    # Search in .text for RIP references pointing to this string
    text_end = text_raw + text_vs
    idx = text_raw
    while idx < text_end - 8:
        pos = binary.find(struct.pack('<Q', str_va), idx, text_end)
        if pos == -1:
            # Try little-endian 32-bit reference
            pos = binary.find(struct.pack('<I', str_rva & 0xFFFFFFFF), idx, text_end)
            if pos == -1:
                break
        func_rva = pos - text_raw + text_va
        results.append(func_rva)
        idx = pos + 1
        if len(results) > 20:
            break
    return results

# Instead of searching for xrefs, let's find the function by its name string
# Go stores function names in .rdata as part of the pclntab

# Let's search for the actual function by looking at .rdata for function name
print("\nSearching for function name strings...")
for name in [b'GetAuthorizationHeader', b'BuildBigModelAuthRequest', b'getAppSalt',
             b'addBigModelSignatureHeaders', b'addBigModelAuthorizationHeaders']:
    idx = rdata_raw
    while idx < rdata_raw + rdata_vs - len(name):
        pos = binary.find(name, idx, rdata_raw + rdata_vs)
        if pos == -1:
            break
        # Show context around this string
        ctx_start = max(rdata_raw, pos - 20)
        ctx_end = min(rdata_raw + rdata_vs, pos + len(name) + 40)
        ctx = binary[ctx_start:ctx_end]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
        rva = pos - rdata_raw + rdata_va
        print(f"  '{name.decode()}' @ RVA 0x{rva:x}: ...{printable}...")

        # Look for pclntab entry: function name is followed by function entry
        # In Go 1.23, function name format: "package.Type.method"
        # The function entry in pclntab contains: entry offset, name offset, etc.

        # Also search for this RVA in .text as a RIP reference target
        # This would tell us which functions reference this string
        idx = pos + 1

# Let's try a different approach: search .text for direct references to these strings
print()
print("=" * 70)
print("Functions that reference Authorization string (0x1fab381)")
print("=" * 70)

auth_str_rva = 0x1fab381
auth_str_va = auth_str_rva + IMAGE_BASE

# Search .text for RIP-relative references to this address
# In x86-64, RIP-relative: effective_addr = RIP_next + disp
# So we need to find: instruction where RIP_next + disp = auth_str_va
# i.e., disp = auth_str_va - RIP_next

# This is complex. Let's just search for the raw VA bytes in .text
text_end = text_raw + text_vs
idx = text_raw
found = 0
while idx < text_end - 7 and found < 10:
    pos = binary.find(struct.pack('<Q', auth_str_va), idx, text_end)
    if pos == -1:
        break
    # Found the VA embedded in .text
    # This is part of an instruction (likely MOV or LEA with RIP-relative)
    func_rva = pos - text_raw + text_va
    # Back up to find the instruction start (look for the opcode)
    # The instruction is likely: mov rcx, qword ptr [rip + disp] or lea rax, [rip + disp]
    # The disp would be at offset pos-3 or pos-4 from the instruction start

    # Show surrounding context
    ctx_start = max(text_raw, pos - 15)
    ctx_end = min(text_end, pos + 10)
    ctx = binary[ctx_start:ctx_end]
    hex_str = ' '.join(f'{b:02x}' for b in ctx)
    print(f"  Found at file offset 0x{pos:x} (RVA ~0x{func_rva:x}): ...{hex_str}...")
    found += 1
    idx = pos + 1

if found == 0:
    # Try 32-bit RIP-relative
    # RIP-relative uses a 32-bit displacement, not the full 64-bit address
    # The displacement = target_addr - (instr_addr + instr_size)
    # We need to scan for instructions that compute to this target

    # Alternative: search .rdata for the string offset relative to rdata start
    # disp32 = target_rva - (instr_rva + instr_size) + IMAGE_BASE
    # This is too complex without full disassembly

    print("  No direct 64-bit VA references found. String likely referenced via RIP-relative.")
    print("  Trying to find by scanning .text for matching displacements...")

    # Let's use capstone on a broader range
    # First, let's just disasm GetAuthorizationHeader area
    print()
    print("Disassembling around cosy/auth package functions (0x1fa0000-0x1fc0000)...")
    # This is too broad. Let's try specific known functions.

# Instead, let's look at the cosy/remoting getAppSalt function
# We know it's referenced at 0x3b9f3b7 as the function name
# The actual function is at 0x882760
print()
print("=" * 70)
print("Full getAppSalt disassembly (0x882760)")
print("=" * 70)

insns, calls, rip_refs, begin, end = disasm_func(0x882760, max_insns=100)
print(f"  Function bounds: RVA 0x{begin:x} - 0x{end:x}")
print(f"  Instructions: {len(insns)}, Calls: {len(calls)}")
print()

for rva, mnem, opstr, sz in insns:
    prefix = "  "
    print(f"{prefix}0x{rva:04x} {mnem:12s} {opstr}")

print()
print(f"  Calls:")
for caller_rva, target in calls:
    if isinstance(target, int):
        print(f"    0x{caller_rva:04x} -> RVA 0x{target:x}")
    else:
        print(f"    0x{caller_rva:04x} -> {target}")

print()
print(f"  RIP references:")
for insn_rva, target_rva in rip_refs:
    content, sec = read_at_rva(target_rva, 40)
    if content:
        try:
            s = content.split(b'\x00')[0].decode('utf-8', errors='replace')
            if len(s) > 2 and all(32 <= ord(c) < 127 for c in s[:15]):
                print(f"    0x{insn_rva:04x} -> RVA 0x{target_rva:x} ({sec}) str='{s[:60]}'")
                continue
        except:
            pass
        # Check if Go string struct
        if len(content) >= 16:
            ptr = struct.unpack('<Q', content[0:8])[0]
            length = struct.unpack('<Q', content[8:16])[0]
            if 0x1000000 < ptr < 0x6000000 and 0 < length < 200:
                str_content, _ = read_at_rva(ptr - IMAGE_BASE, length)
                if str_content:
                    print(f"    0x{insn_rva:04x} -> RVA 0x{target_rva:x} ({sec}) GoStr='{str_content.decode('utf-8', errors='replace')[:60]}'")
                    continue
        hex_str = ' '.join(f'{b:02x}' for b in content[:16])
        print(f"    0x{insn_rva:04x} -> RVA 0x{target_rva:x} ({sec}) {hex_str}")
