"""Deep trace of the signing algorithm in getAppSalt and MainSigning."""
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
data_va, data_raw, data_vs = sections['.data']
pdata_va, pdata_raw, pdata_vs = sections['.pdata']

def rva_to_offset(rva):
    for name, (va, rp, vs) in sections.items():
        if va <= rva < va + vs:
            return rp + (rva - va), name
    return None, 'unknown'

def read_at_rva(rva, size=0x100):
    off, sec = rva_to_offset(rva)
    if off is None:
        return None, sec
    return binary[off:off + size], sec

def read_string_at_rva(rva, max_len=200):
    off, sec = rva_to_offset(rva)
    if off is None:
        return '<invalid>', sec
    # Check if it's a Go string {ptr, len}
    if sec == '.data' or sec == '.rdata':
        ptr = struct.unpack('<Q', binary[off:off+8])[0] - IMAGE_BASE
        length = struct.unpack('<Q', binary[off+8:off+16])[0]
        if 0 < ptr < 0x6000000 and 0 < length < max_len:
            content, _ = read_at_rva(ptr, length)
            if content:
                return content.decode('utf-8', errors='replace'), sec
    # Try as null-terminated C string
    end = binary.find(b'\x00', off, off + max_len)
    if end == -1:
        return binary[off:off + min(max_len, 50)].decode('utf-8', errors='replace'), sec
    return binary[off:end].decode('utf-8', errors='replace'), sec

def resolve_rip(insn_rva, insn):
    op = insn.op_str
    if 'rip' not in op:
        return None
    if '+' in op:
        hex_part = op.split('rip + ')[1].split(']')[0].split(',')[0]
        disp = int(hex_part, 16)
    elif '-' in op:
        hex_part = op.split('rip - ')[1].split(']')[0].split(',')[0]
        disp = -int(hex_part, 16)
    else:
        return None
    rip = IMAGE_BASE + insn_rva + insn.size
    eff = rip + disp - IMAGE_BASE
    return eff

def get_func_bounds(func_rva):
    pdata_end = pdata_raw + pdata_vs
    for poff in range(pdata_raw, pdata_end - 12, 12):
        begin = struct.unpack('<I', binary[poff:poff + 4])[0]
        end = struct.unpack('<I', binary[poff + 4:poff + 8])[0]
        if begin == func_rva:
            return begin, end
    return func_rva, func_rva + 0x500

def disasm_with_refs(func_rva, max_insns=150):
    begin, end = get_func_bounds(func_rva)
    size = min(end - begin + 0x100, 0x1000)
    code, sec = read_at_rva(begin, size)
    if code is None:
        return [], [], [], begin, end

    insns = []
    calls = []
    rip_refs = []

    for insn in md.disasm(code, IMAGE_BASE + begin):
        rva = insn.address - IMAGE_BASE
        if rva > end + 0x100 or len(insns) > max_insns:
            break
        insns.append((rva, insn.mnemonic, insn.op_str, insn.size))

        if insn.mnemonic == 'call':
            if insn.op_str.startswith('0x'):
                target = int(insn.op_str, 16) - IMAGE_BASE
            elif insn.bytes and insn.bytes[0] == 0xe8:
                disp = struct.unpack('<i', insn.bytes[1:5])[0]
                target = rva + insn.size + disp
            else:
                target = insn.op_str
            calls.append((rva, target))

        if 'rip' in insn.op_str and insn.mnemonic in ('lea', 'mov', 'cmp', 'test'):
            target = resolve_rip(rva, insn)
            if target and 0 < target < 0x6000000:
                rip_refs.append((rva, target, insn.mnemonic, insn.op_str))

    return insns, calls, rip_refs, begin, end

# ============================================================
# 1. Full disassembly of getAppSalt (0x882760) with string refs
# ============================================================
print("=" * 70)
print("getAppSalt (0x882760) - Full disassembly with string resolution")
print("=" * 70)

insns, calls, rip_refs, begin, end = disasm_with_refs(0x882760, max_insns=120)
print(f"  Function bounds: RVA 0x{begin:x} - 0x{end:x}")
print(f"  Instructions: {len(insns)}, Calls: {len(calls)}, RIP refs: {len(rip_refs)}")
print()

for rva, mnem, opstr, sz in insns:
    # Highlight important instructions
    marker = ""
    if mnem in ('lea', 'mov') and 'rip' in opstr:
        # Look up the string
        for ref_rva, target, ref_mnem, ref_opstr in rip_refs:
            if ref_rva == rva:
                content, sec = read_at_rva(target, 60)
                if content:
                    try:
                        s = content.split(b'\x00')[0].decode('utf-8', errors='replace')
                        if s and all(32 <= ord(c) < 127 or c in '\r\n\t' for c in s[:10]):
                            marker = f"  # str='{s[:80]}'"
                    except:
                        pass
                break
    elif mnem == 'call':
        # Find the target for this specific call
        call_targets = [t for c, t in calls if c == rva]
        if call_targets:
            t = call_targets[0]
            if isinstance(t, int):
                marker = f"  # call -> 0x{t:x}"
            else:
                marker = f"  # call -> {t}"

    print(f"  0x{rva:05x} {mnem:12s} {opstr:45s}{marker}")

print()
print("  Calls:")
for caller_rva, target in calls:
    if isinstance(target, int):
        print(f"    0x{caller_rva:05x} -> RVA 0x{target:x}")
    else:
        print(f"    0x{caller_rva:05x} -> {target}")

print()
print("  RIP references (resolved):")
for insn_rva, target_rva, mnem, opstr in rip_refs:
    content, sec = read_at_rva(target_rva, 60)
    if content is None:
        continue
    # Try as string
    try:
        s = content.split(b'\x00')[0].decode('utf-8', errors='replace')
        if s and len(s) > 2 and all(32 <= ord(c) < 127 or c in '\r\n\t' for c in s[:10]):
            print(f"    0x{insn_rva:05x} -> RVA 0x{target_rva:x} ({sec}) str='{s[:80]}'")
            continue
    except:
        pass
    # Check Go string
    if len(content) >= 16:
        ptr = struct.unpack('<Q', content[0:8])[0] - IMAGE_BASE
        length = struct.unpack('<Q', content[8:16])[0]
        if 0 < ptr < 0x6000000 and 0 < length < 200:
            str_content, _ = read_at_rva(ptr, length)
            if str_content:
                print(f"    0x{insn_rva:05x} -> RVA 0x{target_rva:x} ({sec}) GoStr='{str_content.decode('utf-8', errors='replace')[:80]}'")
                continue
    hex_str = ' '.join(f'{b:02x}' for b in content[:16])
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in content[:16])
    print(f"    0x{insn_rva:05x} -> RVA 0x{target_rva:x} ({sec}) {hex_str} '{printable}'")

# ============================================================
# 2. Analyze the SHA-256 function (0x4563c0)
# ============================================================
print()
print("=" * 70)
print("SHA-256 function (0x4563c0) - First 50 instructions")
print("=" * 70)

code, sec = read_at_rva(0x4563c0, 0x300)
if code:
    count = 0
    for insn in md.disasm(code, IMAGE_BASE + 0x4563c0):
        rva = insn.address - IMAGE_BASE
        if count > 50:
            break
        print(f"  0x{rva:05x} {insn.mnemonic:12s} {insn.op_str}")
        count += 1

# ============================================================
# 3. Analyze addBigModelSignatureHeaders (0x882680)
# ============================================================
print()
print("=" * 70)
print("addBigModelSignatureHeaders (0x882680)")
print("=" * 70)

insns, calls, rip_refs, begin, end = disasm_with_refs(0x882680, max_insns=80)
print(f"  Function bounds: RVA 0x{begin:x} - 0x{end:x}")
print()

for rva, mnem, opstr, sz in insns:
    marker = ""
    if mnem in ('lea', 'mov') and 'rip' in opstr:
        for ref_rva, target, ref_mnem, ref_opstr in rip_refs:
            if ref_rva == rva:
                content, sec = read_at_rva(target, 60)
                if content:
                    try:
                        s = content.split(b'\x00')[0].decode('utf-8', errors='replace')
                        if s and all(32 <= ord(c) < 127 or c in '\r\n\t' for c in s[:10]):
                            marker = f"  # str='{s[:80]}'"
                    except:
                        pass
                break
    print(f"  0x{rva:05x} {mnem:12s} {opstr:45s}{marker}")

print("\n  Calls:")
for caller_rva, target in calls:
    if isinstance(target, int):
        print(f"    0x{caller_rva:05x} -> RVA 0x{target:x}")
    else:
        print(f"    0x{caller_rva:05x} -> {target}")

# ============================================================
# 4. Search for all API endpoint strings in .rdata
# ============================================================
print()
print("=" * 70)
print("All API endpoint strings in .rdata")
print("=" * 70)

endpoint_patterns = [
    b'/algo/', b'/api/v1/', b'/algo/api',
    b'/ping', b'/chat', b'/complete', b'/embed',
    b'/service/', b'/organizations',
    b'next_edit_predict', b'next_chat_predict',
]

rdata_end = rdata_raw + rdata_vs
for pat in endpoint_patterns:
    idx = rdata_raw
    while idx < rdata_end - len(pat):
        pos = binary.find(pat, idx, rdata_end)
        if pos == -1:
            break
        # Get full path context
        # Walk backward to find start of path (looking for '/' or string boundary)
        start = pos
        while start > rdata_raw and binary[start-1] != 0 and binary[start-1] != ord('/'):
            # Actually, walk forward to find null terminator for full string
            pass
        # Walk forward to find end of string
        end_pos = binary.find(b'\x00', pos, rdata_end)
        if end_pos == -1:
            end_pos = min(rdata_end, pos + 100)
        # Walk backward to find string start
        str_start = pos
        while str_start > rdata_raw and binary[str_start-1] != 0:
            str_start -= 1
        full_str = binary[str_start:end_pos].decode('utf-8', errors='replace')
        if '/' in full_str and len(full_str) > 3:
            rva = str_start - rdata_raw + rdata_va
            print(f"  RVA 0x{rva:x}: '{full_str}'")
        idx = pos + len(pat)

# ============================================================
# 5. Analyze MainSigning (0x8821e0) - focus on data preparation
# ============================================================
print()
print("=" * 70)
print("MainSigning (0x8821e0) - Data preparation for signing")
print("=" * 70)

insns, calls, rip_refs, begin, end = disasm_with_refs(0x8821e0, max_insns=120)
print(f"  Function bounds: RVA 0x{begin:x} - 0x{end:x}")
print()

# Focus on the calls and what data is prepared before them
for rva, mnem, opstr, sz in insns:
    marker = ""
    if mnem in ('lea', 'mov') and 'rip' in opstr:
        for ref_rva, target, ref_mnem, ref_opstr in rip_refs:
            if ref_rva == rva:
                content, sec = read_at_rva(target, 60)
                if content:
                    try:
                        s = content.split(b'\x00')[0].decode('utf-8', errors='replace')
                        if s and all(32 <= ord(c) < 127 or c in '\r\n\t' for c in s[:10]):
                            marker = f"  # str='{s[:80]}'"
                    except:
                        pass
                # Check if it's a format string with %s
                break
    if mnem == 'call':
        target_name = ""
        known_calls = {
            0x882e40: "ExtractConfig",
            0x884080: "ValidateFlags",
            0x885620: "ProcessSliceData",
            0x8840e0: "AddAuthHeaders",
            0xb11200: "FinalHandler",
            0x4563c0: "SHA256",
            0x882760: "getAppSalt",
            0x2dd360: "mapassign_faststr",
        }
        target_val = target if isinstance(target, int) else None
        if target_val and target_val in known_calls:
            target_name = f"  # {known_calls[target_val]}"
        marker += target_name

    print(f"  0x{rva:05x} {mnem:12s} {opstr:45s}{marker}")

print("\n  Calls:")
for caller_rva, target in calls:
    if isinstance(target, int):
        name = ""
        known_calls = {
            0x882e40: "ExtractConfig",
            0x884080: "ValidateFlags",
            0x885620: "ProcessSliceData",
            0x8840e0: "AddAuthHeaders",
            0xb11200: "FinalHandler",
            0x4563c0: "SHA256",
            0x882760: "getAppSalt",
            0x2dd360: "mapassign_faststr",
            0x25c7e0: "time.Format",
        }
        if target in known_calls:
            name = known_calls[target]
        print(f"    0x{caller_rva:05x} -> RVA 0x{target:x} ({name})")
    else:
        print(f"    0x{caller_rva:05x} -> {target}")
