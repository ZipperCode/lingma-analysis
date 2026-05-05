"""Deep analysis of getAppSalt string references and secret keys."""
import struct, base64
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
    name = binary[off:off+8].rstrip(b'\x00').decode()
    va = struct.unpack('<I', binary[off+12:off+16])[0]
    rp = struct.unpack('<I', binary[off+20:off+24])[0]
    vs = struct.unpack('<I', binary[off+16:off+20])[0]
    sections[name] = (va, rp, vs)

text_va, text_raw, text_vs = sections['.text']
rdata_va, rdata_raw, rdata_vs = sections['.rdata']
data_va, data_raw, data_vs = sections['.data']

def rva_offset(rva):
    for name, (va, rp, vs) in sections.items():
        if va <= rva < va + vs:
            return rp + (rva - va), name
    return None, 'unknown'

def read_at_rva(rva, size=0x100):
    off, sec = rva_offset(rva)
    if off is None:
        return None, sec
    return binary[off:off + size], sec

def resolve_rip(insn_rva, op_str):
    if 'rip +' in op_str:
        disp = int(op_str.split('rip + ')[1].split(']')[0].split(',')[0], 16)
    elif 'rip -' in op_str:
        disp = -int(op_str.split('rip - ')[1].split(']')[0].split(',')[0], 16)
    else:
        return None
    rip = IMAGE_BASE + insn_rva + 5
    return rip + disp - IMAGE_BASE

print("=" * 70)
print("ALL string/data references in getAppSalt (0x882760 - 0x882b8a)")
print("=" * 70)

func_start = 0x882760
func_end = 0x882b8a
code = binary[rva_offset(func_start)[0]:rva_offset(func_start)[0] + 0x500]

for insn in md.disasm(code, IMAGE_BASE + func_start):
    rva = insn.address - IMAGE_BASE
    if rva > func_end:
        break
    if 'rip' in insn.op_str and insn.mnemonic in ('lea', 'mov', 'cmp', 'test'):
        target = resolve_rip(rva, insn.op_str)
        if target and 0 < target < 0x6000000:
            content, sec = read_at_rva(target, 80)
            if content is None:
                continue
            try:
                s = content.split(b'\x00')[0].decode('utf-8', errors='replace')
                if len(s) > 2 and all(32 <= ord(c) < 127 or c in '\r\n\t' for c in s[:25]):
                    print(f"  0x{rva:04x}: {insn.mnemonic:8s} {insn.op_str:50s}")
                    print(f"           -> RVA 0x{target:x} ({sec}) STR: '{s[:120]}'")
                    continue
            except:
                pass
            if len(content) >= 16:
                ptr = struct.unpack('<Q', content[0:8])[0]
                length = struct.unpack('<Q', content[8:16])[0]
                if 0x1000000 < ptr < 0x6000000 and 0 < length < 500:
                    str_content, _ = read_at_rva(ptr - IMAGE_BASE, min(length, 200))
                    if str_content:
                        try:
                            decoded = str_content.decode('utf-8', errors='replace')
                            print(f"  0x{rva:04x}: {insn.mnemonic:8s} {insn.op_str:50s}")
                            print(f"           -> GoStr: ptr=0x{ptr:x} len={length} -> '{decoded[:120]}'")
                            continue
                        except:
                            pass
            hex_str = ' '.join(f'{b:02x}' for b in content[:16])
            print(f"  0x{rva:04x}: {insn.mnemonic:8s} {insn.op_str:50s}")
            print(f"           -> RVA 0x{target:x} ({sec}) {hex_str}")

print()
print("=" * 70)
print("Disassembling 0x4563c0 (signing function called by getAppSalt)")
print("=" * 70)

code = binary[rva_offset(0x4563c0)[0]:rva_offset(0x4563c0)[0] + 0x300]
count = 0
for insn in md.disasm(code, IMAGE_BASE + 0x4563c0):
    rva = insn.address - IMAGE_BASE
    if insn.mnemonic == 'ret' and count > 10:
        print(f"  0x{rva:04x} {insn.mnemonic:12s} {insn.op_str}  [RET]")
        break
    if 'rip' in insn.op_str and insn.mnemonic == 'lea':
        target = resolve_rip(rva, insn.op_str)
        if target and 0 < target < 0x6000000:
            content, sec = read_at_rva(target, 40)
            if content:
                try:
                    s = content.split(b'\x00')[0].decode('utf-8', errors='replace')
                    if len(s) > 2 and all(32 <= ord(c) < 127 for c in s[:15]):
                        print(f"  0x{rva:04x} {insn.mnemonic:12s} {insn.op_str}  -> str='{s[:80]}'")
                        count += 1
                        continue
                except:
                    pass
    print(f"  0x{rva:04x} {insn.mnemonic:12s} {insn.op_str}")
    count += 1
    if count > 60:
        print("  ... (truncated)")
        break

print()
print("=" * 70)
print("Secret strings decoded")
print("=" * 70)
for s in ["d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="]:
    try:
        decoded = base64.b64decode(s).decode('utf-8', errors='replace')
        print(f"  base64 '{s}' -> '{decoded}'")
    except:
        print(f"  Not base64: '{s}'")
