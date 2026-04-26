import struct
import sys

EXE_PATH = "C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe"
IMAGE_BASE = 0x140000000

def read_pe():
    with open(EXE_PATH, "rb") as f:
        data = f.read()
    return data

def parse_dos_header(data):
    sig = data[0:2]
    assert sig == b"MZ", f"Not a PE file: {sig}"
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    return e_lfanew

def parse_nt_headers(data, e_lfanew):
    pe_sig = data[e_lfanew:e_lfanew+4]
    assert pe_sig == b"PE\x00\x00"
    offset = e_lfanew + 4
    # COFF Header (20 bytes)
    machine, num_sections, time_stamp, sym_table_ptr, num_syms, \
        opt_size, characteristics = struct.unpack_from("<HHIIIHH", data, offset)
    offset += 20
    # Optional Header
    magic = struct.unpack_from("<H", data, offset)[0]
    assert magic == 0x20b, f"Not PE32+: magic={hex(magic)}"
    image_base = struct.unpack_from("<Q", data, offset + 24)[0]
    section_align = struct.unpack_from("<I", data, offset + 32)[0]
    file_align = struct.unpack_from("<I", data, offset + 36)[0]
    # Data directories start at offset + 112 (for PE32+)
    num_dirs = struct.unpack_from("<I", data, offset + 112)[0]
    dir_offset = offset + 116
    dirs = []
    for i in range(min(num_dirs, 16)):
        rva, size = struct.unpack_from("<II", data, dir_offset + i*8)
        dirs.append((rva, size))
    opt_header_end = offset + opt_size
    return {
        "num_sections": num_sections,
        "image_base": image_base,
        "section_align": section_align,
        "file_align": file_align,
        "opt_header_end": opt_header_end,
        "dirs": dirs,
    }

def parse_sections(data, opt_header_end, num_sections):
    sections = []
    offset = opt_header_end
    for i in range(num_sections):
        name = data[offset:offset+8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, vaddr, raw_size, raw_ptr, reloc_ptr, line_ptr, num_reloc, num_line, chars = \
            struct.unpack_from("<IIIIIHHHI", data, offset + 8)
        sections.append({
            "name": name,
            "vaddr": vaddr,
            "vsize": vsize,
            "raw_ptr": raw_ptr,
            "raw_size": raw_size,
        })
        offset += 40
    return sections

def rva_to_raw(rva, sections):
    for s in sections:
        if s["vaddr"] <= rva < s["vaddr"] + s["vsize"]:
            return rva - s["vaddr"] + s["raw_ptr"]
    return None

def read_at_rva(data, rva, size, sections):
    raw = rva_to_raw(rva, sections)
    if raw is None:
        return None
    return data[raw:raw+size]

def parse_pdata(data, sections, image_base):
    # Find .pdata section
    for s in sections:
        if s["name"] == ".pdata":
            raw_data = data[s["raw_ptr"]:s["raw_ptr"]+s["raw_size"]]
            entries = []
            num = len(raw_data) // 12
            for i in range(num):
                begin, end, unwind = struct.unpack_from("<III", raw_data, i*12)
                entries.append((begin, end, unwind))
            return entries
    return []

def find_function_boundaries(pdata, target_rva):
    for begin, end, unwind in pdata:
        if begin == target_rva:
            return begin, end
    return None, None

if __name__ == "__main__":
    data = read_pe()
    e_lfanew = parse_dos_header(data)
    nt = parse_nt_headers(data, e_lfanew)
    sections = parse_sections(data, nt["opt_header_end"], nt["num_sections"])

    print("=== Sections ===")
    for s in sections:
        print(f"  {s['name']:12s}  RVA={hex(s['vaddr']):10s}  VSize={hex(s['vsize']):10s}  RawPtr={hex(s['raw_ptr']):10s}  RawSize={hex(s['raw_size']):10s}")

    print(f"\nImageBase = {hex(nt['image_base'])}")

    # .text section info
    text_sec = None
    for s in sections:
        if s["name"] == ".text":
            text_sec = s
            break
    print(f"\n.text: RVA={hex(text_sec['vaddr'])}, RawPtr={hex(text_sec['raw_ptr'])}")

    # Parse .pdata
    pdata = parse_pdata(data, sections, nt["image_base"])
    print(f"\n.pdata entries: {len(pdata)}")

    # Find boundaries for our target functions
    targets = [0x882e40, 0x884080, 0x885620, 0x8840e0]
    for t in targets:
        begin, end = find_function_boundaries(pdata, t)
        if begin is not None:
            print(f"  {hex(t)}: begin={hex(begin)} end={hex(end)} size={end-begin}")
        else:
            print(f"  {hex(t)}: NOT FOUND in .pdata")
