"""
分析 cosy/agent/remote-control.NewHeartbeatMessage
这是构建 heartbeat 消息的函数
"""
import struct

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

# Find NewHeartbeatMessage in pclntab
print("=== Finding NewHeartbeatMessage ===")
pos = pe_data.find(b'NewHeartbeatMessage')
if pos >= 0:
    ctx = pe_data[max(0, pos-100):pos+200]
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
    print(f"Found at offset 0x{pos:x}")
    print(f"Context: {printable}")

# Also find cosy/agent/remote-control package strings
print("\n\n=== cosy/agent/remote-control strings ===")
package = b'cosy/agent/remote-control'
start = 0
count = 0
while count < 15:
    pos = pe_data.find(package, start)
    if pos < 0:
        break
    ctx = pe_data[pos:pos+150]
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
    print(f"\n  0x{pos:x}: {printable}")
    start = pos + 1
    count += 1

# Find the function address from pclntab
# Search for "cosy/agent/remote-control.NewHeartbeatMessage"
print("\n\n=== NewHeartbeatMessage function entry ===")
func_full = b'cosy/agent/remote-control.NewHeartbeatMessage'
pos = pe_data.find(func_full)
if pos >= 0:
    print(f"Function name string at 0x{pos:x}")
    # In Go pclntab, the function name is followed by:
    # - function entry point (PC)
    # - function end PC
    # - function entry offset in pclntab
    # The exact format depends on Go version

    # Show bytes after the name string
    end = pos + len(func_full)
    print(f"Bytes after name: {pe_data[end:end+20].hex()}")

# Let's also look for the heartbeat module initialization
print("\n\n=== InitHeartbeat function ===")
init_func = b'cosy/core/heartbeat.InitHeartbeat'
pos = pe_data.find(init_func)
if pos >= 0:
    print(f"InitHeartbeat name at 0x{pos:x}")
    end = pos + len(init_func)
    print(f"Bytes after name: {pe_data[end:end+20].hex()}")

# Find the appendDeviceInformation function which builds the JSON
print("\n\n=== appendDeviceInformation function ===")
append_func = b'cosy/core/heartbeat.appendDeviceInformation'
pos = pe_data.find(append_func)
if pos >= 0:
    print(f"appendDeviceInformation name at 0x{pos:x}")
    end = pos + len(append_func)
    print(f"Bytes after name: {pe_data[end:end+20].hex()}")

# Now let's look for the actual struct type that heartbeat uses
# Search for struct fields that match our JSON
print("\n\n=== Searching for heartbeat struct fields ===")
# The JSON fields we know:
# - session_id (or similar ID)
# - expr_features
# - host_system
# - ide_type
# - ide_types
# - ide_version
# - os_arch
# - os_version
# - product_type
# - tag

# Let's find all JSON tags that appear together in a struct
# Search for consecutive JSON tag strings in .rdata
rdata_section = None
for sec in sections:
    if sec['name'] == '.rdata':
        rdata_section = sec
        break

if rdata_section:
    rdata = pe_data[rdata_section['raw_offset']:rdata_section['raw_offset'] + rdata_section['raw_size']]
    print(f".rdata section: 0x{rdata_section['virtual_address']:x} - 0x{rdata_section['virtual_address'] + rdata_section['virtual_size']:x}")

    # Search for JSON tags in .rdata
    json_tags = [
        b'json:"session_id',
        b'json:"request_id',
        b'json:"expr_features',
        b'json:"host_system',
        b'json:"ide_type',
        b'json:"os_arch',
        b'json:"os_version',
        b'json:"product_type',
    ]

    for tag in json_tags:
        pos = rdata.find(tag)
        if pos >= 0:
            actual_offset = rdata_section['raw_offset'] + pos
            actual_va = rdata_section['virtual_address'] + pos
            print(f"\n  Found '{tag.decode()}' at file offset 0x{actual_offset:x} (VA 0x{actual_va:x})")
            ctx = rdata[max(0, pos-20):pos+80]
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
            print(f"  Context: ...{printable}...")
else:
    print("Could not find .rdata section")
