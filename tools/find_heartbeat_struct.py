"""
从二进制中提取 heartbeat struct 定义
搜索 Go struct 的 JSON tag 信息
"""
import struct

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

# Find all JSON tag strings that are related to heartbeat
# Tags follow the pattern: json:"field_name" or json:"field_name,omitempty"
print("=== All JSON tags near heartbeat-related strings ===")

# Find expr_features position
expr_pos = pe_data.find(b'expr_features')
print(f"expr_features at 0x{expr_pos:x}")

# Find host_system position
host_pos = pe_data.find(b'host_system')
print(f"host_system at 0x{host_pos:x}")

# Show all strings between these two positions and nearby
print(f"\n=== Strings between 0x{expr_pos:x} and 0x{host_pos:x} ===")
region = pe_data[expr_pos:host_pos]
# Extract null-terminated strings
current = []
strings = []
for b in region:
    if 32 <= b < 127:
        current.append(chr(b))
    else:
        if current:
            s = ''.join(current)
            if len(s) >= 3:
                strings.append(s)
            current = []
if current:
    s = ''.join(current)
    if len(s) >= 3:
        strings.append(s)

for s in strings:
    print(f"  {s}")

# Now let's look for the struct that generates the heartbeat body
# The heartbeat code is in cosy/core/heartbeat package
# Let's find functions that build the JSON

print("\n\n=== Heartbeat struct types ===")
# Search for struct type names
heartbeat_types = [
    b'HeartbeatInfo',
    b'HeartbeatReq',
    b'HeartbeatResp',
    b'HeartbeatData',
    b'HeartbeatBody',
    b'HeartbeatParam',
    b'HeartbeatPayload',
    b'HeartbeatMessage',
    b'HeartbeatRequest',
    b' heartbeat',
]

for t in heartbeat_types:
    pos = pe_data.find(t)
    if pos >= 0:
        print(f"\n  Found '{t.decode()}' at 0x{pos:x}")
        ctx = pe_data[max(0, pos-30):pos+80]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
        print(f"  Context: {printable}")

# Let's also look for the actual struct type info in Go runtime type data
# Go stores type information in the .rdata section
# Search for type descriptors

print("\n\n=== Go type names containing 'heartbeat' ===")
# Go type names look like: "cosy/core/heartbeat.HeartbeatInfo"
# or just "HeartbeatInfo"

i = 0
count = 0
while i < len(pe_data) - 9:
    # Look for "heartbeat" followed by printable chars
    if pe_data[i:i+9] == b'heartbeat':
        # Check if this is part of a longer type name
        end = i + 9
        while end < len(pe_data) and 32 <= pe_data[end] < 127:
            end += 1
        type_name = pe_data[i:end].decode('ascii', errors='replace')
        if len(type_name) > 9 and type_name[9:10].isupper():
            # This looks like a type name: heartbeat<CapitalLetter>...
            print(f"  Found type reference: {type_name}")
            count += 1
            if count > 20:
                break
        i = end
        continue
    i += 1

if count == 0:
    print("  No heartbeat type names found with this pattern")

# Search for "ReportHeartbeat" and related function types
print("\n\n=== ReportHeartbeat type references ===")
report_pos = pe_data.find(b'ReportHeartbeat')
if report_pos >= 0:
    ctx = pe_data[max(0, report_pos-50):report_pos+100]
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
    print(f"  ReportHeartbeat at 0x{report_pos:x}")
    print(f"  Context: {printable}")

# Find ALL strings containing "heartbeat" (case sensitive) with length > 9
print("\n\n=== All heartbeat-related identifiers ===")
positions = []
start = 0
while True:
    pos = pe_data.find(b'heartbeat', start)
    if pos < 0:
        break
    # Extract the full identifier
    i_start = pos
    while i_start > 0 and 32 <= pe_data[i_start-1] < 127 and pe_data[i_start-1] not in ' \t\n\r':
        i_start -= 1
    i_end = pos + 9
    while i_end < len(pe_data) and 32 <= pe_data[i_end] < 127:
        i_end += 1

    identifier = pe_data[i_start:i_end].decode('ascii', errors='replace')
    if len(identifier) > 9 and identifier not in ['heartbeat']:
        positions.append((pos, identifier))
    start = pos + 1

# Show unique identifiers
seen = set()
for pos, ident in sorted(positions, key=lambda x: x[0]):
    if ident not in seen:
        seen.add(ident)
        print(f"  0x{pos:07x}: {ident}")
