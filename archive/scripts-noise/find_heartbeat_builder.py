"""
深入分析 heartbeat JSON 构建代码
"""
import struct

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

# Look at the HeartbeatTag1 and nearby JSON strings
print("=== HeartbeatTag1 area ===")
pos = pe_data.find(b'HeartbeatTag1')
if pos >= 0:
    # Show large context around this
    for offset in range(max(0, pos-200), min(len(pe_data), pos+500), 50):
        chunk = pe_data[offset:offset+50]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
        print(f"  0x{offset:07x}: {printable}")

# Look at the heartbeat function list from pclntab
print("\n\n=== Heartbeat function names from pclntab ===")
# The string at 0x3d92535 seems to be concatenated function names
# Let's parse it
func_str_start = 0x3d92535
# Show the raw bytes
for offset in range(func_str_start, func_str_start + 800, 80):
    chunk = pe_data[offset:offset+80]
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
    print(f"  0x{offset:07x}: {printable}")

# Search for JSON field concatenation in heartbeat code
# Look for the specific JSON fields we see in the heartbeat body
print("\n\n=== Searching for heartbeat JSON field combinations ===")
json_fields = [
    b'expr_features',
    b'host_system',
    b'ide_type',
    b'ide_types',
    b'ide_version',
    b'os_arch',
    b'os_version',
    b'product_type',
    b'"tag"',
    b'session_id',
    b'request_id',
]

for field in json_fields:
    pos = pe_data.find(field)
    if pos >= 0:
        # Find ALL occurrences
        positions = []
        start = 0
        while True:
            p = pe_data.find(field, start)
            if p < 0:
                break
            positions.append(p)
            start = p + 1

        print(f"\n  '{field.decode()}' found at {len(positions)} positions:")
        for p in positions[:3]:
            start_ctx = max(0, p - 20)
            end_ctx = min(len(pe_data), p + 60)
            ctx = pe_data[start_ctx:end_ctx]
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
            print(f"    0x{p:07x}: ...{printable}...")

# Now let's look at the actual appendDeviceInformation function
# This should contain the code that builds the JSON
print("\n\n=== Looking for appendDeviceInformation implementation ===")
# First find the function name in pclntab
func_name = b'cosy/core/heartbeat.appendDeviceInformation'
pos = pe_data.find(func_name)
if pos >= 0:
    print(f"  Function name at 0x{pos:x}")
    # The function name in pclntab is followed by the function entry
    # We need to find the actual code

# Let's try a different approach: search for the JSON building pattern
# Look for string literals that look like JSON fields being concatenated
print("\n\n=== Searching for JSON builder patterns ===")
# Search for patterns like `":","` or `":"` or `","` which are common in JSON building
patterns = [
    b'":"',
    b'","',
    b'"{}"',
    b'}}',
]

for pattern in patterns:
    positions = []
    start = 0
    while True:
        p = pe_data.find(pattern, start)
        if p < 0:
            break
        positions.append(p)
        start = p + len(pattern)
        if len(positions) > 20:
            break

    if positions:
        print(f"\n  Pattern '{pattern.decode()}' found at {len(positions)}+ positions")
        # Show a few that are in the .rdata section (likely string constants)
        for p in positions[:5]:
            start_ctx = max(0, p - 30)
            end_ctx = min(len(pe_data), p + 40)
            ctx = pe_data[start_ctx:end_ctx]
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
            print(f"    0x{p:07x}: ...{printable}...")
