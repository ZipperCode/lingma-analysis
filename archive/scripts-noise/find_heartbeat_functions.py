"""
搜索 cosy/core/heartbeat 包中的函数
查找 heartbeat JSON 构建代码
"""
import struct

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

# Search for heartbeat-related function names in pclntab
print("=== Heartbeat-related functions in pclntab ===")
heartbeat_patterns = [
    b'cosy/core/heartbeat',
    b'cosy/algo',
    b'algo/api',
    b'heartbeat',
    b'Heartbeat',
    b'BuildHeartbeat',
    b'HeartbeatReq',
    b'HeartbeatResp',
    b'Encode=1',
]

for pattern in heartbeat_patterns:
    positions = []
    start = 0
    while True:
        pos = pe_data.find(pattern, start)
        if pos < 0:
            break
        positions.append(pos)
        start = pos + len(pattern)

    if positions:
        print(f"\n  Pattern '{pattern.decode()}' found at {len(positions)} positions:")
        for pos in positions[:10]:
            # Show surrounding context
            start_ctx = max(0, pos - 30)
            end_ctx = min(len(pe_data), pos + len(pattern) + 50)
            ctx = pe_data[start_ctx:end_ctx]
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
            print(f"    0x{pos:07x}: ...{printable}...")

# Search for functions that build heartbeat JSON
# Look for string concatenation patterns or JSON building
print("\n\n=== Searching for JSON building code ===")
json_build_patterns = [
    b'buildHeartbeat',
    b'BuildHeartbeat',
    b'heartbeatJSON',
    b'HeartbeatData',
    b'heartbeatData',
    b'heartbeatBody',
    b'HeartbeatBody',
    b'newHeartbeat',
    b'HeartbeatRequest',
    b'heartbeatRequest',
    b'cosy/algo',
    b'algo/handler',
    b'algo/client',
]

for pattern in json_build_patterns:
    pos = pe_data.find(pattern)
    if pos >= 0:
        print(f"  Found '{pattern.decode()}' at 0x{pos:x}")
        # Find all occurrences
        start = 0
        count = 0
        while count < 5:
            pos = pe_data.find(pattern, start)
            if pos < 0:
                break
            start_ctx = max(0, pos - 30)
            end_ctx = min(len(pe_data), pos + len(pattern) + 80)
            ctx = pe_data[start_ctx:end_ctx]
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
            print(f"    0x{pos:07x}: ...{printable}...")
            start = pos + 1
            count += 1

# Now let's look for the encrypt package callers
# We know AesEncryptWithBase64 has callers at:
# 0x88eea6, 0x892305, 0x8926e2, 0xaf33a6, 0xb96f68
# Let's find what functions these callers belong to
print("\n\n=== Finding function names for AesEncryptWithBase64 callers ===")

# Parse pclntab to find function names
# The pclntab magic number is 0xfffffffb or 0xFFFFFFF0
# Search for pclntab header
pclntab_pos = pe_data.find(b'\xfb\xff\xff\xff')
if pclntab_pos < 0:
    pclntab_pos = pe_data.find(b'\xf0\xff\xff\xff')

if pclntab_pos >= 0:
    print(f"  Found pclntab header at 0x{pclntab_pos:x}")
    # Parse header
    magic = struct.unpack('<I', pe_data[pclntab_pos:pclntab_pos+4])[0]
    ptr_size = pe_data[pclntab_pos+4]
    print(f"  Magic: 0x{magic:x}, ptr_size: {ptr_size}")
else:
    print("  pclntab header not found, searching for function table...")

    # Try alternative: search for known function names
    known_funcs = [
        b'AesEncryptWithBase64',
        b'AesDecryptWithBase64',
        b'CustomEncryptV1',
        b'CustomDecryptV1',
        b'pkcs5Padding',
    ]

    for func in known_funcs:
        pos = pe_data.find(func)
        if pos >= 0:
            print(f"  Found '{func.decode()}' at 0x{pos:x}")
