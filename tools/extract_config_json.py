"""
提取嵌入的 URL 配置 JSON，包含端点和认证信息。
"""
import re

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

with open(LINGMA, 'rb') as f:
    data = f.read()

# Find the big JSON config starting near "/algo"
# Key marker: "tongyi.aliyun.com/algo"
markers = [
    b'"tongyi.aliyun.com/algo"',
    b'"lingma.alibabacloud.com/algo"',
    b'"quest_server_endpoint"',
    b'"infer_api_endpoint"',
]

for marker in markers:
    idx = data.find(marker)
    if idx > 0:
        print(f"\n=== Found '{marker.decode()}' at offset {hex(idx)} ===\n")
        # Extract 4000 bytes of context
        context = data[idx - 100:idx + 4000]
        # Try to decode
        text = context.decode('utf-8', errors='replace')
        # Show it
        print(text[:4000])
        print("...")
        break

# Also find "AppSalt" string
print("\n\n=== AppSalt string context ===\n")
idx = data.find(b'AppSalt')
while idx > 0:
    context = data[max(0,idx-50):idx+100]
    print(f"At offset {hex(idx)}: {context[:150]}")
    idx = data.find(b'AppSalt', idx + 1)
    if idx > 0x10000000:
        break

# Also search for "cosy", "lingma", "system" - the hypothesized salt values
print("\n\n=== Searching for salt-like string arrays ===\n")
# Look for the pattern: "cosy" followed by "lingma" followed by "system"
for marker in [b'"cosy"', b'"lingma"', b'"system"']:
    idx = data.find(marker)
    count = 0
    while idx > 0 and count < 5:
        context = data[idx:idx+50]
        print(f"  Offset {hex(idx)}: {context}")
        idx = data.find(marker, idx + 1)
        count += 1
