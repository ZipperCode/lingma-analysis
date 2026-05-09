"""
提取 Lingma 的 URL 配置 JSON。
"""
import json
import re

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

with open(LINGMA, 'rb') as f:
    data = f.read()

# Search for the URL config JSON starting with the known pattern
# "url_config" or "big_model_url_config"
markers = [
    b'"url_config"',
    b'"big_model_url_config"',
    b'"remote_model_config"',
    b'"message_encode"',
    b'"login_encode"',
]

for marker in markers:
    idx = data.find(marker)
    if idx > 0:
        print(f"\n=== Found '{marker.decode()}' at offset {hex(idx)} (RVA 0x{idx - 0x400 + 0x1000:x}) ===\n")
        # Extract surrounding context
        context = data[max(0,idx-200):idx + 2000]
        text = context.decode('utf-8', errors='replace')
        # Clean up and print
        # Find JSON boundaries
        start = text.find('{')
        if start >= 0:
            text = text[start:]
        # Try to find the end
        end = text.find('\x00\x00')
        if end > 0:
            text = text[:end]
        # Print up to 2000 chars
        print(text[:2000])
        print("...")
        break

# Also try: find the full JSON around "tongyi.aliyun.com"
print("\n\n=== Searching for full endpoint config ===\n")
idx = data.find(b'"tongyi.aliyun.com"')
while idx > 0 and idx < 0x3000000:
    # Get 2000 bytes before this
    context = data[max(0,idx-500):idx+500]
    text = context.decode('utf-8', errors='replace')
    # Check if this looks like a JSON config
    if '"url_config"' in text or '"endpoint"' in text or '"login_url"' in text:
        print(f"At offset {hex(idx)}:")
        print(text[:1500])
        print("---")
    idx = data.find(b'"tongyi.aliyun.com"', idx + 1)
