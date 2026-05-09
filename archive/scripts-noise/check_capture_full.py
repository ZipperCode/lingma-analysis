"""
检查 capture 中的完整 HTTP 交互
查看响应和任何额外的头部信息
"""
import json

# Check ALL entries in the capture file
print("=== All entries in capture 1 ===")
with open('capture/lingma-http-capture-body-20260424-222313.jsonl', 'r') as f:
    for i, line in enumerate(f):
        obj = json.loads(line)
        # Show all keys for each entry
        keys = list(obj.keys())
        path = obj.get('path', 'N/A')
        method = obj.get('method', 'N/A')
        status = obj.get('status', 'N/A')
        body_len = obj.get('body_len', 0)
        has_body = 'body_utf8' in obj
        print(f"  Entry {i}: {method} {path} (status={status}, body_len={body_len}, has_body={has_body})")

        # Show response if available
        if 'response' in obj:
            print(f"    Response: {obj['response'][:200]}")
        if 'response_body' in obj:
            print(f"    Response body: {obj['response_body'][:200]}")
        if 'response_headers' in obj:
            print(f"    Response headers: {obj['response_headers']}")

print("\n\n=== All entries in capture 2 ===")
with open('capture/lingma-http-capture-proxynofrida-20260424-235210.jsonl', 'r') as f:
    for i, line in enumerate(f):
        obj = json.loads(line)
        keys = list(obj.keys())
        path = obj.get('path', 'N/A')
        method = obj.get('method', 'N/A')
        status = obj.get('status', 'N/A')
        body_len = obj.get('body_len', 0)
        has_body = 'body_utf8' in obj
        print(f"  Entry {i}: {method} {path} (status={status}, body_len={body_len}, has_body={has_body})")
        if 'response' in obj:
            print(f"    Response: {obj['response'][:200]}")

# Let's also check if there's a proxy config or setup file
print("\n\n=== Checking capture directory ===")
import os
for f in os.listdir('capture/'):
    filepath = os.path.join('capture/', f)
    size = os.path.getsize(filepath)
    print(f"  {f}: {size} bytes")
