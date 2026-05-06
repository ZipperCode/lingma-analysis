#!/usr/bin/env python3
"""测试 HTTP/2 和 curl 绕过 WAF"""
import sys, json, time, subprocess
sys.path.insert(0, "D:/Project/lingma/tools")
from lingma_full_auth import encode_to_string, build_basic_headers
from credential_extractor import decrypt_cache_user
from pathlib import Path

creds = decrypt_cache_user(Path.home() / ".lingma")
uid = creds.get("uid", "")
machine_id = creds.get("_machine_id", "")

body = {
    "ak": "", "sk": "", "securityToken": "",
    "userId": uid, "orgId": "",
    "token": "", "personalToken": "",
    "securityOauthToken": "", "refreshToken": "",
    "needRefresh": False,
    "authInfo": {"userName": "", "orgId": ""}
}
body_str = json.dumps(body, separators=(",", ":"))
encoded_body = encode_to_string(body_str.encode())
headers = build_basic_headers(machine_id)
headers["Content-Length"] = str(len(encoded_body))

ep = "https://lingma.alibabacloud.com/algo/api/v3/user/status"

# 测试1: httpx with HTTP/2
try:
    import httpx
    print("=== httpx HTTP/2 ===")
    with httpx.Client(http2=True, verify=False, timeout=15) as client:
        resp = client.post(ep, content=encoded_body.encode(), headers=headers)
        print(f"  HTTP {resp.status_code} (HTTP/2={resp.http_version == 'HTTP/2'})")
        if resp.status_code == 200:
            print(f"  ✅ {resp.text[:300]}")
        else:
            print(f"  {resp.text[:200]}")
except ImportError:
    print("httpx not available")
except Exception as e:
    print(f"  httpx error: {e}")

time.sleep(1)

# 测试2: curl with HTTP/2
print("\n=== curl HTTP/2 ===")
curl_args = ["curl", "-v", "--http2", "--insecure", "-X", "POST", ep,
    "-H", "Content-Type: application/json"]
for k, v in headers.items():
    curl_args.extend(["-H", f"{k}: {v}"])
curl_args.extend(["--data-binary", encoded_body])

result = subprocess.run(curl_args, capture_output=True, text=True, timeout=15)
print("STDOUT:", result.stdout[-500:] if result.stdout else "(empty)")
print("STDERR:", result.stderr[-500:] if result.stderr else "(empty)")
print("Return code:", result.returncode)

time.sleep(1)

# 测试3: curl with HTTP/1.1
print("\n=== curl HTTP/1.1 ===")
curl_args[2] = "--http1.1"
result2 = subprocess.run(curl_args, capture_output=True, text=True, timeout=15)
print("STDOUT:", result2.stdout[-500:] if result2.stdout else "(empty)")
print("STDERR:", result2.stderr[-500:] if result2.stderr else "(empty)")
