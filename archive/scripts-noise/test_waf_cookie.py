#!/usr/bin/env python3
"""测试 WAF cookie 绕过"""
import sys, json, time, ssl, http.cookiejar, urllib.request
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
body_bytes = encode_to_string(json.dumps(body, separators=(",", ":")).encode()).encode()
headers = build_basic_headers(machine_id)
ep = "https://lingma.alibabacloud.com/algo/api/v3/user/status"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ctx),
    urllib.request.HTTPCookieProcessor(cj))

for i in range(4):
    if i > 0:
        wait = 2 * i
        print(f"\n[等待 {wait}s...]")
        time.sleep(wait)
    print(f"\n=== 第{i+1}次请求 ===")
    req = urllib.request.Request(ep, data=body_bytes, headers=headers, method="POST")
    try:
        resp = opener.open(req, timeout=15)
        print(f"  ✅ HTTP {resp.status}: {resp.read().decode()[:500]}")
        break  # 成功了就不继续了
    except urllib.error.HTTPError as e:
        err = e.read().decode(errors="replace")
        print(f"  HTTP {e.code}")
        print(f"  Body: {err[:150]}")
        if cj:
            cookies = [(c.name, c.value[:25]) for c in cj]
            print(f"  Cookies: {cookies}")

print(f"\n最终 cookies: {[(c.name, c.value[:25]) for c in cj]}")
