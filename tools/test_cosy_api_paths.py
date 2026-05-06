#!/usr/bin/env python3
"""
COSY 凭据获取路径分析脚本
探测所有可能的 API 端点和认证方式
"""
import sys, json, base64, hashlib, ssl, urllib.request, time
sys.path.insert(0, "D:/Project/lingma/tools")
from lingma_full_auth import (
    encode_to_string, decode_string, build_basic_headers, api_call,
    BIG_MODEL_ENDPOINT
)

# 从已有 cache 获取 COSY 凭据
from credential_extractor import decrypt_cache_user
from pathlib import Path

lingma_dir = Path.home() / ".lingma"
if lingma_dir.exists():
    creds = decrypt_cache_user(lingma_dir)
    print(f"[*] 已解密 COSY 凭据")
    cosy_key = creds.get("cosy_key", "")
    oauth_token = creds.get("security_oauth_token", "")
    refresh_token = creds.get("refresh_token", "")
    uid = creds.get("user_id", "5930676910898027")
    machine_id = creds.get("machine_id", "")
    encrypt_info = creds.get("encrypt_user_info", "")
    print(f"  COSY Key: {cosy_key[:30]}...")
    print(f"  OAuth Token: {oauth_token[:20]}...")

# 测试1: 用 COSY Bearer 调 user/status (magic="http" + Bearer COSY)
print(f"\n{'='*60}")
print(f"测试1: /api/v3/user/status + COSY Bearer")
print(f"{'='*60}")
body = {
    "ak": "", "sk": "", "securityToken": "",
    "userId": uid, "orgId": "",
    "token": "", "personalToken": "",
    "securityOauthToken": "", "refreshToken": "",
    "needRefresh": False,
    "authInfo": {"userName": "", "orgId": ""}
}
# 用 COSY Bearer 头
url = f"{BIG_MODEL_ENDPOINT}/api/v3/user/status"
body_str = json.dumps(body, separators=(",", ":"))
encoded_body = encode_to_string(body_str.encode())
headers = build_basic_headers(machine_id)
headers["Authorization"] = f"Bearer COSY.{cosy_key}.{encrypt_info}"
headers["Content-Length"] = str(len(encoded_body))

req = urllib.request.Request(url, data=encoded_body.encode(), headers=headers, method="POST")
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    resp = urllib.request.urlopen(req, context=ctx, timeout=15)
    print(f"  HTTP {resp.status}: {resp.read().decode()[:500]}")
except urllib.error.HTTPError as e:
    print(f"  HTTP {e.code}: {e.read().decode(errors='replace')[:200]}")
except Exception as e:
    print(f"  Error: {e}")

# 测试2: 用 OAuth Bearer 调 user/status
print(f"\n{'='*60}")
print(f"测试2: /api/v3/user/status + OAuth Bearer")
print(f"{'='*60}")
headers2 = build_basic_headers(machine_id)
headers2["Authorization"] = f"Bearer {oauth_token}"
headers2["Content-Length"] = str(len(encoded_body))
req2 = urllib.request.Request(url, data=encoded_body.encode(), headers=headers2, method="POST")
try:
    resp = urllib.request.urlopen(req2, context=ctx, timeout=15)
    print(f"  HTTP {resp.status}: {resp.read().decode()[:500]}")
except urllib.error.HTTPError as e:
    print(f"  HTTP {e.code}: {e.read().decode(errors='replace')[:200]}")
except Exception as e:
    print(f"  Error: {e}")

# 测试3: 用 Signature 模式调 user/status (magic="none")
print(f"\n{'='*60}")
print(f"测试3: /api/v3/user/status + Signature 模式")
print(f"{'='*60}")
date_str = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())
encoded_b64 = base64.b64encode(body_str.encode()).decode()
sig = hashlib.md5(f"{encoded_b64}&d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==&{date_str}".encode()).hexdigest()
headers3 = build_basic_headers(machine_id)
headers3.update({"Date": date_str, "Cosy-Date": date_str, "Cosy-User": encoded_b64, "Signature": sig})
headers3["Content-Length"] = str(len(encoded_body.encode()))
req3 = urllib.request.Request(url, data=encoded_body.encode(), headers=headers3, method="POST")
try:
    resp = urllib.request.urlopen(req3, context=ctx, timeout=15)
    print(f"  HTTP {resp.status}: {resp.read().decode()[:500]}")
except urllib.error.HTTPError as e:
    print(f"  HTTP {e.code}: {e.read().decode(errors='replace')[:200]}")
except Exception as e:
    print(f"  Error: {e}")

# 测试4: 直接调用 Chat API 验证 COSY 凭据有效性
print(f"\n{'='*60}")
print(f"测试4: Chat API (验证 COSY 凭据)")
print(f"{'='*60}")
try:
    from lingma_remote_api import LingmaRemoteAPI
    api = LingmaRemoteAPI(cosy_key=cosy_key, encrypt_user_info=encrypt_info,
                          machine_id=machine_id, user_id=uid)
    result = api.chat("你好，用一句话介绍你自己")
    print(f"  ✅ Chat API 响应: {result[:200]}")
except Exception as e:
    print(f"  Error: {e}")
