#!/usr/bin/env python3
"""
Token 刷新测试脚本

用法：
    python test_refresh_token.py
"""
import json
import urllib.error
import urllib.request
import ssl
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path

# 配置
BIG_MODEL_ENDPOINT = "https://lingma.alibabacloud.com/algo"
COSY_KEY = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
ALT_COSY_KEY = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"


def get_rfc1123_date() -> str:
    """RFC1123 格式日期"""
    return datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')


def md5_sign(body_str: str, date_str: str, use_alt_key: bool = False) -> str:
    """MD5(base64(body) + "&" + key + "&" + date)"""
    encoded = base64.b64encode(body_str.encode()).decode()
    key = ALT_COSY_KEY if use_alt_key else COSY_KEY
    raw = f"{encoded}&{key}&{date_str}"
    return hashlib.md5(raw.encode()).hexdigest()


def build_refresh_headers(body_str: str, machine_id: str, date_str: str = None) -> dict:
    """构造 refresh_token 请求头 (signature 模式)"""
    if date_str is None:
        date_str = get_rfc1123_date()

    encoded = base64.b64encode(body_str.encode()).decode()

    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "User-Agent": "Cosy/20",
        "X-Forwarded-For": "127.0.0.1",
        "Cosy-MachineId": machine_id,
        "Cosy-MachineToken": "",
        "Cosy-MachineType": "",
        "Cosy-MachineCode": "",
        "Cosy-MachineOS": "x86_64_windows",
        "Cosy-ClientType": "2",
        "Cosy-Version": "20",
        "Date": date_str,
        "Cosy-Date": date_str,
        "Cosy-User": encoded,
        "Signature": md5_sign(body_str, date_str),
    }


def refresh_token(security_oauth_token: str, refresh_token_val: str,
                  user_id: str, org_id: str, machine_id: str) -> dict:
    """调用 /api/v3/user/refresh_token"""
    body = {
        "userId": user_id,
        "orgId": org_id,
        "securityOauthToken": security_oauth_token,
        "refreshToken": refresh_token_val,
    }
    body_str = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    url = f"{BIG_MODEL_ENDPOINT}/api/v3/user/refresh_token"
    date_str = get_rfc1123_date()
    headers = build_refresh_headers(body_str, machine_id, date_str)

    print(f"[*] POST {url}")
    print(f"[*] Date: {date_str}")
    print(f"[*] Signature: {headers['Signature']}")
    print(f"[*] Body: {body_str}")

    req = urllib.request.Request(url, data=body_str.encode(), headers=headers, method="POST")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        resp_body = resp.read().decode()
        print(f"\n  [✓] HTTP {resp.status}")
        print(f"  Response: {resp_body[:500]}")
        return json.loads(resp_body) if resp_body else {}

    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors='replace')[:500]
        print(f"\n  [✗] HTTP {e.code}")
        print(f"  Error: {err_body}")
        return {"error": str(e), "code": e.code, "body": err_body}
    except Exception as e:
        print(f"\n  [✗] Error: {e}")
        return {"error": str(e)}


def main():
    # 读取凭据
    config_path = Path.home() / ".lingma" / "portable_config.json"
    if not config_path.exists():
        print("[!] No credentials found")
        return

    with open(config_path) as f:
        creds = json.load(f)

    user_id = creds.get("user_id", "")
    security_oauth_token = creds.get("security_oauth_token", "")
    refresh_token_val = creds.get("refresh_token", "")
    machine_id = creds.get("machine_id", "")
    org_id = creds.get("org_id", "")

    print(f"[*] UserID: {user_id}")
    print(f"[*] SecurityOauthToken: {security_oauth_token[:30]}...")
    print(f"[*] RefreshToken: {refresh_token_val[:30]}...")
    print(f"[*] MachineID: {machine_id}")
    print(f"[*] OrgID: {org_id}")

    result = refresh_token(
        security_oauth_token=security_oauth_token,
        refresh_token_val=refresh_token_val,
        user_id=user_id,
        org_id=org_id,
        machine_id=machine_id,
    )

    print(f"\n[*] Result: {json.dumps(result, indent=2, ensure_ascii=False)[:500]}")


if __name__ == "__main__":
    main()
