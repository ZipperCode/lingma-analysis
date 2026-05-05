#!/usr/bin/env python3
"""
Lingma Token Refresh 直连脚本
基于 IDA Pro 最新反编译 (2026-05-04)

核心函数链:
  doRefreshToken @ 0x14088d660
    └─ BuildBigModelSignRequest(magic="none", POST, "/api/v3/user/refresh_token")
    └─ Client.do() → HTTP POST → 解析 UserStatusResponse
    └─ RefreshUserInfoSecurityToken() → 更新缓存

使用方法:
  # 从便携配置读取
  python tools/lingma_refresh_token.py

  # 手动指定参数
  python tools/lingma_refresh_token.py \
    --user-id "5930676910898027" \
    --security-token "pt-xxx" \
    --refresh-token "rt-yyy" \
    --machine-id "35346164-3866-492d-a339-30773a32652d"
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
import ssl
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ============================================================
# 常量 (IDA 逆向)
# ============================================================

# Cosy-Key (addBigModelSignatureHeaders @ 0x14087e5e0)
COSY_KEY = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
ALT_COSY_KEY = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"

# API 端点
BIG_MODEL_ENDPOINT = "https://lingma.alibabacloud.com/algo"
REFRESH_PATH = "/api/v3/user/refresh_token"

# ============================================================
# 签名算法
# ============================================================

def md5_sign(body_str: str, date_str: str, use_alt_key: bool = False) -> str:
    """
    addBigModelSignatureHeaders 签名

    MD5(base64(body) + "&" + key + "&" + date)

    key = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
        = base64("war, war never changes")
    """
    encoded = base64.b64encode(body_str.encode()).decode()
    key = ALT_COSY_KEY if use_alt_key else COSY_KEY
    raw = f"{encoded}&{key}&{date_str}"
    return hashlib.md5(raw.encode()).hexdigest()


def get_rfc1123_date() -> str:
    """RFC1123 格式日期 (Mon, 02 Jan 2006 15:04:05 GMT)"""
    return datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')


# ============================================================
# 请求头构造 (addBasicHeaders + addBigModelSignatureHeaders)
# ============================================================

def build_headers(body_str: str, machine_id: str, date_str: str = None) -> dict:
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


# ============================================================
# API 调用
# ============================================================

def refresh_token(security_oauth_token: str, refresh_token: str,
                  user_id: str, org_id: str, machine_id: str,
                  endpoint: str = BIG_MODEL_ENDPOINT) -> dict:
    """
    调用 /api/v3/user/refresh_token

    对应 IDA: doRefreshToken @ 0x14088d660
    认证模式: signature (magic="none")

    请求体:
    {
        "userId": "...",
        "orgId": "...",
        "securityOauthToken": "pt-...",
        "refreshToken": "rt-..."
    }

    响应 (UserStatusResponse):
    {
        "securityOauthToken": "pt-...",
        "refreshToken": "rt-...",
        "expireTime": 1783091978172
    }
    """
    body = {
        "userId": user_id,
        "orgId": org_id,
        "securityOauthToken": security_oauth_token,
        "refreshToken": refresh_token,
    }
    body_str = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    url = f"{endpoint}{REFRESH_PATH}"
    date_str = get_rfc1123_date()
    headers = build_headers(body_str, machine_id, date_str)

    print(f"[*] POST {url}")
    print(f"[*] Date: {date_str}")
    print(f"[*] Signature: {headers['Signature']}")
    print(f"[*] Cosy-User: {headers['Cosy-User'][:40]}...")
    print(f"[*] Body: {body_str[:120]}...")

    req = urllib.request.Request(url, data=body_str.encode(), headers=headers, method="POST")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        resp_body = resp.read().decode()
        print(f"\n  [✓] HTTP {resp.status}")

        # 检查失败标志 (doRefreshToken: strings.Index(body, '"success":false'))
        if '"success":false' in resp_body:
            print(f"  [!] 服务端返回错误: {resp_body[:300]}")
            return {"success": False, "raw": resp_body}

        result = json.loads(resp_body) if resp_body else {}
        print(f"  Response: {json.dumps(result, ensure_ascii=False)[:300]}")

        # 验证必要字段 (doRefreshToken: 检查 RefreshToken/SecurityOauthToken/ExpireTime)
        if result.get("refreshToken") and result.get("securityOauthToken"):
            expire = result.get("expireTime", 0)
            print(f"\n  [✓] Token 刷新成功!")
            print(f"      新 SecurityOauthToken: {str(result['securityOauthToken'])[:30]}...")
            print(f"      新 RefreshToken: {str(result['refreshToken'])[:30]}...")
            print(f"      ExpireTime: {expire} ({datetime.fromtimestamp(expire/1000, tz=timezone.utc) if expire > 0 else 'N/A'})")
        else:
            print(f"\n  [!] 响应缺少必要字段")

        return result

    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors="replace")[:500]
        print(f"\n  [✗] HTTP {e.code}")
        print(f"  Error: {err_body}")
        return {"error": str(e), "code": e.code, "body": err_body}
    except Exception as e:
        print(f"\n  [✗] Error: {e}")
        return {"error": str(e)}


# ============================================================
# 凭据读取
# ============================================================

def read_portable_config() -> dict:
    """从便携配置文件读取凭据"""
    paths = [
        Path.home() / ".lingma" / "portable_config.json",
        Path("portable_config.json"),
    ]
    for p in paths:
        if p.exists():
            with open(p) as f:
                return json.load(f)
    return {}


def read_env_config() -> dict:
    """从环境变量读取凭据"""
    return {
        "machine_id": os.environ.get("LINGMA_MACHINE_ID", ""),
        "user_id": os.environ.get("LINGMA_USER_ID", ""),
        "security_oauth_token": os.environ.get("LINGMA_OAUTH_TOKEN", ""),
        "refresh_token": os.environ.get("LINGMA_REFRESH_TOKEN", ""),
        "org_id": os.environ.get("LINGMA_ORG_ID", ""),
    }


# ============================================================
# 主流程
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Lingma Token Refresh")
    parser.add_argument("--user-id", help="User ID")
    parser.add_argument("--org-id", default="", help="Org ID")
    parser.add_argument("--security-token", help="SecurityOauthToken (pt-xxx)")
    parser.add_argument("--refresh-token", help="RefreshToken (rt-yyy)")
    parser.add_argument("--machine-id", help="Machine ID")
    parser.add_argument("--endpoint", default=BIG_MODEL_ENDPOINT, help="API endpoint")
    args = parser.parse_args()

    # 从多来源读取凭据
    creds = {}

    # 优先级: 命令行 > 配置文件 > 环境变量
    if args.user_id and args.security_token and args.refresh_token:
        creds = {
            "user_id": args.user_id,
            "org_id": args.org_id or "",
            "security_oauth_token": args.security_token,
            "refresh_token": args.refresh_token,
            "machine_id": args.machine_id or str(uuid.uuid4()),
        }
    else:
        # 尝试便携配置
        creds = read_portable_config()
        if not creds.get("security_oauth_token"):
            # 尝试环境变量
            creds = read_env_config()

        # 补充 machine_id
        if not creds.get("machine_id"):
            creds["machine_id"] = str(uuid.uuid4())

    # 验证必要字段
    missing = [k for k in ["user_id", "security_oauth_token", "refresh_token"]
               if not creds.get(k)]
    if missing:
        print(f"[!] 缺少必要参数: {missing}")
        print()
        print("从便携配置读取:")
        pc = read_portable_config()
        for k, v in pc.items():
            print(f"  {k}: {str(v)[:40]}")
        print()
        print("或手动指定:")
        print(f"  python {__file__} \\")
        print("    --user-id <uid> --security-token <pt-xxx> --refresh-token <rt-yyy>")
        sys.exit(1)

    print("=" * 60)
    print("Lingma Token Refresh")
    print("基于 IDA Pro 逆向 v2.11.2")
    print("=" * 60)
    print(f"\n[*] UserID: {creds['user_id']}")
    print(f"[*] OrgID: {creds.get('org_id', '')}")
    print(f"[*] MachineID: {creds['machine_id']}")
    print(f"[*] SecurityOauthToken: {str(creds['security_oauth_token'])[:30]}...")
    print(f"[*] RefreshToken: {str(creds['refresh_token'])[:30]}...")

    # 调用 refresh
    print(f"\n{'='*60}")
    print("调用 refresh_token API")
    print(f"{'='*60}")
    result = refresh_token(
        security_oauth_token=creds["security_oauth_token"],
        refresh_token=creds["refresh_token"],
        user_id=creds["user_id"],
        org_id=creds.get("org_id", ""),
        machine_id=creds.get("machine_id", str(uuid.uuid4())),
        endpoint=args.endpoint,
    )

    # 保存新 token (如果成功)
    if result.get("refreshToken") and result.get("securityOauthToken"):
        creds["security_oauth_token"] = result["securityOauthToken"]
        creds["refresh_token"] = result["refreshToken"]
        if result.get("expireTime"):
            creds["expire_time"] = result["expireTime"]

        out_path = Path.home() / ".lingma" / "portable_config.json"
        with open(out_path, "w") as f:
            json.dump(creds, f, indent=2, ensure_ascii=False)
        print(f"\n[*] 凭据已更新: {out_path}")

    print(f"\n[*] 完成!")


if __name__ == "__main__":
    main()
