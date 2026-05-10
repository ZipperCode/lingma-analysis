#!/usr/bin/env python3
"""
Lingma OAuth 管理器 — 完全脱离 Lingma 程序

功能：
  1. OAuth 自主登录（生成 URL → 打开浏览器 → 捕获回调 → 保存凭据）
  2. Token 刷新（使用 refresh_token 获取新的 securityOauthToken）
  3. 凭据管理（查看、导出、删除凭据）

用法：
    # 登录
    python lingma_oauth_manager.py login

    # 刷新 Token
    python lingma_oauth_manager.py refresh

    # 查看凭据
    python lingma_oauth_manager.py status

    # 删除凭据
    python lingma_oauth_manager.py logout
"""
import argparse
import base64
import hashlib
import http.server
import json
import math
import os
import re
import secrets
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
import webbrowser
from datetime import datetime, timezone
from pathlib import Path


# ===== 配置 =====
CALLBACK_PORT = 37510
CONFIG_DIR = Path.home() / '.lingma'
CONFIG_PATH = CONFIG_DIR / 'portable_config.json'

# API 端点
BIG_MODEL_ENDPOINT = "https://lingma.alibabacloud.com/algo"

# Cosy-Key (IDA @ addBigModelSignatureHeaders 0x14087e5e0)
COSY_KEY = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
ALT_COSY_KEY = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"

# Encode=1 解码 (IDA @ CustomDecryptParts)
_ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
_STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def _custom_b64_decode(encoded: str) -> bytes:
    """自定义 base64 解码: 字母表替换后标准 base64 解码"""
    converted = ''.join(_STD_B64[_ALPHA.index(c)] for c in encoded if c in _ALPHA)
    pad = (4 - len(converted) % 4) % 4
    return base64.b64decode(converted + '=' * pad)


def lingma_decode(body: str) -> bytes:
    """Encode=1 解码: 去$ → 反转恢复 → 自定义base64解码"""
    dollar_start = body.find('$')
    if dollar_start < 0:
        rev = body
        E = len(body)
    else:
        pad = 0
        pos = dollar_start
        while pos < len(body) and body[pos] == '$':
            pad += 1
            pos += 1
        rev = body[:dollar_start] + body[dollar_start + pad:]
        E = len(rev)
    BS = math.ceil(E / 3)
    lb = E - 2 * BS
    b2 = rev[:lb]
    b1 = rev[lb:lb + BS]
    b0 = rev[lb + BS:]
    return _custom_b64_decode(b0 + b1 + b2)


def _try_decode(value: str) -> bytes:
    """尝试多种方式解码参数值 (parseAuthToken 逻辑)"""
    # 方式 1: 直接 lingma_decode
    try:
        result = lingma_decode(value)
        print(f"    [dbg] lingma_decode ok, {len(result)} bytes, hex={result[:20].hex()}")
        return result
    except Exception as e:
        print(f"    [dbg] lingma_decode failed: {e}")

    # 方式 2: URL-unescape 后再 lingma_decode (IDA: net_url.unescape)
    try:
        unescaped = urllib.parse.unquote(value)
        if unescaped != value:
            result = lingma_decode(unescaped)
            print(f"    [dbg] unquote+lingma_decode ok, {len(result)} bytes, hex={result[:20].hex()}")
            return result
    except Exception as e:
        print(f"    [dbg] unquote+lingma_decode failed: {e}")

    # 方式 3: URL-unescape (plus 空格) 后再 lingma_decode
    try:
        unescaped = urllib.parse.unquote_plus(value)
        if unescaped != value:
            result = lingma_decode(unescaped)
            print(f"    [dbg] unquote_plus+lingma_decode ok, {len(result)} bytes, hex={result[:20].hex()}")
            return result
    except Exception as e:
        print(f"    [dbg] unquote_plus+lingma_decode failed: {e}")

    # 方式 4: 标准 base64 解码
    try:
        result = base64.b64decode(value)
        print(f"    [dbg] standard base64 ok, {len(result)} bytes, hex={result[:20].hex()}")
        return result
    except Exception as e:
        print(f"    [dbg] standard base64 failed: {e}")

    # 方式 5: URL-unescape 后标准 base64
    try:
        unescaped = urllib.parse.unquote(value)
        if unescaped != value:
            result = base64.b64decode(unescaped)
            print(f"    [dbg] unquote+base64 ok, {len(result)} bytes, hex={result[:20].hex()}")
            return result
    except Exception as e:
        print(f"    [dbg] unquote+base64 failed: {e}")

    # 方式 6: URL-safe base64 解码
    try:
        padded = value + '=' * ((4 - len(value) % 4) % 4)
        result = base64.urlsafe_b64decode(padded)
        print(f"    [dbg] urlsafe base64 ok, {len(result)} bytes, hex={result[:20].hex()}")
        return result
    except Exception as e:
        print(f"    [dbg] urlsafe base64 failed: {e}")

    raise ValueError("All decode attempts failed")


def _decode_bytes_to_text(raw: bytes) -> str:
    """尝试多种编码将 bytes 转为 str"""
    for enc in ('utf-8', 'latin-1', 'gbk', 'gb2312', 'big5'):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            pass
    # 最后尝试 latin-1（不会失败，但可能乱码）
    return raw.decode('latin-1')


def decode_auth_params(params: dict) -> dict:
    """从 URL 参数中解码认证信息 (parseAuthInfoV2 逻辑)"""
    auth_data = {}
    print(f"[*] decode_auth_params called with keys: {list(params.keys())}")

    # 解码 auth 参数 (3 部分: aid, uid, name)
    if 'auth' in params:
        auth_value = params['auth']
        print(f"[*] Decoding auth (len={len(auth_value)}, preview={auth_value[:60]})...")
        try:
            raw = _try_decode(auth_value)
            decoded = _decode_bytes_to_text(raw)
            print(f"[*] auth decoded text: {decoded[:200]}")

            # 尝试 JSON
            try:
                auth_data.update(json.loads(decoded))
                print(f"[*] auth parsed as JSON")
            except json.JSONDecodeError:
                # 尝试 newline 分隔
                parts = decoded.split('\n')
                if len(parts) >= 3:
                    auth_data['aid'] = parts[0]
                    auth_data['uid'] = parts[1]
                    auth_data['name'] = parts[2]
                    print(f"[*] auth parsed as newline-separated")
        except Exception as e:
            print(f"[!] Failed to decode auth: {e}")
            auth_data['auth_raw'] = auth_value

    # 解码 token 参数 (3 部分: securityOauthToken, refreshToken, expireTime)
    if 'token' in params:
        token_value = params['token']
        print(f"[*] Decoding token (len={len(token_value)}, preview={token_value[:60]})...")
        try:
            raw = _try_decode(token_value)
            decoded = _decode_bytes_to_text(raw)
            print(f"[*] token decoded text: {decoded[:200]}")

            try:
                auth_data.update(json.loads(decoded))
                print(f"[*] token parsed as JSON")
            except json.JSONDecodeError:
                parts = decoded.split('\n')
                if len(parts) >= 3:
                    auth_data['security_oauth_token'] = parts[0]
                    auth_data['refresh_token'] = parts[1]
                    try:
                        auth_data['expire_time'] = int(parts[2])
                    except ValueError:
                        auth_data['expire_time'] = parts[2]
                    print(f"[*] token parsed as newline-separated")
        except Exception as e:
            print(f"[!] Failed to decode token: {e}")
            auth_data['token_raw'] = token_value

    # 兼容旧版 URL 参数 (版本 1)
    for k in ('aid', 'uid', 'name'):
        if k in params and k not in auth_data:
            auth_data[k] = params[k]

    if auth_data:
        print(f"[*] decode_auth_params result keys: {list(auth_data.keys())}")
    else:
        print(f"[*] decode_auth_params returned empty (no auth/token params)")
    return auth_data if auth_data else None


# ===== PKCE 工具 =====

def generate_pkce() -> tuple:
    """生成 PKCE 参数: (code_verifier, code_challenge)"""
    verifier = secrets.token_urlsafe(32)[:43]
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return verifier, challenge


# ===== 生成 OAuth URL =====

def generate_login_url(port: int = CALLBACK_PORT, region: str = 'intl', reuse_cookie: bool = True) -> dict:
    """独立生成 Lingma 登录 URL (版本 2)

    Args:
        port: 回调端口
        region: 'intl' 或 'cn'
        reuse_cookie: True=复用已有 cookie (直接 login.htm), False=强制重新登录 (先 logout)
    """
    nonce = uuid.uuid4().hex
    verifier, challenge = generate_pkce()
    machine_id = str(uuid.uuid4()).upper()
    state = f"2-{nonce}"  # 版本 2 前缀

    inner_params = {
        'state': state,
        'challenge': challenge,
        'challenge_method': 'S256',
        'machine_id': machine_id,
        'nonce': nonce,
        'port': str(port),
    }
    inner_query = urllib.parse.urlencode(inner_params)

    if region == 'cn':
        inner_url = f"https://devops.aliyun.com/lingma/login?{inner_query}"
    else:
        inner_url = f"https://lingma.alibabacloud.com/lingma/login?{inner_query}"

    middle_url = f"https://account.alibabacloud.com/login/login.htm?oauth_callback={urllib.parse.quote(inner_url, safe='')}"

    if reuse_cookie:
        # 复用 cookie 模式：直接访问 login.htm，不强制登出
        full_url = middle_url
    else:
        # 强制重新登录模式：先 logout 再 login
        full_url = f"https://account.alibabacloud.com/logout/logout.htm?oauth_callback={urllib.parse.quote(middle_url, safe='')}"

    return {
        'login_url': full_url,
        'nonce': nonce,
        'verifier': verifier,
        'challenge': challenge,
        'machine_id': machine_id,
        'state': state,
    }


# ===== 从 HTML 中提取认证信息 =====

def extract_auth_from_html(html: str) -> dict:
    """从 HTML 中解析 window.user_info 获取认证信息"""
    # 模式 1: window.user_info = '...' (单引号)
    pattern = r"window\.user_info\s*=\s*'(.+?)'\s*;"
    match = re.search(pattern, html, re.DOTALL)
    if match:
        json_str = match.group(1)
        json_str = json_str.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

    # 模式 2: window.user_info = "..." (双引号)
    pattern = r'window\.user_info\s*=\s*"(.+?)"\s*;'
    match = re.search(pattern, html, re.DOTALL)
    if match:
        json_str = match.group(1)
        json_str = json_str.replace('\\"', '"').replace("\\\\", "\\")
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

    # 模式 3: window.user_info = {...} (JSON 对象)
    pattern = r'window\.user_info\s*=\s*({.+?})\s*;'
    match = re.search(pattern, html, re.DOTALL)
    if match:
        json_str = match.group(1)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

    return {}


# ===== 凭据管理 =====

def load_credentials() -> dict:
    """加载凭据"""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    return {}


def save_credentials(creds: dict):
    """保存凭据"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(creds, f, indent=2, ensure_ascii=False)
    print(f'[*] Credentials saved to: {CONFIG_PATH}')


def delete_credentials():
    """删除凭据"""
    if CONFIG_PATH.exists():
        CONFIG_PATH.unlink()
        print('[*] Credentials deleted')
    else:
        print('[!] No credentials to delete')


# ===== OAuth 回调 HTTP 服务器 =====

class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    """处理 Lingma OAuth 回调的 HTTP 处理器"""
    captured = None
    result_event = threading.Event()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        flat = {k: v[0] if len(v) == 1 else v for k, v in params.items()}

        print(f"\n{'='*60}")
        print(f"[*] do_GET: path={self.path}")
        print(f"[*] Query params: {flat}")

        # 保存请求信息
        OAuthCallbackHandler.captured = {
            'method': 'GET',
            'path': self.path,
            'query_params': flat,
            'headers': dict(self.headers),
            'timestamp': time.time(),
        }

        # 检查 URL 参数中是否有认证信息
        # 优先尝试版本 2 格式: 从 URL 参数中解码 auth/token (Encode=1)
        decoded_auth = decode_auth_params(flat)
        if decoded_auth:
            print(f"[*] Auth data decoded from URL params (v2): "
                  f"{json.dumps(decoded_auth, ensure_ascii=False, default=str)[:300]}")
            OAuthCallbackHandler.captured['auth_data'] = decoded_auth
            self._return_user_info_page(decoded_auth)
            OAuthCallbackHandler.result_event.set()
            return

        # 基础认证信息 (版本 1 或旧格式)
        if 'aid' in flat or 'uid' in flat or 'name' in flat:
            auth_data = {}
            for k in ('aid', 'uid', 'name', 'state'):
                if k in flat:
                    auth_data[k] = flat[k]
            OAuthCallbackHandler.captured['auth_data'] = auth_data
            print(f"[*] Auth data captured from URL (v1): {auth_data}")
            self._return_user_info_page(auth_data)
            OAuthCallbackHandler.result_event.set()
            return

        # 检查是否有 OAuth 标准授权码
        if 'code' in flat:
            print(f"[*] OAuth code received: {flat['code'][:30]}...")
            # 不设置 result_event，等待后续回调或 POST

        # 返回 HTML 页面，用于捕获认证信息
        print(f"[*] Returning capture page for {self.path}")
        self._return_capture_page()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''
        body_str = body.decode('utf-8', errors='replace')

        print(f"\n{'='*60}")
        print(f"[*] do_POST: path={self.path}")
        print(f"[*] Body preview: {body_str[:500]}")

        OAuthCallbackHandler.captured = {
            'method': 'POST',
            'path': self.path,
            'body': body_str,
            'headers': dict(self.headers),
            'timestamp': time.time(),
        }

        # 尝试从 POST 请求体中解析认证信息
        auth_data = {}
        try:
            data = json.loads(body_str)

            # 新的 HTML 页面格式: { collected: { ... } }
            if 'collected' in data:
                collected = data['collected']
                print(f"[*] Received collected data with keys: {list(collected.keys())}")

                # 尝试从 collected 中提取 user_info
                if 'user_info' in collected and collected['user_info']:
                    ui = collected['user_info']
                    if isinstance(ui, str):
                        try:
                            ui = json.loads(ui)
                        except json.JSONDecodeError:
                            pass
                    auth_data = ui if isinstance(ui, dict) else {'user_info_raw': str(ui)}

                # 尝试从 URL 参数中提取
                for key in ['auth', 'token', 'aid', 'uid', 'name', 'state']:
                    if key in collected and collected[key]:
                        auth_data[key] = collected[key]

                # 尝试从其他全局变量中提取
                for key in ['userInfo', 'authData', 'auth_info', 'tokenData']:
                    if key in collected and collected[key]:
                        auth_data[key] = collected[key]

            # 旧格式: { user_info: ... }
            elif 'user_info' in data:
                ui = data['user_info']
                if isinstance(ui, str):
                    try:
                        ui = json.loads(ui)
                    except json.JSONDecodeError:
                        pass
                auth_data = ui if isinstance(ui, dict) else {'user_info_raw': str(ui)}

            # 其他格式
            else:
                auth_data = data

        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"[!] Failed to parse POST body: {e}")

        if auth_data:
            OAuthCallbackHandler.captured['auth_data'] = auth_data
            print(f"[*] Auth data extracted from POST body: "
                  f"{json.dumps(auth_data, ensure_ascii=False, default=str)[:300]}")

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

        OAuthCallbackHandler.result_event.set()

    def _send_success(self, message):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(f'<h1>{message}</h1>'.encode('utf-8'))

    def _return_capture_page(self):
        """返回 HTML 页面，用于捕获认证信息"""
        html = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Lingma OAuth Callback</title>
    <style>
        body { font-family: system-ui, sans-serif; text-align: center; padding: 40px; }
        h1 { color: #4CAF50; }
        .debug { margin: 20px auto; max-width: 800px; text-align: left; background: #f5f5f5; padding: 20px; border-radius: 8px; font-size: 12px; }
        pre { overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
    </style>
</head>
<body>
    <h1>OAuth Callback Received</h1>
    <p id="status">Waiting for authentication...</p>
    <script>
        (function() {
            var status = document.getElementById('status');
            var collected = {};

            // 1. 尝试从 URL 参数中提取
            var urlParams = new URLSearchParams(window.location.search);
            urlParams.forEach(function(value, key) {
                collected[key] = value;
            });
            console.log('URL params:', collected);

            // 2. 尝试从 window.user_info 中提取
            if (window.user_info) {
                console.log('Found window.user_info:', window.user_info);
                collected.user_info = window.user_info;
            }

            // 3. 尝试从其他全局变量中提取
            ['user_info', 'userInfo', 'authData', 'auth_info', 'tokenData'].forEach(function(name) {
                if (window[name] && name !== 'user_info') {
                    console.log('Found window.' + name + ':', window[name]);
                    collected[name] = window[name];
                }
            });

            // 4. 发送收集到的信息到服务器
            fetch('/capture', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ collected: collected })
            }).then(function(resp) {
                status.innerHTML = '<p>Data sent to server. You can close this window.</p>';
            }).catch(function(err) {
                status.innerHTML = '<p>Error sending data: ' + err.message + '</p>';
            });
        })();
    </script>
</body>
</html>'''
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def _return_user_info_page(self, auth_data):
        """返回包含用户认证信息的 HTML 页面"""
        print(f"[*] _return_user_info_page called with auth_data: "
              f"{json.dumps(auth_data, ensure_ascii=False, default=str)[:200]}")
        html = f'''<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Login Success</title></head>
<body>
    <h1>Login Success</h1>
    <p>Auth data captured.</p>
    <script>
        window.user_info = '{json.dumps(auth_data)}';
        console.log('window.user_info:', window.user_info);
    </script>
</body>
</html>'''
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def log_message(self, format, *args):
        pass  # 禁用默认 HTTP 日志


# ===== Token 刷新 =====

def md5_sign(body_str: str, date_str: str, use_alt_key: bool = False) -> str:
    """MD5(base64(body) + "&" + key + "&" + date)"""
    encoded = base64.b64encode(body_str.encode()).decode()
    key = ALT_COSY_KEY if use_alt_key else COSY_KEY
    raw = f"{encoded}&{key}&{date_str}"
    return hashlib.md5(raw.encode()).hexdigest()


def get_rfc1123_date() -> str:
    """RFC1123 格式日期"""
    return datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')


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


def refresh_token_api(security_oauth_token: str, refresh_token_val: str,
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

        if '"success":false' in resp_body:
            print(f"  [!] Server error: {resp_body[:300]}")
            return {"success": False, "raw": resp_body}

        result = json.loads(resp_body) if resp_body else {}
        print(f"  Response: {json.dumps(result, ensure_ascii=False)[:300]}")

        if result.get("refreshToken") and result.get("securityOauthToken"):
            expire = result.get("expireTime", 0)
            print(f"\n  [✓] Token refresh success!")
            print(f"      New securityOauthToken: {str(result['securityOauthToken'])[:30]}...")
            print(f"      New refreshToken: {str(result['refreshToken'])[:30]}...")
            print(f"      ExpireTime: {expire}")

        return result

    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors='replace')[:500]
        print(f"\n  [✗] HTTP {e.code}")
        print(f"  Error: {err_body}")
        return {"error": str(e), "code": e.code, "body": err_body}
    except Exception as e:
        print(f"\n  [✗] Error: {e}")
        return {"error": str(e)}


# ===== 命令实现 =====

def _extract_creds_from_auth_data(auth_data: dict, machine_id: str) -> dict:
    """从 auth_data 中提取关键认证信息，支持多种命名风格"""
    if not isinstance(auth_data, dict):
        return {}

    # 统一命名风格映射
    field_map = {
        'user_id': ['user_id', 'uid', 'userId', 'user-id'],
        'name': ['name', 'userName', 'user_name', 'displayName'],
        'aid': ['aid', 'userAid', 'user_aid'],
        'security_oauth_token': ['security_oauth_token', 'securityOauthToken', 'token', 'accessToken', 'access_token'],
        'refresh_token': ['refresh_token', 'refreshToken', 'refresh'],
        'expire_time': ['expire_time', 'expireTime', 'expiresAt', 'expires_at'],
        'org_id': ['org_id', 'orgId', 'organizationId', 'org'],
    }

    creds = {'machine_id': machine_id}

    for standard_name, possible_names in field_map.items():
        for name in possible_names:
            if name in auth_data and auth_data[name]:
                val = auth_data[name]
                # 转换类型
                if standard_name == 'expire_time' and isinstance(val, str):
                    try:
                        val = int(val)
                    except ValueError:
                        pass
                creds[standard_name] = val
                break

    return creds if len(creds) > 1 else {}


def cmd_login(args):
    """OAuth 登录"""
    port = args.port if hasattr(args, 'port') else CALLBACK_PORT
    region = args.region if hasattr(args, 'region') else 'intl'
    timeout = args.timeout if hasattr(args, 'timeout') else 300

    # 生成 OAuth URL
    reuse_cookie = getattr(args, 'reuse_cookie', True)
    info = generate_login_url(port=port, region=region, reuse_cookie=reuse_cookie)
    login_url = info['login_url']

    print(f'[*] Login URL: {login_url}')

    # 启动 HTTP 服务器
    server = http.server.HTTPServer(('127.0.0.1', port), OAuthCallbackHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    # 打开浏览器
    webbrowser.open(login_url)

    # 等待回调
    if not OAuthCallbackHandler.result_event.wait(timeout=timeout):
        print('[!] Timeout')
        return

    # 提取认证信息
    captured = OAuthCallbackHandler.captured
    if captured and 'auth_data' in captured:
        auth_data = captured['auth_data']
        print(f'[*] Auth data captured: {json.dumps(auth_data, indent=2, ensure_ascii=False)}')

        # 尝试从 auth_data 中提取关键信息
        creds = _extract_creds_from_auth_data(auth_data, info['machine_id'])

        if not creds:
            # 检查是否有嵌套的 user_info
            if 'user_info' in auth_data:
                user_info = auth_data['user_info']
                if isinstance(user_info, str):
                    try:
                        user_info = json.loads(user_info)
                    except json.JSONDecodeError:
                        user_info = {}
                creds = _extract_creds_from_auth_data(user_info, info['machine_id'])

        if creds:
            print(f'[*] Extracted credentials: {json.dumps(creds, ensure_ascii=False, default=str)}')
            save_credentials(creds)
        else:
            print('[!] Could not extract credentials from auth_data')
    else:
        print('[!] No auth data captured')


def cmd_refresh(args):
    """刷新 Token"""
    creds = load_credentials()
    if not creds:
        print('[!] No credentials found. Please run "login" first.')
        return

    user_id = creds.get('user_id', '')
    security_oauth_token = creds.get('security_oauth_token', '')
    refresh_token_val = creds.get('refresh_token', '')
    machine_id = creds.get('machine_id', '')
    org_id = creds.get('org_id', '')

    if not all([user_id, security_oauth_token, refresh_token_val]):
        print('[!] Incomplete credentials')
        return

    print(f"[*] UserID: {user_id}")
    print(f"[*] SecurityOauthToken: {security_oauth_token[:30]}...")
    print(f"[*] RefreshToken: {refresh_token_val[:30]}...")
    print(f"[*] MachineID: {machine_id}")

    result = refresh_token_api(
        security_oauth_token=security_oauth_token,
        refresh_token_val=refresh_token_val,
        user_id=user_id,
        org_id=org_id,
        machine_id=machine_id,
    )

    if result.get("refreshToken") and result.get("securityOauthToken"):
        # 更新凭据
        creds['security_oauth_token'] = result['securityOauthToken']
        creds['refresh_token'] = result['refreshToken']
        if result.get('expireTime'):
            creds['expire_time'] = result['expireTime']

        save_credentials(creds)
        print("\n[*] Credentials updated")
    else:
        print("\n[!] Token refresh failed")


def cmd_status(args):
    """查看凭据状态"""
    creds = load_credentials()
    if not creds:
        print('[!] No credentials found')
        return

    print('=== Credentials Status ===')
    for k, v in creds.items():
        if isinstance(v, str) and len(v) > 50:
            print(f'  {k}: {v[:50]}...')
        else:
            print(f'  {k}: {v}')

    # 检查过期时间
    expire_time = creds.get('expire_time', 0)
    if expire_time > 0:
        expire_dt = datetime.fromtimestamp(expire_time / 1000, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        if expire_dt > now:
            remaining = expire_dt - now
            print(f'\n[*] Token expires in: {remaining}')
        else:
            print(f'\n[!] Token expired')


def cmd_logout(args):
    """删除凭据"""
    delete_credentials()


# ===== 主流程 =====

def main():
    parser = argparse.ArgumentParser(description='Lingma OAuth Manager')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # login
    login_parser = subparsers.add_parser('login', help='OAuth login')
    login_parser.add_argument('--port', type=int, default=CALLBACK_PORT, help='Callback port')
    login_parser.add_argument('--region', default='intl', choices=['intl', 'cn'], help='Region')
    login_parser.add_argument('--timeout', type=int, default=300, help='Timeout in seconds')
    login_parser.add_argument('--reuse-cookie', action='store_true', default=True, dest='reuse_cookie',
                              help='Reuse existing login cookie (default: True)')
    login_parser.add_argument('--force-login', action='store_false', default=True, dest='reuse_cookie',
                              help='Force re-login (ignore existing cookie)')

    # refresh
    refresh_parser = subparsers.add_parser('refresh', help='Refresh token')

    # status
    status_parser = subparsers.add_parser('status', help='Show credentials status')

    # logout
    logout_parser = subparsers.add_parser('logout', help='Delete credentials')

    args = parser.parse_args()

    if args.command == 'login':
        cmd_login(args)
    elif args.command == 'refresh':
        cmd_refresh(args)
    elif args.command == 'status':
        cmd_status(args)
    elif args.command == 'logout':
        cmd_logout(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
