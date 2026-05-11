#!/usr/bin/env python3
"""
Lingma OAuth 自主登录 v5.0 — 完全脱离 Lingma 程序

基于 IDA Pro 逆向 + chrome-devtools 实时验证的完整 OAuth 流程。

关键修复:
  1. state="2-{nonce}" → 触发 V2 回调（含 Encode=1 编码的 auth+token）
  2. 三层嵌套 URL → 正确走阿里云登录流程
  3. 持久化 machine_id → 从 ~/.lingma/cache/id 读取
  4. 三种回调场景处理 → V2/V1/页面捕获

已确认的流程:
  [Client] state="2-{nonce}" + PKCE + machine_id
      → [Browser] 三层 URL: logout → login → lingma/login
      → [lingma.alibabacloud.com] 服务端 OAuth token 交换
      → [redirect] localhost:37510/auth/callback?state=2-xxx&auth=<V2>&token=<V2>
      → [Local Server] Decode V2 params → 完整凭据

用法:
  python lingma_oauth_complete.py login              # OAuth 登录（独立模式）
  python lingma_oauth_complete.py login --lsp        # 通过 LSP 获取 URL
  python lingma_oauth_complete.py status             # 查看凭据
  python lingma_oauth_complete.py refresh            # 刷新 Token（如可用）
  python lingma_oauth_complete.py manual             # 手动导入 window.user_info
  python lingma_oauth_complete.py decode <string>    # 测试 Encode=1 解码
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


# ============================================================
# 常量
# ============================================================
CALLBACK_PORT = 37510
LSP_PORT = 37010
CONFIG_DIR = Path.home() / ".lingma"
CONFIG_PATH = CONFIG_DIR / "portable_config.json"

COSY_KEY = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
ALT_COSY_KEY = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"

BIG_MODEL_ENDPOINT = "https://lingma.alibabacloud.com/algo"
OAUTH_BASE_URL = "https://lingma.alibabacloud.com/lingma/login"

ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


# ============================================================
# Encode=1 编解码 (IDA @ encodeToString 0x1404549e0)
# ============================================================
def _custom_b64_encode(data: bytes) -> str:
    std = base64.b64encode(data).decode().rstrip('=')
    return ''.join(ALPHA[STD_B64.index(c)] for c in std)


def _custom_b64_decode(encoded: str) -> bytes:
    converted = ''.join(STD_B64[ALPHA.index(c)] for c in encoded if c in ALPHA)
    pad = (4 - len(converted) % 4) % 4
    return base64.b64decode(converted + '=' * pad)


def encode_to_string(data: bytes) -> str:
    encoded = _custom_b64_encode(data)
    E = len(encoded)
    f = E // 3  # floor(E/3) — b0 block size
    c = math.ceil(E / 3)
    pad = (4 - E % 4) % 4
    b0, b1, b2 = encoded[:f], encoded[f:2 * c], encoded[2 * c:]
    return b2 + '$' * pad + b1 + b0


def decode_string(body: str) -> bytes:
    dollar_start = body.find('$')
    if dollar_start < 0:
        clean = body
    else:
        p = 0
        pos = dollar_start
        while pos < len(body) and body[pos] == '$':
            p += 1
            pos += 1
        clean = body[:dollar_start] + body[dollar_start + p:]
    E = len(clean)
    c = math.ceil(E / 3)
    f = E // 3
    lb = E - 2 * c  # b2 size
    b1_size = 2 * c - f
    b2, b1, b0 = clean[:lb], clean[lb:lb + b1_size], clean[lb + b1_size:]
    return _custom_b64_decode(b0 + b1 + b2)


def custom_decrypt_parts(encoded: str, expected_parts: int = 3) -> list:
    try:
        unescaped = urllib.parse.unquote(encoded)
        decoded = decode_string(unescaped)
        text = decoded.decode('utf-8')
        parts = text.split('\n', expected_parts - 1)
        if len(parts) >= expected_parts:
            return parts
    except Exception:
        pass
    return []


# ============================================================
# 签名算法 (IDA @ addBigModelSignatureHeaders 0x14087e5e0)
# ============================================================
def md5_sign(encoded_body: str, date_str: str, use_alt_key: bool = False) -> str:
    key = ALT_COSY_KEY if use_alt_key else COSY_KEY
    raw = f"{encoded_body}&{key}&{date_str}"
    return hashlib.md5(raw.encode()).hexdigest()


def get_rfc1123_date() -> str:
    return datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')


def build_sign_headers(body: str, machine_id: str, security_token: str = "") -> dict:
    date_str = get_rfc1123_date()
    encoded = base64.b64encode(body.encode()).decode()
    headers = {
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
        "Signature": md5_sign(encoded, date_str),
    }
    if security_token:
        headers["Cosy-SecurityOauthToken"] = security_token
    return headers


# ============================================================
# PKCE + OAuth URL (IDA @ PrepareLoginRequest 0x141a198a0)
# ============================================================
def generate_pkce() -> tuple:
    verifier = secrets.token_urlsafe(32)[:43]
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return verifier, challenge


def build_oauth_url(nonce: str, port: int, challenge: str, machine_id: str,
                    region: str = "intl") -> str:
    params = urllib.parse.urlencode({
        "nonce": nonce,
        "port": port,
        "state": f"2-{nonce}",
        "challenge": challenge,
        "challenge_method": "S256",
        "machine_id": machine_id,
    })
    base = "https://devops.aliyun.com/lingma/login" if region == "cn" else OAUTH_BASE_URL
    return f"{base}?{params}"


def build_full_login_url(inner_url: str, reuse_cookie: bool = True) -> str:
    """
    三层嵌套 URL (IDA @ PrepareLoginRequest):
      外层: account.alibabacloud.com/logout/logout.htm
      中层: account.alibabacloud.com/login/login.htm
      内层: lingma.alibabacloud.com/lingma/login?state=2-xxx&...
    """
    middle = f"https://account.alibabacloud.com/login/login.htm?oauth_callback={urllib.parse.quote(inner_url, safe='')}"
    if reuse_cookie:
        return middle
    return f"https://account.alibabacloud.com/logout/logout.htm?oauth_callback={urllib.parse.quote(middle, safe='')}"


# ============================================================
# Machine ID 持久化
# ============================================================
def get_machine_id() -> str:
    id_path = CONFIG_DIR / "cache" / "id"
    if id_path.exists():
        mid = id_path.read_text().strip()
        if mid:
            print(f"[*] Machine ID (持久): {mid}")
            return mid
    mid = str(uuid.uuid4())
    print(f"[*] Machine ID (新生成): {mid}")
    return mid


# ============================================================
# 凭据管理
# ============================================================
def load_credentials() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_credentials(creds: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(creds, f, indent=2, ensure_ascii=False)
    print(f"[*] 凭据已保存: {CONFIG_PATH}")


# ============================================================
# V2 回调解析 (IDA @ parseAuthInfo 0x141a21660)
# ============================================================
def parse_callback_v2(params: dict) -> dict:
    result = {}

    if "auth" in params:
        parts = custom_decrypt_parts(params["auth"], 3)
        if len(parts) >= 3:
            result["uid"] = parts[0]
            result["aid"] = parts[1]
            result["name"] = parts[2]
            print(f"    [V2-auth] uid={parts[0][:20]} name={parts[2][:30]}")
        else:
            print(f"    [V2-auth] 解码失败 ({len(parts)} parts)")

    if "token" in params:
        parts = custom_decrypt_parts(params["token"], 3)
        if len(parts) >= 3:
            result["security_oauth_token"] = parts[0]
            result["refresh_token"] = parts[1]
            try:
                result["expire_time"] = int(parts[2])
            except ValueError:
                result["expire_time"] = parts[2]
            print(f"    [V2-token] pt={parts[0][:20]}... rt={parts[1][:20]}...")
        else:
            print(f"    [V2-token] 解码失败 ({len(parts)} parts)")

    # V1 兼容
    if not result.get("uid"):
        for k in ("aid", "uid", "name"):
            if k in params and k not in result:
                result[k] = params[k]
        if result.get("uid"):
            print(f"    [V1] uid={result['uid']}")

    return result


# ============================================================
# HTML 中 window.user_info 提取
# ============================================================
def extract_user_info_from_html(html: str) -> dict:
    for pattern in [
        r"window\.user_info\s*=\s*'(.+?)'\s*;",
        r'window\.user_info\s*=\s*"(.+?)"\s*;',
        r'window\.user_info\s*=\s*({.+?})\s*;',
    ]:
        match = re.search(pattern, html, re.DOTALL)
        if match:
            text = match.group(1)
            text = text.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                try:
                    return json.loads(json.loads(text))
                except Exception:
                    pass
    return {}


# ============================================================
# HTTP 回调服务器
# ============================================================
class CallbackHandler(http.server.BaseHTTPRequestHandler):
    captured = None
    result_event = threading.Event()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        flat = {k: v[0] for k, v in params.items()}

        print(f"\n{'='*60}")
        print(f"[*] GET {self.path[:200]}")
        print(f"[*] 参数: {list(flat.keys())}")

        for k, v in flat.items():
            preview = v[:60] + "..." if len(v) > 60 else v
            print(f"    {k}: {preview}")

        path = parsed.path

        if path in ("/auth/callback", "/auth/callback/"):
            self._handle_callback(flat)
        elif path == "/auth/start":
            self._send_text("OK")
        else:
            self._send_capture_page()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        try:
            data = json.loads(body.decode("utf-8"))
            if isinstance(data, dict) and data:
                CallbackHandler.captured = {"source": "POST", "data": data}
                CallbackHandler.result_event.set()
        except Exception:
            pass
        self._send_json({"status": "ok"})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def _handle_callback(self, flat: dict):
        auth_data = parse_callback_v2(flat)

        # 验证 nonce
        state = flat.get("state", "")
        nonce = state.split("-", 1)[-1] if "-" in state else state
        nonce_valid = nonce in _nonce_map

        print(f"    Nonce valid: {nonce_valid}")
        fmt = "V2" if "auth" in flat else "V1" if "aid" in flat else "empty"
        print(f"    Format: {fmt}")

        # 保存认证数据
        if auth_data:
            CallbackHandler.captured = {"auth_data": auth_data, "format": fmt}
            self._send_success_page(auth_data)
            CallbackHandler.result_event.set()
        else:
            # 没有认证参数 → 返回捕获页面
            self._send_capture_page()

    def _send_success_page(self, auth_data: dict):
        user_name = auth_data.get("name", "Unknown")
        user_id = auth_data.get("uid", auth_data.get("aid", ""))
        has_token = bool(auth_data.get("security_oauth_token"))

        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/><title>Lingma OAuth</title></head>
<body style="font-family:system-ui;text-align:center;padding:60px">
<h1 style="color:{'#4CAF50' if has_token else '#FF9800'}">{'登录成功' if has_token else '部分成功'}</h1>
<p>用户: {user_name} ({user_id})</p>
<p>{'Token 已获取，可关闭窗口' if has_token else '获取基本信息，缺少 token'}</p>
<script>
window.user_info = '{json.dumps(auth_data, ensure_ascii=False)}';
if (window.opener) window.close();
</script>
</body></html>"""
        self._send_html(html)

    def _send_capture_page(self):
        html = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"/><title>OAuth Capture</title></head>
<body style="font-family:system-ui;text-align:center;padding:40px">
<h2>等待认证...</h2>
<div id="status"></div>
<script>
(function() {
    var collected = {};
    var urlParams = new URLSearchParams(window.location.search);
    urlParams.forEach(function(v, k) { collected[k] = v; });
    if (window.user_info) collected.user_info = window.user_info;
    if (Object.keys(collected).length > 0) {
        fetch('/capture', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(collected)
        }).then(function() {
            document.getElementById('status').innerHTML = '<p>已发送，可关闭。</p>';
        });
    }
})();
</script>
</body></html>"""
        self._send_html(html)

    def _send_html(self, html: str):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _send_text(self, text: str):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(text.encode())

    def _send_json(self, data: dict):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        pass


_nonce_map = {}


# ============================================================
# LSP WebSocket (备用)
# ============================================================
def get_login_url_via_lsp() -> dict:
    try:
        import websocket as ws_lib
    except ImportError:
        print("[!] 缺少 websocket-client 库: pip install websocket-client")
        return {}

    ws = ws_lib.create_connection(f"ws://127.0.0.1:{LSP_PORT}", timeout=10)
    result = {}
    try:
        frame = json.dumps({
            "jsonrpc": "2.0", "method": "initialize", "id": 1,
            "params": {
                "processId": None,
                "clientInfo": {"name": "lingma-oauth-v5", "version": "5.0"},
                "rootUri": "file:///C:/sim", "capabilities": {},
                "workspaceFolders": [{"uri": "file:///C:/sim", "name": "sim"}],
            }
        }, separators=(",", ":"))
        ws.send(f"Content-Length: {len(frame.encode())}\r\n\r\n{frame}")
        ws.settimeout(3)
        try:
            ws.recv()
        except Exception:
            pass

        frame2 = json.dumps({"jsonrpc": "2.0", "method": "auth/login", "id": 3, "params": {}},
                            separators=(",", ":"))
        ws.send(f"Content-Length: {len(frame2.encode())}\r\n\r\n{frame2}")
        ws.settimeout(30)

        deadline = time.time() + 25
        while time.time() < deadline:
            try:
                raw = ws.recv()
            except ws_lib.WebSocketTimeoutException:
                continue
            except Exception:
                break
            raw_bytes = raw.encode() if isinstance(raw, str) else raw
            # 简单解析 LSP
            for m in re.finditer(r'"result"\s*:\s*{(.*?)}', raw_bytes.decode('utf-8', errors='replace')):
                urls = re.findall(r'https?://[^\s"\'\\]+', m.group(0))
                if urls:
                    result["login_url"] = urls[0]
                    break
    except Exception as e:
        print(f"  [!] LSP Error: {e}")
    finally:
        try:
            ws.close()
        except Exception:
            pass
    return result


# ============================================================
# 命令实现
# ============================================================
def cmd_login(args):
    port = args.port
    region = args.region
    timeout = args.timeout
    machine_id = get_machine_id()

    print("=" * 60)
    print("Lingma OAuth v5.0 — 自主登录")
    print(f"模式: {'LSP' if args.lsp else '独立'} | 区域: {region} | 端口: {port}")
    print("=" * 60)

    # Phase 1: 获取登录 URL
    if args.lsp:
        info = get_login_url_via_lsp()
        if not info.get("login_url"):
            print("[!] LSP 获取失败，请确认 Lingma 运行中")
            return
        login_url = info["login_url"]
        state = ""
        qp = urllib.parse.parse_qs(urllib.parse.urlparse(login_url).query)
        state = qp.get("state", [""])[0]
        nonce = state.split("-", 1)[-1] if "-" in state else state
        _nonce_map[nonce] = {"ts": time.time()}
    else:
        nonce = uuid.uuid4().hex
        verifier, challenge = generate_pkce()
        _nonce_map[nonce] = {"ts": time.time(), "verifier": verifier}

        inner_url = build_oauth_url(nonce, port, challenge, machine_id, region)
        login_url = build_full_login_url(inner_url, reuse_cookie=True)

    print(f"\n[*] 登录 URL ({len(login_url)} chars):")
    print(f"    {login_url[:150]}...")

    # Phase 2: 启动回调服务器
    print(f"\n[*] 启动回调服务器: http://127.0.0.1:{port}")
    server = http.server.HTTPServer(("127.0.0.1", port), CallbackHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # Phase 3: 打开浏览器
    print(f"[*] 打开浏览器...")
    webbrowser.open(login_url)
    print(f"[*] 等待认证回调 (超时 {timeout}s)...\n")

    if not CallbackHandler.result_event.wait(timeout=timeout):
        print("[!] 超时，未收到回调")
        server.shutdown()
        return

    server.shutdown()
    captured = CallbackHandler.captured
    if not captured:
        print("[!] 未获取到数据")
        return

    auth_data = captured.get("auth_data", {})
    if not auth_data:
        print("[!] 回调数据为空")
        return

    print(f"\n{'='*60}")
    print("[*] 认证数据:")
    for k, v in auth_data.items():
        preview = v[:50] + "..." if isinstance(v, str) and len(v) > 50 else v
        print(f"    {k}: {preview}")

    # Phase 4: 保存凭据
    creds = {
        "machine_id": machine_id,
        "uid": auth_data.get("uid", auth_data.get("aid", "")),
        "aid": auth_data.get("aid", ""),
        "name": auth_data.get("name", ""),
        "security_oauth_token": auth_data.get("security_oauth_token",
                                                auth_data.get("token", "")),
        "refresh_token": auth_data.get("refresh_token", ""),
        "expire_time": auth_data.get("expire_time", 0),
        "login_time": time.time(),
    }

    if creds["security_oauth_token"] and creds["refresh_token"]:
        print(f"\n[OK] 完整凭据获取成功! (*^▽^*)")
    elif creds["uid"]:
        print(f"\n[!] 仅获取基本信息（缺少 token），尝试使用 V2 格式")
    else:
        print(f"\n[!] 凭据不完整")
        return

    # 尝试从本地 Lingma 缓存提取 COSY 凭据（Chat API 所需）
    _merge_cosy_credentials(creds)

    save_credentials(creds)


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


# Embedded RSA public key (IDA @ 0x1425bd8e8, 1024-bit PKIX)
_RSA_PUBKEY_PEM = """\
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPoH+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----"""


def generate_cosy_credentials(creds: dict) -> tuple:
    """
    本地生成 cosy_key + encrypt_user_info (IDA @ SaveUserInfo 0x14088e260).

    流程: userInfo JSON → AES-128-CBC(randomKey) → encrypt_user_info
          randomKey → RSA-PKCS1v15(embeddedPubKey) → Base64 → cosy_key
    """
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # CosyUserInfo inner fields (Go struct JSON tags, verified from cache)
    inner_info = {
        "name": creds.get("name", ""),
        "aid": creds.get("aid", creds.get("uid", "")),
        "uid": creds.get("uid", ""),
        "yx_uid": "",
        "organization_id": "",
        "organization_name": "",
        "staffId": "",
        "avatar_url": "",
        "key": "",
        "encrypt_user_info": "",
        "user_source_channel": "",
        "security_oauth_token": creds.get("security_oauth_token", ""),
        "refresh_token": creds.get("refresh_token", ""),
        "expire_time": 0,
        "user_type": "",
        "data_policy_agreed": False,
        "email": "",
        "is_data_policy_modifiable": False,
        "is_quota_exceeded": False,
        "organization_tags": None,
    }
    user_json = json.dumps(inner_info, separators=(",", ":"), ensure_ascii=False)

    # Random 16-byte AES key (uuid.uuid4().hex[:16])
    temp_key = uuid.uuid4().hex[:16].encode("utf-8")

    # RSA encrypt temp key → Base64 → cosy_key
    pub_key = load_pem_public_key(_RSA_PUBKEY_PEM.encode())
    encrypted_key = pub_key.encrypt(temp_key, asym_padding.PKCS1v15())
    cosy_key = base64.b64encode(encrypted_key).decode()

    # AES-128-CBC encrypt user info (key=IV=temp_key, PKCS7 padding)
    cipher = Cipher(algorithms.AES(temp_key), modes.CBC(temp_key))
    encryptor = cipher.encryptor()
    padded = _pkcs7_pad(user_json.encode("utf-8"))
    encrypted_info = encryptor.update(padded) + encryptor.finalize()
    encrypt_user_info = base64.b64encode(encrypted_info).decode()

    return cosy_key, encrypt_user_info


def _merge_cosy_credentials(creds: dict):
    """优先本地生成 COSY 凭据，回退到本地缓存提取"""
    # 尝试本地生成
    if creds.get("security_oauth_token") and creds.get("refresh_token"):
        try:
            cosy_key, encrypt_user_info = generate_cosy_credentials(creds)
            creds["cosy_key"] = cosy_key
            creds["encrypt_user_info"] = encrypt_user_info
            creds["user_id"] = creds.get("uid", "")
            print("[*] 已本地生成 COSY 凭据（RSA+AES，无需服务器）")
            return
        except Exception as e:
            print(f"[!] 本地生成 COSY 凭据失败: {e}，尝试从缓存提取...")

    # 回退: 从本地 ~/.lingma/cache/user 提取
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        cache_dir = Path.home() / ".lingma" / "cache"
        user_path = cache_dir / "user"
        id_path = cache_dir / "id"

        if not user_path.exists() or not id_path.exists():
            return

        mid = id_path.read_text().strip()
        enc_data = base64.b64decode(user_path.read_text().strip())
        key = mid[:16].encode()
        cipher = Cipher(algorithms.AES(key), modes.CBC(key))
        dec = cipher.decryptor()
        plain = dec.update(enc_data) + dec.finalize()
        plain = plain[:-plain[-1]]
        data = json.loads(plain.decode())

        if data.get("key") and data.get("encrypt_user_info"):
            creds["cosy_key"] = data["key"]
            creds["encrypt_user_info"] = data["encrypt_user_info"]
            creds["user_id"] = data.get("uid", creds.get("uid", ""))
            print("[*] 已从本地缓存提取 COSY 凭据（用于 Chat API）")
    except Exception:
        pass


def cmd_status(args):
    creds = load_credentials()
    if not creds:
        print("[!] 未找到凭据，请先登录")
        return

    print("=== 凭据状态 ===")
    for k, v in creds.items():
        preview = v[:50] + "..." if isinstance(v, str) and len(v) > 50 else v
        print(f"  {k}: {preview}")

    expire = creds.get("expire_time", 0)
    if isinstance(expire, (int, float)) and expire > 0:
        try:
            dt = datetime.fromtimestamp(expire / 1000, tz=timezone.utc)
            remaining = dt - datetime.now(timezone.utc)
            if remaining.total_seconds() > 0:
                print(f"\n[*] Token 有效期剩余: {remaining}")
            else:
                print(f"\n[!] Token 已过期")
        except Exception:
            pass


def cmd_refresh(args):
    """Token refresh via lingma_token_refresh module (v3 SIGN + LSP fallback)."""
    try:
        from lingma_token_refresh import auto_refresh_and_update, load_credentials as load_v3_creds
    except ImportError:
        print("[!] lingma_token_refresh.py not found")
        return

    v3_creds = load_v3_creds()
    print(f"[*] 刷新 Token...")
    print(f"    UID: {v3_creds.get('user_id', '')}")
    print(f"    Token: {v3_creds.get('pt_token', '')[:30]}...")
    print(f"    Refresh: {v3_creds.get('rt_token', '')[:30]}...")

    result = auto_refresh_and_update(v3_creds)

    if result.get('success'):
        print(f"\n[OK] Token 刷新成功! (method: {result.get('method', 'unknown')})")
        if result.get('security_oauth_token'):
            print(f"    New PT: {result['security_oauth_token'][:30]}...")
        if result.get('expire_time'):
            print(f"    Expire: {result['expire_time']}")
    else:
        print(f"\n[!] 所有刷新路径均失败")
        print(f"    建议: python lingma_oauth_complete.py login")


def cmd_manual(args):
    print("[*] 粘贴 window.user_info 内容 (JSON 字符串)，或输入文件路径:")
    user_input = input().strip()

    p = Path(user_input)
    if p.exists():
        user_input = p.read_text(encoding="utf-8").strip()
        print(f"[*] 从文件读取: {p}")

    try:
        user_info = json.loads(user_input)
    except json.JSONDecodeError:
        try:
            user_info = json.loads(json.loads(user_input))
        except Exception:
            print("[!] 无法解析 JSON")
            return

    print(f"[*] 解析成功:")
    print(f"    aid: {user_info.get('aid', 'N/A')}")
    print(f"    uid: {user_info.get('uid', 'N/A')}")
    print(f"    name: {user_info.get('name', 'N/A')}")

    token = user_info.get("securityOauthToken", "")
    refresh = user_info.get("refreshToken", "")
    expire = user_info.get("expireTime", 0)
    auth_status = user_info.get("authStatus", {})
    org_id = auth_status.get("orgId", "") if isinstance(auth_status, dict) else ""

    if token:
        print(f"    token: {token[:30]}...")
    if refresh:
        print(f"    refresh: {refresh[:30]}...")
    print(f"    expire: {expire}")

    if not token or not refresh:
        print("\n[!] 缺少 token 或 refreshToken")
        return

    creds = {
        "machine_id": get_machine_id(),
        "uid": user_info.get("uid", user_info.get("aid", "")),
        "aid": user_info.get("aid", ""),
        "name": user_info.get("name", ""),
        "security_oauth_token": token,
        "refresh_token": refresh,
        "expire_time": expire,
        "org_id": org_id,
        "login_time": time.time(),
    }
    save_credentials(creds)
    print(f"\n[OK] 凭据保存成功!")


def cmd_decode(args):
    encoded = args.value
    print(f"[*] 解码: {encoded[:80]}...")
    try:
        decoded = decode_string(encoded)
        text = decoded.decode("utf-8", errors="replace")
        print(f"[OK] 解码结果: {text}")
    except Exception as e:
        print(f"[!] 解码失败: {e}")

    parts = custom_decrypt_parts(encoded, 3)
    if parts:
        print(f"\n[*] 分割为 {len(parts)} 部分:")
        for i, p in enumerate(parts):
            print(f"    Part {i}: {p}")


def cmd_url(args):
    port = args.port
    region = args.region
    machine_id = get_machine_id()
    nonce = uuid.uuid4().hex
    verifier, challenge = generate_pkce()

    inner_url = build_oauth_url(nonce, port, challenge, machine_id, region)
    full_url = build_full_login_url(inner_url, reuse_cookie=True)

    print(f"[*] 内层 URL:")
    print(f"    {inner_url}")
    print(f"\n[*] 完整登录 URL:")
    print(f"    {full_url}")
    print(f"\n[*] Nonce: {nonce}")
    print(f"[*] Machine ID: {machine_id}")
    print(f"[*] State: 2-{nonce}")


# ============================================================
# CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="Lingma OAuth v5.0 — 自主登录")
    sub = parser.add_subparsers(dest="command")

    # login
    p_login = sub.add_parser("login", help="OAuth 登录")
    p_login.add_argument("--lsp", action="store_true", help="通过 LSP 获取 URL")
    p_login.add_argument("--port", type=int, default=CALLBACK_PORT)
    p_login.add_argument("--region", default="intl", choices=["intl", "cn"])
    p_login.add_argument("--timeout", type=int, default=300)

    # status
    sub.add_parser("status", help="查看凭据")

    # refresh
    sub.add_parser("refresh", help="刷新 Token")

    # manual
    sub.add_parser("manual", help="手动导入 window.user_info")

    # decode
    p_decode = sub.add_parser("decode", help="测试 Encode=1 解码")
    p_decode.add_argument("value", help="要解码的值")

    # url
    p_url = sub.add_parser("url", help="仅生成登录 URL")
    p_url.add_argument("--port", type=int, default=CALLBACK_PORT)
    p_url.add_argument("--region", default="intl", choices=["intl", "cn"])

    args = parser.parse_args()

    if args.command == "login":
        cmd_login(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "refresh":
        cmd_refresh(args)
    elif args.command == "manual":
        cmd_manual(args)
    elif args.command == "decode":
        cmd_decode(args)
    elif args.command == "url":
        cmd_url(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
