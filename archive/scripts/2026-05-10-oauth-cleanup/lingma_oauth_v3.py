#!/usr/bin/env python3
"""
Lingma OAuth 自主实现 v3 — 基于 IDA Pro 逆向分析

完全模拟 Lingma.exe 的 OAuth 流程，脱离 Lingma 程序独立运行。

IDA 分析确认的流程：
  1. 本地 HTTP 服务监听 37510 端口
  2. 生成 PKCE + nonce + machine_id 构造登录 URL
  3. 浏览器认证后 → lingma.alibabacloud.com 处理 auth code
  4. lingma.alibabacloud.com 重定向到 localhost:37510/auth/callback?nonce=...&auth=<Encode1>&token=<Encode1>
  5. 本地 LoginCallback 解码 auth (aid/uid/name) + token (securityOauthToken/refreshToken/expireTime)
  6. Token 刷新通过 /algo/api/v3/user/refresh_token

用法：
    python lingma_oauth_v3.py login          # OAuth 登录
    python lingma_oauth_v3.py refresh        # 刷新 Token
    python lingma_oauth_v3.py status         # 查看凭据
    python lingma_oauth_v3.py chat "你好"    # 测试 Chat API
"""
import argparse
import base64
import hashlib
import http.server
import json
import math
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


# ===== 常量 =====
CALLBACK_PORT = 37510
CONFIG_DIR = Path.home() / '.lingma'
CONFIG_PATH = CONFIG_DIR / 'auth_v3.json'

# Encode=1 字母表 (IDA @ 0x1424ABF3C)
_ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
_STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

# Cosy-Key (IDA @ addBigModelSignatureHeaders)
COSY_KEY = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="

# API
BIGMODEL_API = "https://lingma.alibabacloud.com/algo"


# ===== Encode=1 编解码 =====

def _custom_b64_decode(encoded: str) -> bytes:
    """自定义 base64 解码: 字母表替换后标准 base64 解码"""
    converted = ''.join(_STD_B64[_ALPHA.index(c)] for c in encoded if c in _ALPHA)
    pad = (4 - len(converted) % 4) % 4
    return base64.b64decode(converted + '=' * pad)


def lingma_encode(data: str) -> str:
    """Encode=1 编码 (CustomEncryptParts 的逆运算)

    正确流程: 先转自定义字母表, 再分块重排
    decode: body → split(lb,BS,BS) → b2+b1+b0 → custom→std → b64decode
    encode: b64 → std→custom → split(BS,BS,lb) → b0+b1+b2 → body
    """
    raw = data.encode('utf-8')
    b64 = base64.b64encode(raw).rstrip(b'=').decode()

    # 先转自定义字母表
    custom = ''.join(_ALPHA[_STD_B64.index(c)] if c in _STD_B64 else c for c in b64)

    # 分块重排: decode 时 b2+b1+b0 = custom_b64
    # 所以 body = b0+b1+b2 = custom[2*BS:] + custom[BS:2*BS] + custom[:BS]
    E = len(custom)
    BS = math.ceil(E / 3)

    result = custom[2 * BS:] + custom[BS:2 * BS] + custom[:BS]

    # 填充 $ 到 4 的倍数
    pad_len = (4 - len(result) % 4) % 4
    if pad_len:
        result += '$' * pad_len

    return result


def lingma_decode(body: str) -> str:
    """Encode=1 解码 (CustomDecryptParts)

    IDA @ code.alibaba_inc_com_cosy_encrypt.CustomDecryptParts:
    1. 去 $ 填充
    2. 分 3 块 (BS = ceil(E/3), lb = E - 2*BS)
    3. 反转块顺序
    4. 自定义 base64 解码
    """
    dollar_start = body.find('$')
    if dollar_start >= 0:
        pad = 0
        pos = dollar_start
        while pos < len(body) and body[pos] == '$':
            pad += 1
            pos += 1
        body = body[:dollar_start] + body[dollar_start + pad:]

    E = len(body)
    BS = math.ceil(E / 3)
    lb = E - 2 * BS

    b0 = body[:lb]
    b1 = body[lb:lb + BS]
    b2 = body[lb + BS:]

    raw = _custom_b64_decode(b2 + b1 + b0)
    return raw.decode('utf-8', errors='replace')


def custom_decrypt_parts(encoded: str, num_parts: int = 3) -> list[str]:
    """CustomDecryptParts: 解码后按换行分割为 N 部分

    IDA 分析: parseAuthInfoV2 和 parseAuthToken 都调用 CustomDecryptParts(value, 3)
    返回 []string{part1, part2, part3}
    """
    try:
        decoded = lingma_decode(encoded)
    except Exception:
        # 备用: URL unescape 后再试
        try:
            unescaped = urllib.parse.unquote(encoded)
            decoded = lingma_decode(unescaped)
        except Exception:
            return []

    parts = decoded.split('\n')
    return parts[:num_parts]


# ===== PKCE 工具 =====

def generate_pkce() -> tuple[str, str]:
    """生成 PKCE 参数: (code_verifier, code_challenge)"""
    verifier = secrets.token_urlsafe(32)[:43]
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return verifier, challenge


# ===== OAuth URL 生成 =====

def generate_login_url(port: int = CALLBACK_PORT) -> dict:
    """
    生成 Lingma 登录 URL

    IDA @ cosy_auth._ptr_HttpServer.PrepareLoginRequest:
    - nonce = UUID 去掉 "-" (32 字符)
    - state = "<prefix>-<nonce>" (prefix 随版本不同)
    - PKCE challenge = SHA256(verifier) base64url
    - machine_id = UUID 格式
    - 三层嵌套 URL: logout.htm → login.htm → lingma/login
    """
    nonce = uuid.uuid4().hex
    verifier, challenge = generate_pkce()
    machine_id = str(uuid.uuid4())  # 小写 UUID, 匹配实际格式
    # state 前缀: 1- = 强制完整登录, 2- = 复用 cookie
    state = f"2-{nonce}"

    inner_params = {
        'state': state,
        'challenge': challenge,
        'challenge_method': 'S256',
        'machine_id': machine_id,
        'nonce': nonce,
        'port': str(port),
    }
    inner_query = urllib.parse.urlencode(inner_params)
    inner_url = f"https://lingma.alibabacloud.com/lingma/login?{inner_query}"

    middle_url = f"https://account.alibabacloud.com/login/login.htm?oauth_callback={urllib.parse.quote(inner_url, safe='')}"

    return {
        'login_url': middle_url,
        'inner_url': inner_url,
        'nonce': nonce,
        'verifier': verifier,
        'challenge': challenge,
        'machine_id': machine_id,
        'state': state,
    }


# ===== 认证签名 =====

def get_rfc1123_date() -> str:
    """RFC1123 格式日期"""
    return datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')


def md5_sign(body_str: str, date_str: str) -> str:
    """MD5(base64(body) + "\\n" + cosy_key + "\\n" + date + "\\n" + body + "\\n" + normalized_path)

    IDA @ addBigModelSignatureHeaders (0x14087e5e0):
    实际签名公式: md5(payload_b64 + "\\n" + key + "\\n" + date + "\\n" + body + "\\n" + path)
    简化版: md5(b64(body) + "&" + key + "&" + date)
    """
    encoded = base64.b64encode(body_str.encode()).decode()
    raw = f"{encoded}&{COSY_KEY}&{date_str}"
    return hashlib.md5(raw.encode()).hexdigest()


def build_auth_headers(body_str: str, machine_id: str, security_token: str = "",
                       date_str: str = None) -> dict:
    """构造认证请求头"""
    if date_str is None:
        date_str = get_rfc1123_date()

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
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
        "Cosy-User": base64.b64encode(body_str.encode()).decode(),
        "Signature": md5_sign(body_str, date_str),
    }

    if security_token:
        headers["Cosy-SecurityOauthToken"] = security_token

    return headers


# ===== HTTP 回调服务器 =====

class AuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    """
    模拟 Lingma 本地 HTTP 服务器的 /auth/callback 端点

    IDA @ cosy_auth._ptr_HttpServer.LoginCallback:
    - 解析 URL 参数
    - 验证 nonce
    - 调用 parseAuthInfo 解码 auth + token
    - 调用 loginWithUserInfo 完成登录
    """
    captured_result = None
    result_event = threading.Event()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        flat = {k: v[0] for k, v in params.items()}

        path = parsed.path

        if path == '/auth/callback':
            self._handle_auth_callback(flat)
        elif path == '/auth/start':
            self._handle_auth_start(flat)
        else:
            self._handle_default(flat)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''

        try:
            data = json.loads(body.decode('utf-8'))
            if isinstance(data, dict) and data:
                AuthCallbackHandler.captured_result = {
                    'source': 'POST',
                    'data': data,
                }
                AuthCallbackHandler.result_event.set()
        except Exception:
            pass

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

    def _handle_auth_callback(self, params: dict):
        """处理 /auth/callback — 模拟 LoginCallback"""
        print(f'\n{"="*60}')
        print(f'[*] 收到 /auth/callback 请求喵~ φ(≧ω≦*)♪')
        print(f'[*] 参数: {list(params.keys())}')

        nonce = params.get('nonce', '')
        auth_encoded = params.get('auth', '')
        token_encoded = params.get('token', '')

        auth_data = {}

        # V2: 解码 auth + token (Encode=1)
        if auth_encoded:
            print(f'[*] 解码 auth 参数 (len={len(auth_encoded)})...')
            parts = custom_decrypt_parts(auth_encoded, 3)
            if len(parts) >= 3:
                auth_data['aid'] = parts[0]
                auth_data['uid'] = parts[1]
                auth_data['name'] = parts[2]
                print(f'    aid:  {parts[0]}')
                print(f'    uid:  {parts[1]}')
                print(f'    name: {parts[2]}')
            else:
                print(f'    [!] auth 解码失败, 得到 {len(parts)} 部分')

        if token_encoded:
            print(f'[*] 解码 token 参数 (len={len(token_encoded)})...')
            parts = custom_decrypt_parts(token_encoded, 3)
            if len(parts) >= 3:
                auth_data['security_oauth_token'] = parts[0]
                auth_data['refresh_token'] = parts[1]
                try:
                    auth_data['expire_time'] = int(parts[2])
                except ValueError:
                    auth_data['expire_time'] = parts[2]
                print(f'    securityOauthToken: {parts[0][:30]}...')
                print(f'    refreshToken:      {parts[1][:30]}...')
                print(f'    expireTime:        {parts[2]}')
            else:
                print(f'    [!] token 解码失败, 得到 {len(parts)} 部分')

        # V1 备用: 直接从 URL 参数读取
        for k in ('aid', 'uid', 'name'):
            if k not in auth_data and k in params:
                auth_data[k] = params[k]

        if not auth_data:
            # 可能是只带 nonce 的回调, 没有编码数据
            # 检查是否有其他有用的参数
            for k, v in params.items():
                if k != 'nonce' and v:
                    print(f'    未识别参数: {k}={v[:50]}')

        # 保存 nonce/machine_id
        if nonce:
            auth_data['nonce'] = nonce

        # 生成成功页面 (模拟 loginResultPageWithStep)
        self._send_success_page(auth_data)

        if auth_data.get('security_oauth_token') or auth_data.get('aid'):
            AuthCallbackHandler.captured_result = auth_data
            AuthCallbackHandler.result_event.set()

    def _handle_auth_start(self, params: dict):
        """处理 /auth/start"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')

    def _handle_default(self, params: dict):
        """默认处理 — 返回捕获页面"""
        html = '''<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Lingma OAuth</title></head>
<body style="font-family:system-ui;text-align:center;padding:40px">
<h2>OAuth 回调服务器运行中</h2>
<p>等待认证回调...</p>
<script>
(function() {
    // 收集所有可能的认证信息
    var collected = {};
    var urlParams = new URLSearchParams(window.location.search);
    urlParams.forEach(function(v, k) { collected[k] = v; });
    if (window.user_info) collected.user_info = window.user_info;

    if (Object.keys(collected).length > 0) {
        fetch('/capture', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(collected)
        });
    }
})();
</script>
</body>
</html>'''
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def _send_success_page(self, auth_data: dict):
        """生成登录成功页面"""
        user_name = auth_data.get('name', 'Unknown')
        user_id = auth_data.get('uid', auth_data.get('aid', ''))

        html = f'''<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8"/>
  <title>通义灵码 · Lingma</title>
</head>
<body>
<script>
    window.product_type = 'lingma';
    window.build_form = 'plugin';
    window.login_step = 'final';
    window.error_code = 0;
    window.user_name = '{user_name}';
    window.user_id = '{user_id}';
    window.user_info = '{json.dumps(auth_data, ensure_ascii=False)}';
    window.policy_agreed = true;
    window.official_commands_end = true;
</script>
<div style="font-family:system-ui;text-align:center;padding:60px">
    <h1 style="color:#4CAF50">登录成功</h1>
    <p>用户: {user_name}</p>
    <p>Token 已捕获, 可以关闭此窗口。</p>
</div>
</body>
</html>'''
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def log_message(self, format, *args):
        pass


# ===== 凭据管理 =====

def load_credentials() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    return {}


def save_credentials(creds: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(creds, f, indent=2, ensure_ascii=False)
    print(f'[*] 凭据已保存到: {CONFIG_PATH}')


# ===== 命令实现 =====

def cmd_login(args):
    """OAuth 登录"""
    port = args.port
    timeout = args.timeout

    # 1. 生成登录 URL
    info = generate_login_url(port=port)
    login_url = info['login_url']

    print(f'[*] Lingma OAuth v3 登录启动喵~ φ(≧ω≦*)♪')
    print(f'[*] 回调端口: {port}')
    print(f'[*] 登录 URL: {login_url[:120]}...')
    print(f'[*] Nonce:    {info["nonce"]}')
    print(f'[*] Machine:  {info["machine_id"]}')
    print()

    # 2. 启动 HTTP 服务器
    server = http.server.HTTPServer(('127.0.0.1', port), AuthCallbackHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print(f'[*] HTTP 回调服务器已启动: http://127.0.0.1:{port}')

    # 3. 打开浏览器
    print(f'[*] 打开浏览器进行登录...')
    webbrowser.open(login_url)
    print(f'[*] 等待认证回调 (超时 {timeout}s)...')
    print()

    # 4. 等待回调
    if not AuthCallbackHandler.result_event.wait(timeout=timeout):
        print('[!] 超时, 未收到认证回调')
        server.shutdown()
        return

    # 5. 处理结果
    result = AuthCallbackHandler.captured_result
    server.shutdown()

    if not result:
        print('[!] 未获取到认证数据')
        return

    print(f'\n{"="*60}')
    print('[*] 认证数据获取成功喵~ o(*￣︶￣*)o')

    creds = {
        'user_id': result.get('uid', result.get('user_id', '')),
        'user_name': result.get('name', ''),
        'aid': result.get('aid', ''),
        'security_oauth_token': result.get('security_oauth_token', result.get('securityOauthToken', '')),
        'refresh_token': result.get('refresh_token', result.get('refreshToken', '')),
        'expire_time': result.get('expire_time', result.get('expireTime', 0)),
        'machine_id': info['machine_id'],
        'org_id': result.get('org_id', result.get('orgId', '')),
        'login_time': time.time(),
    }

    # 打印关键信息
    for k, v in creds.items():
        if isinstance(v, str) and len(v) > 50:
            print(f'  {k}: {v[:50]}...')
        else:
            print(f'  {k}: {v}')

    # 检查有效性
    if creds['security_oauth_token'] and creds['refresh_token']:
        print('\n[✓] 完整凭据获取成功!')
        save_credentials(creds)
    elif creds['aid']:
        print('\n[!] 获取到基础认证信息, 但缺少 token')
        print('[!] 可能是 V1 回调格式, 尝试使用...')
        save_credentials(creds)
    else:
        print('\n[!] 凭据不完整')


def cmd_refresh(args):
    """刷新 Token"""
    creds = load_credentials()
    if not creds:
        print('[!] 未找到凭据, 请先运行 login')
        return

    user_id = creds.get('user_id', '')
    security_token = creds.get('security_oauth_token', '')
    refresh_token = creds.get('refresh_token', '')
    machine_id = creds.get('machine_id', '')
    org_id = creds.get('org_id', '')

    if not all([user_id, security_token, refresh_token]):
        print('[!] 凭据不完整, 缺少必要字段')
        return

    print(f'[*] 刷新 Token...')
    print(f'    UserID:    {user_id}')
    print(f'    Token:     {security_token[:30]}...')
    print(f'    Refresh:   {refresh_token[:30]}...')
    print(f'    MachineID: {machine_id}')

    body = {
        "userId": user_id,
        "orgId": org_id or "",
        "securityOauthToken": security_token,
        "refreshToken": refresh_token,
    }
    body_str = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    url = f"{BIGMODEL_API}/api/v3/user/refresh_token"
    date_str = get_rfc1123_date()
    headers = build_auth_headers(body_str, machine_id, security_token, date_str)

    print(f'\n[*] POST {url}')
    print(f'[*] Signature: {headers["Signature"]}')

    req = urllib.request.Request(url, data=body_str.encode(), headers=headers, method="POST")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        resp_body = resp.read().decode()
        print(f'\n[✓] HTTP {resp.status}')
        print(f'    Response: {resp_body[:300]}')

        result = json.loads(resp_body) if resp_body else {}

        if result.get('refreshToken') and result.get('securityOauthToken'):
            creds['security_oauth_token'] = result['securityOauthToken']
            creds['refresh_token'] = result['refreshToken']
            if result.get('expireTime'):
                creds['expire_time'] = result['expireTime']
            save_credentials(creds)
            print(f'\n[✓] Token 刷新成功喵~ (´｡• ᵕ •｡`) ♡')
            print(f'    新 Token: {result["securityOauthToken"][:30]}...')
            print(f'    新 Refresh: {result["refreshToken"][:30]}...')
        else:
            print(f'\n[!] Token 刷新失败')
            print(f'    响应: {json.dumps(result, ensure_ascii=False)[:300]}')

    except urllib.error.HTTPError as e:
        err = e.read().decode(errors='replace')[:500]
        print(f'\n[✗] HTTP {e.code}: {err}')
    except Exception as e:
        print(f'\n[✗] 错误: {e}')


def cmd_status(args):
    """查看凭据状态"""
    creds = load_credentials()
    if not creds:
        print('[!] 未找到凭据')
        return

    print('=== 凭据状态 ===')
    for k, v in creds.items():
        if isinstance(v, str) and len(v) > 50:
            print(f'  {k}: {v[:50]}...')
        else:
            print(f'  {k}: {v}')

    expire_time = creds.get('expire_time', 0)
    if isinstance(expire_time, (int, float)) and expire_time > 0:
        try:
            expire_dt = datetime.fromtimestamp(expire_time / 1000, tz=timezone.utc)
            now = datetime.now(timezone.utc)
            remaining = expire_dt - now
            if remaining.total_seconds() > 0:
                print(f'\n[*] Token 有效期剩余: {remaining}')
            else:
                print(f'\n[!] Token 已过期')
        except Exception:
            pass


def cmd_decode(args):
    """测试 Encode=1 解码"""
    encoded = args.value
    print(f'[*] 解码: {encoded[:80]}...')
    try:
        decoded = lingma_decode(encoded)
        print(f'[✓] 解码结果: {decoded}')
    except Exception as e:
        print(f'[✗] 解码失败: {e}')

    # 尝试分割为 3 部分
    parts = custom_decrypt_parts(encoded, 3)
    if parts:
        print(f'\n[*] 分割为 3 部分:')
        for i, p in enumerate(parts):
            print(f'  Part {i}: {p}')


def cmd_manual(args):
    """手动导入认证数据

    从浏览器 lingma.alibabacloud.com 页面的 window.user_info 提取认证信息。
    用法:
      1. 正常登录 Lingma → 浏览器打开认证页面
      2. 在认证成功页面按 F12 → Console → 输入 JSON.stringify(JSON.parse(window.user_info))
      3. 复制输出内容，粘贴到本命令
    """
    print('[*] 等待粘贴 window.user_info 内容...')
    print('[*] (直接粘贴后按 Enter，或输入文件路径)')
    print()

    user_input = input().strip()

    # 尝试作为文件路径读取
    input_path = Path(user_input)
    if input_path.exists():
        with open(input_path, 'r', encoding='utf-8') as f:
            user_input = f.read().strip()
        print(f'[*] 从文件读取: {input_path}')

    # 尝试解析 JSON
    try:
        user_info = json.loads(user_input)
    except json.JSONDecodeError:
        # 可能是 window.user_info 的原始值 (带引号的 JSON 字符串)
        try:
            user_info = json.loads(json.loads(user_input))
        except Exception:
            print('[!] 无法解析 JSON 数据')
            print('[*] 提示: 在浏览器 Console 中运行 JSON.stringify(JSON.parse(window.user_info)) 获取')
            return

    print(f'\n[*] 解析成功喵~ φ(≧ω≦*)♪')
    print(f'    aid:  {user_info.get("aid", "N/A")}')
    print(f'    uid:  {user_info.get("uid", "N/A")}')
    print(f'    name: {user_info.get("name", "N/A")}')

    token = user_info.get('securityOauthToken', '')
    refresh = user_info.get('refreshToken', '')
    expire = user_info.get('expireTime', 0)

    print(f'    token:  {token[:30]}...' if token else '    token:  N/A')
    print(f'    refresh: {refresh[:30]}...' if refresh else '    refresh: N/A')
    print(f'    expire: {expire}')

    auth_status = user_info.get('authStatus', {})
    org_id = auth_status.get('orgId', '') if isinstance(auth_status, dict) else ''

    if not token or not refresh:
        print('\n[!] 缺少 token 或 refreshToken，请确认页面已完全加载')
        return

    creds = {
        'user_id': user_info.get('uid', user_info.get('aid', '')),
        'user_name': user_info.get('name', ''),
        'aid': user_info.get('aid', ''),
        'security_oauth_token': token,
        'refresh_token': refresh,
        'expire_time': expire,
        'machine_id': str(uuid.uuid4()),
        'org_id': org_id,
        'login_time': time.time(),
    }

    save_credentials(creds)
    print(f'\n[✓] 凭据保存成功喵~ o(*￣︶￣*)o')


def cmd_url(args):
    """仅生成登录 URL (不启动服务器)"""
    port = args.port
    info = generate_login_url(port=port)
    print(f'[*] 登录 URL:')
    print(f'    {info["login_url"]}')
    print()
    print(f'[*] 内部 URL (实际处理认证):')
    print(f'    {info["inner_url"]}')
    print()
    print(f'[*] Nonce:    {info["nonce"]}')
    print(f'[*] Machine:  {info["machine_id"]}')
    print(f'[*] State:    {info["state"]}')
    print(f'[*] Port:     {port}')


def main():
    parser = argparse.ArgumentParser(description='Lingma OAuth v3 — 自主实现')
    subparsers = parser.add_subparsers(dest='command')

    # login
    p_login = subparsers.add_parser('login', help='OAuth 登录')
    p_login.add_argument('--port', type=int, default=CALLBACK_PORT)
    p_login.add_argument('--timeout', type=int, default=300)

    # refresh
    subparsers.add_parser('refresh', help='刷新 Token')

    # status
    subparsers.add_parser('status', help='查看凭据')

    # decode
    p_decode = subparsers.add_parser('decode', help='测试 Encode=1 解码')
    p_decode.add_argument('value', help='要解码的值')

    # manual
    subparsers.add_parser('manual', help='手动导入 window.user_info')

    # url
    p_url = subparsers.add_parser('url', help='仅生成登录 URL')
    p_url.add_argument('--port', type=int, default=CALLBACK_PORT)

    args = parser.parse_args()

    if args.command == 'login':
        cmd_login(args)
    elif args.command == 'refresh':
        cmd_refresh(args)
    elif args.command == 'status':
        cmd_status(args)
    elif args.command == 'decode':
        cmd_decode(args)
    elif args.command == 'manual':
        cmd_manual(args)
    elif args.command == 'url':
        cmd_url(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
