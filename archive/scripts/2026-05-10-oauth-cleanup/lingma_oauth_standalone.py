#!/usr/bin/env python3
"""
Lingma OAuth 独立登录脚本 v1.0 — 完全脱离 Lingma 程序

功能：
  1. 生成 PKCE OAuth URL（独立模式，无需 Lingma 运行）
  2. 启动 HTTP 服务器监听 37510
  3. 打开浏览器完成登录
  4. 捕获回调并提取认证信息（支持 URL 参数 / POST 请求体 / HTML script 标签）
  5. 保存凭据到配置文件

用法：
    python lingma_oauth_standalone.py              # 默认模式
    python lingma_oauth_standalone.py --region cn  # 国内版
    python lingma_oauth_standalone.py --port 35710 # 自定义端口
"""
import argparse
import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
import uuid
import webbrowser
from pathlib import Path


# ===== 配置 =====
CALLBACK_PORT = 37510


# ===== PKCE 工具 =====

def generate_pkce() -> tuple:
    """生成 PKCE 参数: (code_verifier, code_challenge)"""
    verifier = secrets.token_urlsafe(32)[:43]
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return verifier, challenge


# ===== 生成 OAuth URL =====

def generate_login_url(port: int = CALLBACK_PORT, region: str = 'intl') -> dict:
    """
    独立生成 Lingma 登录 URL

    基于 IDA Pro 逆向分析的 PrepareLoginRequest 函数逻辑：
    1. 生成 nonce（UUID 去掉 "-"）
    2. 生成 PKCE challenge（verifier + SHA256 challenge）
    3. 构造最内层 URL：https://lingma.alibabacloud.com/lingma/login?...
    4. 嵌套三层 URL 结构：
       - 最外层：account.alibabacloud.com/logout/logout.htm?oauth_callback=<middle>
       - 中间层：account.alibabacloud.com/login/login.htm?oauth_callback=<inner>
       - 最内层：lingma.alibabacloud.com/lingma/login?state=...&challenge=...
    """
    nonce = uuid.uuid4().hex
    verifier, challenge = generate_pkce()
    machine_id = str(uuid.uuid4()).upper()
    state = f"1-{nonce}"

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
    """
    从 HTML 中解析 window.user_info 获取认证信息

    支持多种格式：
    - window.user_info = '{"aid":"..."}' (JSON 字符串)
    - window.user_info = "{...}" (JSON 字符串，双引号)
    - window.user_info = {...} (JSON 对象)
    """
    # 模式 1: window.user_info = '...' (单引号)
    pattern = r"window\.user_info\s*=\s*'(.+?)'\s*;"
    match = re.search(pattern, html, re.DOTALL)
    if match:
        json_str = match.group(1)
        # 处理转义字符
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

    # 模式 3: window.user_info = {...} (JSON 对象，无引号)
    pattern = r'window\.user_info\s*=\s*({.+?})\s*;'
    match = re.search(pattern, html, re.DOTALL)
    if match:
        json_str = match.group(1)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

    return {}


# ===== OAuth 回调 HTTP 服务器 =====

class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    """处理 Lingma OAuth 回调的 HTTP 处理器"""
    captured = None
    result_event = threading.Event()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        flat = {k: v[0] if len(v) == 1 else v for k, v in params.items()}

        # 保存请求信息
        OAuthCallbackHandler.captured = {
            'method': 'GET',
            'path': self.path,
            'query_params': flat,
            'headers': dict(self.headers),
            'timestamp': time.time(),
        }

        # 检查 URL 参数中是否有认证信息
        if 'auth' in flat or 'token' in flat or 'aid' in flat:
            self._handle_auth_params(flat)
        else:
            # 返回 HTML 页面，用于捕获认证信息
            self._return_capture_page()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''

        # 保存请求信息
        OAuthCallbackHandler.captured = {
            'method': 'POST',
            'path': self.path,
            'body': body.decode('utf-8', errors='replace'),
            'headers': dict(self.headers),
            'timestamp': time.time(),
        }

        # 尝试解析请求体中的认证信息
        self._parse_body(body)

    def _handle_auth_params(self, params: dict):
        """处理 URL 参数中的认证信息"""
        auth_data = {}

        if 'auth' in params:
            auth_data['auth'] = params['auth']
        if 'token' in params:
            auth_data['token'] = params['token']
        if 'aid' in params:
            auth_data['aid'] = params['aid']
        if 'uid' in params:
            auth_data['uid'] = params['uid']
        if 'name' in params:
            auth_data['name'] = params['name']

        # 保存认证信息
        OAuthCallbackHandler.captured['auth_data'] = auth_data

        # 返回成功页面
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(b'<h1>Login Success</h1>')

        # 设置事件
        OAuthCallbackHandler.result_event.set()

    def _parse_body(self, body: bytes):
        """解析请求体中的认证信息"""
        try:
            data = json.loads(body.decode('utf-8'))
            OAuthCallbackHandler.captured['auth_data'] = data
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        # 返回成功响应
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

        # 设置事件
        OAuthCallbackHandler.result_event.set()

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
        .info { margin: 20px auto; max-width: 600px; text-align: left; background: #f5f5f5; padding: 20px; border-radius: 8px; }
        pre { overflow-x: auto; }
    </style>
</head>
<body>
    <h1>OAuth Callback Received</h1>
    <p>Waiting for authentication...</p>
    <div id="status"></div>
    <script>
        (function() {
            // 尝试从页面中提取认证信息
            var userInfo = window.user_info;
            if (userInfo) {
                document.getElementById('status').innerHTML = '<p>user_info found, sending to server...</p>';
                fetch('/capture', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ user_info: userInfo })
                }).then(function() {
                    document.getElementById('status').innerHTML = '<p>Credentials sent. You can close this window.</p>';
                });
            } else {
                document.getElementById('status').innerHTML = '<p>No user_info found in page.</p>';
            }
        })();
    </script>
</body>
</html>'''
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))


# ===== 保存凭据 =====

def save_credentials(auth_data: dict):
    """保存认证信息到配置文件"""
    config_dir = Path.home() / '.lingma'
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / 'portable_config.json'

    with open(config_path, 'w') as f:
        json.dump(auth_data, f, indent=2, ensure_ascii=False)

    print(f'[*] Credentials saved to: {config_path}')


# ===== 主流程 =====

def main():
    parser = argparse.ArgumentParser(description='Lingma OAuth Standalone Login')
    parser.add_argument('--port', type=int, default=CALLBACK_PORT, help='Callback port')
    parser.add_argument('--region', default='intl', choices=['intl', 'cn'], help='Region')
    parser.add_argument('--timeout', type=int, default=300, help='Timeout in seconds')
    args = parser.parse_args()

    port = args.port
    region = args.region
    timeout = args.timeout

    # 生成 OAuth URL
    info = generate_login_url(port=port, region=region)
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
        print(f'[*] Auth data: {auth_data}')
        save_credentials(auth_data)
    else:
        print('[!] No auth data captured')


if __name__ == '__main__':
    main()
