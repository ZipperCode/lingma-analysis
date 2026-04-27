#!/usr/bin/env python3
"""
OAuth 回调拦截器 — 半自动 bootstrap.

1. 从 Lingma websocket 获取 login URL, 改写 port
2. 启动本地 HTTP server 监听回调
3. 用户浏览器完成 OAuth 登录
4. 捕获回调 → token exchange → user/login → 写 credentials.json

用法:
    python3 oauth_intercept.py [--port PORT] [--output PATH]
"""

import base64, hashlib, http.server, json, math, os, re, secrets, ssl, sys, time, urllib.parse, uuid
from pathlib import Path

ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
USER_LOGIN_AES_KEY = b'QbgzpWzN7tfe43gf'
CAPTURE_PORT = 37520
OUTPUT_PATH = './auth/credentials.json'

# ===== Encode=1 =====
def custom_b64_encode(data):
    std = base64.b64encode(data).decode().rstrip('=')
    return ''.join(ALPHA[STD_B64.index(c)] for c in std)

def lingma_encode(data):
    encoded = custom_b64_encode(data)
    E = len(encoded)
    BS = math.ceil(E / 3)
    pad = (4 - E % 4) % 4
    b0 = encoded[:BS]
    b1 = encoded[BS:2 * BS] if 2 * BS <= E else (encoded[BS:] if BS < E else "")
    b2 = encoded[2 * BS:] if 2 * BS <= E else ""
    return b2 + '$' * pad + b1 + b0

def aes_encrypt(data, key):
    from Crypto.Cipher import AES
    k = key if isinstance(key, bytes) else key.encode()
    pad_len = 16 - len(data) % 16
    padded = data + bytes([pad_len] * pad_len)
    cipher = AES.new(k, AES.MODE_CBC, iv=k)
    return cipher.encrypt(padded)

# ===== Lingma websocket =====
def get_login_url(ws_uri="ws://127.0.0.1:37010"):
    import websocket as wslib

    ws = wslib.create_connection(ws_uri, timeout=10)

    def send_lsp(method, params, msg_id):
        body = json.dumps({'jsonrpc': '2.0', 'id': msg_id, 'method': method, 'params': params}, ensure_ascii=False)
        ws.send(f'Content-Length: {len(body.encode())}\r\n\r\n{body}')

    def recv_msgs(timeout=5):
        ws.settimeout(timeout)
        msgs = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                raw = ws.recv()
            except:
                break
            text = raw if isinstance(raw, str) else raw.decode()
            offset = 0
            while True:
                hdr_end = text.find('\r\n\r\n', offset)
                if hdr_end < 0: break
                hdr = text[offset:hdr_end]
                cl = None
                for line in hdr.split('\r\n'):
                    if 'content-length:' in line.lower():
                        cl = int(line.split(':')[1].strip())
                if cl is None: break
                body_start = hdr_end + 4
                msgs.append(json.loads(text[body_start:body_start + cl]))
                offset = body_start + cl
        return msgs

    # Initialize
    send_lsp('initialize', {
        'processId': None, 'clientInfo': {'name': 'oauth-intercept', 'version': '1.0'},
        'rootUri': 'file:///tmp/intercept', 'capabilities': {},
        'workspaceFolders': [{'uri': 'file:///tmp/intercept', 'name': 'intercept'}],
    }, 1)
    time.sleep(0.3)
    ws.settimeout(2)
    try: ws.recv()
    except: pass

    # Get fresh login URL
    print('[*] auth/login -> Lingma websocket...')
    send_lsp('auth/login', {}, 2)
    msgs = recv_msgs(10)

    login_url = None
    for m in msgs:
        result_str = json.dumps(m.get('result', {}))
        urls = re.findall(r'https?://[^\s\"\\\\]+', result_str)
        for u in urls:
            if 'login' in u and 'lingma' in u:
                login_url = u
                break
        if login_url:
            break

    ws.close()
    return login_url

def rewrite_port(url_str, new_port):
    parsed = urllib.parse.urlparse(url_str)
    params = urllib.parse.parse_qs(parsed.query)
    params['port'] = [str(new_port)]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))

def wrap_for_browser(login_url):
    inner = 'https://account.alibabacloud.com/login/login.htm?oauth_callback=' + urllib.parse.quote(login_url, safe='')
    return 'https://account.alibabacloud.com/logout/logout.htm?oauth_callback=' + urllib.parse.quote(inner, safe='')

# ===== HTTP Callback Server =====
class CallbackHandler(http.server.BaseHTTPRequestHandler):
    captured = None
    server_port = CAPTURE_PORT

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        flat = {k: v[0] if len(v) == 1 else v for k, v in params.items()}

        CallbackHandler.captured = {
            'path': self.path,
            'params': flat,
            'headers': dict(self.headers),
            'timestamp': time.time(),
        }

        referer = self.headers.get('Referer', '')
        print(f'\n{"=" * 60}')
        print(f'[+] OAuth callback received!')
        print(f'  Path: {self.path}')
        print(f'  Referer: {referer[:200] if referer else "NONE"}')
        # Extract client_id from referer if present
        if 'client_id=' in referer:
            import re as _re
            m = _re.search(r'client_id=([^&\s]+)', referer)
            if m:
                print(f'  *** CLIENT_ID FOUND: {m.group(1)} ***')
        for k, v in flat.items():
            val = str(v)
            print(f'  {k}: {val[:80]}')

        code = flat.get('code', '')
        if code:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(b'<h1>Authorization successful</h1><p>You may close this window.</p>')
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(b'<h1>Callback received</h1><p>Processing...</p>')

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, format, *args):
        pass

# ===== Token Exchange =====
def exchange_code(code, redirect_uri, client_id, code_verifier):
    import urllib.request as ur

    data = urllib.parse.urlencode({
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'client_id': client_id,
        'code_verifier': code_verifier,
    }).encode()

    req = ur.Request('https://oauth.alibabacloud.com/v1/token', data=data)
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    resp = ur.urlopen(req, timeout=30, context=ctx)
    return json.loads(resp.read())

def decode_id_token(id_token):
    parts = id_token.split('.')
    if len(parts) < 2:
        return {}
    payload = parts[1]
    padding = (4 - len(payload) % 4) % 4
    return json.loads(base64.urlsafe_b64decode(payload + '=' * padding))

# ===== Remote user/login =====
def remote_user_login(access_token, refresh_token, user_id, username, machine_id, token_expire_ms):
    import urllib.request as ur

    body = json.dumps({
        'token': access_token,
        'refreshToken': refresh_token,
        'userId': user_id,
        'username': username,
        'machineId': machine_id,
        'expireTime': token_expire_ms,
    }, separators=(',', ':')).encode()

    encrypted = aes_encrypt(body, USER_LOGIN_AES_KEY)
    encoded_body = lingma_encode(encrypted)

    rfc1123 = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

    req = ur.Request(
        'https://lingma.alibabacloud.com/algo/api/v3/user/login?Encode=1',
        data=encoded_body.encode(),
        method='POST'
    )
    req.add_header('Content-Type', 'application/json')
    req.add_header('Date', rfc1123)
    req.add_header('Appcode', 'cosy')
    req.add_header('User-Agent', 'Go-http-client/1.1')

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        resp = ur.urlopen(req, timeout=30, context=ctx)
        return json.loads(resp.read())
    except ur.HTTPError as e:
        body = e.read().decode()
        print(f'  [!] user/login HTTP {e.code}: {body[:300]}')
        return None

# ===== Main =====
def main():
    import argparse
    parser = argparse.ArgumentParser(description='Lingma OAuth callback interceptor')
    parser.add_argument('--port', type=int, default=37520)
    parser.add_argument('--ws-uri', default='ws://127.0.0.1:37010')
    parser.add_argument('--output', default='./auth/credentials.json')
    parser.add_argument('--login-url', help='skip websocket, use provided login URL')
    args = parser.parse_args()

    global CAPTURE_PORT, OUTPUT_PATH
    CAPTURE_PORT = args.port
    OUTPUT_PATH = args.output

    # Step 1: Get login URL
    if args.login_url:
        login_url = args.login_url
    else:
        login_url = get_login_url(args.ws_uri)
        if not login_url:
            print('[!] Failed to get login URL. Is Lingma running?')
            print('    Try: python3 oauth_intercept.py --login-url "https://..."')
            sys.exit(1)

    print(f'\n[*] Login URL: {login_url[:120]}...')

    # Extract machine_id from login URL
    parsed = urllib.parse.urlparse(login_url)
    params = urllib.parse.parse_qs(parsed.query)
    machine_id = params.get('machine_id', ['unknown'])[0]
    nonce = params.get('nonce', [''])[0]
    challenge = params.get('challenge', [''])[0]
    print(f'[*] machine_id: {machine_id}')

    # Step 2: Rewrite port
    rewritten = rewrite_port(login_url, CAPTURE_PORT)
    print(f'[*] Rewritten port: {CAPTURE_PORT}')

    # Step 3: Wrap for browser
    browser_url = wrap_for_browser(rewritten)

    # Step 4: Start HTTP server
    CallbackHandler.server_port = CAPTURE_PORT
    server = http.server.HTTPServer(('127.0.0.1', CAPTURE_PORT), CallbackHandler)
    server.timeout = 1

    print(f'\n[*] HTTP server listening on http://127.0.0.1:{CAPTURE_PORT}')
    print(f'[*] Waiting for OAuth callback (timeout 5 min)...')
    print(f'\n{"=" * 60}')
    print(f'Open this URL in your browser:')
    print(f'{browser_url}')
    print(f'{"=" * 60}\n')

    # Try to open browser automatically
    try:
        import webbrowser
        webbrowser.open(browser_url)
    except:
        pass

    # Step 5: Wait for callback
    deadline = time.time() + 300
    while time.time() < deadline and CallbackHandler.captured is None:
        server.handle_request()
    server.server_close()

    if CallbackHandler.captured is None:
        print('\n[!] No callback received within timeout.')
        sys.exit(1)

    # Step 6: Process callback
    captured = CallbackHandler.captured
    code = captured['params'].get('code', '')

    if not code:
        print('[!] No authorization code in callback.')
        print(f'    Params: {json.dumps(captured["params"], indent=2)}')
        # Check for Lingma-specific auth/token params
        auth_param = captured['params'].get('auth', '')
        token_param = captured['params'].get('token', '')
        if auth_param or token_param:
            print('[!] Lingma-specific callback detected (auth/token params).')
            print('    These require Lingma binary to decode.')
            print('    Saving raw callback data...')
            output = {
                'schema_version': 1,
                'source': 'oauth_intercept_raw',
                'machine_id': machine_id,
                'callback': captured['params'],
            }
            os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
            with open(OUTPUT_PATH, 'w') as f:
                json.dump(output, f, indent=2)
            print(f'    Saved to {OUTPUT_PATH}')
        sys.exit(1)

    print(f'\n[+] Authorization code captured.')

    # Step 7: Token exchange
    # We need client_id and code_verifier. PKCE was set by Lingma server.
    # Try using machine_id as client_id first
    print(f'[*] Exchanging code for tokens...')

    redirect_uri = f'http://127.0.0.1:{CAPTURE_PORT}/callback'

    # Try token exchange with machine_id as client_id
    try:
        # We don't have the PKCE code_verifier (Lingma's server generated it)
        # So we can't do standard token exchange
        # Instead, try without code_verifier (some OAuth implementations allow this)
        tokens = exchange_code(code, redirect_uri, machine_id, '')
        print(f'[+] Token exchange successful!')
    except Exception as e:
        print(f'[!] Token exchange failed: {e}')
        print(f'    The PKCE verifier is held by Lingma server.')
        print(f'    Saving raw OAuth code for manual processing.')
        output = {
            'schema_version': 1,
            'source': 'oauth_intercept_code',
            'machine_id': machine_id,
            'authorization_code': code,
            'redirect_uri': redirect_uri,
        }
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        with open(OUTPUT_PATH, 'w') as f:
            json.dump(output, f, indent=2)
        print(f'    Saved to {OUTPUT_PATH}')
        sys.exit(1)

    access_token = tokens.get('access_token', '')
    refresh_token = tokens.get('refresh_token', '')
    id_token = tokens.get('id_token', '')
    expires_in = tokens.get('expires_in', 3600)

    print(f'  access_token: {access_token[:20]}...')
    print(f'  refresh_token: {refresh_token[:20]}...')

    # Decode id_token
    user_id = ''
    username = ''
    if id_token:
        claims = decode_id_token(id_token)
        user_id = claims.get('sub', '')
        username = claims.get('name', claims.get('email', ''))
        print(f'  user_id: {user_id}')
        print(f'  username: {username}')

    # Step 8: Remote user/login
    token_expire_ms = str(int(time.time() * 1000) + expires_in * 1000)
    print(f'\n[*] Calling remote user/login...')

    login_resp = remote_user_login(access_token, refresh_token, user_id, username, machine_id, token_expire_ms)

    # Step 9: Write credentials.json
    now = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    credential = {
        'schema_version': 1,
        'source': 'oauth_intercept',
        'lingma_version_hint': '2.11.1',
        'obtained_at': now,
        'updated_at': now,
        'token_expire_time': token_expire_ms,
        'auth': {
            'cosy_key': '',
            'encrypt_user_info': '',
            'user_id': user_id,
            'machine_id': machine_id,
        },
        'oauth': {
            'access_token': access_token,
            'refresh_token': refresh_token,
        },
    }

    if login_resp and login_resp.get('key'):
        credential['auth']['cosy_key'] = login_resp.get('key', '')
        credential['auth']['encrypt_user_info'] = login_resp.get('encrypt_user_info', '')
        if login_resp.get('uid'):
            credential['auth']['user_id'] = login_resp['uid']
        print(f'[+] Remote user/login successful!')
    else:
        print(f'[!] Remote user/login failed (old Signature required).')
        print(f'    Credentials saved with cosy_key empty.')
        print(f'    Run: go run ./cmd/lingma-auth-bootstrap --use-lingma=true')
        print(f'    Or use the access_token to complete derivation another way.')

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, 'w') as f:
        json.dump(credential, f, indent=2)

    print(f'\n[+] Credentials written to {OUTPUT_PATH}')
    print(f'    cosy_key: {"present" if credential["auth"]["cosy_key"] else "EMPTY - needs manual completion"}')

if __name__ == '__main__':
    main()
