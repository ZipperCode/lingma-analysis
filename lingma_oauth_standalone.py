#!/usr/bin/env python3
"""
Lingma OAuth Standalone — 完全独立，零本地依赖

不读取任何本地缓存/配置，登录成功后直接打印全部凭据。
支持云服务器（--manual 模式：生成链接 → 任意设备浏览器登录 → 粘贴回调 URL）。

依赖: pip install cryptography

Usage:
    python lingma_oauth_standalone.py login                # 本地浏览器自动登录
    python lingma_oauth_standalone.py login --manual       # 云服务器：手动粘贴回调
    python lingma_oauth_standalone.py login --port 8080    # 指定回调端口
"""
import base64
import hashlib
import http.server
import json
import math
import secrets
import sys
import threading
import time
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ============================================================
# Encode=1 编解码 (IDA 逆向)
# ============================================================
_ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def _b64_custom_encode(data: bytes) -> str:
    s = base64.b64encode(data).decode().rstrip('=')
    return ''.join(_ALPHA[_STD.index(c)] for c in s)


def _b64_custom_decode(enc: str) -> bytes:
    conv = ''.join(_STD[_ALPHA.index(c)] for c in enc if c in _ALPHA)
    pad = (4 - len(conv) % 4) % 4
    return base64.b64decode(conv + '=' * pad)


def encode_v1(data: bytes) -> str:
    e = _b64_custom_encode(data)
    E = len(e)
    f = E // 3
    c = math.ceil(E / 3)
    pad = (4 - E % 4) % 4
    return e[2 * c:] + '$' * pad + e[f:2 * c] + e[:f]


def decode_v1(body: str) -> bytes:
    pos = body.find('$')
    if pos < 0:
        clean, E = body, len(body)
    else:
        p = 0
        i = pos
        while i < len(body) and body[i] == '$':
            p += 1; i += 1
        clean = body[:pos] + body[pos + p:]
        E = len(clean)
    c = math.ceil(E / 3)
    f = E // 3
    lb = E - 2 * c
    return _b64_custom_decode(clean[lb + 2 * c - f:] + clean[lb:lb + 2 * c - f] + clean[:lb])


def decrypt_parts(encoded: str, n: int = 3) -> list:
    try:
        raw = decode_v1(urllib.parse.unquote(encoded))
        return raw.decode('utf-8').split('\n', n - 1)
    except Exception:
        return []


# ============================================================
# PKCE + OAuth URL
# ============================================================
def pkce() -> tuple:
    v = secrets.token_urlsafe(32)[:43]
    c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode()
    return v, c


def oauth_url(nonce: str, port: int, challenge: str, machine_id: str) -> str:
    inner = "https://lingma.alibabacloud.com/lingma/login?" + urllib.parse.urlencode({
        "nonce": nonce, "port": port, "state": f"2-{nonce}",
        "challenge": challenge, "challenge_method": "S256", "machine_id": machine_id,
    })
    return "https://account.alibabacloud.com/login/login.htm?oauth_callback=" + urllib.parse.quote(inner, safe='')


# ============================================================
# COSY 凭据本地生成 (IDA @ SaveUserInfo 0x14088e260)
# ============================================================
_RSA_PUB = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----"""


def make_cosy(uid: str, aid: str, name: str, pt: str, rt: str) -> tuple:
    """本地生成 cosy_key + encrypt_user_info（RSA-1024 + AES-128-CBC）"""
    from cryptography.hazmat.primitives.asymmetric import padding as ap
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    inner = json.dumps({
        "name": name, "aid": aid, "uid": uid, "yx_uid": "",
        "organization_id": "", "organization_name": "", "staffId": "",
        "avatar_url": "", "key": "", "encrypt_user_info": "",
        "user_source_channel": "", "security_oauth_token": pt,
        "refresh_token": rt, "expire_time": 0, "user_type": "",
        "data_policy_agreed": False, "email": "",
        "is_data_policy_modifiable": False, "is_quota_exceeded": False,
        "organization_tags": None,
    }, separators=(",", ":"), ensure_ascii=False)

    key = uuid.uuid4().hex[:16].encode()
    pub = load_pem_public_key(_RSA_PUB.encode())
    cosy_key = base64.b64encode(pub.encrypt(key, ap.PKCS1v15())).decode()

    cipher = Cipher(algorithms.AES(key), modes.CBC(key))
    enc = cipher.encryptor()
    data = inner.encode()
    pad = 16 - len(data) % 16
    eui = base64.b64encode(enc.update(data + bytes([pad] * pad)) + enc.finalize()).decode()
    return cosy_key, eui


# ============================================================
# COSY Bearer 签名 (IDA 逆向)
# ============================================================
COSY_SIGN_KEY = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="

def sign_headers(path: str, body: str, cosy_key: str, encrypt_user_info: str,
                 user_id: str, machine_id: str) -> dict:
    date = str(int(time.time()))
    sig_path = path.split('?')[0]
    if sig_path.startswith('/algo'):
        sig_path = sig_path[5:]

    payload = base64.b64encode(json.dumps({
        "cosyVersion": "2.11.2", "ideVersion": "", "info": encrypt_user_info,
        "requestId": uuid.uuid4().hex, "version": "v1",
    }, separators=(',', ':')).encode()).decode()

    sig = hashlib.md5(f"{payload}\n{cosy_key}\n{date}\n{body if body else ''}\n{sig_path}".encode()).hexdigest()

    h = {
        "Content-Type": "application/json", "Accept": "application/json",
        "Cosy-Version": "2.11.2", "Cosy-MachineId": machine_id,
        "Cosy-MachineOS": "x86_64_linux", "Cosy-ClientType": "2",
        "Authorization": f"Bearer COSY.{payload}.{sig}",
        "Appcode": "cosy", "Cosy-Date": date, "Cosy-Key": cosy_key,
        "Cosy-User": user_id, "Cosy-SigPath": sig_path,
        "Cosy-Data-Policy": "AGREE",
    }
    if body:
        h["Cosy-BodyHash"] = hashlib.md5(body.encode()).hexdigest()
        h["Cosy-BodyLength"] = str(len(body))
    return h


# ============================================================
# API 验证
# ============================================================
BASE = "https://lingma.alibabacloud.com"


def _curl(method: str, path: str, body: str, headers: dict, timeout: int = 30) -> tuple:
    """返回 (stdout, returncode)"""
    import subprocess
    cmd = ["curl", "-s", "--compressed", "--max-time", str(timeout)]
    if method == "POST":
        cmd.extend(["-X", "POST"])
    for k, v in headers.items():
        cmd.extend(["-H", f"{k}: {v}"])
    if body:
        cmd.extend(["-d", body])
    cmd.append(f"{BASE}{path}")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    return r.stdout, r.returncode


def verify_models(cosy_key: str, eui: str, user_id: str, machine_id: str) -> dict:
    """GET /algo/api/v2/model/list — 获取可用模型列表"""
    path = "/algo/api/v2/model/list"
    headers = sign_headers(path, "", cosy_key, eui, user_id, machine_id)
    out, rc = _curl("GET", path, "", headers)
    try:
        data = json.loads(out)
        models = data.get("chat", []) + data.get("inline", [])
        return {"ok": len(models) > 0, "count": len(models), "models": models[:5]}
    except (json.JSONDecodeError, KeyError):
        return {"ok": False, "raw": out[:200]}


def verify_chat(cosy_key: str, eui: str, user_id: str, machine_id: str) -> dict:
    """POST chat — 发送一个最小聊天请求验证流式响应"""
    path = "/algo/api/v2/service/pro/sse/agent_chat_generation"
    full_path = f"{path}?FetchKeys=llm_model_result&AgentId=agent_common"
    body = json.dumps({
        "request_id": uuid.uuid4().hex, "stream": True, "source": 0, "version": "3",
        "parameters": {"temperature": 0.1}, "agent_id": "agent_common",
        "task_id": "question_refine",
        "model_config": {"key": "", "model": "", "is_vl": False, "is_reasoning": False,
                         "format": "", "api_key": "", "url": "", "source": ""},
        "messages": [
            {"role": "system", "content": "You are a helpful assistant.",
             "response_meta": {"id": "", "usage": {}}, "reasoning_content_signature": ""},
            {"role": "user", "content": "Reply with just the word: OK",
             "response_meta": {"id": "", "usage": {}}, "reasoning_content_signature": ""},
        ],
    }, separators=(",", ":"))
    headers = sign_headers(path, body, cosy_key, eui, user_id, machine_id)
    headers["Accept"] = "text/event-stream"
    headers["Cache-Control"] = "no-cache"
    out, rc = _curl("POST", full_path, body, headers, timeout=30)

    if not out.strip():
        return {"ok": False, "error": "empty response"}

    # 解析 SSE 提取回复
    contents = []
    for line in out.split("\n"):
        if not line.startswith("data:"):
            continue
        try:
            outer = json.loads(line[5:])
            inner_body = outer.get("body", "")
            if not inner_body or inner_body == "[DONE]":
                continue
            inner = json.loads(inner_body)
            for c in inner.get("choices", []):
                t = c.get("delta", {}).get("content", "")
                if t:
                    contents.append(t)
        except (json.JSONDecodeError, KeyError):
            pass

    reply = "".join(contents)
    return {"ok": bool(reply), "reply": reply[:200], "bytes": len(out)}


def verify_all(cosy_key: str, eui: str, user_id: str, machine_id: str) -> dict:
    """运行全部接口验证"""
    print("\n[*] Running API verification...")
    results = {}

    print("    [1/2] GET /algo/api/v2/model/list ... ", end="", flush=True)
    r = verify_models(cosy_key, eui, user_id, machine_id)
    results["models"] = r
    if r["ok"]:
        print(f"OK ({r['count']} models)")
        for m in r["models"][:3]:
            print(f"          - {m.get('display_name','?')} ({m.get('key','?')})")
    else:
        print(f"FAIL")
        print(f"          {r.get('raw', r.get('error', ''))[:150]}")

    print("    [2/2] POST chat (simple message) ... ", end="", flush=True)
    r = verify_chat(cosy_key, eui, user_id, machine_id)
    results["chat"] = r
    if r["ok"]:
        print(f"OK")
        print(f"          Reply: {r['reply']!r}")
    else:
        print(f"FAIL")
        print(f"          {r.get('error', '')[:150]}")

    all_ok = results["models"]["ok"] and results["chat"]["ok"]
    print(f"\n    Result: {'ALL PASSED' if all_ok else 'SOME FAILED'}")
    return {"all_ok": all_ok, **results}


# ============================================================
# 回调解析
# ============================================================
def parse_callback(params: dict) -> dict:
    out = {}
    if "auth" in params:
        p = decrypt_parts(params["auth"], 3)
        if len(p) >= 3:
            out["uid"], out["aid"], out["name"] = p[0], p[1], p[2]
    if "token" in params:
        p = decrypt_parts(params["token"], 3)
        if len(p) >= 3:
            out["pt"] = p[0]
            out["rt"] = p[1]
            out["expire"] = p[2]
    for k in ("aid", "uid", "name"):
        if k in params and k not in out:
            out[k] = params[k]
    return out


# ============================================================
# HTTP 回调服务器
# ============================================================
class _Handler(http.server.BaseHTTPRequestHandler):
    result = None
    event = threading.Event()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        data = parse_callback(params)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        if data.get("pt"):
            _Handler.result = data
            _Handler.event.set()
            self.wfile.write(b"<html><body><h2>Login OK</h2><p>Credentials captured. Close this tab.</p></body></html>")
        else:
            self.wfile.write(b"<html><body><h2>Waiting...</h2></body></html>")

    def log_message(self, *a):
        pass


def _wait_callback(port: int, timeout: int) -> dict:
    srv = http.server.HTTPServer(("0.0.0.0", port), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ok = _Handler.event.wait(timeout=timeout)
    srv.shutdown()
    return _Handler.result if ok else None


def _manual_input(timeout: int) -> dict:
    print(f"\n[*] 等待手动输入回调 URL（超时 {timeout}s）...")
    print("[*] 在浏览器登录后，复制地址栏的完整 URL 粘贴到下方：\n")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            raw = input("回调 URL> ").strip()
        except EOFError:
            break
        if not raw:
            continue
        parsed = urllib.parse.urlparse(raw)
        params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        data = parse_callback(params)
        if data:
            return data
        print("[!] 解析失败，请粘贴完整的回调 URL")
    return None


# ============================================================
# 主流程
# ============================================================
def do_login(port: int = 37510, timeout: int = 300, manual: bool = False):
    machine_id = str(uuid.uuid4())
    nonce = uuid.uuid4().hex
    verifier, challenge = pkce()

    url = oauth_url(nonce, port, challenge, machine_id)

    print("=" * 60)
    print("Lingma OAuth Standalone")
    print(f"Machine ID: {machine_id}")
    print(f"Mode: {'Manual' if manual else 'Browser'}")
    print("=" * 60)
    print(f"\n[*] Login URL:\n    {url}\n")

    if manual:
        print("[*] 请在任意设备的浏览器中打开上面的链接")
        print("[*] 登录成功后浏览器会跳转，复制地址栏完整 URL 粘贴到下方\n")
        auth = _manual_input(timeout)
    else:
        import webbrowser
        print(f"[*] Callback server: 0.0.0.0:{port}")
        webbrowser.open(url)
        auth = _wait_callback(port, timeout)

    if not auth:
        print("\n[!] Timeout or no data")
        sys.exit(1)

    uid = auth.get("uid", auth.get("aid", ""))
    aid = auth.get("aid", uid)
    name = auth.get("name", "")
    pt = auth.get("pt", "")
    rt = auth.get("rt", "")
    expire = auth.get("expire", "")

    if not pt:
        print("\n[!] Missing token, login incomplete")
        sys.exit(1)

    print(f"\n[*] Generating COSY credentials...")
    cosy_key, eui = make_cosy(uid, aid, name, pt, rt)

    # 输出全部凭据
    print("\n" + "=" * 60)
    print("ALL CREDENTIALS")
    print("=" * 60)
    print(f"machine_id:             {machine_id}")
    print(f"uid:                    {uid}")
    print(f"aid:                    {aid}")
    print(f"name:                   {name}")
    print(f"security_oauth_token:   {pt}")
    print(f"refresh_token:          {rt}")
    print(f"expire_time:            {expire}")
    print(f"cosy_key:               {cosy_key}")
    print(f"encrypt_user_info:      {eui}")
    print("=" * 60)

    # 运行 API 接口验证
    verify_result = verify_all(cosy_key, eui, uid, machine_id)

    # 最终汇总
    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    models_ok = verify_result["models"]["ok"]
    chat_ok = verify_result["chat"]["ok"]
    model_count = verify_result["models"].get("count", 0) if models_ok else 0
    print(f"OAuth Login:            OK")
    print(f"COSY Generation:        OK")
    print(f"Model List API:         {'OK (' + str(model_count) + ' models)' if models_ok else 'FAIL'}")
    print(f"Chat API:               {'OK' if chat_ok else 'FAIL'}")
    overall = 'ALL PASSED — credentials are fully functional' if verify_result["all_ok"] else 'SOME CHECKS FAILED'
    print(f"Overall:                {overall}")
    print("=" * 60)

    if not verify_result["all_ok"]:
        sys.exit(2)


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] == "login":
        manual = "--manual" in args
        port = 37510
        for i, a in enumerate(args):
            if a == "--port" and i + 1 < len(args):
                port = int(args[i + 1])
        timeout = 300
        for i, a in enumerate(args):
            if a == "--timeout" and i + 1 < len(args):
                timeout = int(args[i + 1])
        do_login(port=port, timeout=timeout, manual=manual)
    else:
        print("Usage:")
        print("  python lingma_oauth_standalone.py login [--manual] [--port PORT] [--timeout SEC]")
