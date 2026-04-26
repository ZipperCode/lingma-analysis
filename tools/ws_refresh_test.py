"""Quick test: trigger auth/refreshToken via LSP WebSocket, check response."""
import json
import base64
import os
import websocket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

CACHE_DIR = os.path.expandvars(r"C:\Users\Zipper\.lingma\cache")

# Read machine_id
with open(os.path.join(CACHE_DIR, "id"), 'r') as f:
    machine_id = f.read().strip()
print(f"[*] machine_id: {machine_id}")

# Decrypt user cache
with open(os.path.join(CACHE_DIR, "user"), 'rb') as f:
    encrypted_raw = f.read().strip()
encrypted = base64.b64decode(encrypted_raw)
key = machine_id[:16].encode('utf-8')
cipher = AES.new(key, AES.MODE_CBC, iv=key)
user_data = json.loads(unpad(cipher.decrypt(encrypted), 16).decode('utf-8'))

sec_token = user_data['security_oauth_token']
refresh_tok = user_data['refresh_token']
expire_time = user_data['expire_time']

print(f"[*] security_oauth_token: {sec_token[:30]}...")
print(f"[*] refresh_token: {refresh_tok[:30]}...")
print(f"[*] expire_time: {expire_time}")

def make_frame(method, params=None, msg_id=1):
    body = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        body["params"] = params
    body["id"] = msg_id
    content = json.dumps(body, ensure_ascii=False)
    return f"Content-Length: {len(content.encode('utf-8'))}\r\n\r\n{content}"

def parse_frame(text):
    if '\r\n\r\n' in text:
        headers, body = text.split('\r\n\r\n', 1)
        for line in headers.split('\r\n'):
            if line.lower().startswith('content-length:'):
                length = int(line.split(':')[1].strip())
                return json.loads(body[:length])
        return json.loads(body)
    return json.loads(text)

# Connect
print("[*] Connecting to ws://127.0.0.1:37010 ...")
ws = websocket.create_connection("ws://127.0.0.1:37010", timeout=10)
print("[*] Connected!")

# Initialize
print("[1] initialize...")
ws.send(make_frame("initialize", {
    "processId": os.getpid(),
    "clientInfo": {"name": "test", "version": "1.0"},
    "locale": "zh-CN",
    "rootPath": "C:/test",
    "capabilities": {}
}, 1))
ws.settimeout(3)
try:
    raw = ws.recv()
    print(f"    init resp: {parse_frame(raw).get('result',{}).get('capabilities',{})}")
except:
    print("    (no init response expected)")

# Initialized
print("[2] initialized...")
ws.send(make_frame("initialized", {}, 2))

# Auth status check first
print("[3] auth/getStatus...")
ws.send(make_frame("auth/getStatus", {}, 3))
ws.settimeout(5)
try:
    raw = ws.recv()
    status = parse_frame(raw)
    print(f"    status: {json.dumps(status, ensure_ascii=False)[:500]}")
except Exception as e:
    print(f"    error: {e}")

# Send auth/refreshToken
print("[4] auth/refreshToken...")
ws.send(make_frame("auth/refreshToken", {
    "securityOauthToken": sec_token,
    "refreshToken": refresh_tok,
    "tokenExpireTime": expire_time
}, 4))

ws.settimeout(15)
try:
    raw = ws.recv()
    resp = parse_frame(raw)
    print(f"\n{'='*60}")
    print(f"REFRESH RESPONSE:")
    print(json.dumps(resp, ensure_ascii=False, indent=2)[:2000])
    print(f"{'='*60}")
except Exception as e:
    print(f"    error: {e}")

# Check for extra messages
print("[5] waiting for extra messages...")
for i in range(5):
    try:
        raw = ws.recv()
        extra = parse_frame(raw)
        print(f"    extra[{i}]: {json.dumps(extra, ensure_ascii=False)[:300]}")
    except:
        break

ws.close()
print("[*] Done!")
