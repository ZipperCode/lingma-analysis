"""Test auth/refreshToken with EXPIRED token to force remote refresh."""
import frida
import json
import os
import base64
import time
import websocket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

CACHE_DIR = os.path.expandvars(r"C:\Users\Zipper\.lingma\cache")
SCRIPT_PATH = os.path.join(os.path.dirname(__file__), 'frida_minimal_hook.js')

# Load credentials
with open(os.path.join(CACHE_DIR, "id"), 'r') as f:
    machine_id = f.read().strip()
with open(os.path.join(CACHE_DIR, "user"), 'rb') as f:
    encrypted_raw = f.read().strip()
encrypted = base64.b64decode(encrypted_raw)
key = machine_id[:16].encode('utf-8')
cipher = AES.new(key, AES.MODE_CBC, iv=key)
user_data = json.loads(unpad(cipher.decrypt(encrypted), 16).decode('utf-8'))

with open(SCRIPT_PATH, 'r') as f:
    hook_js = f.read()

events = []
def on_message(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']
        print(f"[FRIDA] {p.get('type','?')}: {json.dumps(p, ensure_ascii=False)[:300]}")
        events.append(p)
    elif msg['type'] == 'log':
        print(f"[FRIDA LOG] {msg['payload']}")

print("[*] Attaching Frida...")
device = frida.get_local_device()
processes = device.enumerate_processes()
lingma = [p for p in processes if p.name and 'lingma' in p.name.lower()]
pid = lingma[0].pid
session = device.attach(pid)
script = session.create_script(hook_js)
script.on('message', on_message)
script.load()
time.sleep(1)

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

ws = websocket.create_connection("ws://127.0.0.1:37010", timeout=10)

# Initialize
ws.send(make_frame("initialize", {
    "processId": os.getpid(),
    "clientInfo": {"name": "frida", "version": "1.0"},
    "locale": "zh-CN",
    "rootPath": "C:/test",
    "capabilities": {}
}, 1))
ws.settimeout(3)
try: ws.recv()
except: pass

# Test 1: Normal refresh (valid token)
print("\n=== Test 1: Normal refresh (valid token) ===")
ws.send(make_frame("auth/refreshToken", {
    "securityOauthToken": user_data['security_oauth_token'],
    "refreshToken": user_data['refresh_token'],
    "tokenExpireTime": user_data['expire_time']
}, 2))
ws.settimeout(10)
try:
    raw = ws.recv()
    resp = parse_frame(raw)
    print(f"Result: success={resp.get('result',{}).get('success')}, uid={resp.get('result',{}).get('uid')}, expire={resp.get('result',{}).get('tokenExpireTime')}")
except Exception as e:
    print(f"Error: {e}")

# Test 2: Expired token (set expire_time to past)
print("\n=== Test 2: EXPIRED token ===")
past_expire = int(time.time() * 1000) - 86400000  # 1 day ago in ms
print(f"Using fake expire_time: {past_expire} (1 day ago)")
ws.send(make_frame("auth/refreshToken", {
    "securityOauthToken": user_data['security_oauth_token'],
    "refreshToken": user_data['refresh_token'],
    "tokenExpireTime": past_expire
}, 3))
ws.settimeout(30)  # longer timeout for remote call
try:
    raw = ws.recv()
    resp = parse_frame(raw)
    print(f"Result: {json.dumps(resp, ensure_ascii=False)[:800]}")
except Exception as e:
    print(f"Error: {e}")

# Test 3: Expired token with garbage tokens
print("\n=== Test 3: GARBAGE tokens (expired) ===")
ws.send(make_frame("auth/refreshToken", {
    "securityOauthToken": "pt-deadbeef00000000000000000",
    "refreshToken": "rt-deadbeef00000000000000000",
    "tokenExpireTime": past_expire
}, 4))
ws.settimeout(30)
try:
    raw = ws.recv()
    resp = parse_frame(raw)
    print(f"Result: {json.dumps(resp, ensure_ascii=False)[:800]}")
except Exception as e:
    print(f"Error: {e}")

print("\n[*] Waiting 15s for Frida events...")
time.sleep(15)

print(f"\n=== All Frida events ({len(events)}) ===")
for e in events:
    t = e.get('type','?')
    if t in ('connect', 'sni', 'http', 'http_recv'):
        print(f"  [{t}] {json.dumps(e, ensure_ascii=False)[:300]}")

ws.close()
script.unload()
session.detach()
print("[*] Done!")
