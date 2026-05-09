"""Frida attach + WS auth/refreshToken trigger — minimal version."""
import frida
import json
import os
import base64
import time
import threading
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

# Read Frida script
with open(SCRIPT_PATH, 'r') as f:
    hook_js = f.read()

# Frida message handler
events = []
def on_message(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']
        print(f"[FRIDA] {p.get('type','?')}: {json.dumps(p, ensure_ascii=False)[:300]}")
        events.append(p)
    elif msg['type'] == 'log':
        print(f"[FRIDA LOG] {msg['payload']}")
    elif msg['type'] == 'error':
        print(f"[FRIDA ERR] {msg}")

# Attach Frida
print("[*] Attaching Frida to running Lingma...")
device = frida.get_local_device()
processes = device.enumerate_processes()
lingma = [p for p in processes if p.name and 'lingma' in p.name.lower()]
if not lingma:
    print("[!] Lingma not running!")
    exit(1)

pid = lingma[0].pid
print(f"[*] PID: {pid}")
session = device.attach(pid)
script = session.create_script(hook_js)
script.on('message', on_message)
script.load()
time.sleep(1)

# Connect WS and trigger refreshToken
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

print("[*] Connecting WebSocket...")
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
try:
    ws.recv()
except:
    pass

# Trigger refreshToken
print("[*] Sending auth/refreshToken...")
ws.send(make_frame("auth/refreshToken", {
    "securityOauthToken": user_data['security_oauth_token'],
    "refreshToken": user_data['refresh_token'],
    "tokenExpireTime": user_data['expire_time']
}, 2))

# Wait for response
ws.settimeout(20)
start = time.time()
try:
    raw = ws.recv()
    resp = parse_frame(raw)
    elapsed = time.time() - start
    print(f"[*] Response in {elapsed:.1f}s: {json.dumps(resp, ensure_ascii=False)[:500]}")
except Exception as e:
    print(f"[*] WS recv error: {e}")

# Wait a bit more for any async Frida events
print("[*] Waiting 10s for Frida events...")
time.sleep(10)

print("\n=== All Frida events ===")
for e in events:
    print(f"  [{e.get('type','?')}] {json.dumps(e, ensure_ascii=False)[:200]}")

ws.close()
script.unload()
session.detach()
print("[*] Done!")
