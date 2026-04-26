"""Spawn Lingma with Frida from startup — capture ALL connections including initial."""
import frida
import json
import os
import base64
import time
import uuid
import sys
import websocket
import subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

LINGMA_EXE = "C:/Users/Zipper/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe"
LINGMA_DIR = os.path.dirname(LINGMA_EXE)

SCRIPT_PATH = os.path.join(os.path.dirname(__file__), 'frida_minimal_hook.js')
with open(SCRIPT_PATH, 'r') as f:
    hook_js = f.read()

# First, kill any existing Lingma
print("[*] Killing existing Lingma...")
try:
    subprocess.run(["taskkill", "/F", "/IM", "Lingma.exe"], capture_output=True)
    time.sleep(2)
except: pass

# Spawn Lingma with Frida
print("[*] Spawning Lingma with Frida...")
device = frida.get_local_device()

events = []
def on_message(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']
        t = p.get('type','?')
        if t == 'sni': print(f"[SNI] {p['sni']}")
        elif t == 'connect': print(f"[CONNECT] {p['ip']}:{p['port']}")
        elif t == 'http':
            d = p.get('data','')[:300]
            if '101' not in d:  # filter out WebSocket upgrade
                print(f"[HTTP>>] {d}")
        elif t == 'http_recv':
            d = p.get('data','')[:300]
            if '101' not in d:
                print(f"[<<HTTP] {d}")
        events.append(p)
    elif msg['type'] == 'log':
        l = msg['payload']
        if any(x in l for x in ['SNI','CONNECT','HTTP SEND','HTTP RECV']):
            print(f"[Frida] {l[:300]}")

# Spawn
pid = device.spawn([LINGMA_EXE, "start"], cwd=LINGMA_DIR)
session = device.attach(pid)

# Inject hook script BEFORE resuming
script = session.create_script(hook_js)
script.on('message', on_message)
script.load()

# RESUME — this is when Lingma starts executing
print("[*] RESUMING Lingma — watching for initial connections...")
device.resume(pid)

# Wait for Lingma to start
print("[*] Waiting for port 37010...")
for i in range(60):
    time.sleep(1)
    try:
        s = __import__('socket').create_connection(('127.0.0.1', 37010), timeout=1)
        s.close()
        print(f"[*] Lingma ready after {i+1}s")
        break
    except:
        if i % 5 == 0: print(f"   waiting {i}s...")
else:
    print("[!] Lingma didn't start")
    sys.exit(1)

# Wait a bit more for any startup HTTP requests
print("[*] Waiting 10s for startup requests...")
time.sleep(10)

print(f"\n=== Events during startup ({len(events)}) ===")
for e in events:
    t = e.get('type','?')
    if t in ('connect', 'sni', 'http', 'http_recv'):
        print(f"  [{t}] {json.dumps(e, ensure_ascii=False)[:300]}")

# Now trigger login (we know cache/user exists from before)
print("\n[*] Connecting WebSocket for login...")
ws = websocket.create_connection("ws://127.0.0.1:37010", timeout=10)

def make_frame(method, params=None, msg_id=1):
    body = {"jsonrpc": "2.0", "method": method, "id": msg_id}
    if params is not None: body["params"] = params
    content = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
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

def parse_frames(payload):
    msgs = []
    offset = 0
    marker = b"\r\n\r\n"
    while offset < len(payload):
        header_end = payload.find(marker, offset)
        if header_end < 0: break
        header = payload[offset:header_end].decode("ascii", errors="replace")
        cl = None
        for line in header.split("\r\n"):
            if line.lower().startswith("content-length:"):
                cl = int(line.split(":", 1)[1].strip()); break
        if cl is None: break
        body_start = header_end + len(marker)
        body_end = body_start + cl
        if body_end > len(payload): break
        msgs.append(json.loads(payload[body_start:body_end]))
        offset = body_end
    return msgs

# Initialize
ws.send(make_frame("initialize", {
    "processId": None,
    "clientInfo": {"name": "frida-spawn", "version": "1.0"},
    "rootUri": "file:///C:/test",
    "capabilities": {},
    "workspaceFolders": [{"uri": "file:///C:/test", "name": "workspace"}],
}, 1))
ws.settimeout(3)
try:
    raw = ws.recv()
    for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
        print(f"    init ok")
except: pass

# Check if login needed
ws.send(make_frame("auth/status", {}, 2))
ws.settimeout(5)
try:
    raw = ws.recv()
    for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
        r = m.get('result', {})
        status = r.get('status', '?')
        print(f"    auth status={status}")
except: pass

# If not logged in, trigger login
if status != 2:
    print("[*] Triggering auth/login...")
    ws.send(make_frame("auth/login", {}, 3))
    ws.settimeout(20)
    for i in range(10):
        try:
            raw = ws.recv()
            for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
                if m.get('method') == 'auth/report':
                    print(f"    LOGIN SUCCESS: {m['params'].get('name')}")
                    status = 2
                elif 'result' in m:
                    print(f"    login resp: {json.dumps(m['result'], ensure_ascii=False)[:150]}")
        except websocket.WebSocketTimeoutException:
            break
        except: break

if status != 2:
    print("[!] Login failed, exiting")
    ws.close()
    session.detach()
    sys.exit(1)

# Wait for any post-login network activity
print("[*] Waiting 10s for post-login activity...")
time.sleep(10)

# Send a chat request
request_id = uuid.uuid4().hex
print(f"\n[*] Sending chat/ask (id={request_id})...")
ws.send(make_frame("chat/ask", {
    "requestId": request_id,
    "chatTask": "FREE_INPUT",
    "chatContext": None,
    "sessionId": "",
    "codeLanguage": "",
    "isReply": False,
    "source": 1,
    "questionText": "What is the capital of France?",
    "stream": True,
    "taskDefinitionType": "",
    "extra": None,
    "sessionType": "chat",
    "targetAgent": "",
    "pluginPayloadConfig": None,
    "mode": "normal",
    "shellType": "",
    "customModel": None,
}, 4))

# Wait for step_end
print("[*] Waiting for step_end...")
ws.settimeout(60)
got_step_end = False
while not got_step_end:
    try:
        raw = ws.recv()
    except websocket.WebSocketTimeoutException:
        break
    except: break
    for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
        method = m.get("method", "")
        params = m.get("params", {})
        if method == "chat/process_step_callback":
            step = params.get("step", "")
            print(f"    step: {step}")
            if step == "step_end" and params.get("requestId") == request_id:
                got_step_end = True
                print("    GOT step_end!")
        elif method:
            print(f"    push: {method[:60]}")
        elif "result" in m:
            print(f"    resp: {json.dumps(m['result'], ensure_ascii=False)[:150]}")

if got_step_end:
    # Send trigger
    trigger_id = uuid.uuid4().hex
    ws.send(make_frame("chat/ask", {
        "requestId": trigger_id,
        "chatTask": "FREE_INPUT",
        "chatContext": None, "sessionId": "", "codeLanguage": "",
        "isReply": True, "source": 1, "questionText": "OK",
        "stream": True, "taskDefinitionType": "", "extra": None,
        "sessionType": "chat", "targetAgent": "",
        "pluginPayloadConfig": None, "mode": "normal",
        "shellType": "", "customModel": None,
    }, 5))

    # Collect answer
    answer = []
    ws.settimeout(10)
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            raw = ws.recv()
        except websocket.WebSocketTimeoutException:
            if answer:
                break
            else:
                continue
        except: break
        for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
            if m.get("method") == "chat/answer":
                t = m.get("params", {}).get("text", "")
                if t: answer.append(t); print(f"    answer: {t[:100]}")

    print(f"\n=== ANSWER: {''.join(answer)[:500]} ===")

print(f"\n=== ALL Frida Events ({len(events)}) ===")
for e in events:
    t = e.get('type','?')
    if t in ('connect', 'sni', 'http', 'http_recv'):
        print(f"  [{t}] {json.dumps(e, ensure_ascii=False)[:300]}")

ws.close()
session.detach()
# Keep Lingma running for future tests
print("[*] Done! (Lingma still running)")
