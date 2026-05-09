"""Complete chat flow with Frida — exact copy of lingma_client.py"""
import frida
import json
import os
import time
import uuid
import websocket

SCRIPT_PATH = os.path.join(os.path.dirname(__file__), 'frida_minimal_hook.js')

with open(SCRIPT_PATH, 'r') as f:
    hook_js = f.read()

events = []
def on_message(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']
        t = p.get('type','?')
        if t == 'sni': print(f"[SNI] {p['sni']}")
        elif t == 'connect': print(f"[CONNECT] {p['ip']}:{p['port']}")
        elif t == 'http': print(f"[HTTP>>] len={p.get('len')} {p.get('data','')[:200]}")
        elif t == 'http_recv': print(f"[<<HTTP] len={p.get('len')} {p.get('data','')[:200]}")
        events.append(p)
    elif msg['type'] == 'log':
        l = msg['payload']
        if any(x in l for x in ['SNI','CONNECT','HTTP','TLS']):
            print(f"[Frida] {l[:300]}")

print("[*] Attaching Frida...")
device = frida.get_local_device()
lingma = [p for p in device.enumerate_processes() if p.name and 'lingma' in p.name.lower()]
session = device.attach(lingma[0].pid)
script = session.create_script(hook_js)
script.on('message', on_message)
script.load()
time.sleep(1)

def make_frame(method, params=None, msg_id=1):
    body = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        body["params"] = params
    body["id"] = msg_id
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
    """Parse multiple LSP frames from one recv."""
    msgs = []
    offset = 0
    marker = b"\r\n\r\n"
    while offset < len(payload):
        header_end = payload.find(marker, offset)
        if header_end < 0: break
        header = payload[offset:header_end].decode("ascii", errors="replace")
        content_length = None
        for line in header.split("\r\n"):
            if line.lower().startswith("content-length:"):
                content_length = int(line.split(":", 1)[1].strip())
                break
        if content_length is None: break
        body_start = header_end + len(marker)
        body_end = body_start + content_length
        if body_end > len(payload): break
        msgs.append(json.loads(payload[body_start:body_end]))
        offset = body_end
    return msgs

workspace = "file:///C:/test"
print("[*] Connecting WebSocket...")
ws = websocket.create_connection("ws://127.0.0.1:37010", timeout=10)

# Initialize (matching _initialize)
print("[1] initialize...")
ws.send(make_frame("initialize", {
    "processId": None,
    "clientInfo": {"name": "lingma-client", "version": "1.0"},
    "rootUri": workspace,
    "capabilities": {},
    "workspaceFolders": [{"uri": workspace, "name": "workspace"}],
}, 1))
ws.settimeout(3)
try:
    raw = ws.recv()
    for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
        print(f"    init: {json.dumps(m, ensure_ascii=False)[:200]}")
except: pass

# Check auth
print("[2] auth/status...")
ws.send(make_frame("auth/status", {}, 2))
ws.settimeout(3)
try:
    raw = ws.recv()
    for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
        r = m.get('result', {})
        print(f"    auth: status={r.get('status')}, name={r.get('name')}, id={r.get('id')}")
except: pass

# Step 1: Send the real question
request_id = uuid.uuid4().hex
print(f"\n[3] chat/ask (question, id={request_id})...")
chat_params = {
    "requestId": request_id,
    "chatTask": "FREE_INPUT",
    "chatContext": None,
    "sessionId": "",
    "codeLanguage": "",
    "isReply": False,
    "source": 1,
    "questionText": "Say hello",
    "stream": True,
    "taskDefinitionType": "",
    "extra": None,
    "sessionType": "chat",
    "targetAgent": "",
    "pluginPayloadConfig": None,
    "mode": "normal",
    "shellType": "",
    "customModel": None,
}
ws.send(make_frame("chat/ask", chat_params, 3))

# Step 2: Wait for step_end
print("[*] Waiting for step_end (watch for Frida SNI/CONNECT)...")
got_step_end = False
deadline = time.time() + 60
ws.settimeout(10)
while time.time() < deadline and not got_step_end:
    try:
        raw = ws.recv()
    except websocket.WebSocketTimeoutException:
        print("    (timeout tick)")
        continue
    except Exception as e:
        print(f"    error: {e}")
        break

    data = raw.encode('utf-8') if isinstance(raw, str) else raw
    for msg in parse_frames(data):
        method = msg.get("method", "")
        params = msg.get("params", {})
        if method == "chat/process_step_callback":
            step = params.get("step", "")
            print(f"    step: {step} requestId={params.get('requestId','')[:16]}")
            if step == "step_end" and params.get("requestId") == request_id:
                got_step_end = True
                print("    >>> GOT step_end!")
        elif method:
            print(f"    push: {method[:60]}")
        elif "result" in msg:
            print(f"    resp: {json.dumps(msg['result'], ensure_ascii=False)[:150]}")
        elif "error" in msg:
            print(f"    err: {msg['error']}")

if not got_step_end:
    print("[!] No step_end received!")
    ws.close()
    script.unload()
    session.detach()
    exit(1)

# Step 3: Send trigger (isReply=True, questionText="OK")
trigger_id = uuid.uuid4().hex
print(f"\n[4] chat/ask (trigger, id={trigger_id})...")
trigger_params = dict(chat_params)
trigger_params["requestId"] = trigger_id
trigger_params["questionText"] = "OK"
trigger_params["isReply"] = True
ws.send(make_frame("chat/ask", trigger_params, 4))

# Collect answer
print("[*] Collecting answer...")
full_text = []
deadline = time.time() + 45
ws.settimeout(10)
last_answer_time = None
while time.time() < deadline:
    try:
        raw = ws.recv()
    except websocket.WebSocketTimeoutException:
        if last_answer_time and time.time() - last_answer_time > 3:
            break
        continue
    except Exception as e:
        break

    data = raw.encode('utf-8') if isinstance(raw, str) else raw
    for msg in parse_frames(data):
        method = msg.get("method", "")
        params = msg.get("params", {})
        if method == "chat/answer" and params.get("requestId") == trigger_id:
            text = params.get("text", "")
            if text:
                full_text.append(text)
                last_answer_time = time.time()
                print(f"    answer chunk: {text[:100]}")
        elif method:
            print(f"    push: {method[:60]}")

answer = "".join(full_text)
print(f"\n=== ANSWER: {answer[:500]} ===")

print(f"\n=== Frida Events ({len(events)}) ===")
for e in events:
    t = e.get('type','?')
    if t in ('connect', 'sni', 'http', 'http_recv'):
        print(f"  [{t}] {json.dumps(e, ensure_ascii=False)[:250]}")

ws.close()
script.unload()
session.detach()
print("[*] Done!")
