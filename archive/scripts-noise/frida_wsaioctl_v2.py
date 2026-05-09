"""Hook WSAIoctl — FIXED signed/unsigned comparison for SIO_GET_EXTENSION_FUNCTION_POINTER."""
import frida
import json
import time
import uuid
import websocket
import sys

SCRIPT = r"""
'use strict';

var ws2 = Process.getModuleByName('ws2_32.dll');
var ws2exports = ws2.enumerateExports();

// SIO codes as UNSIGNED 32-bit
var SIO_GET_EXTENSION = 0xC8000006;
var SIO_SET_COMPATIBILITY = 0x98000004;

function toUnsigned(v) {
    return v >>> 0;
}

// ===== Hook WSAIoctl — capture ConnectEx function pointer =====
var wsaioctl = ws2exports.filter(function(e) { return e.name === 'WSAIoctl'; });
if (wsaioctl.length > 0) {
    Interceptor.attach(wsaioctl[0].address, {
        onEnter: function(args) {
            this.code = args[1].toInt32();
            this.codeUnsigned = toUnsigned(this.code);
            this.sock = args[0].toInt32();
            this.lpvInBuffer = args[2];
            this.cbInBuffer = args[3].toInt32();
            this.lpvOutBuffer = args[4];
            this.lpcbBytesReturned = args[5];

            var codeHex = '0x' + this.codeUnsigned.toString(16).toUpperCase();

            if (this.codeUnsigned === SIO_GET_EXTENSION) {
                console.log('[WSAIoctl] SIO_GET_EXTENSION_FUNCTION_POINTER fd=' + this.sock);
                // Read the GUID to identify which function
                try {
                    var guidBytes = this.lpvInBuffer.readByteArray(this.cbInBuffer);
                    if (guidBytes) {
                        var hex = '';
                        var arr = new Uint8Array(guidBytes);
                        for (var i = 0; i < Math.min(arr.length, 16); i++) {
                            hex += ('0' + arr[i].toString(16)).slice(-2);
                        }
                        // Known GUIDs:
                        // ConnectEx: 25a207b9-ddf3-4660-8ee9-76e58c74063e
                        console.log('  [GUID] hex=' + hex);
                        send({type: 'wsaioctl_guid', fd: this.sock, guid_hex: hex, size: this.cbInBuffer});

                        if (hex === 'b907a225f3dd60468ee976e58c74063e') {
                            console.log('  *** THIS IS ConnectEx GUID! ***');
                        }
                    }
                } catch(e) {
                    console.log('  [GUID read err] ' + e);
                }
            } else if (this.codeUnsigned === SIO_SET_COMPATIBILITY) {
                console.log('[WSAIoctl] SIO_SET_COMPATIBILITY_MODE fd=' + this.sock);
            } else {
                console.log('[WSAIoctl] fd=' + this.sock + ' code=' + codeHex);
            }
        },
        onLeave: function(retval) {
            if (this.codeUnsigned === SIO_GET_EXTENSION) {
                console.log('[WSAIoctl] GET_EXTENSION ret=' + retval);
                try {
                    if (this.lpvOutBuffer && !this.lpvOutBuffer.isNull()) {
                        var funcPtr = this.lpvOutBuffer.readPointer();
                        if (funcPtr && !funcPtr.isNull()) {
                            var modName = 'unknown';
                            Process.enumerateModules().forEach(function(m) {
                                if (funcPtr.compare(m.base) >= 0 && funcPtr.compare(m.base.add(m.size)) < 0) {
                                    modName = m.name + '+' + funcPtr.sub(m.base).toString(16);
                                }
                            });
                            console.log('[WSAIoctl] Got function @ ' + modName);
                            send({type: 'extension_ptr', fd: this.sock, module: modName, ptr: funcPtr.toString()});

                            // Hook this function (should be ConnectEx)
                            try {
                                Interceptor.attach(funcPtr, {
                                    onEnter: function(args) {
                                        var s = args[0].toInt32();
                                        console.log('[ConnectEx-DYNAMIC] fd=' + s);
                                        send({type: 'connect_ex_call', fd: s});
                                        try {
                                            var addr = args[1];
                                            if (addr && !addr.isNull()) {
                                                var af = addr.readU16();
                                                if (af === 2) {
                                                    var port = addr.add(2).readU16();
                                                    port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                                                    var ip = addr.add(4).readU8()+'.'+addr.add(5).readU8()+'.'+addr.add(6).readU8()+'.'+addr.add(7).readU8();
                                                    console.log('  -> ' + ip + ':' + port);
                                                    send({type: 'connect', fn: 'ConnectEx(dynamic)', ip: ip, port: port});
                                                }
                                            }
                                        } catch(e) {}
                                    }
                                });
                                console.log('[Hook] ConnectEx (dynamic) SUCCESS');
                            } catch(e) {
                                console.log('[Hook FAIL] ConnectEx dynamic: ' + e);
                            }
                        }
                    }
                } catch(e) {
                    console.log('[Output read err] ' + e);
                }
            }
        }
    });
    console.log('[Hook] WSAIoctl OK');
}

// ===== Hook WSASocketW =====
var wsaSock = ws2exports.filter(function(e) { return e.name === 'WSASocketW'; });
if (wsaSock.length > 0) {
    Interceptor.attach(wsaSock[0].address, {
        onEnter: function(args) {
            this.af = args[0].toInt32();
            this.type = args[1].toInt32();
            this.protocol = args[2].toInt32();
        },
        onLeave: function(retval) {
            var sock = retval.toInt32();
            if (sock > 0 && sock < 65535) {
                console.log('[WSASocketW] fd=' + sock + ' af=' + this.af + ' type=' + this.type + ' proto=' + this.protocol);
                send({type: 'socket', fd: sock, af: this.af, type: this.type, proto: this.protocol});
            }
        }
    });
    console.log('[Hook] WSASocketW OK');
}

// ===== Hook GetAddrInfoW =====
var gaiw = ws2exports.filter(function(e) { return e.name === 'GetAddrInfoW'; });
if (gaiw.length > 0) {
    Interceptor.attach(gaiw[0].address, {
        onEnter: function(args) {
            try {
                var host = args[0].readUtf16String();
                if (host && host.length > 0 && host !== '0.0.0.0') {
                    console.log('[GetAddrInfoW] "' + host + '"');
                    send({type: 'dns', fn: 'GetAddrInfoW', host: host});
                }
            } catch(e) {
                try {
                    // Manual wide char reading
                    var bytes = args[0].readByteArray(128);
                    if (bytes) {
                        var arr = new Uint8Array(bytes);
                        var chars = '';
                        for (var i = 0; i < arr.length; i += 2) {
                            if (arr[i] === 0 && arr[i+1] === 0) break;
                            chars += String.fromCharCode(arr[i] | (arr[i+1] << 8));
                        }
                        if (chars.length > 0) {
                            console.log('[GetAddrInfoW] raw="' + chars + '"');
                            send({type: 'dns', fn: 'GetAddrInfoW', host: chars});
                        }
                    }
                } catch(e2) {}
            }
        }
    });
}

// ===== Hook send/WSASend to track data =====
['send', 'WSASend'].forEach(function(name) {
    var f = ws2exports.filter(function(e) { return e.name === name; });
    if (f.length > 0) {
        Interceptor.attach(f[0].address, {
            onEnter: function(args) {
                this.sock = args[0].toInt32();
                if (name === 'send') {
                    this.len = args[2].toInt32();
                    this.buf = args[1];
                } else {
                    try {
                        var count = args[2].toInt32();
                        for (var i = 0; i < count && i < 4; i++) {
                            var wsaBuf = args[1].add(i * 16);
                            this.len = wsaBuf.readUInt();
                            if (this.len > 0) break;
                        }
                    } catch(e) { this.len = 0; }
                }
                if (this.len > 0 && this.len < 65536) {
                    this.hasData = true;
                }
            },
            onLeave: function(retval) {
                if (this.hasData && this.len > 5) {
                    console.log('[SEND] fd=' + this.sock + ' len=' + this.len);
                    send({type: 'send', fd: this.sock, len: this.len});
                }
            }
        });
    }
});

// ===== Hook WSARecv to capture incoming data =====
var wsarecv = ws2exports.filter(function(e) { return e.name === 'WSARecv'; });
if (wsarecv.length > 0) {
    Interceptor.attach(wsarecv[0].address, {
        onEnter: function(args) {
            this.sock = args[0].toInt32();
        },
        onLeave: function(retval) {
            if (retval.toInt32() === 0) {
                // Data was received, try to read it
                try {
                    // WSARecv buffers are filled by the completion routine or I/O completion
                    // The data is in the buffers passed to WSARecv
                    // For now just log
                } catch(e) {}
            }
        }
    });
}

// ===== Hook recv =====
var recvFunc = ws2exports.filter(function(e) { return e.name === 'recv'; });
if (recvFunc.length > 0) {
    Interceptor.attach(recvFunc[0].address, {
        onEnter: function(args) {
            this.sock = args[0].toInt32();
            this.buf = args[1];
            this.maxLen = args[2].toInt32();
        },
        onLeave: function(retval) {
            var len = retval.toInt32();
            if (len > 10 && len < 65536 && this.buf && !this.buf.isNull()) {
                console.log('[RECV] fd=' + this.sock + ' len=' + len);
                send({type: 'recv', fd: this.sock, len: len});
            }
        }
    });
    console.log('[Hook] recv OK');
}

console.log('[ALL HOOKS READY]');
send({type: 'ready'});
"""

# ===== WebSocket helpers =====
def make_frame(method, params=None, msg_id=1):
    body = {"jsonrpc": "2.0", "method": method, "id": msg_id}
    if params is not None: body["params"] = params
    content = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    return f"Content-Length: {len(content.encode('utf-8'))}\r\n\r\n{content}"

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

# ===== Main =====
events = []

def on_msg(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']; t = p.get('type','?')
        if t == 'connect':
            print(f"[CONNECT] {p.get('fn','?')} -> {p.get('ip','?')}:{p.get('port','?')}")
        elif t == 'connect_ex_call':
            print(f"[ConnectEx CALL] fd={p.get('fd','?')}")
        elif t == 'extension_ptr':
            print(f"[EXTENSION] fd={p['fd']} -> {p['module']}")
        elif t == 'dns':
            print(f"[DNS] {p.get('fn','?')}: {p.get('host','?')}")
        elif t == 'socket':
            print(f"[SOCKET] fd={p['fd']} af={p['af']} type={p['type']} proto={p['proto']}")
        elif t == 'send':
            print(f"[SEND] fd={p['fd']} len={p['len']}")
        elif t == 'recv':
            print(f"[RECV] fd={p['fd']} len={p['len']}")
        elif t == 'wsaioctl_guid':
            print(f"[GUID] fd={p['fd']} hex={p['guid_hex']}")
        elif t == 'ready':
            print("[*] Ready!")
        else:
            print(f"[{t}] {json.dumps(p, ensure_ascii=False)[:200]}")
        events.append(p)
    elif msg['type'] == 'log':
        l = msg['payload']
        if any(x in l for x in ['WSAIoctl', 'ConnectEx', 'GetAddrInfo', 'WSASocketW', 'SEND', 'RECV', 'ALL HOOKS', 'GUID', 'Got function']):
            print(f"[Frida] {l[:400]}")

# Attach Frida
print("[*] Attaching Frida...")
device = frida.get_local_device()
lingma = [p for p in device.enumerate_processes() if p.name and 'lingma' in p.name.lower()]
pid = lingma[0].pid
print(f"[*] PID: {pid}")

session = device.attach(pid)
script = session.create_script(SCRIPT)
script.on('message', on_msg)
script.load()
time.sleep(2)

# Trigger chat
print("\n[*] Triggering chat...")
ws = websocket.create_connection("ws://127.0.0.1:37010", timeout=10)
ws.send(make_frame("initialize", {
    "processId": None, "clientInfo": {"name": "test", "version": "1.0"},
    "rootUri": "file:///C:/test", "capabilities": {},
    "workspaceFolders": [{"uri": "file:///C:/test", "name": "workspace"}],
}, 1))
ws.settimeout(3)
try: ws.recv()
except: pass

request_id = uuid.uuid4().hex
ws.send(make_frame("chat/ask", {
    "requestId": request_id, "chatTask": "FREE_INPUT",
    "chatContext": None, "sessionId": "", "codeLanguage": "",
    "isReply": False, "source": 1, "questionText": "Say hi",
    "stream": True, "taskDefinitionType": "", "extra": None,
    "sessionType": "chat", "targetAgent": "",
    "pluginPayloadConfig": None, "mode": "normal",
    "shellType": "", "customModel": None,
}, 3))

got_step_end = False
deadline = time.time() + 60
ws.settimeout(5)
while time.time() < deadline and not got_step_end:
    try:
        raw = ws.recv()
    except websocket.WebSocketTimeoutException:
        continue
    except: break
    for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
        if m.get("method") == "chat/process_step_callback":
            step = m.get("params", {}).get("step", "")
            if step == "step_end": got_step_end = True; print("    step_end!")
if got_step_end:
    trigger_id = uuid.uuid4().hex
    ws.send(make_frame("chat/ask", {
        "requestId": trigger_id, "chatTask": "FREE_INPUT",
        "chatContext": None, "sessionId": "", "codeLanguage": "",
        "isReply": True, "source": 1, "questionText": "OK",
        "stream": True, "taskDefinitionType": "", "extra": None,
        "sessionType": "chat", "targetAgent": "",
        "pluginPayloadConfig": None, "mode": "normal",
        "shellType": "", "customModel": None,
    }, 4))
    answer = []
    ws.settimeout(10)
    t0 = time.time()
    while time.time() - t0 < 15:
        try:
            raw = ws.recv()
        except websocket.WebSocketTimeoutException:
            if answer: break
            continue
        except: break
        for m in parse_frames(raw.encode('utf-8') if isinstance(raw, str) else raw):
            if m.get("method") == "chat/answer":
                text = m.get("params", {}).get("text", "")
                if text: answer.append(text)
    print(f"ANSWER: {''.join(answer)[:200]}")
ws.close()
time.sleep(5)

# Summary
print(f"\n=== SUMMARY ({len(events)} events) ===")
for cat in ['dns', 'connect', 'connect_ex_call', 'extension_ptr', 'send', 'recv', 'socket', 'wsaioctl_guid']:
    cat_events = [e for e in events if e.get('type') == cat]
    if cat_events:
        print(f"\n--- {cat} ({len(cat_events)}) ---")
        for e in cat_events[:20]:
            print(f"  {json.dumps(e, ensure_ascii=False)[:300]}")

script.unload()
session.detach()
print("[*] Done!")
