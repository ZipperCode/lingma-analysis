"""
Frida script: Start Lingma, attach, hook HTTP functions,
trigger auth/refreshToken via LSP WebSocket, capture all network activity.

Goal: Find what REMOTE HTTP endpoint the local Lingma process actually calls
when performing token refresh.
"""
import frida
import time
import json
import sys
import subprocess
import os
import hashlib
import struct
import threading
from datetime import datetime, timezone
import websocket

# Use original Lingma with 'start' subcommand
LINGMA_EXE = "C:/Users/Zipper/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe"
LINGMA_CMD = [LINGMA_EXE, "start"]
LSP_PORT = 37010
CALLBACK_PORT = 37510

# ============================================================
# Frida Hook Script (JavaScript)
# ============================================================
HOOK_SCRIPT = r"""
'use strict';

var base = null;
var hooked = {};

// Find Lingma module
Process.enumerateModules().forEach(function(m) {
    if (m.name.toLowerCase().indexOf('lingma') >= 0) {
        base = m.base;
        console.log('[Module] ' + m.name + ' base=' + base + ' size=' + m.size.toString(16));
    }
});

if (!base) {
    console.log('[WARN] Lingma module not found by name, using main module');
    base = Process.mainModule.base;
    console.log('[Module] main base=' + base);
}

// ============================================================
// Hook 1: WSASend — capture ALL socket writes (including TLS)
// ============================================================
var ws2 = Process.getModuleByName('ws2_32.dll');
var ws2exports = ws2.enumerateExports();

function findExport(name) {
    var results = ws2exports.filter(function(e) { return e.name === name; });
    return results.length > 0 ? results[0].address : null;
}

// Hook connect — track what servers Lingma talks to
var connectAddr = findExport('connect');
if (connectAddr) {
    Interceptor.attach(connectAddr, {
        onEnter: function(args) {
            var sockfd = args[0].toInt32();
            var addr = args[1];
            try {
                var family = addr.readU16();
                if (family === 2) { // AF_INET
                    var port = addr.add(2).readU16();
                    port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                    var ip = addr.add(4).readU8() + '.' + addr.add(5).readU8() + '.' +
                            addr.add(6).readU8() + '.' + addr.add(7).readU8();
                    var ts = new Date().toISOString();
                    console.log('[CONNECT] ' + ts + ' -> ' + ip + ':' + port);
                    send({type: 'connect', ip: ip, port: port, ts: ts});
                }
            } catch(e) {}
        }
    });
    console.log('[Hook] connect OK');
}

// Hook WSASend — capture all data sent
var wsasendAddr = findExport('WSASend');
if (wsasendAddr) {
    Interceptor.attach(wsasendAddr, {
        onEnter: function(args) {
            var sockfd = args[0].toInt32();
            var lpBuffers = args[1];
            var dwBufferCount = args[2].toInt32();

            for (var i = 0; i < dwBufferCount && i < 16; i++) {
                var buf = lpBuffers.add(i * 16); // WSABUF is 16 bytes (len:8, buf:8)
                var len = buf.readUInt();
                var ptr = buf.add(8).readPointer();

                if (len > 0 && len < 200000) {
                    try {
                        var data = ptr.readByteArray(Math.min(len, 2000));
                        var arr = new Uint8Array(data);

                        // Check if it's plaintext HTTP
                        var header = '';
                        for (var j = 0; j < Math.min(arr.length, 12); j++) {
                            var c = arr[j];
                            if (c >= 32 && c < 127) header += String.fromCharCode(c);
                            else header += '\\x' + c.toString(16);
                        }

                        var isHttp = false;
                        var preview = '';
                        for (var j = 0; j < Math.min(arr.length, 200); j++) {
                            var c = arr[j];
                            if (c >= 32 && c < 127) preview += String.fromCharCode(c);
                            else if (c === 10 || c === 13) preview += String.fromCharCode(c);
                        }

                        if (preview.indexOf('POST') >= 0 || preview.indexOf('GET') >= 0 ||
                            preview.indexOf('HTTP/') >= 0 || preview.indexOf('Host:') >= 0 ||
                            preview.indexOf('Content-Length') >= 0 || preview.indexOf('Authorization') >= 0 ||
                            preview.indexOf('COSY.') >= 0 || preview.indexOf('Signature') >= 0) {
                            isHttp = true;
                            console.log('[WSASend HTTP] fd=' + sockfd + ' len=' + len);
                            console.log('---BEGIN---');
                            console.log(preview.substring(0, 5000));
                            console.log('---END---');
                            send({type: 'http_send', len: len, preview: preview.substring(0, 5000)});
                        }

                        // Check for TLS ClientHello (record type 0x16, version 0x0301/0x0303)
                        if (arr.length > 5 && arr[0] === 0x16 && arr[1] === 0x03) {
                            var tlsVer = arr[1].toString(16) + '.' + arr[2].toString(16);
                            console.log('[WSASend TLS] fd=' + sockfd + ' len=' + len + ' ver=0x' + tlsVer);

                            // Extract SNI from ClientHello
                            // Skip: record header(5) + handshake header(4) + client_version(2) + random(32) + session_id_len(1+var) + cipher_suites_len(2+var) + compression_len(1+var)
                            var pos = 5 + 4 + 2 + 32; // skip to session_id
                            if (pos < arr.length) {
                                var sidLen = arr[pos];
                                pos += 1 + sidLen; // skip session_id
                                if (pos + 2 < arr.length) {
                                    var csLen = (arr[pos] << 8) | arr[pos+1];
                                    pos += 2 + csLen; // skip cipher_suites
                                    if (pos + 1 < arr.length) {
                                        var compLen = arr[pos];
                                        pos += 1 + compLen; // skip compression
                                        // Now at extensions
                                        if (pos + 2 < arr.length) {
                                            var extLen = (arr[pos] << 8) | arr[pos+1];
                                            pos += 2;
                                            var extEnd = pos + extLen;
                                            while (pos + 4 < extEnd && pos + 4 < arr.length) {
                                                var extType = (arr[pos] << 8) | arr[pos+1];
                                                var extDataLen = (arr[pos+2] << 8) | arr[pos+3];
                                                pos += 4;
                                                if (extType === 0x0000 && pos + 2 < arr.length && pos + 2 < extEnd) {
                                                    // SNI extension
                                                    var sniListLen = (arr[pos] << 8) | arr[pos+1];
                                                    pos += 2;
                                                    if (pos + 3 < arr.length && arr[pos] === 0x00) {
                                                        var nameLen = (arr[pos+1] << 8) | arr[pos+2];
                                                        pos += 3;
                                                        if (pos + nameLen < arr.length) {
                                                            var sni = '';
                                                            for (var k = 0; k < nameLen; k++) {
                                                                sni += String.fromCharCode(arr[pos+k]);
                                                            }
                                                            console.log('[TLS SNI] ' + sni);
                                                            send({type: 'tls_sni', sni: sni, len: len});
                                                        }
                                                    }
                                                    break;
                                                }
                                                pos += extDataLen;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } catch(e) {
                        console.log('[WSASend error] ' + e.message);
                    }
                }
            }
        }
    });
    console.log('[Hook] WSASend OK');
}

// ============================================================
// Hook 2: Go HTTP functions — find by scanning exports
// ============================================================
var lingmaMod = null;
Process.enumerateModules().forEach(function(m) {
    if (m.name.toLowerCase().indexOf('lingma') >= 0 || m.name.toLowerCase().indexOf('.exe') >= 0) {
        lingmaMod = m;
    }
});

if (lingmaMod) {
    var exports = lingmaMod.enumerateExports();
    console.log('[Exports] Lingma has ' + exports.length + ' exports');

    // Look for HTTP-related Go exports
    var httpExports = [];
    exports.forEach(function(e) {
        var name = e.name || '';
        if (name.indexOf('RoundTrip') >= 0 ||
            name.indexOf('http') >= 0 ||
            name.indexOf('Do') >= 0 && name.indexOf('Request') >= 0 ||
            name.indexOf('writeHeader') >= 0 ||
            name.indexOf('writeRequest') >= 0 ||
            name.indexOf('NewRequest') >= 0 ||
            name.indexOf('refreshToken') >= 0 ||
            name.indexOf('RefreshToken') >= 0 ||
            name.indexOf('refresh_token') >= 0 ||
            name.indexOf('doRefresh') >= 0 ||
            name.indexOf('remoting') >= 0 ||
            name.indexOf('remoting/api') >= 0 ||
            name.indexOf('cosy') >= 0) {
            httpExports.push(e);
            console.log('[GoExport] ' + name + ' @ ' + e.address);
        }
    });

    if (httpExports.length > 0) {
        // Hook all HTTP-related exports
        httpExports.forEach(function(exp) {
            try {
                Interceptor.attach(exp.address, {
                    onEnter: function(args) {
                        this.fnName = exp.name;
                        this.enterTs = Date.now();
                        // Try to read Go string arguments (args[0]=ptr, args[1]=len pattern)
                        var summary = '';
                        for (var i = 0; i < 8; i += 2) {
                            try {
                                var ptr = args[i];
                                var len = args[i+1];
                                if (ptr && !ptr.isNull() && len && len.toInt32() > 0 && len.toInt32() < 10000) {
                                    var s = ptr.readUtf8String(Math.min(len.toInt32(), 200));
                                    summary += ' arg' + (i/2) + '="' + s + '"';
                                }
                            } catch(e) {}
                        }
                        if (summary) {
                            console.log('[Go:' + exp.name + ']' + summary);
                            send({type: 'go_call', fn: exp.name, args: summary});
                        }
                    },
                    onLeave: function(retval) {
                        var elapsed = Date.now() - this.enterTs;
                        if (elapsed > 100) {
                            console.log('[Go:' + this.fnName + '] took ' + elapsed + 'ms');
                        }
                    }
                });
                console.log('[GoHook] ' + exp.name + ' hooked');
            } catch(e) {
                console.log('[GoHook] FAILED ' + exp.name + ': ' + e.message);
            }
        });
    } else {
        console.log('[GoExports] No HTTP-related exports found');
    }
}

console.log('[Frida] All hooks installed, ready for auth/refreshToken test');
send({type: 'ready'});
"""

# ============================================================
# WebSocket LSP Client (uses websocket-client library)
# ============================================================
def make_lsp_frame(method, params=None, msg_id=1):
    """Create LSP-framed JSON-RPC message string."""
    body = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        body["params"] = params
    body["id"] = msg_id
    content = json.dumps(body, ensure_ascii=False)
    frame = f"Content-Length: {len(content.encode('utf-8'))}\r\n\r\n{content}"
    return frame

def parse_lsp_frame(text):
    """Parse LSP Content-Length framed message, return JSON body."""
    if '\r\n\r\n' in text:
        headers, body = text.split('\r\n\r\n', 1)
        for line in headers.split('\r\n'):
            if line.lower().startswith('content-length:'):
                length = int(line.split(':')[1].strip())
                return json.loads(body[:length])
        return json.loads(body)
    return json.loads(text)

def on_frida_message(msg, data):
    """Handle messages from Frida JS"""
    if msg['type'] == 'send':
        payload = msg.get('payload', {})
        ptype = payload.get('type', '')
        if ptype == 'ready':
            print("[Frida] Hooks ready!")
        elif ptype == 'connect':
            print(f"[NET] Connect -> {payload['ip']}:{payload['port']}")
        elif ptype == 'tls_sni':
            print(f"[TLS] SNI: {payload['sni']}")
        elif ptype == 'http_send':
            print(f"[HTTP] len={payload['len']}")
            print(payload.get('preview', '')[:2000])
        elif ptype == 'go_call':
            print(f"[Go] {payload['fn']}: {payload.get('args', '')[:500]}")
        else:
            print(f"[Frida] {payload}")
    elif msg['type'] == 'error':
        print(f"[Frida ERROR] {msg.get('description', '')}")
    elif msg['type'] == 'log':
        print(f"[Frida LOG] {msg['payload']}")

def main():
    print("=" * 60)
    print("Lingma OAuth Token Refresh — Network Trace")
    print("=" * 60)

    # Step 1: Check if Lingma is already running
    device = frida.get_local_device()
    processes = device.enumerate_processes()
    lingma_procs = [p for p in processes if p.name and 'lingma' in p.name.lower()]

    lingma_process = None
    if lingma_procs:
        print(f"[*] Lingma already running (PID: {lingma_procs[0].pid})")
        pid = lingma_procs[0].pid
    else:
        # Step 2: Start Lingma
        print(f"[*] Starting Lingma: {' '.join(LINGMA_CMD)}")
        lingma_process = subprocess.Popen(
            LINGMA_CMD,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=os.path.dirname(LINGMA_EXE)
        )
        print(f"[*] Lingma PID: {lingma_process.pid}")

        # Wait for LSP port to be available
        print("[*] Waiting for LSP port 37010...")
        for i in range(60):
            time.sleep(1)
            try:
                s = socket.create_connection(('127.0.0.1', LSP_PORT), timeout=1)
                s.close()
                print(f"[*] LSP ready after {i+1}s")
                break
            except:
                if i % 5 == 0:
                    print(f"   waiting... ({i}s)")
        else:
            print("[!] LSP not ready after 60s")
            if lingma_process:
                lingma_process.terminate()
            return

        pid = lingma_process.pid

    # Step 3: Attach Frida
    print(f"[*] Attaching Frida to PID {pid}...")
    try:
        session = device.attach(pid)
    except Exception as e:
        print(f"[!] Frida attach failed: {e}")
        print("[*] Trying with spawn...")
        pid = device.spawn(LINGMA_CMD)
        session = device.attach(pid)
        device.resume(pid)
        print(f"[*] Spawned PID {pid}")

    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_frida_message)
    script.load()

    # Wait for Frida hooks to be ready
    time.sleep(3)

    # Step 4: Connect to LSP WebSocket and trigger auth/refreshToken
    print("\n[*] Connecting to LSP (127.0.0.1:37010)...")

    # Load token data
    from Crypto.Cipher import AES
    import base64

    cache_dir = os.path.expandvars(r"C:\Users\Zipper\.lingma\cache")

    # Read machine_id from cache/id
    id_file = os.path.join(cache_dir, "id")
    with open(id_file, 'r') as f:
        machine_id = f.read().strip()
    print(f"[*] machine_id: {machine_id}")

    # Read and base64-decode encrypted user data
    user_file = os.path.join(cache_dir, "user")
    with open(user_file, 'rb') as f:
        encrypted_user_raw = f.read().strip()
    encrypted_user = base64.b64decode(encrypted_user_raw)

    # Decrypt user cache with AES-128-CBC
    key = machine_id[:16].encode('utf-8')
    # PKCS7 padding — pycryptodome handles it with proper unpadding
    from Crypto.Util.Padding import unpad
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    decrypted = unpad(cipher.decrypt(encrypted_user), 16)
    user_data = json.loads(decrypted.decode('utf-8'))

    security_oauth_token = user_data.get('security_oauth_token', '')
    refresh_token = user_data.get('refresh_token', '')
    expire_time = user_data.get('expire_time', '')

    print(f"[*] security_oauth_token: {security_oauth_token[:20]}...")
    print(f"[*] refresh_token: {refresh_token[:20]}...")
    print(f"[*] expire_time: {expire_time}")

    ws = None
    try:
        print("\n[*] Connecting WebSocket to ws://127.0.0.1:37010 ...")
        ws = websocket.create_connection("ws://127.0.0.1:37010", timeout=10)
        print("[*] WebSocket connected!")

        # Step 1: Send initialize (LSP requires it)
        print("\n[1] Sending initialize...")
        init_frame = make_lsp_frame("initialize", {
            "processId": os.getpid(),
            "clientInfo": {"name": "frida-test", "version": "1.0.0"},
            "locale": "zh-CN",
            "rootPath": "C:/test",
            "capabilities": {}
        }, 1)
        ws.send(init_frame)
        time.sleep(1)

        # Read initialize response
        ws.settimeout(3)
        try:
            raw = ws.recv()
            init_resp = parse_lsp_frame(raw)
            print(f"[*] Initialize OK: {json.dumps(init_resp, ensure_ascii=False)[:300]}")
        except Exception as e:
            print(f"[*] Initialize read: {e}")

        # Step 2: Send initialized notification
        print("\n[2] Sending initialized...")
        init_done = make_lsp_frame("initialized", {}, 2)
        ws.send(init_done)

        # Step 3: Check auth status first
        print("\n[3] Checking auth/status...")
        auth_status = make_lsp_frame("auth/getStatus", {}, 3)
        ws.send(auth_status)
        ws.settimeout(5)
        try:
            raw = ws.recv()
            status_resp = parse_lsp_frame(raw)
            print(f"[*] Auth status: {json.dumps(status_resp, ensure_ascii=False)[:500]}")
        except Exception as e:
            print(f"[*] Auth status read: {e}")

        # Step 4: NOW trigger auth/refreshToken — this is what we want to trace!
        print("\n[4] >>> Sending auth/refreshToken <<<")
        print("    (Frida hooks are active — watch for HTTP requests!)")
        refresh_frame = make_lsp_frame("auth/refreshToken", {
            "securityOauthToken": security_oauth_token,
            "refreshToken": refresh_token,
            "tokenExpireTime": expire_time
        }, 4)
        ws.send(refresh_frame)

        # Read refreshToken response
        ws.settimeout(20)
        try:
            raw = ws.recv()
            refresh_resp = parse_lsp_frame(raw)
            print(f"\n[*] refreshToken response:")
            print(json.dumps(refresh_resp, ensure_ascii=False, indent=2)[:1000])
        except Exception as e:
            print(f"[*] refreshToken read: {e}")

        # Wait for any async network activity
        print("\n[*] Waiting 20s for async network activity...")
        for i in range(20):
            time.sleep(1)
            # Try to read any additional messages
            try:
                raw = ws.recv()
                extra = parse_lsp_frame(raw)
                print(f"[*] Extra msg: {json.dumps(extra, ensure_ascii=False)[:300]}")
            except:
                pass

    except Exception as e:
        print(f"[!] WebSocket error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        if ws:
            ws.close()

    print("\n" + "=" * 60)
    print("[*] Trace complete. Check output above for:")
    print("    - [CONNECT] — TCP connections made by Lingma")
    print("    - [TLS SNI] — TLS Server Name Indication (hostnames)")
    print("    - [HTTP] — Plaintext HTTP data captured")
    print("    - [Go] — Go function calls with arguments")
    print("=" * 60)

    # Cleanup
    script.unload()
    session.detach()

    if lingma_process:
        print("[*] Terminating Lingma...")
        lingma_process.terminate()
        lingma_process.wait(timeout=5)

if __name__ == '__main__':
    main()
