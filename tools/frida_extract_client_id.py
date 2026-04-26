"""Frida script to extract OAuth client_id from Lingma process memory.

Approach: Hook the Go HTTP client when it makes OAuth requests,
or scan memory for client_id patterns.
"""
import frida
import json
import time
import sys

SCRIPT = r"""
'use strict';

// ===== Approach 1: Scan known binary regions for client_id string =====
// The client_id would be populated in memory as a Go string

// ===== Approach 2: Hook WinHttpSendRequest / WinHttpConnect =====
var winhttp = Process.getModuleByName('winhttp.dll');
if (winhttp) {
    var exports = winhttp.enumerateExports();

    // Hook WinHttpConnect to see what hosts are connected to
    var connectFn = exports.filter(function(e) { return e.name === 'WinHttpConnect'; });
    if (connectFn.length > 0) {
        Interceptor.attach(connectFn[0].address, {
            onEnter: function(args) {
                try {
                    var host = args[1].readUtf16String();
                    if (host && host.length > 0) {
                        console.log('[WinHttpConnect] host=' + host);
                        send({type: 'winhttp_connect', host: host});
                    }
                } catch(e) {}
            }
        });
    }

    // Hook WinHttpOpenRequest to see request paths
    var openReq = exports.filter(function(e) { return e.name === 'WinHttpOpenRequest'; });
    if (openReq.length > 0) {
        Interceptor.attach(openReq[0].address, {
            onEnter: function(args) {
                try {
                    var path = args[1].readUtf16String();
                    if (path && path.length > 0 && (
                        path.includes('oauth') || path.includes('client') ||
                        path.includes('token') || path.includes('login') ||
                        path.includes('auth') || path.includes('register')
                    )) {
                        console.log('[WinHttpOpenRequest] path=' + path);
                        send({type: 'winhttp_path', path: path});
                    }
                } catch(e) {}
            }
        });
    }

    // Hook WinHttpSendRequest to capture headers
    var sendReq = exports.filter(function(e) { return e.name === 'WinHttpSendRequest'; });
    if (sendReq.length > 0) {
        Interceptor.attach(sendReq[0].address, {
            onEnter: function(args) {
                try {
                    var headers = args[2].readUtf16String();
                    if (headers && headers.length > 0) {
                        if (headers.includes('client_id') || headers.includes('oauth') ||
                            headers.includes('Cosy-Key') || headers.includes('Authorization')) {
                            console.log('[WinHttpSendRequest] headers snippet: ' + headers.substring(0, 400));
                            send({type: 'winhttp_headers', headers: headers});
                        }
                    }
                } catch(e) {}
            }
        });
    }

    console.log('[Hook] WinHTTP functions OK');
} else {
    console.log('[!] winhttp.dll not loaded');
}

// ===== Approach 3: Hook DNS for oauth-related hosts =====
var ws2 = Process.getModuleByName('ws2_32.dll');
var ws2exports = ws2.enumerateExports();

var getAddrInfoW = ws2exports.filter(function(e) { return e.name === 'GetAddrInfoW'; });
if (getAddrInfoW.length > 0) {
    Interceptor.attach(getAddrInfoW[0].address, {
        onEnter: function(args) {
            try {
                var host = args[0].readUtf16String();
                if (host && host.length > 0) {
                    if (host.includes('oauth') || host.includes('signin') ||
                        host.includes('alibabacloud') || host.includes('aliyun')) {
                        console.log('[GetAddrInfoW] OAUTH HOST: ' + host);
                        send({type: 'dns_oauth', host: host});
                    }
                }
            } catch(e) {}
        }
    });
}

// ===== Approach 4: Hook WSASend to capture OAuth HTTP request data =====
var wsasend = ws2exports.filter(function(e) { return e.name === 'WSASend'; });
if (wsasend.length > 0) {
    Interceptor.attach(wsasend[0].address, {
        onEnter: function(args) {
            this.sock = args[0].toInt32();
            this.buf = args[1];
            this.bufCount = args[2].toInt32();

            try {
                var totalLen = 0;
                for (var i = 0; i < this.bufCount && i < 4; i++) {
                    var wsaBuf = this.buf.add(i * 16);
                    totalLen += wsaBuf.readUInt();
                }

                if (totalLen > 50 && totalLen < 10000) {
                    // Try to read the data
                    try {
                        var data = this.buf.add(8).readByteArray(Math.min(totalLen, 500));
                        if (data) {
                            var text = '';
                            var arr = new Uint8Array(data);
                            for (var j = 0; j < arr.length; j++) {
                                var b = arr[j];
                                text += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
                            }
                            if (text.includes('client_id') || text.includes('oauth') ||
                                text.includes('grant_type') || text.includes('code_verifier') ||
                                text.includes('redirect_uri') || text.includes('refresh_token')) {
                                console.log('[WSASend OAUTH] ' + text.substring(0, 400));
                                send({type: 'wsasend_oauth', data: text});
                            }
                        }
                    } catch(e) {}
                }
            } catch(e) {}
        }
    });
}

console.log('[ALL HOOKS READY]');
send({type: 'ready'});
"""


def main():
    print("[*] Attaching to Lingma...")
    device = frida.get_local_device()

    processes = [p for p in device.enumerate_processes()
                 if p.name and 'lingma' in p.name.lower()]
    if not processes:
        print("[!] Lingma not running")
        sys.exit(1)

    pid = processes[0].pid
    print(f"[*] PID: {pid}")

    session = device.attach(pid)
    script = session.create_script(SCRIPT)

    captures = []

    def on_msg(msg, data):
        if msg['type'] == 'send':
            p = msg['payload']
            t = p.get('type', '?')
            if t == 'ready':
                print("[*] Frida hooks ready!")
            elif t == 'dns_oauth':
                print(f"[DNS OAUTH] {p['host']}")
            elif t == 'winhttp_connect':
                print(f"[WinHTTP CONNECT] {p['host']}")
            elif t == 'winhttp_path':
                print(f"[WinHTTP PATH] {p['path']}")
            elif t == 'winhttp_headers':
                print(f"[WinHTTP HEADERS] {p['headers'][:300]}")
            elif t == 'wsasend_oauth':
                print(f"[WSASend OAUTH] {p['data'][:300]}")
            captures.append(p)
        elif msg['type'] == 'log':
            print(f"[Frida] {msg['payload'][:300]}")

    script.on('message', on_msg)
    script.load()

    # Keep running to capture events
    print("\n[*] Monitoring for OAuth activity (60s)...")
    print("[*] Trigger a login or chat in your Lingma IDE to generate network activity")
    time.sleep(60)

    # Summary
    if captures:
        print(f"\n=== Captured {len(captures)} events ===")
        for c in captures:
            t = c.get('type', '?')
            print(f"  [{t}] {json.dumps({k:v for k,v in c.items() if k != 'type'}, ensure_ascii=False)[:300]}")
    else:
        print("\n[!] No OAuth-related events captured")
        print("    Try triggering auth/login via WebSocket or restarting Lingma")

    script.unload()
    session.detach()


if __name__ == '__main__':
    main()
