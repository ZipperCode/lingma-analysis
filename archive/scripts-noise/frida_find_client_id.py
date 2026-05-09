"""
Frida 脚本：定位 Lingma 的 OAuth client_id。

策略（按优先级）：
  1. 扫描二进制内存中的 OAuth URL 字符串（可能包含 client_id）
  2. 在 TLS 加密之前 hook Go HTTP 请求写入，捕获 plaintext body
  3. 触发 auth/refreshToken 或 auth/syncUserInfo 来激发远端 OAuth 请求
  4. 从捕获的 HTTP 请求中提取 client_id

平台：Windows（macOS 也可用但需调整）
"""

import frida
import json
import os
import time
import sys
import base64
import hashlib
import struct
import websocket
from pathlib import Path

# ============================================================
# 配置 —— 按你的环境修改
# ============================================================
LSP_PORT = 37010
CALLBACK_PORT = 37510

# 结果收集
found_urls = []
captured_requests = []
found_strings = set()

# ============================================================
# Frida Hook 脚本 (JavaScript)
# ============================================================
HOOK_SCRIPT = r"""
'use strict';

// ============================================================
// Part 0: 查找 Lingma 模块
// ============================================================
var lingmaMod = null;
Process.enumerateModules().forEach(function(m) {
    var name = m.name.toLowerCase();
    if (name.indexOf('lingma') >= 0 || name.indexOf('.exe') >= 0) {
        if (!lingmaMod || m.size > lingmaMod.size) {
            lingmaMod = m;
        }
    }
});

if (!lingmaMod) {
    console.log('[ERROR] Lingma module not found!');
    send({type: 'error', msg: 'Lingma module not found'});
} else {
    console.log('[Module] ' + lingmaMod.name + ' base=' + lingmaMod.base + ' size=' + lingmaMod.size.toString(16));
    send({type: 'module', name: lingmaMod.name, base: lingmaMod.base.toString(), size: lingmaMod.size});
}

var base = lingmaMod ? lingmaMod.base : null;
var modSize = lingmaMod ? lingmaMod.size : 0;

// ============================================================
// Part 1: 扫描二进制中的 OAuth 相关字符串
// ============================================================
function scanOAuthStrings() {
    if (!lingmaMod) return;

    console.log('[Scanner] Scanning binary for OAuth strings...');

    var keywords = [
        'oauth', 'client_id', 'client_secret', 'signin.alibabacloud',
        'alibabacloud.com/oauth', 'alibaba-inc.com/oauth',
        'openid', 'redirect_uri', 'grant_type', 'refresh_token',
        'code_challenge', 'pkce', 'response_type',
    ];

    // 读取整个模块的 .rdata/.data 段
    var ranges = Process.enumerateRanges({
        protection: 'r--',
        coalesce: true
    });

    ranges.forEach(function(range) {
        // 检查是否在 Lingma 模块内
        if (range.base.compare(base) >= 0 &&
            range.base.compare(base.add(modSize)) < 0) {

            var size = range.size;
            if (size > 100 * 1024 * 1024) return; // 跳过超大区域

            try {
                var data = range.base.readByteArray(Math.min(size, 50 * 1024 * 1024));
                if (!data) return;

                var text = '';
                var arr = new Uint8Array(data);
                // 提取可打印字符串（最小长度 8）
                var current = '';
                for (var i = 0; i < arr.length; i++) {
                    var b = arr[i];
                    if (b >= 32 && b < 127) {
                        current += String.fromCharCode(b);
                    } else {
                        if (current.length >= 8) {
                            var low = current.toLowerCase();
                            var matched = false;
                            for (var k = 0; k < keywords.length; k++) {
                                if (low.indexOf(keywords[k]) >= 0) {
                                    matched = true;
                                    break;
                                }
                            }
                            if (matched) {
                                console.log('[STRING] ' + current.substring(0, 300));
                                send({type: 'found_string', value: current.substring(0, 500)});
                            }
                        }
                        current = '';
                    }
                }
            } catch(e) {
                // skip unreadable
            }
        }
    });

    console.log('[Scanner] String scan done');
    send({type: 'scan_done'});
}

// ============================================================
// Part 2: 扫描内存中所有包含 "client_id" 或 "oauth" 的字符串
// ============================================================
function scanMemoryForClientId() {
    console.log('[Scanner] Scanning ALL memory for client_id patterns...');

    var patterns = [
        'client_id=', 'client_id%3D',
        '&client_id=', 'client_secret=',
        '/oauth2/', '/oauth/',
        'signin.alibabacloud', 'oauth.alibabacloud',
        'refresh_token&', 'grant_type=refresh',
    ];

    var ranges = Process.enumerateRanges('r--');
    var found = {};

    ranges.forEach(function(range) {
        if (range.size > 50 * 1024 * 1024) return;

        try {
            var bytes = range.base.readByteArray(Math.min(range.size, 10 * 1024 * 1024));
            if (!bytes) return;

            var arr = new Uint8Array(bytes);
            var text = '';
            for (var i = 0; i < arr.length; i++) {
                var b = arr[i];
                text += (b >= 32 && b < 127) ? String.fromCharCode(b) : '\n';
            }

            for (var p = 0; p < patterns.length; p++) {
                var idx = text.indexOf(patterns[p]);
                if (idx >= 0) {
                    // 提取周围内容
                    var start = Math.max(0, idx - 50);
                    var end = Math.min(text.length, idx + 500);
                    var ctx = text.substring(start, end).replace(/\n/g, '\\n');

                    if (!found[ctx]) {
                        found[ctx] = true;
                        console.log('[OAUTH_MATCH] pattern="' + patterns[p] + '" ctx=' + ctx.substring(0, 400));
                        send({type: 'oauth_context', pattern: patterns[p], context: ctx.substring(0, 500)});
                    }
                }
            }
        } catch(e) {}
    });

    console.log('[Scanner] Memory scan done');
    send({type: 'mem_scan_done'});
}

// ============================================================
// Part 3: Hook Go HTTP 请求写入（在 TLS 加密之前）
// ============================================================

// Go 的 net/http 包会用 Write 把 HTTP 请求序列化到 buf，再交给 tls.Conn
// 我们尝试 hook crypto/tls 的 Write（它收到的是 plaintext）

// 首先枚举所有模块的导出函数，找到 Go 的 HTTP 相关符号
function findGoHttpFunctions() {
    if (!lingmaMod) return [];

    var exports = lingmaMod.enumerateExports();
    console.log('[Exports] Lingma has ' + exports.length + ' exports');

    var candidates = [];
    var wantKeywords = [
        'RoundTrip', 'Do', 'Post', 'PostForm', 'Get',
        'writeHeader', 'writeRequest', 'writeBody',
        'NewRequest', 'NewRequestWithContext',
        'ReadResponse', 'send',
        'tls', 'TLS', 'Write',
        'refreshToken', 'RefreshToken', 'refresh_token',
        'syncUserInfo', 'SyncUserInfo',
        'oauth', 'OAuth',
        'postForm', 'PostForm',
        'Client.Do', 'Transport.RoundTrip',
    ];

    exports.forEach(function(e) {
        var name = e.name || '';
        for (var i = 0; i < wantKeywords.length; i++) {
            if (name.indexOf(wantKeywords[i]) >= 0) {
                candidates.push({name: name, address: e.address});
                console.log('[GoExport] ' + name + ' @ ' + e.address);
                send({type: 'go_export', name: name, address: e.address.toString()});
                break;
            }
        }
    });

    return candidates;
}

var goHttpFuncs = findGoHttpFunctions();

// ============================================================
// Part 4: Hook Go runtime 的 write 函数（捕获 plaintext HTTP）
// ============================================================

// Go 的 crypto/tls 中的 Write 函数：写入的是 plaintext
// 我们需要找到 tls.Conn.Write 并 hook 它
// 但由于没有符号，我们尝试通过 pattern 匹配

// 或者更简单：hook Windows 的 WSASend（TLS 加密前 Go 会调用它）
// 但实际上 Go 先做 TLS 再调 WSASend，所以 WSASend 捕获的是加密数据

// 更好的方法：hook Go 的内部函数
// Go 1.18+ 在 Windows 上对 TLS 使用 crypto/tls
// crypto/tls.(*Conn).Write 在加密前收到 plaintext
// crypto/tls.(*Conn).readRecord 读取解密后的数据

// 如果没有导出符号，我们尝试 hook WinHTTP API
// 但 Go 不用 WinHTTP...

// 最终方案：Hook Go HTTP 相关的导出函数
function hookGoFunctions() {
    goHttpFuncs.forEach(function(fn) {
        try {
            Interceptor.attach(fn.address, {
                onEnter: function(args) {
                    this.fnName = fn.name;
                    // 尝试读取 Go string 参数
                    // Go string: ptr + len，通常通过栈传递或寄存器
                    var summary = '';
                    // 在 x64 Windows，前4个参数在 rcx, rdx, r8, r9
                    // Go 用栈传参，我们需要看具体情况
                    try {
                        // 尝试读取可能的字符串参数
                        var regs = [this.context.rcx, this.context.rdx, this.context.r8, this.context.r9];
                        for (var i = 0; i < 4; i++) {
                            var ptr = regs[i];
                            if (ptr && !ptr.isNull()) {
                                try {
                                    var s = ptr.readUtf8String(500);
                                    if (s && s.length > 0 && s.length < 500) {
                                        var printable = true;
                                        for (var j = 0; j < Math.min(s.length, 20); j++) {
                                            var c = s.charCodeAt(j);
                                            if (c < 32 && c !== 10 && c !== 13) { printable = false; break; }
                                        }
                                        if (printable) {
                                            summary += ' arg' + i + '="' + s.substring(0, 200) + '"';
                                        }
                                    }
                                } catch(e) {}
                            }
                        }
                    } catch(e) {}

                    if (summary && summary.length > 0) {
                        console.log('[Go:' + fn.name + ']' + summary);
                        send({type: 'go_call', fn: fn.name, args: summary});
                    }
                }
            });
            console.log('[Hooked] ' + fn.name);
        } catch(e) {
            console.log('[Hook Failed] ' + fn.name + ': ' + e.message);
        }
    });
}

hookGoFunctions();

// ============================================================
// Part 5: Hook WinHTTP/WinINet 如果 Go 使用了它们
// ============================================================
try {
    var winhttp = Process.getModuleByName('winhttp.dll');
    if (winhttp) {
        var winhttpExports = winhttp.enumerateExports();
        // WinHttpSendRequest - 可以看到完整的 HTTP 请求（plaintext）
        var sendReq = winhttpExports.filter(function(e) {
            return e.name === 'WinHttpSendRequest';
        });
        if (sendReq.length > 0) {
            Interceptor.attach(sendReq[0].address, {
                onEnter: function(args) {
                    var hRequest = args[0];
                    var pwszHeaders = args[1];
                    var dwHeadersLength = args[2].toInt32();
                    var lpOptional = args[3];
                    var dwOptionalLength = args[4].toInt32();
                    var dwTotalLength = args[5].toInt32();

                    var headers = '';
                    if (pwszHeaders && !pwszHeaders.isNull() && dwHeadersLength > 0) {
                        try {
                            headers = pwszHeaders.readUtf16String(dwHeadersLength);
                        } catch(e) {}
                    }

                    var body = '';
                    if (lpOptional && !lpOptional.isNull() && dwOptionalLength > 0) {
                        try {
                            body = lpOptional.readUtf8String(Math.min(dwOptionalLength, 5000));
                        } catch(e) {}
                    }

                    if (headers.indexOf('OAuth') >= 0 || headers.indexOf('oauth') >= 0 ||
                        body.indexOf('client_id') >= 0 || body.indexOf('refresh_token') >= 0 ||
                        body.indexOf('grant_type') >= 0 || headers.indexOf('alibabacloud') >= 0) {
                        console.log('[WinHTTP Send] headers=' + headers + ' body=' + body);
                        send({type: 'winhttp_send', headers: headers, body: body});
                    }
                }
            });
            console.log('[Hook] WinHttpSendRequest OK');
        }

        // WinHttpReceiveResponse
        var recvResp = winhttpExports.filter(function(e) {
            return e.name === 'WinHttpReceiveResponse';
        });
        if (recvResp.length > 0) {
            Interceptor.attach(recvResp[0].address, {
                onEnter: function(args) {
                    this.hRequest = args[0];
                },
                onLeave: function(retval) {
                    // Just log that a response was received
                }
            });
        }
    }
} catch(e) {
    console.log('[WinHTTP] Not available: ' + e.message);
}

// ============================================================
// Part 6: Hook WSASend 捕捉 TLS 连接元数据和 SNI
// ============================================================
try {
    var ws2 = Process.getModuleByName('ws2_32.dll');
    var ws2exports = ws2.enumerateExports();

    var connectAddr = null;
    ws2exports.forEach(function(e) {
        if (e.name === 'connect') connectAddr = e.address;
        if (e.name === 'WSAConnect') {
            // Also hook WSAConnect
            Interceptor.attach(e.address, {
                onEnter: function(args) {
                    var addr = args[1];
                    try {
                        var family = addr.readU16();
                        if (family === 2) {
                            var port = addr.add(2).readU16();
                            port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                            var ip = addr.add(4).readU8() + '.' + addr.add(5).readU8() + '.' +
                                    addr.add(6).readU8() + '.' + addr.add(7).readU8();
                            console.log('[WSAConnect] -> ' + ip + ':' + port);
                            send({type: 'connect', ip: ip, port: port});
                        }
                    } catch(e) {}
                }
            });
        }
    });

    if (connectAddr) {
        Interceptor.attach(connectAddr, {
            onEnter: function(args) {
                var addr = args[1];
                try {
                    var family = addr.readU16();
                    if (family === 2) {
                        var port = addr.add(2).readU16();
                        port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                        var ip = addr.add(4).readU8() + '.' + addr.add(5).readU8() + '.' +
                                addr.add(6).readU8() + '.' + addr.add(7).readU8();
                        console.log('[connect] -> ' + ip + ':' + port);
                        send({type: 'connect', ip: ip, port: port});
                    }
                } catch(e) {}
            }
        });
        console.log('[Hook] connect OK');
    }

    // Hook WSASend for TLS ClientHello SNI extraction
    var wsasendAddr = null;
    ws2exports.forEach(function(e) {
        if (e.name === 'WSASend') wsasendAddr = e.address;
    });

    if (wsasendAddr) {
        Interceptor.attach(wsasendAddr, {
            onEnter: function(args) {
                var lpBuffers = args[1];
                var dwBufferCount = args[2].toInt32();

                for (var i = 0; i < dwBufferCount && i < 16; i++) {
                    var buf = lpBuffers.add(i * 16);
                    var len = buf.readUInt();
                    var ptr = buf.add(8).readPointer();

                    if (len > 0 && len < 200000) {
                        try {
                            var data = ptr.readByteArray(Math.min(len, 3000));
                            var arr = new Uint8Array(data);

                            // Check for TLS ClientHello (record type 0x16)
                            if (arr.length > 5 && arr[0] === 0x16 && arr[1] === 0x03) {
                                // Parse SNI
                                var pos = 5 + 4 + 2 + 32;
                                if (pos < arr.length) {
                                    var sidLen = arr[pos];
                                    pos += 1 + sidLen;
                                    if (pos + 2 < arr.length) {
                                        var csLen = (arr[pos] << 8) | arr[pos+1];
                                        pos += 2 + csLen;
                                        if (pos + 1 < arr.length) {
                                            var compLen = arr[pos];
                                            pos += 1 + compLen;
                                            if (pos + 2 < arr.length) {
                                                var extLen = (arr[pos] << 8) | arr[pos+1];
                                                pos += 2;
                                                var extEnd = pos + extLen;
                                                while (pos + 4 < extEnd && pos + 4 < arr.length) {
                                                    var extType = (arr[pos] << 8) | arr[pos+1];
                                                    var extDataLen = (arr[pos+2] << 8) | arr[pos+3];
                                                    pos += 4;
                                                    if (extType === 0x0000 && pos + 2 < arr.length && pos + 2 < extEnd) {
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
                                                                send({type: 'tls_sni', sni: sni});
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

                            // Check for plaintext HTTP
                            var preview = '';
                            for (var j = 0; j < Math.min(arr.length, 500); j++) {
                                var c = arr[j];
                                if (c >= 32 && c < 127) preview += String.fromCharCode(c);
                                else if (c === 10 || c === 13) preview += String.fromCharCode(c);
                            }
                            if (preview.indexOf('POST ') >= 0 || preview.indexOf('GET ') >= 0 ||
                                preview.indexOf('HTTP/') >= 0) {
                                console.log('[PLAINTEXT HTTP] len=' + len + '\n' + preview.substring(0, 3000));
                                send({type: 'http_plaintext', data: preview.substring(0, 5000)});
                            }
                        } catch(e) {}
                    }
                }
            }
        });
        console.log('[Hook] WSASend OK');
    }
} catch(e) {
    console.log('[WS2] Error: ' + e.message);
}

// ============================================================
// Part 7: 也尝试 hook winhttp 中的 WinHttpSendRequest 等
// ============================================================
try {
    // 有些 Go 的移植版本会使用 WinHTTP
    var winhttpMod = Process.getModuleByName('winhttp.dll');
} catch(e) {}

console.log('[Frida] All hooks installed');
send({type: 'ready'});
"""


# ============================================================
# Python 控制端
# ============================================================

def on_frida_message(msg, data):
    """处理 Frida 发回的消息"""
    if msg['type'] == 'send':
        p = msg.get('payload', {})
        t = p.get('type', '')

        if t == 'ready':
            print("[Frida] All hooks ready!")

        elif t == 'module':
            print(f"[Module] {p['name']} base={p['base']} size={hex(p['size'])}")

        elif t == 'found_string':
            s = p['value']
            found_strings.add(s)
            print(f"[STRING] {s[:200]}")

        elif t == 'oauth_context':
            ctx = p['context']
            found_strings.add(ctx)
            print(f"[OAUTH_CTX] pattern='{p['pattern']}' context={ctx[:300]}")

        elif t == 'go_export':
            print(f"[GoExport] {p['name']} @ {p['address']}")

        elif t == 'go_call':
            print(f"[GoCall] {p['fn']}: {p['args'][:300]}")

        elif t == 'connect':
            print(f"[TCP] -> {p['ip']}:{p['port']}")

        elif t == 'tls_sni':
            sni = p['sni']
            print(f"[TLS SNI] {sni}")
            found_urls.append(sni)

        elif t == 'http_plaintext':
            d = p['data']
            print(f"\n{'='*60}")
            print(f"[PLAINTEXT HTTP]")
            print(d[:2000])
            print(f"{'='*60}\n")
            captured_requests.append(d)

        elif t == 'winhttp_send':
            print(f"[WinHTTP] headers={p.get('headers','')[:500]}")
            print(f"[WinHTTP] body={p.get('body','')[:500]}")
            captured_requests.append(p)

        elif t == 'scan_done' or t == 'mem_scan_done':
            print(f"[Scanner] {t}")

        elif t == 'error':
            print(f"[ERROR] {p['msg']}")

    elif msg['type'] == 'error':
        print(f"[Frida ERROR] {msg.get('description', '')}")
    elif msg['type'] == 'log':
        l = msg['payload']
        print(f"[Frida LOG] {l[:500]}")


def make_lsp_frame(method, params=None, msg_id=1):
    """构造 LSP 消息"""
    body = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        body["params"] = params
    body["id"] = msg_id
    content = json.dumps(body, ensure_ascii=False)
    frame = f"Content-Length: {len(content.encode('utf-8'))}\r\n\r\n{content}"
    return frame


def parse_lsp_frame(text):
    """解析 LSP 消息"""
    if '\r\n\r\n' in text:
        headers, body = text.split('\r\n\r\n', 1)
        for line in headers.split('\r\n'):
            if line.lower().startswith('content-length:'):
                length = int(line.split(':')[1].strip())
                return json.loads(body[:length])
        return json.loads(body)
    return json.loads(text)


def trigger_refresh_token(expired=False):
    """通过 LSP WebSocket 触发 refreshToken 操作"""
    cache_dir = os.path.expandvars(r"C:\Users\Zipper\.lingma\cache")

    # 读取 machine_id
    id_file = os.path.join(cache_dir, "id")
    if not os.path.exists(id_file):
        alt_cache = os.path.expandvars(r"C:\Users\Zipper\.lingma\vscode\sharedClientCache\cache")
        alt_id = os.path.join(alt_cache, "id")
        if os.path.exists(alt_id):
            id_file = alt_id
            cache_dir = alt_cache

    with open(id_file, 'r') as f:
        machine_id = f.read().strip()
    print(f"[*] machine_id: {machine_id}")

    # 读取 user 文件
    user_file = os.path.join(cache_dir, "user")
    if not os.path.exists(user_file):
        print("[!] user file not found!")
        return

    with open(user_file, 'rb') as f:
        encrypted_raw = f.read().strip()

    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    encrypted = base64.b64decode(encrypted_raw)
    key = machine_id[:16].encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    decrypted = unpad(cipher.decrypt(encrypted), 16)
    user_data = json.loads(decrypted.decode('utf-8'))

    security_oauth_token = user_data.get('security_oauth_token', '')
    refresh_token = user_data.get('refresh_token', '')
    expire_time = user_data.get('expire_time', '')

    print(f"[*] security_oauth_token: {security_oauth_token[:30]}...")
    print(f"[*] refresh_token: {refresh_token[:30]}...")
    print(f"[*] expire_time: {expire_time}")

    # 连接 LSP
    print(f"\n[*] Connecting LSP WebSocket (127.0.0.1:{LSP_PORT})...")
    ws = websocket.create_connection(f"ws://127.0.0.1:{LSP_PORT}", timeout=10)
    print("[*] Connected!")

    # initialize
    print("[1] Sending initialize...")
    ws.send(make_lsp_frame("initialize", {
        "processId": os.getpid(),
        "clientInfo": {"name": "client_id_finder", "version": "1.0"},
        "locale": "zh-CN",
        "rootPath": "C:/test",
        "capabilities": {}
    }, 1))
    ws.settimeout(3)
    try:
        raw = ws.recv()
        resp = parse_lsp_frame(raw)
        print(f"[*] Initialize: {json.dumps(resp, ensure_ascii=False)[:200]}")
    except Exception as e:
        print(f"[*] Init response: {e}")

    # auth/status
    print("\n[2] Checking auth/status...")
    ws.send(make_lsp_frame("auth/status", {}, 2))
    ws.settimeout(5)
    try:
        raw = ws.recv()
        status = parse_lsp_frame(raw)
        print(f"[*] Status: {json.dumps(status, ensure_ascii=False)[:500]}")
    except Exception as e:
        print(f"[*] Status: {e}")

    # 触发 refreshToken
    if expired:
        past = int(time.time() * 1000) - 86400000  # 1天前
        print(f"\n[3] >>> Sending auth/refreshToken (EXPIRED, time={past}) <<<")
        params = {
            "securityOauthToken": security_oauth_token,
            "refreshToken": refresh_token,
            "tokenExpireTime": past
        }
    else:
        print(f"\n[3] >>> Sending auth/refreshToken <<<")
        params = {
            "securityOauthToken": security_oauth_token,
            "refreshToken": refresh_token,
            "tokenExpireTime": expire_time
        }

    ws.send(make_lsp_frame("auth/refreshToken", params, 3))

    ws.settimeout(30)
    try:
        raw = ws.recv()
        resp = parse_lsp_frame(raw)
        print(f"\n[*] refreshToken response:")
        print(json.dumps(resp, ensure_ascii=False, indent=2)[:1500])
    except Exception as e:
        print(f"[*] refreshToken response: {e}")

    # 等待异步网络活动
    print("\n[*] Waiting 30s for async network activity (Frida hooks are capturing)...")
    for i in range(30):
        time.sleep(1)
        try:
            raw = ws.recv()
            extra = parse_lsp_frame(raw)
            print(f"[*] Extra: {json.dumps(extra, ensure_ascii=False)[:300]}")
        except:
            pass

    ws.close()


def main():
    print("=" * 60)
    print("Lingma client_id Finder")
    print("=" * 60)

    # 1. 找到 Lingma 进程
    device = frida.get_local_device()
    processes = device.enumerate_processes()
    lingma_procs = [p for p in processes if p.name and 'lingma' in p.name.lower()]

    if not lingma_procs:
        print("[!] Lingma not running! Start Lingma first.")
        print("    Run: C:\\Users\\Zipper\\.lingma\\bin\\2.11.2\\x86_64_windows\\Lingma.exe start")
        sys.exit(1)

    pid = lingma_procs[0].pid
    print(f"[*] Lingma PID: {pid}")

    # 2. attach Frida
    print(f"[*] Attaching Frida...")
    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_frida_message)
    script.load()

    # 等待 hooks 就绪
    time.sleep(5)

    # 3. 触触发 refreshToken 两次
    # 第一次：用正常/过期 token 触发实际的远端 OAuth 调用
    print("\n" + "=" * 60)
    print("Test 1: 用过期时间触发 refreshToken（强制远端调用）")
    print("=" * 60)
    try:
        trigger_refresh_token(expired=True)
    except Exception as e:
        print(f"[!] Test 1 error: {e}")
        import traceback
        traceback.print_exc()

    # 等待一下让 Frida 捕获所有事件
    time.sleep(5)

    print("\n" + "=" * 60)
    print("Test 2: 正常 refreshToken")
    print("=" * 60)
    try:
        trigger_refresh_token(expired=False)
    except Exception as e:
        print(f"[!] Test 2 error: {e}")

    time.sleep(10)

    # 4. 汇总结果
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)

    print(f"\n--- Found OAuth Strings ({len(found_strings)}) ---")
    for s in sorted(found_strings):
        if any(kw in s.lower() for kw in ['client_id', 'oauth', 'signin', 'token', 'refresh']):
            print(f"  {s[:200]}")

    print(f"\n--- Captured URLs/SNIs ({len(found_urls)}) ---")
    for u in found_urls:
        print(f"  {u}")

    print(f"\n--- Captured HTTP Requests ({len(captured_requests)}) ---")
    for i, r in enumerate(captured_requests):
        print(f"\n  [{i}] {str(r)[:1000]}")

    # 5. 特别搜索 client_id 模式
    print("\n--- Searching for client_id pattern in all captured data ---")
    all_text = '\n'.join(found_strings) + '\n' + '\n'.join(found_urls) + '\n'
    for req in captured_requests:
        all_text += str(req) + '\n'

    import re
    client_id_patterns = [
        r'client_id[=:]\s*([a-zA-Z0-9_\-\.]+)',
        r'client_id%3D([a-zA-Z0-9_\-\.]+)',
        r'"client_id"\s*:\s*"([^"]+)"',
        r'client_id=([^&\s]+)',
    ]
    for pat in client_id_patterns:
        matches = re.findall(pat, all_text, re.IGNORECASE)
        for m in matches:
            print(f"  >>> POTENTIAL CLIENT_ID: {m}")

    print("\n[*] Done!")
    script.unload()
    session.detach()


if __name__ == '__main__':
    main()
