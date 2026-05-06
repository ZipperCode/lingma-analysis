#!/usr/bin/env python3
"""
Frida 深度 Hook: 捕获 Lingma HTTP 请求构建全过程

Hook 策略:
  1. net/http.(*Client).Do — Go HTTP 客户端入口 (捕获完整请求)
  2. net/http.(*Client).do — 同上 (小写变体)
  3. WSASend — Windows Socket 层 (捕获 TLS 加密前的明文)
  4. 导出函数名枚举 — 找到目标函数的确切导出名
"""
import frida
import sys
import time
import json
import os
from datetime import datetime

# ============================================================
# Frida JS 脚本
# ============================================================
HOOK_SCRIPT = r"""
'use strict';

var baseAddr = null;
var foundFunctions = {};

// ============================================================
// Phase 1: 枚举导出函数，找到目标
// ============================================================
function enumerateTargetFunctions() {
    console.log('[Phase 1] Enumerating exports for target functions...');

    var targets = [
        'Client.Do', 'Client.do',
        'buildRequest', 'BuildBigModelSignRequest',
        'addBasicHeaders', 'addBigModelSignatureHeaders',
        'addBigModelAuthorizationHeaders',
        'fetchAuthStatusWithUri', 'GetQuotaAndTokenById',
        'CompleteUserLogin', 'SaveUserInfo',
        'encodeToString', 'decodeString',
        'getAuthPayload', 'getAuthSignature',
        'AuthToken',
        'net_http__ptr_Client_Do', 'net_http__ptr_Client_do',
    ];

    var module = Process.modules[0];
    baseAddr = module.base;
    console.log('[Base] ' + module.name + ' @ ' + baseAddr);

    var exports = Module.enumerateExports(module.name);
    console.log('[Exports] Total: ' + exports.length);

    // Find matching exports
    exports.forEach(function(exp) {
        var name = exp.name.toLowerCase();
        targets.forEach(function(t) {
            if (name.indexOf(t.toLowerCase()) >= 0) {
                if (!foundFunctions[t]) {
                    foundFunctions[t] = [];
                }
                foundFunctions[t].push({
                    name: exp.name,
                    address: exp.address,
                    type: exp.type
                });
                console.log('[Found] ' + exp.name + ' -> ' + exp.address);
            }
        });
    });

    console.log('\n[Summary] Found functions:');
    for (var key in foundFunctions) {
        console.log('  ' + key + ':');
        foundFunctions[key].forEach(function(f) {
            console.log('    [' + f.type + '] ' + f.name + ' @ ' + f.address);
        });
    }
}

// ============================================================
// Phase 2: Hook WSASend (socket 层明文捕获)
// ============================================================
function hookWSASend() {
    var ws2 = Process.getModuleByName('ws2_32.dll');
    if (!ws2) { console.log('[!] ws2_32.dll not found'); return; }

    var exp = ws2.enumerateExports();
    var sendExps = exp.filter(function(e) {
        return e.name === 'WSASend' || e.name === 'send';
    });

    sendExps.forEach(function(e) {
        try {
            Interceptor.attach(e.address, {
                onEnter: function(args) {
                    var buf = e.name === 'WSASend' ? args[1].add(8).readPointer() : args[1];
                    var len = e.name === 'WSASend' ? args[1].readUInt() : args[2].toInt32();

                    if (len < 50 || len > 500000) return;

                    try {
                        var data = buf.readUtf8String(Math.min(len, 100000));
                        var isHttp = data.indexOf('POST ') >= 0 || data.indexOf('GET ') >= 0 ||
                                     data.indexOf('HTTP/') >= 0 || data.indexOf('Host:') >= 0 ||
                                     data.indexOf('Content-Length:') >= 0 ||
                                     data.indexOf('User-Agent:') >= 0 ||
                                     data.indexOf('lingma.') >= 0 ||
                                     data.indexOf('alibabacloud.com') >= 0 ||
                                     data.indexOf('tongyi.aliyun.com') >= 0;

                        if (isHttp) {
                            var ts = new Date().toISOString();
                            console.log('\n==================== [WSASend] ' + ts + ' ====================');
                            console.log('Socket: ' + args[0].toInt32() + ' Length: ' + len);
                            console.log(data.substring(0, 15000));

                            // Try hexdump for binary/TLS data
                            if (data.indexOf('HTTP') < 0 && data.length > 100) {
                                console.log('[Hex Dump - first 256 bytes]:');
                                var hexStr = '';
                                for (var i = 0; i < Math.min(len, 256); i++) {
                                    var byte = buf.add(i).readU8();
                                    hexStr += ('0' + byte.toString(16)).slice(-2);
                                    if ((i + 1) % 32 === 0) hexStr += '\n';
                                }
                                console.log(hexStr);
                            }
                            console.log('========================================\n');
                        }
                    } catch(e) {}
                }
            });
            console.log('[Hook] ' + e.name + ' hooked');
        } catch(ex) {
            console.log('[!] Failed to hook ' + e.name + ': ' + ex);
        }
    });
}

// ============================================================
// Phase 3: Hook Go net/http Client.Do
// ============================================================
function hookGoHTTPClient() {
    var clientDo = foundFunctions['Client.Do'] || foundFunctions['Client.do'] ||
                   foundFunctions['net_http__ptr_Client_Do'] || foundFunctions['net_http__ptr_Client_do'];

    if (!clientDo || clientDo.length === 0) {
        console.log('[!] Client.Do not found in exports, trying alternative search...');

        // Search more broadly
        var module = Process.modules[0];
        var exports = Module.enumerateExports(module.name);
        exports.forEach(function(exp) {
            if (exp.name.indexOf('net_http') >= 0 &&
                (exp.name.indexOf('Client') >= 0 && exp.name.indexOf('Do') >= 0)) {
                console.log('[Found Alt] ' + exp.name + ' @ ' + exp.address);
                hookDo(exp.name, exp.address);
            }
        });
        return;
    }

    clientDo.forEach(function(f) {
        hookDo(f.name, f.address);
    });
}

function hookDo(name, addr) {
    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                var ts = new Date().toISOString();
                console.log('\n--- [' + name + '] ' + ts + ' ---');

                // Go Client.Do signature: Do(ctx, req) or Do(req)
                // req is a struct with method, url, header, body fields
                // Try to read strings from request struct
                try {
                    // For Go *http.Request: offset depends on Go version
                    // Try common offsets for Method string, URL string
                    var reqPtr = args[1]; // Usually the second arg is *http.Request

                    // Try reading method string (ptr at offset 0x20-0x30)
                    for (var off = 0x10; off < 0x80; off += 8) {
                        try {
                            var strPtr = reqPtr.add(off).readPointer();
                            if (strPtr) {
                                var str = strPtr.readCString();
                                if (str === 'POST' || str === 'GET' || str === 'PUT' || str === 'DELETE') {
                                    console.log('  Method: ' + str + ' (offset 0x' + off.toString(16) + ')');
                                }
                            }
                        } catch(e) {}
                    }

                    // Try reading URL (Go url.URL struct)
                    // The URL is typically a pointer at offset 0x28 or so
                    try {
                        var urlPtr = reqPtr.add(0x28).readPointer();
                        if (urlPtr) {
                            // url.URL has fields: Scheme, Opaque, Host, Path, etc.
                            // Each is a Go string: pointer + length
                            for (var soff = 0x0; soff < 0x80; soff += 0x10) {
                                try {
                                    var sPtr = urlPtr.add(soff).readPointer();
                                    var sLen = urlPtr.add(soff + 8).readUInt();
                                    if (sLen > 0 && sLen < 2000 && sPtr) {
                                        var val = sPtr.readUtf8String(Math.min(sLen, 500));
                                        if (val.indexOf('://') >= 0 || val.indexOf('/algo/') >= 0 ||
                                            val.indexOf('api/') >= 0 || val.indexOf('lingma') >= 0) {
                                            console.log('  URL part @ 0x' + soff.toString(16) + ': ' + val);
                                        }
                                    }
                                } catch(e) {}
                            }
                        }
                    } catch(e) {}

                } catch(e) {
                    console.log('  [Error reading request: ' + e + ']');
                }
            },
            onLeave: function(retval) {
                // Check return value
                try {
                    // Go return convention: RAX = first return value, RDX = second (error)
                    var errPtr = this.context.rdx;
                    if (errPtr) {
                        var errStr = errPtr.readCString();
                        if (errStr && errStr.length > 0) {
                            console.log('  Error: ' + errStr);
                        }
                    }
                } catch(e) {}
                console.log('  [Returned]');
            }
        });
        console.log('[Hook] ' + name + ' hooked successfully');
    } catch(e) {
        console.log('[!] Failed to hook ' + name + ': ' + e);
    }
}

// ============================================================
// Phase 4: Hook 关键 Go 函数 (直接搜符号)
// ============================================================
function hookGoFunction(symbolPattern, hookName) {
    var module = Process.modules[0];
    var exports = Module.enumerateExports(module.name);

    exports.forEach(function(exp) {
        if (exp.name.indexOf(symbolPattern) >= 0) {
            console.log('[HookTarget] ' + exp.name + ' @ ' + exp.address);

            try {
                Interceptor.attach(exp.address, {
                    onEnter: function(args) {
                        var ts = new Date().toISOString();
                        console.log('\n>>> [' + hookName + '] @ ' + ts);

                        // Dump first few args as strings/ints
                        for (var i = 0; i < Math.min(6, args.length); i++) {
                            try {
                                // Try as string pointer
                                var strPtr = ptr(args[i]);
                                if (strPtr) {
                                    var s = strPtr.readCString();
                                    if (s && s.length > 0 && s.length < 200) {
                                        console.log('  arg[' + i + '] = "' + s + '"');
                                        continue;
                                    }
                                }
                            } catch(e) {}
                            console.log('  arg[' + i + '] = 0x' + args[i].toString(16));
                        }
                    },
                    onLeave: function(retval) {
                        console.log('<<< [' + hookName + ']');
                    }
                });
            } catch(e) {
                console.log('[!] Hook failed: ' + e);
            }
        }
    });
}

// ============================================================
// 主入口
// ============================================================
function main() {
    console.log('========================================');
    console.log('  Lingma HTTP Capture - Frida Deep Hook');
    console.log('========================================');

    enumerateTargetFunctions();

    if (Object.keys(foundFunctions).length === 0) {
        console.log('[!] No target functions found, falling back to aggressive scanning...');

        var module = Process.modules[0];
        var exports = Module.enumerateExports(module.name);

        // Show all exports that look relevant
        var relevant = exports.filter(function(e) {
            var n = e.name.toLowerCase();
            return n.indexOf('http') >= 0 || n.indexOf('auth') >= 0 ||
                   n.indexOf('tls') >= 0 || n.indexOf('request') >= 0 ||
                   n.indexOf('sign') >= 0 || n.indexOf('encrypt') >= 0 ||
                   n.indexOf('header') >= 0 || n.indexOf('fetch') >= 0 ||
                   n.indexOf('cosy') >= 0 || n.indexOf('user/status') >= 0;
        });

        if (relevant.length > 0) {
            console.log('\n[Relevant exports] (' + relevant.length + '):');
            relevant.forEach(function(e) {
                console.log('  [' + e.type + '] ' + e.name);
            });
        }
    }

    // Hook WSASend always
    hookWSASend();

    // Hook Go HTTP client
    hookGoHTTPClient();

    // Hook specific functions by symbol pattern
    hookGoFunction('encodeToString', 'EncodeToString');
    hookGoFunction('Signature', 'Signature');
    hookGoFunction('buildRequest', 'BuildRequest');

    console.log('\n[+] All hooks installed, waiting for traffic...');
}

main();
"""


def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        print(payload)
    elif message['type'] == 'error':
        print(f"[!] Error: {message.get('description', '')}")
    else:
        print(f"[!] {message}")


def main():
    # Find Lingma process
    try:
        processes = frida.get_local_device().enumerate_processes()
        lingma_procs = [p for p in processes if 'lingma' in p.name.lower()]
    except Exception as e:
        print(f"[!] Frida enumeration failed: {e}")
        sys.exit(1)

    if not lingma_procs:
        print("[!] Lingma 未运行")
        print("[*] 请先启动 Lingma 后再运行此脚本")
        print("    例如: start \"\" \"C:/Users/Zipper/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe\"")
        sys.exit(1)

    pid = lingma_procs[0].pid
    print(f"[*] 附加到 Lingma (PID: {pid})...")

    session = frida.attach(pid)
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()

    print(f"[*] Hook 已加载，等待 HTTP 请求...")
    print(f"[*] 请操作 Lingma (如触发生成/登录等)")
    print(f"[*] 按 Ctrl+C 停止\n")

    try:
        # Keep running until interrupted
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] 停止 Hook")

    script.unload()
    session.detach()


if __name__ == '__main__':
    main()
