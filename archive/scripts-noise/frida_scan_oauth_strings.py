"""
轻量级 Frida 脚本：快速扫描 Lingma 二进制中所有 OAuth 相关字符串。

用途：在不触发任何网络请求的情况下，直接从二进制文件中定位 client_id 候选值。

Usage:
    python tools/frida_scan_oauth_strings.py
"""

import frida
import sys
import re
import time

SCRIPT = r"""
'use strict';

var lingmaMod = null;
Process.enumerateModules().forEach(function(m) {
    var name = m.name.toLowerCase();
    if (name.indexOf('lingma') >= 0 || (name.indexOf('.exe') >= 0 && m.size > 50 * 1024 * 1024)) {
        if (!lingmaMod || m.size > lingmaMod.size) {
            lingmaMod = m;
        }
    }
});

if (!lingmaMod) {
    console.log('[ERROR] Lingma module not found');
    send({type: 'error'});
} else {
    console.log('[Module] ' + lingmaMod.name + ' size=' + lingmaMod.size.toString(16));
    send({type: 'module', name: lingmaMod.name, size: lingmaMod.size});
}

var base = lingmaMod.base;
var modSize = lingmaMod.size;

// 提取所有可打印字符串（最小长度 4）
function extractStrings(data, minLen) {
    var strings = [];
    var current = '';
    for (var i = 0; i < data.length; i++) {
        var b = data[i];
        if (b >= 32 && b < 127) {
            current += String.fromCharCode(b);
        } else {
            if (current.length >= minLen) {
                strings.push(current);
            }
            current = '';
        }
    }
    if (current.length >= minLen) {
        strings.push(current);
    }
    return strings;
}

// 扫描模块的数据段
function scanModule() {
    var interesting = [];
    var keywords = [
        'client_id', 'client_secret', 'clientId', 'ClientId', 'CLIENT_ID',
        'oauth', 'OAuth', 'OAUTH',
        'signin.alibabacloud', 'oauth.alibabacloud',
        'alibabacloud.com/oauth', 'alibaba-inc.com/oauth',
        'openid', 'redirect_uri', 'grant_type', 'refresh_token',
        'code_challenge', 'response_type',
        'lingma', 'Lingma', 'cosy', 'COSY',
        'appKey', 'appSecret', 'AppKey', 'AppSecret',
        'dingtalk', 'alibaba', 'alipay',
        'authorize', 'Authorize',
    ];

    var ranges = Process.enumerateRanges({
        protection: 'r--',
        coalesce: true
    });

    var totalScanned = 0;
    var allMatches = {};

    ranges.forEach(function(range) {
        // 只扫描 Lingma 模块内的区域
        if (range.base.compare(base) < 0) return;
        if (range.base.compare(base.add(modSize)) > 0) return;
        if (range.size > 100 * 1024 * 1024) return;

        totalScanned++;

        try {
            var bytes = range.base.readByteArray(Math.min(range.size, 30 * 1024 * 1024));
            if (!bytes) return;

            var arr = new Uint8Array(bytes);
            var strings = extractStrings(arr, 4);

            strings.forEach(function(s) {
                var low = s.toLowerCase();
                for (var k = 0; k < keywords.length; k++) {
                    if (low.indexOf(keywords[k]) >= 0) {
                        if (!allMatches[s]) {
                            allMatches[s] = true;
                            interesting.push(s);
                        }
                        break;
                    }
                }
            });
        } catch(e) {}
    });

    console.log('[Scanner] Scanned ' + totalScanned + ' regions, found ' + interesting.length + ' interesting strings');

    // 发送结果（分批以避免消息过大）
    var batch = [];
    interesting.forEach(function(s, i) {
        batch.push(s);
        if (batch.length >= 50 || i === interesting.length - 1) {
            send({type: 'strings', data: batch});
            batch = [];
        }
    });

    send({type: 'done', total: interesting.length});
}

// 也搜索内存堆区域中的 OAuth 请求痕迹
function scanHeapForRequests() {
    var interesting = [];
    var patterns = [
        /https?:\/\/[a-zA-Z0-9\.\-]+\.alibabacloud\.com\/[^\s\x00]{1,300}/g,
        /https?:\/\/[a-zA-Z0-9\.\-]+\/oauth2?\/[^\s\x00]{1,300}/g,
        /client_id[=:][a-zA-Z0-9_\-\.]{4,100}/g,
        /refresh_token[=:][a-zA-Z0-9_\-\.]{4,200}/g,
    ];

    var ranges = Process.enumerateRanges('rw-');
    var seen = {};

    ranges.forEach(function(range) {
        if (range.size > 30 * 1024 * 1024) return;

        try {
            var bytes = range.base.readByteArray(range.size);
            if (!bytes) return;
            var arr = new Uint8Array(bytes);
            var text = '';
            // 只提取可打印字符（替换不可打印为空格）
            for (var i = 0; i < Math.min(arr.length, 5 * 1024 * 1024); i++) {
                var b = arr[i];
                text += (b >= 32 && b < 127) ? String.fromCharCode(b) : ' ';
            }

            patterns.forEach(function(pattern) {
                var match;
                while ((match = pattern.exec(text)) !== null) {
                    var val = match[0];
                    if (!seen[val]) {
                        seen[val] = true;
                        interesting.push(val);
                    }
                }
            });
        } catch(e) {}
    });

    console.log('[HeapScan] Found ' + interesting.length + ' request-like strings');
    send({type: 'heap_strings', data: interesting});
}

// 执行扫描
scanModule();
scanHeapForRequests();
send({type: 'finished'});
"""


def main():
    print("[*] Attaching to Lingma...")
    device = frida.get_local_device()
    processes = device.enumerate_processes()
    lingma = [p for p in processes if p.name and 'lingma' in p.name.lower()]

    if not lingma:
        print("[!] Lingma not running!")
        sys.exit(1)

    pid = lingma[0].pid
    print(f"[*] PID: {pid}")

    session = device.attach(pid)
    script = session.create_script(SCRIPT)

    all_strings = []
    heap_strings = []

    def on_msg(msg, data):
        if msg['type'] == 'send':
            p = msg['payload']
            t = p.get('type', '')
            if t == 'module':
                print(f"[*] Module: {p['name']} ({hex(p['size'])} bytes)")
            elif t == 'strings':
                all_strings.extend(p['data'])
                for s in p['data']:
                    print(f"  [STR] {s[:200]}")
            elif t == 'heap_strings':
                heap_strings.extend(p['data'])
                for s in p['data']:
                    print(f"  [HEAP] {s[:200]}")
            elif t == 'done':
                print(f"\n[*] Total strings found: {p['total']}")
            elif t == 'finished':
                print("[*] Scanning complete!")
        elif msg['type'] == 'log':
            print(f"[LOG] {msg['payload'][:300]}")

    script.on('message', on_msg)
    script.load()

    # 等待扫描完成
    print("[*] Scanning... (this may take 30-60 seconds)")
    time.sleep(60)

    # 分析结果
    print("\n" + "=" * 60)
    print("ANALYSIS RESULTS")
    print("=" * 60)

    all_data = '\n'.join(all_strings + heap_strings)

    # 查找 URL 模式
    urls = re.findall(r'https?://[a-zA-Z0-9\.\-\/]+\.alibabacloud\.com[^\s\x00]{0,200}', all_data)
    print(f"\n--- Alibaba Cloud URLs ({len(urls)}) ---")
    for u in sorted(set(urls)):
        print(f"  {u}")

    oauth_urls = re.findall(r'https?://[^\s\x00]*oauth[^\s\x00]{0,200}', all_data, re.IGNORECASE)
    print(f"\n--- OAuth URLs ({len(oauth_urls)}) ---")
    for u in sorted(set(oauth_urls)):
        print(f"  {u}")

    # 查找可能的 client_id
    client_id_patterns = [
        (r'client_id[=:]\s*([a-zA-Z0-9_\-\.]{4,100})', 'client_id param'),
        (r'"client_id"\s*:\s*"([^"]+)"', 'JSON client_id'),
        (r'client_id=([a-zA-Z0-9_\-\.]+)', 'URL client_id'),
        (r'client_id%3D([a-zA-Z0-9_\-\.]+)', 'URL-encoded'),
    ]

    print(f"\n--- Potential Client IDs ---")
    found_clients = set()
    for pat, label in client_id_patterns:
        matches = re.findall(pat, all_data, re.IGNORECASE)
        for m in matches:
            if m not in found_clients:
                found_clients.add(m)
                print(f"  [{label}] {m}")

    if not found_clients:
        print("  (no client_id found in strings)")

    # 查找与 OAuth 相关的所有字符串
    oauth_keywords = ['client_id', 'client_secret', 'appKey', 'appSecret', 'app_key', 'app_secret']
    print(f"\n--- All Auth-Related Strings ---")
    for kw in oauth_keywords:
        for s in all_strings + heap_strings:
            if kw.lower() in s.lower():
                print(f"  [{kw}] {s[:200]}")
                break  # 只打印第一条包含该关键词的

    script.unload()
    session.detach()


if __name__ == '__main__':
    main()
