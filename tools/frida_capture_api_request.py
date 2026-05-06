#!/usr/bin/env python3
"""
Frida Hook: 捕获 Lingma 对 /api/v3/user/status 的 HTTP 请求

使用方法:
  1. 确保 Lingma 正在运行
  2. python tools/frida_capture_api_request.py
  3. 在浏览器中完成 OAuth 认证
  4. 脚本会输出 Lingma 发出的完整 HTTP 请求细节
"""
import frida
import json
import sys
import time
import os

script_code = """
'use strict';

// Hook Go HTTP client's Do method
// Lingma uses net/http.(*Client).Do
var Client_do = Module.findExportByName("nethttp.dll", "net_http__ptr_Client_do");
if (Client_do) {
    console.log("[*] Found Client.do at " + Client_do);
    Interceptor.attach(Client_do, {
        onEnter: function(args) {
            // args[0] = client, args[1] = request
            var req = args[1];
            if (!req) return;

            // Try to read request details from Go structures
            try {
                // Go http.Request structure offsets may vary
                var methodPtr = ptr(req).add(0x20); // Method string ptr+len
                var urlPtr = ptr(req).add(0x30);    // URL struct ptr
                var headerPtr = ptr(req).add(0x48); // Header ptr
                var bodyPtr = ptr(req).add(0x60);   // Body ptr

                var method = ptr(methodPtr).readPointer().readCString();
                var url = ptr(urlPtr).readPointer().add(0x10).readPointer().readCString();

                if (url && url.indexOf("user/status") >= 0) {
                    console.log("\\n[=== CAPTURED /api/v3/user/status REQUEST ===]");
                    console.log("Method: " + method);
                    console.log("URL: " + url);

                    // Try to read headers
                    try {
                        var headerMap = ptr(headerPtr).readPointer();
                        if (headerMap) {
                            // Go map iteration
                            console.log("Headers: (see full dump below)");
                        }
                    } catch(e) {}
                }
            } catch(e) {}
        }
    });
} else {
    console.log("[!] net_http__ptr_Client_do not found, trying alternative hooks...");
}

// Fallback: hook send/Write syscalls
// Hook io.Copy or http.request.write
var writeMethod = Module.findExportByName("ws2_32.dll", "send");
if (writeMethod) {
    Interceptor.attach(writeMethod, {
        onEnter: function(args) {
            var sock = args[0].toInt32();
            var buf = args[1];
            var len = args[2].toInt32();
            if (len > 50 && len < 2000) {
                var data = buf.readCString();
                if (data && (data.indexOf("user/status") >= 0 || data.indexOf("POST") >= 0)) {
                    console.log("\\n[=== WS2_32.send CAPTURE ===]");
                    console.log("Socket: " + sock + " Length: " + len);
                    try {
                        var fullData = buf.readByteArray(len);
                        console.log(hexdump(fullData, { offset: 0, length: len, header: true, ansi: true }));
                    } catch(e) {
                        console.log("Data: " + data);
                    }
                }
            }
        }
    });
}
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    else:
        print(f"[!] {message}")

def main():
    # Find Lingma process
    try:
        session = frida.attach("Lingma.exe")
    except Exception as e:
        print(f"[!] 请确保 Lingma.exe 正在运行")
        print(f"    Error: {e}")
        sys.exit(1)

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()

    print("[*] Frida Hook 已启动，等待 Lingma 调用 /api/v3/user/status...")
    print("[*] 请在浏览器中完成 OAuth 认证（如果尚未登录）")
    print("[*] 按 Ctrl+C 停止\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] 停止")
        session.detach()

if __name__ == "__main__":
    main()
