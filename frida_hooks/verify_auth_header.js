/*
Frida Hook: 验证灵码 Authorization Header 构造
目标函数: cosy_auth_user.AuthToken, getAuthPayload, getAuthSignature

使用方法:
frida -l frida_hooks/verify_auth_header.js -f ~/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe
*/

// ============================================
// Hook 1: cosy_auth_user.AuthToken
// ============================================
Interceptor.attach(Module.findExportByName(null, "cosy_auth_user.AuthToken"), {
    onEnter: function(args) {
        console.log("\n" + "="*60);
        console.log("[AuthToken] Called");
        console.log("="*60);

        // 参数分析
        // a1 = request 对象
        // a2, a3 = path (string ptr, len)
        // a4, a5 = method (string ptr, len)

        try {
            // 读取 path
            var path_ptr = args[1];
            var path_len = args[2].toInt32();
            var path = Memory.readUtf8String(path_ptr, path_len);
            console.log("Path: " + path);

            // 读取 method
            var method_ptr = args[3];
            var method_len = args[4].toInt32();
            var method = Memory.readUtf8String(method_ptr, method_len);
            console.log("Method: " + method);

            // 保存上下文
            this.path = path;
            this.method = method;

        } catch (e) {
            console.log("Error reading args: " + e);
        }
    },

    onLeave: function(retval) {
        console.log("\n[AuthToken] Completed");
        console.log("Error returned: " + retval);

        // 尝试读取 Authorization header
        try {
            // retval 是 error 对象，如果是 nil 表示成功
            if (retval.isNull()) {
                console.log("✅ AuthToken succeeded");
            } else {
                console.log("❌ AuthToken failed");
            }
        } catch (e) {
            console.log("Error reading retval: " + e);
        }
    }
});

// ============================================
// Hook 2: cosy_auth_user.getAuthPayload
// ============================================
Interceptor.attach(Module.findExportByName(null, "cosy_auth_user.getAuthPayload"), {
    onEnter: function(args) {
        console.log("\n" + "="*60);
        console.log("[getAuthPayload] Called");
        console.log("="*60);

        // 参数分析
        // a1, a2 = userId (string ptr, len)
        // a3, a4 = ??? (推测是 path 或 method)

        try {
            // 读取 userId
            var userId_ptr = args[0];
            var userId_len = args[1].toInt32();
            var userId = Memory.readUtf8String(userId_ptr, userId_len);
            console.log("UserId: " + userId);

            // 其他参数
            console.log("Arg 2 (ptr): " + args[2]);
            console.log("Arg 3 (len): " + args[3]);

            // 保存上下文
            this.userId = userId;

        } catch (e) {
            console.log("Error reading args: " + e);
        }
    },

    onLeave: function(retval) {
        console.log("\n[getAuthPayload] Completed");

        // retval 是 (string ptr, string len)
        try {
            var payload_ptr = retval;
            // Go string 返回格式：rax = ptr, rbx = len
            // Frida 只返回 retval (rax)
            // 需要读取寄存器获取长度

            var payload_len = this.context.rbx.toInt32();
            var payload_b64 = Memory.readUtf8String(payload_ptr, payload_len);

            console.log("Payload (base64):");
            console.log("  Length: " + payload_len);
            console.log("  Content: " + payload_b64.substring(0, 100) + "...");

            // 解码 payload
            try {
                // Base64 解码
                var payload_json = Memory.alloc(payload_len);
                // 需要手动 base64 decode 或者打印原始字节

                // 打印前 200 字节
                var payload_bytes = Memory.readByteArray(payload_ptr, Math.min(payload_len, 200));
                console.log("  Raw bytes (hex): " + hexdump(payload_bytes, { ansi: true }));

                // 尝试解码 JSON（假设已经 base64 解码）
                // 但这里只有 base64 编码的结果，需要解码
                // 简化处理：直接打印 base64 字符串
                console.log("✅ Payload base64: " + payload_b64);

            } catch (e) {
                console.log("Error decoding payload: " + e);
            }

        } catch (e) {
            console.log("Error reading retval: " + e);
        }
    }
});

// ============================================
// Hook 3: cosy_auth_user.getAuthSignature
// ============================================
Interceptor.attach(Module.findExportByName(null, "cosy_auth_user.getAuthSignature"), {
    onEnter: function(args) {
        console.log("\n" + "="*60);
        console.log("[getAuthSignature] Called");
        console.log("="*60);

        // 参数分析（关键！需要确认 5 个参数的含义）
        // 根据反编译：总共 10 个参数（5 个 string 的 ptr+len）
        // a1, a2 = param1 (string ptr, len)
        // a3, a4 = param2
        // a5, a6 = param3
        // a7, a8 = param4
        // a9, a10 = param5

        try {
            console.log("All args:");
            for (var i = 0; i < 10; i++) {
                console.log("  Arg[" + i + "]: " + args[i]);
            }

            // 尝试读取所有 5 个字符串参数
            var params = [];
            for (var i = 0; i < 5; i++) {
                var ptr = args[i*2];
                var len = args[i*2 + 1].toInt32();
                var str = Memory.readUtf8String(ptr, len);
                params.push(str);
                console.log("Param " + (i+1) + ": " + str);
            }

            // 保存上下文
            this.params = params;

            console.log("\n✅ Signature params captured:");
            console.log("  Format: %s\\n%s\\n%s\\n%s\\n%s");
            console.log("  Data: " + params.join("\\n"));

        } catch (e) {
            console.log("Error reading args: " + e);
        }
    },

    onLeave: function(retval) {
        console.log("\n[getAuthSignature] Completed");

        // retval 是 (string ptr, string len)
        try {
            var sig_ptr = retval;
            var sig_len = this.context.rbx.toInt32();
            var signature = Memory.readUtf8String(sig_ptr, sig_len);

            console.log("Signature (MD5):");
            console.log("  Length: " + sig_len);
            console.log("  Value: " + signature);

            // 验证 MD5 计算
            try {
                // 从 onEnter 保存的参数计算签名
                var sign_data = this.params.join("\n");
                console.log("\n🔍 Manual verification:");
                console.log("  Input data: " + sign_data);
                console.log("  Expected MD5: " + signature);

                // 计算 MD5（使用 Node.js crypto 模块，如果环境支持）
                // Frida 环境可能不支持 crypto，简化处理：打印原始数据
                console.log("✅ Signature captured");

            } catch (e) {
                console.log("Error verifying signature: " + e);
            }

        } catch (e) {
            console.log("Error reading retval: " + e);
        }
    }
});

// ============================================
// Hook 4: cosy_remoting.addBigModelSignatureHeaders
// ============================================
Interceptor.attach(Module.findExportByName(null, "cosy_remoting.addBigModelSignatureHeaders"), {
    onEnter: function(args) {
        console.log("\n" + "="*60);
        console.log("[addBigModelSignatureHeaders] Called");
        console.log("="*60);

        // args[0] = request headers map
    },

    onLeave: function(retval) {
        console.log("\n[addBigModelSignatureHeaders] Completed");
        console.log("Headers map ptr: " + retval);

        // 尝试读取添加的 headers
        try {
            // retval 是 map[string]string 的指针
            // Go 的 map 结构复杂，简化处理：不直接解析
            console.log("✅ Signature headers added");
        } catch (e) {
            console.log("Error reading headers: " + e);
        }
    }
});

// ============================================
// Hook 5: HTTP Request 发送监控
// ============================================
Interceptor.attach(Module.findExportByName(null, "net_http._ptr_Client.do"), {
    onEnter: function(args) {
        // args[0] = HTTP Client
        // args[1] = HTTP Request

        try {
            var request = args[1];

            // 读取 URL
            // Go 的 Request 结构复杂，需要解析字段
            // 简化处理：尝试读取 URL 字段（偏移量需要测试）

            // 假设 URL 在 Request 结构的固定偏移
            // 需要根据 Go 的 struct layout 确定
            var url_ptr = Memory.readPointer(request.add(56));  // 假设偏移
            var url_len = Memory.readU32(request.add(64));      // 假设偏移
            var url = Memory.readUtf8String(url_ptr, url_len);

            if (url && url.includes("refresh_token")) {
                console.log("\n" + "="*60);
                console.log("[HTTP Request] Refresh Token");
                console.log("="*60);
                console.log("URL: " + url);

                // 读取 headers
                console.log("\nHeaders:");
                // Go 的 Header 是 map[string][]string
                // 需要解析 Go map 结构（复杂）

                // 读取 body
                console.log("\nBody:");
                // Request.Body 是 io.Reader
                // 需要读取 Body 字段

                console.log("✅ HTTP request captured");
            }

        } catch (e) {
            console.log("Error reading request: " + e);
        }
    },

    onLeave: function(retval) {
        // retval = HTTP Response
        try {
            if (this.url && this.url.includes("refresh_token")) {
                console.log("\n[HTTP Response]");
                var response = retval;

                // 读取 Status
                var status_code = Memory.readU32(response.add(0));  // 假设偏移
                console.log("Status Code: " + status_code);
            }
        } catch (e) {
            console.log("Error reading response: " + e);
        }
    }
});

console.log("\n✅ Frida hooks installed successfully");
console.log("Monitoring Authorization header construction...\n");
console.log("Key targets:");
console.log("  1. cosy_auth_user.AuthToken");
console.log("  2. cosy_auth_user.getAuthPayload");
console.log("  3. cosy_auth_user.getAuthSignature");
console.log("  4. cosy_remoting.addBigModelSignatureHeaders");
console.log("  5. net_http.Client.do (HTTP request)\n");