/*
Frida Hook: 灵码认证头构造综合监控
监控目标：
1. getAuthPayload - Payload 构造
2. getAuthSignature - 签名计算
3. AuthToken - 认证头最终构造
4. 用户状态检查函数 - 触发认证

使用方法:
frida -l frida_hooks/comprehensive_auth_monitor.js -f ~/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe
*/

console.log("\n" + "="*60);
console.log("✅ 灵码认证头构造综合监控 Hook");
console.log("="*60);
console.log("监控目标:");
console.log("  1. cosy_auth_user.getAuthPayload");
console.log("  2. cosy_auth_user.getAuthSignature");
console.log("  3. cosy_auth_user.AuthToken");
console.log("  4. /api/v3/user/status 调用");
console.log("\n等待函数调用...\n");

// ============================================
// Hook 1: getAuthPayload
// ============================================
Interceptor.attach(Module.findExportByName(null, "cosy_auth_user.getAuthPayload"), {
    onEnter: function(args) {
        console.log("\n" + "="*60);
        console.log("[1/3] getAuthPayload Called");
        console.log("="*60);

        try {
            // args[0-1] = userId (ptr, len)
            var userId_ptr = args[0];
            var userId_len = args[1].toInt32();
            var userId = Memory.readUtf8String(userId_ptr, userId_len);
            console.log("UserId: " + userId);

            this.userId = userId;

        } catch (e) {
            console.log("Error: " + e);
        }
    },

    onLeave: function(retval) {
        try {
            var payload_ptr = retval;
            var payload_len = this.context.rbx.toInt32();
            var payload_b64 = Memory.readUtf8String(payload_ptr, payload_len);

            console.log("Payload (base64, len=" + payload_len + "):");
            console.log("  " + payload_b64.substring(0, 80) + "...");

            // 尝试解码 payload
            console.log("\n✅ Payload 构造完成");

        } catch (e) {
            console.log("Error: " + e);
        }
    }
});

// ============================================
// Hook 2: getAuthSignature
// ============================================
Interceptor.attach(Module.findExportByName(null, "cosy_auth_user.getAuthSignature"), {
    onEnter: function(args) {
        console.log("\n" + "="*60);
        console.log("[2/3] getAuthSignature Called");
        console.log("="*60);

        try {
            // 读取所有 5 个参数
            var params = [];
            var paramNames = [];  // 用于标识参数含义

            for (var i = 0; i < 5; i++) {
                var ptr = args[i*2];
                var len = args[i*2 + 1].toInt32();
                var str = Memory.readUtf8String(ptr, len);
                params.push(str);

                // 根据内容推测参数名
                if (str.match(/^\d+$/)) {
                    paramNames.push("userId (推测)");
                } else if (str.startsWith("pt-")) {
                    paramNames.push("securityOauthToken (推测)");
                } else if (str.startsWith("rt-")) {
                    paramNames.push("refreshToken (推测)");
                } else if (str.startsWith("/api/")) {
                    paramNames.push("path (推测)");
                } else if (str === "POST" || str === "GET") {
                    paramNames.push("method (推测)");
                } else {
                    paramNames.push("unknown");
                }

                console.log("Param[" + i + "] (" + paramNames[i] + "): " + str);
            }

            this.params = params;
            this.paramNames = paramNames;

            // 打印拼接后的字符串
            console.log("\n签名字符串（拼接后）：");
            console.log("\"" + params.join("\\n") + "\"");

        } catch (e) {
            console.log("Error: " + e);
        }
    },

    onLeave: function(retval) {
        try {
            var sig_ptr = retval;
            var sig_len = this.context.rbx.toInt32();
            var signature = Memory.readUtf8String(sig_ptr, sig_len);

            console.log("\nSignature (MD5): " + signature);

            console.log("\n✅ 签名计算完成");
            console.log("参数顺序总结:");
            for (var i = 0; i < 5; i++) {
                console.log("  " + i + ": " + this.paramNames[i]);
            }

        } catch (e) {
            console.log("Error: " + e);
        }
    }
});

// ============================================
// Hook 3: AuthToken
// ============================================
Interceptor.attach(Module.findExportByName(null, "cosy_auth_user.AuthToken"), {
    onEnter: function(args) {
        console.log("\n" + "="*60);
        console.log("[3/3] AuthToken Called");
        console.log("="*60);

        try {
            var path_ptr = args[1];
            var path_len = args[2].toInt32();
            var path = Memory.readUtf8String(path_ptr, path_len);

            var method_ptr = args[3];
            var method_len = args[4].toInt32();
            var method = Memory.readUtf8String(method_ptr, method_len);

            console.log("Path: " + path);
            console.log("Method: " + method);

            this.path = path;
            this.method = method;

        } catch (e) {
            console.log("Error: " + e);
        }
    },

    onLeave: function(retval) {
        console.log("\n✅ AuthToken 完成");

        // 检查是否是 refresh token 调用
        if (this.path && this.path.includes("refresh_token")) {
            console.log("\n🎉 检测到 Refresh Token 调用！");
            console.log("  Path: " + this.path);
            console.log("  Method: " + this.method);
        }
    }
});

// ============================================
// Hook 4: HTTP POST 请求监控
// ============================================
Interceptor.attach(Module.findExportByName(null, "net_http._ptr_Client.do"), {
    onEnter: function(args) {
        try {
            // args[1] = HTTP Request
            var request = args[1];

            // 尝试读取 URL（需要根据 Go struct layout 确定偏移）
            // 简化处理：监控所有包含 "api/v3" 或 "refresh" 的请求

            // 假设 URL 在固定偏移（需要实际测试）
            var url_ptr = Memory.readPointer(request.add(56));
            var url_len = Memory.readU32(request.add(64));
            var url = Memory.readUtf8String(url_ptr, url_len);

            if (url && (url.includes("api/v3") || url.includes("refresh"))) {
                console.log("\n" + "="*60);
                console.log("[HTTP] 关键请求检测");
                console.log("="*60);
                console.log("URL: " + url);

                this.url = url;
            }

        } catch (e) {
            // URL 读取失败，忽略
        }
    },

    onLeave: function(retval) {
        if (this.url) {
            try {
                var response = retval;
                var status_code = Memory.readU32(response.add(0));

                console.log("Response Status: " + status_code);
            } catch (e) {
                // Response 读取失败，忽略
            }
        }
    }
});

console.log("\n💡 使用提示:");
console.log("  1. 此脚本会监控所有认证相关函数");
console.log("  2. 当灵码启动或调用 refresh token 时，会自动输出详细信息");
console.log("  3. 观察参数顺序，验证 IDA 分析结果");
console.log("  4. 预期签名参数顺序:");
console.log("     Param[0]: userId");
console.log("     Param[1]: securityOauthToken");
console.log("     Param[2]: refreshToken");
console.log("     Param[3]: path");
console.log("     Param[4]: method");
console.log("\n" + "="*60 + "\n");