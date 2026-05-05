/*
Frida Hook: 使用硬编码地址验证签名参数顺序
目标函数地址（IDA Pro 分析结果）：
- cosy_auth_user.getAuthSignature: 0x14088c4e0
- cosy_auth_user.getAuthPayload: 0x14088c720
- cosy_auth_user.AuthToken: 0x14088b740

使用方法:
frida -l frida_hooks/hook_by_address.js -f ~/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe
*/

console.log("\n" + "="*60);
console.log("✅ Frida Hook 使用硬编码地址");
console.log("="*60);
console.log("目标函数:");
console.log("  - getAuthSignature @ 0x14088c4e0");
console.log("  - getAuthPayload @ 0x14088c720");
console.log("  - AuthToken @ 0x14088b740");
console.log("\n等待函数调用...\n");

// ============================================
// Hook 1: getAuthSignature (0x14088c4e0)
// ============================================
Interceptor.attach(ptr("0x14088c4e0"), {
    onEnter: function(args) {
        console.log("\n" + "="*60);
        console.log("[getAuthSignature] Called!");
        console.log("="*60);

        try {
            // 读取所有 5 个字符串参数
            var params = [];
            var paramNames = [];

            for (var i = 0; i < 5; i++) {
                var ptr_arg = args[i*2];
                var len_arg = args[i*2 + 1];

                // Go string: ptr + len (两个参数)
                // 需要将 len_arg 转换为整数
                var len = len_arg.toInt32();
                var str = Memory.readUtf8String(ptr_arg, len);
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
            console.log("Args dump:");
            for (var i = 0; i < 10; i++) {
                console.log("  args[" + i + "] = " + args[i]);
            }
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
            console.log("Error reading retval: " + e);
            console.log("  retval (rax) = " + retval);
            console.log("  rbx = " + this.context.rbx);
        }
    }
});

// ============================================
// Hook 2: getAuthPayload (0x14088c720)
// ============================================
Interceptor.attach(ptr("0x14088c720"), {
    onEnter: function(args) {
        console.log("\n" + "="*60);
        console.log("[getAuthPayload] Called");
        console.log("="*60);

        try {
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

            console.log("\n✅ Payload 构造完成");

        } catch (e) {
            console.log("Error: " + e);
        }
    }
});

// ============================================
// Hook 3: AuthToken (0x14088b740)
// ============================================
Interceptor.attach(ptr("0x14088b740"), {
    onEnter: function(args) {
        console.log("\n" + "="*60);
        console.log("[AuthToken] Called");
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

        if (this.path && this.path.includes("refresh_token")) {
            console.log("\n🎉 检测到 Refresh Token 调用！");
            console.log("  Path: " + this.path);
            console.log("  Method: " + this.method);
        }
    }
});

console.log("\n💡 提示:");
console.log("  - 灵码程序启动后会自动调用用户状态检查");
console.log("  - Token 快过期时会调用 refresh token");
console.log("  - 观察参数顺序，验证 IDA 分析结果\n");