/*
Frida Hook: 使用模块基地址 + 偏移量验证签名参数顺序
IDA Pro 分析地址（相对于模块基地址 0x140000000）：
- cosy_auth_user.getAuthSignature: 0x14088c4e0 (偏移 0x88c4e0)
- cosy_auth_user.getAuthPayload: 0x14088c720 (偏移 0x88c720)
- cosy_auth_user.AuthToken: 0x14088b740 (偏移 0x88b740)

使用方法:
frida -l frida_hooks/hook_with_base.js -f ~/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe
*/

console.log("\n" + "="*60);
console.log("✅ Frida Hook 使用模块基地址 + 偏移量");
console.log("="*60);

// 找到 Lingma.exe 模块
var lingmaModule = Process.findModuleByName("Lingma.exe");

if (!lingmaModule) {
    console.log("❌ 未找到 Lingma.exe 模块，请检查程序名称");
    console.log("可用模块列表:");
    Process.enumerateModules().forEach(function(m) {
        if (m.name.indexOf("Lingma") !== -1 || m.name.indexOf("lingma") !== -1) {
            console.log("  - " + m.name + " @ " + m.base);
        }
    });
} else {
    console.log("模块基地址: " + lingmaModule.base);
    console.log("模块大小: " + lingmaModule.size);

    // 计算实际函数地址
    var baseOffset = ptr("0x140000000");  // IDA Pro 分析时的基地址

    // 函数偏移量（相对于 IDA 基地址）
    var offsets = {
        getAuthSignature: ptr("0x88c4e0"),
        getAuthPayload: ptr("0x88c720"),
        AuthToken: ptr("0x88b740")
    };

    // 计算实际地址
    function calculateAddress(offset) {
        return lingmaModule.base.add(offset.sub(baseOffset));
    }

    var addresses = {
        getAuthSignature: calculateAddress(offsets.getAuthSignature),
        getAuthPayload: calculateAddress(offsets.getAuthPayload),
        AuthToken: calculateAddress(offsets.AuthToken)
    };

    console.log("\n实际函数地址:");
    console.log("  - getAuthSignature: " + addresses.getAuthSignature);
    console.log("  - getAuthPayload: " + addresses.getAuthPayload);
    console.log("  - AuthToken: " + addresses.AuthToken);
    console.log("\n等待函数调用...\n");

    // ============================================
    // Hook 1: getAuthSignature
    // ============================================
    Interceptor.attach(addresses.getAuthSignature, {
        onEnter: function(args) {
            console.log("\n" + "="*60);
            console.log("[getAuthSignature] Called!");
            console.log("="*60);

            try {
                var params = [];
                var paramNames = [];

                for (var i = 0; i < 5; i++) {
                    var ptr_arg = args[i*2];
                    var len_arg = args[i*2 + 1];
                    var len = len_arg.toInt32();
                    var str = Memory.readUtf8String(ptr_arg, len);
                    params.push(str);

                    if (str.match(/^\d+$/)) {
                        paramNames.push("userId");
                    } else if (str.startsWith("pt-")) {
                        paramNames.push("securityOauthToken");
                    } else if (str.startsWith("rt-")) {
                        paramNames.push("refreshToken");
                    } else if (str.startsWith("/api/")) {
                        paramNames.push("path");
                    } else if (str === "POST" || str === "GET") {
                        paramNames.push("method");
                    } else {
                        paramNames.push("unknown");
                    }

                    console.log("Param[" + i + "] (" + paramNames[i] + "): " + str);
                }

                this.params = params;
                this.paramNames = paramNames;

                console.log("\n签名字符串：");
                console.log("\"" + params.join("\\n") + "\"");

            } catch (e) {
                console.log("Error: " + e);
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
                console.log("参数顺序:");
                for (var i = 0; i < 5; i++) {
                    console.log("  " + i + ": " + this.paramNames[i]);
                }

            } catch (e) {
                console.log("Error: " + e);
                console.log("  retval = " + retval);
                console.log("  rbx = " + this.context.rbx);
            }
        }
    });

    // ============================================
    // Hook 2: getAuthPayload
    // ============================================
    Interceptor.attach(addresses.getAuthPayload, {
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
    // Hook 3: AuthToken
    // ============================================
    Interceptor.attach(addresses.AuthToken, {
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
    console.log("  - 灵码启动后会自动调用用户状态检查");
    console.log("  - Token 快过期时会调用 refresh token");
    console.log("  - 观察参数顺序验证 IDA 分析\n");
}