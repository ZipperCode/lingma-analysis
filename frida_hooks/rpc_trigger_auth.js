/*
Frida RPC: 主动调用灵码认证函数，触发签名计算

使用方法:
frida -l frida_hooks/rpc_trigger_auth.js -f ~/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe

在 Frida REPL 中调用:
rpc.exports.triggerAuthToken(path, method);
rpc.exports.triggerRefreshToken(userId, secToken, refreshToken);
*/

console.log("\n" + "="*60);
console.log("✅ Frida RPC - 主动触发认证函数");
console.log("="*60);

var lingmaModule = Process.findModuleByName("Lingma.exe");

if (!lingmaModule) {
    console.log("❌ 未找到 Lingma.exe 模块");
} else {
    console.log("模块基地址: " + lingmaModule.base);

    var baseIDA = 0x140000000;
    var baseOffset = parseInt(lingmaModule.base) - baseIDA;

    var addresses = {
        getAuthSignature: ptr(0x14088c4e0 + baseOffset),
        getAuthPayload: ptr(0x14088c720 + baseOffset),
        AuthToken: ptr(0x14088b740 + baseOffset),
        doRefreshToken: ptr(0x14088d660 + baseOffset)  // 添加 refresh token 主函数
    };

    console.log("函数地址:");
    console.log("  getAuthSignature: " + addresses.getAuthSignature);
    console.log("  getAuthPayload: " + addresses.getAuthPayload);
    console.log("  AuthToken: " + addresses.AuthToken);
    console.log("  doRefreshToken: " + addresses.doRefreshToken);

    // 安装 Hook（用于监控）
    Interceptor.attach(addresses.getAuthSignature, {
        onEnter: function(args) {
            console.log("\n[Hook] getAuthSignature Called");

            var params = [];
            for (var i = 0; i < 5; i++) {
                var ptr_arg = args[i*2];
                var len = args[i*2 + 1].toInt32();
                var str = Memory.readUtf8String(ptr_arg, len);
                params.push(str);
                console.log("Param[" + i + "]: " + str);
            }

            this.params = params;
        },

        onLeave: function(retval) {
            try {
                var sig_len = this.context.rbx.toInt32();
                var signature = Memory.readUtf8String(retval, sig_len);
                console.log("\nSignature: " + signature);
            } catch (e) {
                console.log("Error: " + e);
            }
        }
    });

    console.log("\n✅ Hooks 安装完成");

    // RPC 导出函数
    rpc.exports = {
        /**
         * 触发 AuthToken 函数（模拟认证）
         * @param {string} path - API 路径
         * @param {string} method - HTTP 方法
         */
        triggerAuthToken: function(path, method) {
            console.log("\n[RPC] triggerAuthToken: " + path + " " + method);

            // 创建 Go string（ptr + len）
            var pathPtr = Memory.allocUtf8String(path);
            var pathLen = path.length;

            var methodPtr = Memory.allocUtf8String(method);
            var methodLen = method.length;

            // 创建空的 HTTP Request 对象（简化处理）
            // 实际需要完整的 Go struct，这里只是测试

            console.log("⚠️ AuthToken 需要完整的 Request struct");
            console.log("   暂时无法直接调用，需要使用 doRefreshToken");
        },

        /**
         * 触发 doRefreshToken 函数（完整 refresh 流程）
         * @param {string} userId - 用户 ID
         * @param {string} secToken - SecurityOauthToken
         * @param {string} refreshToken - RefreshToken
         */
        triggerRefreshToken: function(userId, secToken, refreshToken) {
            console.log("\n[RPC] triggerRefreshToken");
            console.log("  userId: " + userId);
            console.log("  secToken: " + secToken);
            console.log("  refreshToken: " + refreshToken);

            // doRefreshToken 需要完整的 context 和参数
            // 这里先监控 Hook，等待灵码自动触发

            console.log("⚠️ doRefreshToken 需要完整参数");
            console.log("   建议等待灵码自动触发，或使用 WebSocket refresh");
        },

        /**
         * 直接调用 getAuthSignature（测试签名计算）
         * @param {string} userId
         * @param {string} secToken
         * @param {string} refreshToken
         * @param {string} path
         * @param {string} method
         */
        testSignature: function(userId, secToken, refreshToken, path, method) {
            console.log("\n[RPC] testSignature - 直接调用签名函数");

            // 创建 Go strings
            var strings = [userId, secToken, refreshToken, path, method];
            var args = [];

            for (var i = 0; i < 5; i++) {
                var strPtr = Memory.allocUtf8String(strings[i]);
                var strLen = strings[i].length;
                args.push(strPtr);
                args.push(strLen);
            }

            console.log("调用 getAuthSignature...");

            try {
                // 调用函数（Go calling convention: args 在栈上）
                // 简化处理：直接调用并观察 Hook 输出

                var func = new NativeFunction(addresses.getAuthSignature, 'pointer', [
                    'pointer', 'int',  // param0
                    'pointer', 'int',  // param1
                    'pointer', 'int',  // param2
                    'pointer', 'int',  // param3
                    'pointer', 'int'   // param4
                ]);

                var result = func(
                    args[0], args[1],
                    args[2], args[3],
                    args[4], args[5],
                    args[6], args[7],
                    args[8], args[9]
                );

                console.log("✅ 函数调用成功");
                console.log("  retval: " + result);

                // 读取签名（rbx 存储长度）
                var sigLen = 32;  // MD5 长度固定 32
                var signature = Memory.readUtf8String(result, sigLen);
                console.log("  signature: " + signature);

                return {
                    success: true,
                    signature: signature,
                    params: strings
                };

            } catch (e) {
                console.log("❌ 调用失败: " + e);
                return {
                    success: false,
                    error: e.toString()
                };
            }
        }
    };

    console.log("\n✅ RPC 函数已导出:");
    console.log("  triggerAuthToken(path, method)");
    console.log("  triggerRefreshToken(userId, secToken, refreshToken)");
    console.log("  testSignature(userId, secToken, refreshToken, path, method)");
    console.log("\n💡 在 Frida REPL 中调用测试");
}