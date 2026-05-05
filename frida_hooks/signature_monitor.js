/*
Frida: 签名参数顺序验证（简化版）

使用方法：
frida -l frida_hooks/signature_monitor.js -f C:/Users/Zipper/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe

在 Frida REPL 中测试:
rpc.exports.triggerRefresh()
*/

console.log("\n" + "="*60);
console.log("✅ 签名参数顺序验证 Hook");
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
        doRefreshToken: ptr(0x14088d660 + baseOffset)
    };

    console.log("\n函数地址:");
    console.log("  getAuthSignature: " + addresses.getAuthSignature);
    console.log("  getAuthPayload: " + addresses.getAuthPayload);
    console.log("  AuthToken: " + addresses.AuthToken);
    console.log("  doRefreshToken: " + addresses.doRefreshToken);

    // ========== 核心 Hook: getAuthSignature ==========
    console.log("\n安装 getAuthSignature Hook...");

    Interceptor.attach(addresses.getAuthSignature, {
        onEnter: function(args) {
            console.log("\n" + "="*60);
            console.log("[Hook] getAuthSignature Called");
            console.log("="*60);

            // Go calling convention: 参数在栈上，args[i*2] = ptr, args[i*2+1] = len
            console.log("\n签名参数（5个字符串）:");

            this.params = [];
            for (var i = 0; i < 5; i++) {
                try {
                    var ptr_arg = args[i*2];
                    var len = args[i*2 + 1].toInt32();
                    var str = Memory.readUtf8String(ptr_arg, len);

                    this.params.push(str);

                    // 显示参数内容（截取显示）
                    var display = str.length > 50 ? str.substring(0, 50) + "..." : str;
                    console.log("  [" + i + "] length=" + len + " value=\"" + display + "\"");
                } catch (e) {
                    console.log("  [" + i + "] (读取失败: " + e + ")");
                    this.params.push("(error)");
                }
            }

            console.log("\n参数顺序推测:");
            console.log("  理论顺序: userId → secToken → refreshToken → path → method");
            console.log("  实际数据:");
            console.log("    [0] userId: " + this.params[0].substring(0, 20));
            console.log("    [1] secToken: " + this.params[1].substring(0, 30));
            console.log("    [2] refreshToken: " + this.params[2].substring(0, 30));
            console.log("    [3] path: " + this.params[3]);
            console.log("    [4] method: " + this.params[4]);
        },

        onLeave: function(retval) {
            console.log("\n签名结果:");
            console.log("  retval pointer: " + retval);

            try {
                // MD5 签名固定长度 32
                var signature = Memory.readUtf8String(retval, 32);
                console.log("  MD5 signature: " + signature);

                // 验证签名格式
                if (/^[a-f0-9]{32}$/.test(signature)) {
                    console.log("  ✅ 签名格式正确（32字符 hex）");
                } else {
                    console.log("  ⚠️ 签名格式异常");
                }
            } catch (e) {
                console.log("  (签名读取失败: " + e + ")");
            }

            // 输出完整的签名字符串（用于手动验证）
            if (this.params.length === 5 && this.params[2] !== "(error)") {
                var sign_data = this.params.join("\n");
                console.log("\n完整签名字符串:");
                console.log(sign_data);
            }
        }
    });

    // ========== Hook doRefreshToken（监控完整流程）==========
    console.log("\n安装 doRefreshToken Hook...");

    Interceptor.attach(addresses.doRefreshToken, {
        onEnter: function(args) {
            console.log("\n" + "="*60);
            console.log("[Hook] doRefreshToken Called - HTTP Refresh 开始");
            console.log("="*60);
            this.startTime = Date.now();
        },

        onLeave: function(retval) {
            var duration = Date.now() - this.startTime;
            console.log("\n[Hook] doRefreshToken Returned - HTTP Refresh 完成");
            console.log("  耗时: " + duration + " ms");
        }
    });

    console.log("\n✅ Hooks 安装完成");
    console.log("\n💡 等待灵码自动触发认证，或手动触发:");
    console.log("   在 Frida REPL 中运行: rpc.exports.triggerRefresh()");

    // ========== RPC 导出函数 ==========
    rpc.exports = {
        triggerRefresh: function() {
            console.log("\n[RPC] 手动触发 token refresh...");
            console.log("提示: 需要通过 WebSocket 或其他方式触发");
            console.log("请运行: python tools/ws_refresh_test.py");
        }
    };
}