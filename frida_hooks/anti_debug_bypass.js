/*
Frida: 运行保护兼容 + 签名参数监控

使用方法：
方案 1：spawn 模式（推荐）
frida -l frida_hooks/anti_debug_bypass.js -f ~/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe

方案 2：attach 模式（Lingma 已经运行）
frida -l frida_hooks/anti_debug_bypass.js Lingma.exe
*/

console.log("\n" + "="*60);
console.log("✅ Frida 运行保护兼容 + 签名参数监控");
console.log("="*60);

var lingmaModule = Process.findModuleByName("Lingma.exe");

if (!lingmaModule) {
    console.log("❌ 未找到 Lingma.exe 模块");
    console.log("💡 提示：如果是 attach 模式，请确保 Lingma 正在运行");
} else {
    console.log("模块基地址: " + lingmaModule.base);

    // ========== 运行保护兼容 Hooks ==========
    console.log("\n[1] 安装运行保护兼容 Hooks...");

    // Hook IsDebuggerPresent
    var isDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
    if (isDebuggerPresent) {
        Interceptor.replace(isDebuggerPresent, new NativeCallback(function() {
            return 0;  // 返回未附加状态
        }, 'int', []));
        console.log("  ✅ IsDebuggerPresent 已兼容处理");
    }

    // Hook CheckRemoteDebuggerPresent
    var checkRemoteDebugger = Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent");
    if (checkRemoteDebugger) {
        Interceptor.replace(checkRemoteDebugger, new NativeCallback(function(handle, pbDebuggerPresent) {
            Memory.writeU8(pbDebuggerPresent, 0);
            return 1;
        }, 'int', ['pointer', 'pointer']));
        console.log("  ✅ CheckRemoteDebuggerPresent 已兼容处理");
    }

    // Hook NtQueryInformationProcess
    var ntQueryInfo = Module.findExportByName("ntdll.dll", "NtQueryInformationProcess");
    if (ntQueryInfo) {
        Interceptor.attach(ntQueryInfo, {
            onEnter: function(args) {
                this.processInformationClass = args[1].toInt32();
            },
            onLeave: function(retval) {
                // ProcessDebugPort (7) 或 ProcessDebugObjectHandle (30)
                if (this.processInformationClass === 7 || this.processInformationClass === 30) {
                    retval.replace(0);
                }
            }
        });
        console.log("  ✅ NtQueryInformationProcess 已绕过");
    }

    // ========== 认证函数 Hooks ==========
    console.log("\n[2] 安装认证函数 Hooks...");

    var baseIDA = 0x140000000;
    var baseOffset = parseInt(lingmaModule.base) - baseIDA;

    var addresses = {
        getAuthSignature: ptr(0x14088c4e0 + baseOffset),
        getAuthPayload: ptr(0x14088c720 + baseOffset),
        AuthToken: ptr(0x14088b740 + baseOffset),
        doRefreshToken: ptr(0x14088d660 + baseOffset)
    };

    console.log("函数地址:");
    console.log("  getAuthSignature: " + addresses.getAuthSignature);
    console.log("  getAuthPayload: " + addresses.getAuthPayload);
    console.log("  AuthToken: " + addresses.AuthToken);
    console.log("  doRefreshToken: " + addresses.doRefreshToken);

    // Hook getAuthSignature - 监控签名参数顺序
    Interceptor.attach(addresses.getAuthSignature, {
        onEnter: function(args) {
            console.log("\n[Hook] getAuthSignature Called");
            console.log("参数数量: 5 (userId, secToken, refreshToken, path, method)");

            this.params = [];
            for (var i = 0; i < 5; i++) {
                var ptr_arg = args[i*2];
                var len = args[i*2 + 1].toInt32();

                try {
                    var str = Memory.readUtf8String(ptr_arg, len);
                    this.params.push(str);
                    console.log("  Param[" + i + "]: " + str.substring(0, 50) + (len > 50 ? "..." : ""));
                } catch (e) {
                    console.log("  Param[" + i + "]: (读取失败: " + e + ")");
                }
            }

            // 尝试读取寄存器中的签名长度（rbx）
            this.sigLenAddr = this.context.rbx;
        },

        onLeave: function(retval) {
            try {
                // Go convention: 签名长度可能在 rbx 或栈上
                console.log("\nSignature (MD5):");
                console.log("  retval: " + retval);

                // 尝试读取签名（假设长度为 32，MD5 固定长度）
                var signature = Memory.readUtf8String(retval, 32);
                console.log("  signature: " + signature);
            } catch (e) {
                console.log("  (签名读取失败: " + e + ")");
            }

            // 输出参数顺序验证
            console.log("\n验证参数顺序:");
            console.log("  顺序: userId → secToken → refreshToken → path → method");
            console.log("  实际顺序:");
            for (var i = 0; i < this.params.length; i++) {
                var paramName = ["userId", "secToken", "refreshToken", "path", "method"][i];
                console.log("    [" + i + "] (" + paramName + "): " + this.params[i].substring(0, 30));
            }
        }
    });

    // Hook doRefreshToken - 监控完整的刷新流程
    Interceptor.attach(addresses.doRefreshToken, {
        onEnter: function(args) {
            console.log("\n[Hook] doRefreshToken Called");
            console.log("触发完整的 HTTP refresh 流程");

            // 记录触发时间
            this.startTime = Date.now();
        },

        onLeave: function(retval) {
            var duration = Date.now() - this.startTime;
            console.log("\n[Hook] doRefreshToken Returned");
            console.log("耗时: " + duration + " ms");
            console.log("返回值: " + retval);
        }
    });

    console.log("\n✅ Hooks 安装完成");
    console.log("\n💡 等待灵码程序自动触发认证流程...");
    console.log("   或者通过 WebSocket auth/refreshToken 手动触发");
}
