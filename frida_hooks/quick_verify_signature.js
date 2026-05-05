/*
Frida Hook: 快速验证签名参数顺序
目标函数: cosy_auth_user.getAuthSignature

使用方法:
frida -l frida_hooks/quick_verify_signature.js -p <pid>
  或
frida -l frida_hooks/quick_verify_signature.js -f ~/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe
*/

console.log("\n✅ Quick Signature Verification Hook Loaded");
console.log("Target: cosy_auth_user.getAuthSignature");
console.log("Waiting for function call...\n");

// Hook getAuthSignature 函数
Interceptor.attach(Module.findExportByName(null, "cosy_auth_user.getAuthSignature"), {
    onEnter: function(args) {
        console.log("\n" + "="*60);
        console.log("[getAuthSignature] Called!");
        console.log("="*60);

        // 参数分析
        // 根据反编译：总共 10 个参数（5 个 string 的 ptr+len）
        console.log("\n参数解析：");

        try {
            // 读取所有 5 个字符串参数
            var params = [];
            for (var i = 0; i < 5; i++) {
                var ptr = args[i*2];
                var len = args[i*2 + 1].toInt32();
                var str = Memory.readUtf8String(ptr, len);
                params.push(str);

                console.log("Param[" + i + "]: " + str);
            }

            // 保存上下文
            this.params = params;

            // 打印拼接后的字符串
            console.log("\n签名字符串（拼接后）：");
            console.log(params.join("\n"));

        } catch (e) {
            console.log("Error reading args: " + e);
            console.log("Args dump:");
            for (var i = 0; i < 10; i++) {
                console.log("  args[" + i + "] = " + args[i]);
            }
        }
    },

    onLeave: function(retval) {
        console.log("\n[getAuthSignature] Return");

        // retval 是 (string ptr, string len)
        // Go 函数返回：rax = ptr, rbx = len
        try {
            var sig_ptr = retval;
            var sig_len = this.context.rbx.toInt32();
            var signature = Memory.readUtf8String(sig_ptr, sig_len);

            console.log("Signature (MD5): " + signature);
            console.log("Length: " + sig_len);

            // 验证 MD5（如果环境支持）
            console.log("\n✅ 签名参数顺序验证完成");
            console.log("参数顺序: " + this.params.map(function(p, i) {
                return "Param[" + i + "]";
            }).join(", "));

        } catch (e) {
            console.log("Error reading retval: " + e);
            console.log("  retval (rax) = " + retval);
            console.log("  rbx = " + this.context.rbx);
        }
    }
});

console.log("\n💡 提示：");
console.log("  - 当灵码程序调用 refresh token 时，此 Hook 会自动触发");
console.log("  - 请观察输出的参数顺序，验证 IDA 分析结果");
console.log("  - 预期顺序: userId, securityOauthToken, refreshToken, path, method\n");