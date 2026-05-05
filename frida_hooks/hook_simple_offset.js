/*
Frida Hook: 使用模块基地址 + 偏移量验证签名参数顺序
IDA Pro 分析地址：
- 基地址: 0x140000000
- getAuthSignature: 0x14088c4e0 (偏移 0x88c4e0)
- getAuthPayload: 0x14088c720 (偏移 0x88c720)
- AuthToken: 0x14088b740 (偏移 0x88b740)

使用方法:
frida -l frida_hooks/hook_simple_offset.js -f ~/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe
*/

console.log("\n" + "="*60);
console.log("✅ Frida Hook - 使用简单偏移量");
console.log("="*60);

var lingmaModule = Process.findModuleByName("Lingma.exe");

if (!lingmaModule) {
    console.log("❌ 未找到 Lingma.exe 模块");
    Process.enumerateModules().forEach(function(m) {
        if (m.name.indexOf("Lingma") !== -1 || m.name.indexOf("lingma") !== -1) {
            console.log("  - " + m.name + " @ " + m.base);
        }
    });
} else {
    console.log("模块基地址: " + lingmaModule.base);
    console.log("模块大小: " + lingmaModule.size);

    // 使用简单偏移量（直接使用 IDA 基地址 + 偏移）
    var baseIDA = 0x140000000;

    // 计算实际地址：基地址 + (IDA地址 - IDA基地址)
    var baseOffset = parseInt(lingmaModule.base) - baseIDA;

    var addresses = {
        getAuthSignature: ptr(0x14088c4e0 + baseOffset),
        getAuthPayload: ptr(0x14088c720 + baseOffset),
        AuthToken: ptr(0x14088b740 + baseOffset)
    };

    console.log("\n计算结果:");
    console.log("  基地址偏移: " + baseOffset);
    console.log("  getAuthSignature: " + addresses.getAuthSignature);
    console.log("  getAuthPayload: " + addresses.getAuthPayload);
    console.log("  AuthToken: " + addresses.AuthToken);

    console.log("\n验证地址是否在模块范围内:");
    var moduleStart = parseInt(lingmaModule.base);
    var moduleEnd = moduleStart + lingmaModule.size;

    console.log("  模块范围: 0x" + moduleStart.toString(16) + " - 0x" + moduleEnd.toString(16));
    console.log("  getAuthSignature 是否在范围内: " +
        (parseInt(addresses.getAuthSignature) >= moduleStart &&
         parseInt(addresses.getAuthSignature) < moduleEnd));

    console.log("\n等待函数调用...\n");

    // Hook getAuthSignature
    Interceptor.attach(addresses.getAuthSignature, {
        onEnter: function(args) {
            console.log("\n[getAuthSignature] Called");

            try {
                var params = [];
                for (var i = 0; i < 5; i++) {
                    var ptr_arg = args[i*2];
                    var len = args[i*2 + 1].toInt32();
                    var str = Memory.readUtf8String(ptr_arg, len);
                    params.push(str);
                    console.log("Param[" + i + "]: " + str);
                }

                this.params = params;
                console.log("\n签名字符串: \"" + params.join("\\n") + "\"");

            } catch (e) {
                console.log("Error: " + e);
            }
        },

        onLeave: function(retval) {
            try {
                var sig_len = this.context.rbx.toInt32();
                var signature = Memory.readUtf8String(retval, sig_len);
                console.log("\nSignature (MD5): " + signature);
                console.log("✅ 验证完成");

            } catch (e) {
                console.log("Error: " + e);
            }
        }
    });

    console.log("✅ Hooks 安装成功\n");
}