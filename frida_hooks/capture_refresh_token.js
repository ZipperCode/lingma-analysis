/*
Frida Hook：抓取灵码真实的 refresh token 请求
目标函数：cosy_auth_user.doRefreshToken (地址 0x14088d660)

使用方法：
frida -l frida_hooks/capture_refresh_token.js -f ~/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe
*/

// 监控 HTTP POST 请求（refresh token）
Interceptor.attach(Module.findExportByName(null, "net_http._ptr_Client.do"), {
    onEnter: function(args) {
        // 检查 URL 是否是 refresh_token 端点
        try {
            var request = args[1];  // HTTP Request 对象

            // 尝试获取 URL
            var url = request.URL.toString();
            if (url && url.includes("refresh_token")) {
                console.log("\n" + "="*60);
                console.log("[Refresh Token Request Detected]");
                console.log("="*60);
                console.log("URL: " + url);

                // 获取请求头
                var headers = request.Header;
                console.log("\nHeaders:");
                for (var i = 0; i < headers.length; i++) {
                    console.log("  " + headers[i].Key + ": " + headers[i].Value);
                }

                // 获取请求体
                var body = request.Body;
                console.log("\nBody (raw):");
                console.log("  " + body.toString());

                // 保存到文件
                var timestamp = Date.now();
                var filename = "/tmp/lingma_refresh_" + timestamp + ".json";
                var data = {
                    "url": url,
                    "headers": headers,
                    "body": body.toString(),
                    "timestamp": timestamp
                };

                // 写入文件（如果环境支持）
                try {
                    var file = new File(filename, "w");
                    file.write(JSON.stringify(data, null, 2));
                    file.flush();
                    file.close();
                    console.log("\n✅ Saved to: " + filename);
                } catch (e) {
                    console.log("\n⚠️ File write failed: " + e);
                }
            }
        } catch (e) {
            console.log("Error: " + e);
        }
    },

    onLeave: function(retval) {
        // 可以在这里获取响应
        console.log("Response status: " + retval);
    }
});

// 监控签名计算函数
Interceptor.attach(Module.findExportByName(null, "cosy_remoting.BuildBigModelSignRequest"), {
    onEnter: function(args) {
        console.log("\n" + "="*60);
        console.log("[BuildBigModelSignRequest Called]");
        console.log("="*60);

        // 尝试读取参数
        try {
            // 参数可能包含签名输入数据
            var context = args[0];
            console.log("Context ptr: " + context);

            // 记录调用栈
            console.log("\nBacktrace:");
            var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
            for (var i = 0; i < bt.length; i++) {
                console.log("  " + bt[i]);
            }
        } catch (e) {
            console.log("Error: " + e);
        }
    },

    onLeave: function(retval) {
        console.log("Return value: " + retval);
    }
});

// 监控 Encode 编码函数
Interceptor.attach(Module.findExportByName(null, "cosy_remoting.encodeRequestBody"), {
    onEnter: function(args) {
        console.log("\n" + "="*60);
        console.log("[encodeRequestBody Called]");
        console.log("="*60);

        // 获取 Encode 参数
        try {
            var encode_type = args[1];  // Encode=1 or Encode=2
            console.log("Encode type: " + encode_type);

            // 获取原始数据
            var data_ptr = args[0];
            var data_len = args[2];
            var data = Memory.readUtf8String(data_ptr, data_len);
            console.log("\nOriginal data:");
            console.log("  " + data);

        } catch (e) {
            console.log("Error: " + e);
        }
    },

    onLeave: function(retval) {
        // 获取编码后的数据
        try {
            var encoded_ptr = retval;
            var encoded = Memory.readUtf8String(encoded_ptr);
            console.log("\nEncoded data:");
            console.log("  " + encoded);
        } catch (e) {
            console.log("Error: " + e);
        }
    }
});

console.log("\n✅ Frida hooks installed successfully");
console.log("Monitoring refresh token requests...\n");