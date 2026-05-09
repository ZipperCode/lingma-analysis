console.log("Frida IDA-address Hook starting...");

var mod = Process.getModuleByName("Lingma.exe");
var base = mod.base;
console.log("Base: " + base);

// Addresses from IDA (RVA = IDA_addr - 0x140000000)
var functions = {
    // buildRequest chain
    buildRequest:              { rva: 0x87cc20 },
    addBasicHeaders:           { rva: 0x87ef20 },
    addBigModelSignature:      { rva: 0x87e5e0 },
    addBigModelAuthorization:  { rva: 0x87ea20 },
    shouldEncryptBody:         { rva: 0x87e500 },
    shouldAddEncodeParam:      { rva: 0x87e3c0 },
    // Encoding
    encodeToString:            { rva: 0x4549e0 },
    // Auth
    getAuthPayload:            { rva: 0x88c720 },
    getAuthSignature:          { rva: 0x88c4e0 },
    // Refresh
    doRefreshToken:            { rva: 0x88d660 },
    AuthToken:                 { rva: 0x88b740 },
};

// Also hook crypto/tls.Conn.Write to capture plaintext
var cryptoMods = [];
Process.enumerateModules().forEach(function(m) {
    if (m.name.indexOf("crypto") >= 0 || m.name.toLowerCase().indexOf("tls") >= 0) {
        cryptoMods.push(m);
    }
});
console.log("Crypto/TLS modules: " + cryptoMods.length);

// Hook target functions
function hookByRVA(name, rva) {
    var addr = base.add(rva);
    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                var ts = new Date().toISOString();
                console.log("\n>>> [" + name + "] " + ts);
                // Dump first 8 args as hex
                for (var i = 0; i < 8; i++) {
                    try {
                        console.log("  arg[" + i + "] = 0x" + args[i].toString(16));
                        // Try to read as string pointer
                        try {
                            var s = ptr(args[i]).readCString();
                            if (s && s.length > 0 && s.length < 200) {
                                console.log("       = \"" + s + "\"");
                            }
                        } catch(e2) {}
                        // Try to read as Go string {ptr, len}
                        try {
                            var strPtr = ptr(args[i]).readPointer();
                            var strLen = ptr(args[i]).add(8).readUInt();
                            if (strLen > 0 && strLen < 5000 && strPtr) {
                                var s = strPtr.readUtf8String(strLen);
                                console.log("       = (GoStr,len=" + strLen + ") \"" + s.substring(0, 200) + "\"");
                            }
                        } catch(e3) {}
                    } catch(e1) {
                        console.log("  arg[" + i + "] = <error>");
                    }
                }
            },
            onLeave: function(retval) {
                console.log("<<< [" + name + "] ret=0x" + retval.toString(16));
            }
        });
        console.log("Hooked: " + name + " @ " + addr);
    } catch(e) {
        console.log("FAIL: " + name + " @ " + addr + " - " + e);
    }
}

// Hook each function
Object.keys(functions).forEach(function(name) {
    hookByRVA(name, functions[name].rva);
});

// Hook WSASend to capture socket-level traffic
var ws2 = Process.getModuleByName("ws2_32.dll");
if (ws2) {
    try {
        var ws2exps = ws2.enumerateExports ? ws2.enumerateExports() : [];
        if (ws2exps.length === 0) {
            // Frida 17 - try other method
            console.log("ws2 exports not available via standard method");
        }
        ws2exps.forEach(function(e) {
            if (e.name === "WSASend") {
                Interceptor.attach(e.address, {
                    onEnter: function(args) {
                        try {
                            var bufCount = args[2].toInt32();
                            var totalLen = 0;
                            for (var i = 0; i < bufCount && i < 16; i++) {
                                totalLen += args[1].add(i * 16).readUInt();
                            }
                            if (totalLen < 80 || totalLen > 500000) return;
                            var dataPtr = args[1].add(8).readPointer();
                            var firstLen = args[1].readUInt();
                            var data = dataPtr.readUtf8String(Math.min(firstLen, 5000));
                            if (data.indexOf("alibabacloud") >= 0 || data.indexOf("tongyi") >= 0 ||
                                data.indexOf("POST ") >= 0 || data.indexOf("user/status") >= 0 ||
                                data.indexOf("refresh_token") >= 0 || data.indexOf("algo") >= 0) {
                                var ts = new Date().toISOString();
                                console.log("\n===== [WSASend] " + ts + " total=" + totalLen + " =====");
                                console.log(data.substring(0, 8000));
                                console.log("========================================\n");
                            }
                        } catch(e) {}
                    }
                });
                console.log("Hooked WSASend");
            }
        });
    } catch(e) {
        console.log("WSASend hook error: " + e);
    }
}

console.log("\nAll hooks installed!");
