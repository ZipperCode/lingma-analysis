/**
 * Frida Script for Lingma OAuth Login Flow Monitoring
 * Target: lingma.exe (Windows x64)
 * Purpose: Complete OAuth flow interception and CosyUserInfo struct dump
 */

// ========== 辅助函数 ==========

/**
 * 读取 Go 字符串 (GoString: ptr + len)
 */
function readGoString(ptr) {
    if (ptr.isNull()) return null;
    try {
        const strPtr = ptr.readPointer();
        const strLen = ptr.add(Process.pointerSize).readU64();
        if (strLen > 0 && strLen < 100000) {
            return strPtr.readUtf8String(Number(strLen));
        }
        return null;
    } catch (e) {
        return `[Error reading GoString: ${e.message}]`;
    }
}

/**
 * 读取 Go byte slice (slice: ptr + len + cap)
 */
function readGoByteSlice(ptr) {
    if (ptr.isNull()) return null;
    try {
        const slicePtr = ptr.readPointer();
        const sliceLen = ptr.add(Process.pointerSize).readU64();
        if (sliceLen > 0 && sliceLen < 100000) {
            const bytes = slicePtr.readByteArray(Number(sliceLen));
            return {
                hex: hexdump(bytes, { ansi: true }),
                raw: bytes,
                length: sliceLen
            };
        }
        return null;
    } catch (e) {
        return `[Error reading GoByteSlice: ${e.message}]`;
    }
}

/**
 * Dump 结构体内存
 */
function dumpStruct(ptr, size, name) {
    if (ptr.isNull()) {
        console.log(`[!] ${name} pointer is NULL`);
        return null;
    }
    try {
        const bytes = ptr.readByteArray(size);
        console.log(`\n${'='.repeat(80)}`);
        console.log(`[DUMP] ${name} @ ${ptr} (${size} bytes)`);
        console.log(`${'='.repeat(80)}`);
        console.log(hexdump(bytes, { ansi: true, offset: 0 }));
        return bytes;
    } catch (e) {
        console.log(`[!] Error dumping ${name}: ${e.message}`);
        return null;
    }
}

/**
 * 从结构体偏移读取 Go 字符串
 */
function readStringFromOffset(structPtr, offset) {
    const fieldPtr = structPtr.add(offset);
    return readGoString(fieldPtr);
}

/**
 * 从结构体偏移读取时间戳 (int64)
 */
function readInt64FromOffset(structPtr, offset) {
    return structPtr.add(offset).readS64();
}

// ========== 主逻辑 ==========

console.log('\n' + '='.repeat(80));
console.log('[*] Lingma OAuth Monitor - Starting');
console.log('[*] Target: lingma.exe');
console.log('='.repeat(80) + '\n');

// 查找 lingma.exe 模块
const lingmaModule = Process.findModuleByName('lingma.exe');
if (!lingmaModule) {
    console.log('[!] Cannot find lingma.exe module');
    // 尝试枚举所有模块找到主程序
    const modules = Process.enumerateModules();
    const mainModule = modules.find(m => m.name.includes('.exe'));
    if (mainModule) {
        console.log(`[*] Found main module: ${mainModule.name} @ ${mainModule.base}`);
    } else {
        console.log('[!] No exe module found');
    }
} else {
    console.log(`[*] Found lingma.exe @ ${lingmaModule.base}`);
}

// ========== 1. OAuth 登录启动监控 ==========

// LoginStart (0x141a10680)
console.log('[*] Hooking LoginStart (0x141a10680)');
Interceptor.attach(Module.findBaseAddress('lingma.exe').add(0x1a10680), {
    onEnter: function(args) {
        console.log('\n' + '='.repeat(80));
        console.log('[HOOK] LoginStart');
        console.log('='.repeat(80));

        // 尝试读取栈上的参数
        const sp = this.context.sp;
        console.log('[*] Stack Pointer: ' + sp);

        // Go 参数通常在栈上
        for (let i = 0; i < 8; i++) {
            try {
                const paramPtr = sp.add(i * Process.pointerSize).readPointer();
                console.log(`[*]   SP+0x${(i * 8).toString(16)}: ${paramPtr}`);
            } catch (e) {}
        }
    },
    onLeave: function(retval) {
        console.log('[*] LoginStart returned');
        console.log('[*]   Return: ' + retval);
    }
});

// generatePKCEChallenge (0x141a197a0)
console.log('[*] Hooking generatePKCEChallenge (0x141a197a0)');
Interceptor.attach(Module.findBaseAddress('lingma.exe').add(0x1a197a0), {
    onEnter: function(args) {
        console.log('\n' + '='.repeat(80));
        console.log('[HOOK] generatePKCEChallenge');
        console.log('='.repeat(80));

        const sp = this.context.sp;
        console.log('[*] Stack Pointer: ' + sp);

        // 打印栈内容
        for (let i = 0; i < 12; i++) {
            try {
                const paramPtr = sp.add(i * Process.pointerSize).readPointer();
                console.log(`[*]   SP+0x${(i * 8).toString(16)}: ${paramPtr}`);

                // 尝试读取为字符串
                if (!paramPtr.isNull() && paramPtr.compare(ptr('0x10000')) > 0) {
                    try {
                        const str = paramPtr.readCString(50);
                        if (str && str.length > 2 && str.length < 100) {
                            console.log(`[*]      -> String: "${str}"`);
                        }
                    } catch (e) {}
                }
            } catch (e) {}
        }
    },
    onLeave: function(retval) {
        console.log('[*] generatePKCEChallenge returned');

        // Go 返回值在栈上
        const sp = this.context.sp;
        try {
            // 返回值通常是两个字符串（verifier + challenge）
            const ret1 = sp.readPointer();
            const len1 = sp.add(Process.pointerSize).readU64();
            console.log(`[*]   Ret1: ptr=${ret1}, len=${len1}`);
            if (len1 > 0 && len1 < 100) {
                console.log(`[*]   Verifier: "${ret1.readUtf8String(Number(len1))}"`);
            }

            const ret2 = sp.add(Process.pointerSize * 2).readPointer();
            const len2 = sp.add(Process.pointerSize * 3).readU64();
            console.log(`[*]   Ret2: ptr=${ret2}, len=${len2}`);
            if (len2 > 0 && len2 < 100) {
                console.log(`[*]   Challenge: "${ret2.readUtf8String(Number(len2))}"`);
            }
        } catch (e) {
            console.log(`[!] Error reading return values: ${e.message}`);
        }
    }
});

// PrepareLoginRequest (0x141a198a0)
console.log('[*] Hooking PrepareLoginRequest (0x141a198a0)');
Interceptor.attach(Module.findBaseAddress('lingma.exe').add(0x1a198a0), {
    onEnter: function(args) {
        console.log('\n' + '='.repeat(80));
        console.log('[HOOK] PrepareLoginRequest');
        console.log('='.repeat(80));

        const sp = this.context.sp;
        console.log('[*] Stack Pointer: ' + sp);

        // 打印前20个栈参数
        for (let i = 0; i < 20; i++) {
            try {
                const paramPtr = sp.add(i * Process.pointerSize).readPointer();
                console.log(`[*]   SP+0x${(i * 8).toString(16)}: ${paramPtr}`);
            } catch (e) {}
        }
    },
    onLeave: function(retval) {
        console.log('[*] PrepareLoginRequest returned');
    }
});

// ========== 2. OAuth 回调处理监控 ==========

// HandleAuthCallback (0x141a18dc0)
console.log('[*] Hooking HandleAuthCallback (0x141a18dc0)');
Interceptor.attach(Module.findBaseAddress('lingma.exe').add(0x1a18dc0), {
    onEnter: function(args) {
        console.log('\n' + '='.repeat(80));
        console.log('[HOOK] HandleAuthCallback');
        console.log('='.repeat(80));

        const sp = this.context.sp;
        console.log('[*] Stack Pointer: ' + sp);

        // 打印栈参数并尝试识别 LoginAuthCallbackParam 结构体
        console.log('[*] Parameters:');
        for (let i = 0; i < 30; i++) {
            try {
                const paramPtr = sp.add(i * Process.pointerSize).readPointer();
                const offset = i * 8;
                console.log(`[*]   SP+0x${offset.toString(16).padStart(2, '0')}: ${paramPtr}`);

                // 尝试读取字符串
                if (!paramPtr.isNull() && paramPtr.compare(ptr('0x10000')) > 0) {
                    try {
                        const str = paramPtr.readCString(100);
                        if (str && str.length > 5 && str.length < 500 && /^[\x20-\x7E]+$/.test(str)) {
                            console.log(`[*]      -> "${str}"`);
                        }
                    } catch (e) {}
                }
            } catch (e) {}
        }

        // 尝试读取 Go slice/string 参数
        console.log('[*] Trying to read Go slice/string parameters:');
        for (let i = 0; i < 10; i++) {
            try {
                // Go string/slice: ptr, len, [cap]
                const base = sp.add(i * Process.pointerSize * 2);
                const strOrSlice = readGoString(base);
                if (strOrSlice && strOrSlice.length > 10 && strOrSlice.length < 2000) {
                    console.log(`[*]   Param ${i}: "${strOrSlice}"`);
                }
            } catch (e) {}
        }
    },
    onLeave: function(retval) {
        console.log('[*] HandleAuthCallback returned');
    }
});

// parseAuthInfoV3 (0x141a21b80)
console.log('[*] Hooking parseAuthInfoV3 (0x141a21b80)');
Interceptor.attach(Module.findBaseAddress('lingma.exe').add(0x1a21b80), {
    onEnter: function(args) {
        console.log('\n' + '='.repeat(80));
        console.log('[HOOK] parseAuthInfoV3');
        console.log('='.repeat(80));

        const sp = this.context.sp;
        console.log('[*] Stack Pointer: ' + sp);

        // 尝试读取输入的 auth 字符串
        console.log('[*] Input parameters:');
        for (let i = 0; i < 10; i++) {
            try {
                const base = sp.add(i * Process.pointerSize);
                const maybeStr = readGoString(base);
                if (maybeStr && maybeStr.length > 10) {
                    console.log(`[*]   Param ${i}: "${maybeStr}"`);
                }
            } catch (e) {}
        }
    },
    onLeave: function(retval) {
        console.log('[*] parseAuthInfoV3 returned');

        // 尝试读取返回的结构体
        const sp = this.context.sp;
        console.log('[*] Return values on stack:');
        for (let i = 0; i < 20; i++) {
            try {
                const val = sp.add(i * Process.pointerSize).readPointer();
                console.log(`[*]   SP+0x${(i * 8).toString(16)}: ${val}`);
            } catch (e) {}
        }
    }
});

// parseAuthToken (0x141a213e0)
console.log('[*] Hooking parseAuthToken (0x141a213e0)');
Interceptor.attach(Module.findBaseAddress('lingma.exe').add(0x1a213e0), {
    onEnter: function(args) {
        console.log('\n' + '='.repeat(80));
        console.log('[HOOK] parseAuthToken');
        console.log('='.repeat(80));

        const sp = this.context.sp;
        console.log('[*] Stack Pointer: ' + sp);

        // 读取 token_string 输入
        console.log('[*] Input parameters:');
        for (let i = 0; i < 10; i++) {
            try {
                const base = sp.add(i * Process.pointerSize);
                const maybeStr = readGoString(base);
                if (maybeStr && maybeStr.length > 10) {
                    console.log(`[*]   Param ${i}: "${maybeStr}"`);

                    // 检查是否包含 \n 分隔符
                    if (maybeStr.includes('\n')) {
                        console.log('[*]   -> Found \\n separator in token_string!');
                        const parts = maybeStr.split('\n');
                        console.log(`[*]   -> Split into ${parts.length} parts:`);
                        parts.forEach((part, idx) => {
                            console.log(`[*]      Part ${idx}: "${part}"`);
                        });
                    }
                }
            } catch (e) {}
        }
    },
    onLeave: function(retval) {
        console.log('[*] parseAuthToken returned');
    }
});

// CustomDecryptParts (0x140455ca0)
console.log('[*] Hooking CustomDecryptParts (0x140455ca0)');
Interceptor.attach(Module.findBaseAddress('lingma.exe').add(0x455ca0), {
    onEnter: function(args) {
        console.log('\n' + '='.repeat(80));
        console.log('[HOOK] CustomDecryptParts');
        console.log('='.repeat(80));

        const sp = this.context.sp;
        console.log('[*] Stack Pointer: ' + sp);

        // 打印参数
        console.log('[*] Parameters:');
        for (let i = 0; i < 15; i++) {
            try {
                const paramPtr = sp.add(i * Process.pointerSize).readPointer();
                console.log(`[*]   SP+0x${(i * 8).toString(16)}: ${paramPtr}`);

                // 尝试读取字符串
                if (!paramPtr.isNull() && paramPtr.compare(ptr('0x10000')) > 0) {
                    try {
                        const str = paramPtr.readCString(200);
                        if (str && str.length > 2 && str.length < 500 && /^[\x20-\x7E]+$/.test(str)) {
                            console.log(`[*]      -> "${str}"`);
                        }
                    } catch (e) {}
                }
            } catch (e) {}
        }
    },
    onLeave: function(retval) {
        console.log('[*] CustomDecryptParts returned');

        // 检查返回的分隔符和结果
        const sp = this.context.sp;
        console.log('[*] Return values:');
        for (let i = 0; i < 10; i++) {
            try {
                const base = sp.add(i * Process.pointerSize);
                const maybeStr = readGoString(base);
                if (maybeStr && maybeStr.length > 0) {
                    console.log(`[*]   Ret ${i}: "${maybeStr}"`);
                }
            } catch (e) {}
        }
    }
});

// ========== 3. Token 存储监控 ==========

// CompleteLoginWithSelectAccount (0x141a0fee0)
console.log('[*] Hooking CompleteLoginWithSelectAccount (0x141a0fee0)');
Interceptor.attach(Module.findBaseAddress('lingma.exe').add(0x1a0fee0), {
    onEnter: function(args) {
        console.log('\n' + '='.repeat(80));
        console.log('[HOOK] CompleteLoginWithSelectAccount');
        console.log('='.repeat(80));

        const sp = this.context.sp;
        console.log('[*] Stack Pointer: ' + sp);
    },
    onLeave: function(retval) {
        console.log('[*] CompleteLoginWithSelectAccount returned');
    }
});

// CompleteUserLogin (0x141a12200)
console.log('[*] Hooking CompleteUserLogin (0x141a12200)');
Interceptor.attach(Module.findBaseAddress('lingma.exe').add(0x1a12200), {
    onEnter: function(args) {
        console.log('\n' + '='.repeat(80));
        console.log('[HOOK] CompleteUserLogin');
        console.log('='.repeat(80));

        const sp = this.context.sp;
        console.log('[*] Stack Pointer: ' + sp);
    },
    onLeave: function(retval) {
        console.log('[*] CompleteUserLogin returned');
    }
});

// saveUserInfoAndQuota (0x141a11ee0)
console.log('[*] Hooking saveUserInfoAndQuota (0x141a11ee0)');
Interceptor.attach(Module.findBaseAddress('lingma.exe').add(0x1a11ee0), {
    onEnter: function(args) {
        console.log('\n' + '='.repeat(80));
        console.log('[HOOK] saveUserInfoAndQuota');
        console.log('='.repeat(80));

        const sp = this.context.sp;
        console.log('[*] Stack Pointer: ' + sp);
    },
    onLeave: function(retval) {
        console.log('[*] saveUserInfoAndQuota returned');
    }
});

// SaveUserInfo (0x14088e260) - **关键监控点**
console.log('[*] Hooking SaveUserInfo (0x14088e260) - KEY MONITORING POINT');
Interceptor.attach(Module.findBaseAddress('lingma.exe').add(0x88e260), {
    onEnter: function(args) {
        console.log('\n' + '='.repeat(80));
        console.log('[HOOK] SaveUserInfo - DUMPING CosyUserInfo STRUCT (288 bytes)');
        console.log('='.repeat(80));

        const sp = this.context.sp;
        console.log('[*] Stack Pointer: ' + sp);

        // Go 参数在栈上，尝试找到 CosyUserInfo 指针
        console.log('[*] Searching for CosyUserInfo pointer on stack...');

        for (let i = 0; i < 20; i++) {
            try {
                const maybeStructPtr = sp.add(i * Process.pointerSize).readPointer();

                // 检查是否可能是有效的结构体指针
                if (!maybeStructPtr.isNull() && maybeStructPtr.compare(ptr('0x10000')) > 0) {
                    console.log(`[*]   Candidate at SP+0x${(i * 8).toString(16)}: ${maybeStructPtr}`);

                    // 尝试读取并验证 CosyUserInfo 结构体
                    try {
                        // 读取前16字节看看是否合理
                        const preview = maybeStructPtr.readByteArray(16);
                        const previewHex = Array.from(new Uint8Array(preview)).map(b => b.toString(16).padStart(2, '0')).join(' ');
                        console.log(`[*]      Preview: ${previewHex}`);

                        // 尝试读取 offset 0x80 和 0x90 的字符串指针（SecurityOauthToken 和 RefreshToken）
                        try {
                            const tokenPtr80 = maybeStructPtr.add(0x80).readPointer();
                            const tokenLen80 = maybeStructPtr.add(0x88).readU64();
                            const tokenPtr90 = maybeStructPtr.add(0x90).readPointer();
                            const tokenLen90 = maybeStructPtr.add(0x98).readU64();

                            // 检查长度是否合理（token 通常 50-500 字符）
                            if (tokenLen80 > 10 && tokenLen80 < 1000 && tokenLen90 > 10 && tokenLen90 < 1000) {
                                console.log(`[*]      Potential token at 0x80: ptr=${tokenPtr80}, len=${tokenLen80}`);
                                console.log(`[*]      Potential token at 0x90: ptr=${tokenPtr90}, len=${tokenLen90}`);

                                // 尝试读取 token
                                try {
                                    const token80 = tokenPtr80.readUtf8String(Number(tokenLen80));
                                    const token90 = tokenPtr90.readUtf8String(Number(tokenLen90));

                                    if (token80 && (token80.startsWith('pt-') || token80.includes('token'))) {
                                        console.log(`[+] FOUND! SecurityOauthToken (0x80): "${token80}"`);
                                    }
                                    if (token90 && (token90.startsWith('rt-') || token90.includes('refresh'))) {
                                        console.log(`[+] FOUND! RefreshToken (0x90): "${token90}"`);
                                    }

                                    // 如果两个都找到了，dump 整个结构体
                                    if (token80 && token90) {
                                        console.log(`\n[SUCCESS] Found CosyUserInfo structure at ${maybeStructPtr}`);
                                        dumpStruct(maybeStructPtr, 288, 'CosyUserInfo');

                                        // 读取其他关键字段
                                        console.log('\n[KEY FIELDS]');
                                        try {
                                            const expireTime = maybeStructPtr.add(0xa0).readS64();
                                            console.log(`[*] TokenExpireTime (0xa0): ${expireTime} (${new Date(Number(expireTime) * 1000).toISOString()})`);
                                        } catch (e) {}

                                        // 尝试读取更多字符串字段
                                        const offsets = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0xb0, 0xc0];
                                        for (const off of offsets) {
                                            try {
                                                const str = readStringFromOffset(maybeStructPtr, off);
                                                if (str && str.length > 2) {
                                                    console.log(`[*] String at offset 0x${off.toString(16)}: "${str}"`);
                                                }
                                            } catch (e) {}
                                        }

                                        break; // 找到了就退出循环
                                    }
                                } catch (e) {
                                    console.log(`[!] Error reading tokens: ${e.message}`);
                                }
                            }
                        } catch (e) {}
                    } catch (e) {}
                }
            } catch (e) {}
        }
    },
    onLeave: function(retval) {
        console.log('[*] SaveUserInfo returned');
    }
});

// ========== 4. HTTP 服务器监控 ==========

// CreateHttpServer (0x141b48d00)
console.log('[*] Hooking CreateHttpServer (0x141b48d00)');
Interceptor.attach(Module.findBaseAddress('lingma.exe').add(0x1b48d00), {
    onEnter: function(args) {
        console.log('\n' + '='.repeat(80));
        console.log('[HOOK] CreateHttpServer');
        console.log('='.repeat(80));

        const sp = this.context.sp;
        console.log('[*] Stack Pointer: ' + sp);
    },
    onLeave: function(retval) {
        console.log('[*] CreateHttpServer returned');
    }
});

// LoginCallback_fm (0x141b499c0)
console.log('[*] Hooking LoginCallback_fm (0x141b499c0)');
Interceptor.attach(Module.findBaseAddress('lingma.exe').add(0x1b499c0), {
    onEnter: function(args) {
        console.log('\n' + '='.repeat(80));
        console.log('[HOOK] LoginCallback_fm - OAuth Callback Handler');
        console.log('='.repeat(80));

        const sp = this.context.sp;
        console.log('[*] Stack Pointer: ' + sp);

        // 读取 HTTP 回调参数
        console.log('[*] HTTP Callback parameters:');
        for (let i = 0; i < 20; i++) {
            try {
                const base = sp.add(i * Process.pointerSize);
                const maybeStr = readGoString(base);
                if (maybeStr && maybeStr.length > 5 && maybeStr.length < 2000) {
                    console.log(`[*]   Param ${i}: "${maybeStr}"`);

                    // 检查是否包含 OAuth 参数
                    if (maybeStr.includes('code=') || maybeStr.includes('state=') || maybeStr.includes('token')) {
                        console.log('[+] Found OAuth callback parameter!');
                    }
                }
            } catch (e) {}
        }
    },
    onLeave: function(retval) {
        console.log('[*] LoginCallback_fm returned');
    }
});

console.log('\n' + '='.repeat(80));
console.log('[*] All hooks installed successfully');
console.log('[*] Waiting for OAuth login flow...');
console.log('='.repeat(80) + '\n');