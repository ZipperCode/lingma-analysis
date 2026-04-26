"""
Comprehensive Frida hook to capture Lingma's encryption pipeline.

Hooks:
1. AesEncryptWithBase64 - captures key, plaintext, ciphertext
2. encodeToString - captures the encoded output and encoding alphabet
3. encodeTo - captures the encoding process
4. encodeRequestBody - captures input JSON and output encoded body
5. CustomDecryptParts - captures decryption details
6. AesDecryptWithBase64 - captures decryption key and result

This script outputs all captured data to help reconstruct the full encoding pipeline.
"""

import frida
import sys
import json
import time

# Known addresses from GoReSym analysis
IMAGE_BASE = 0x140000000  # PE ImageBase

FUNCTIONS = {
    'encrypt.AesEncryptWithBase64': 0x455da0,
    'encrypt.AesDecryptWithBase64': 0x455f40,
    'encrypt.(*encoding).encodeToString': 0x4549e0,
    'encrypt.(*encoding).encodeTo': 0x454c80,
    'encrypt.(*encoding).decode': 0x455680,
    'encrypt.pkcs5Padding': 0x456280,
    'encrypt.CustomDecryptParts': 0x455ca0,
    'encrypt.Md5Encode': 0x4563c0,
    'encrypt.Md5EncodeBytes': 0x4565a0,
    'encrypt.XxHashHexString': 0x456780,
    'encodeRequestBody': 0x881820,
    'shouldEncryptBody': 0x882680,
}

SCRIPT = """
// Frida script for Lingma encryption analysis

// Helper: read Go string
function readGoStr(addr, len) {
    if (addr.isNull() || len === 0 || len > 100000) return '';
    try {
        return addr.readUtf8String(len);
    } catch (e) {
        return '';
    }
}

// Helper: read Go slice as hex
function readGoSlice(addr) {
    if (addr.isNull()) return '';
    try {
        const array = addr.readPointer();
        const len = addr.add(8).readUInt();
        if (len === 0 || len > 100000) return '';
        return array.readByteArray(len);
    } catch (e) {
        return '';
    }
}

// Helper: convert bytes to hex string
function toHex(bytes) {
    if (!bytes) return '';
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper: try to decode bytes as UTF-8
function toUtf8(bytes) {
    if (!bytes) return '';
    try {
        return new TextDecoder('utf-8', {fatal: false}).decode(bytes);
    } catch (e) {
        return '';
    }
}

// Hook AesEncryptWithBase64
// Go ABI: RAX = key (slice), RBX/RCX = plaintext (slice)
// On stack (Go 1.17+ abiInternal): key_ptr, key_len, key_cap, data_ptr, data_len, data_cap
function hookAesEncrypt() {
    const base = Module.findBaseAddress('Lingma.exe') || ptr('0x140000000');
    const aesAddr = base.add(0x455da0);

    console.log('\\n=== Hooking AesEncryptWithBase64 at ' + aesAddr + ' ===');

    Interceptor.attach(aesAddr, {
        onEnter: function(args) {
            // In Go 1.17+, arguments are on the stack
            // For AesEncryptWithBase64(key, data):
            // Stack layout depends on ABI
            // Try reading from stack
            const keyPtr = this.context.rax;
            const dataPtr = this.context.rbx || this.context.rcx;

            console.log('\\n[AesEncryptWithBase64] called');
            console.log('  RAX (key ptr?): ' + keyPtr);
            console.log('  RBX: ' + this.context.rbx);
            console.log('  RCX: ' + this.context.rcx);
            console.log('  RDX: ' + this.context.rdx);
            console.log('  RSI: ' + this.context.rsi);
            console.log('  RDI: ' + this.context.rdi);

            // Read key (try RAX as slice pointer)
            if (!keyPtr.isNull()) {
                try {
                    const keyArr = keyPtr.readPointer();
                    const keyLen = keyPtr.add(8).readUInt();
                    console.log('  Key length: ' + keyLen);
                    if (keyLen > 0 && keyLen <= 64) {
                        const keyBytes = keyArr.readByteArray(keyLen);
                        console.log('  Key (hex): ' + toHex(keyBytes));
                        console.log('  Key (utf8): ' + toUtf8(keyBytes));
                    }
                } catch (e) {
                    console.log('  Failed to read key: ' + e.message);
                }
            }

            // Read plaintext
            if (dataPtr && !dataPtr.isNull()) {
                try {
                    const dataArr = dataPtr.readPointer();
                    const dataLen = dataPtr.add(8).readUInt();
                    console.log('  Data length: ' + dataLen);
                    if (dataLen > 0 && dataLen <= 100000) {
                        const dataBytes = dataArr.readByteArray(Math.min(dataLen, 512));
                        console.log('  Data (hex, first 512): ' + toHex(dataBytes));
                        console.log('  Data (utf8): ' + toUtf8(dataBytes));
                    }
                } catch (e) {
                    console.log('  Failed to read data: ' + e.message);
                }
            }
        },
        onLeave: function(retval) {
            console.log('[AesEncryptWithBase64] return: ' + retval);
            // Try to read return value as Go string (RAX = ptr, RDX = len)
            if (!retval.isNull()) {
                try {
                    const retPtr = retval.readPointer();
                    const retLen = retval.add(8).readUInt();
                    if (retLen > 0 && retLen <= 100000) {
                        const retBytes = retPtr.readByteArray(Math.min(retLen, 512));
                        console.log('  Return (hex, first 512): ' + toHex(retBytes));
                        console.log('  Return (utf8): ' + toUtf8(retBytes));
                    }
                } catch (e) {
                    console.log('  Failed to read return: ' + e.message);
                }
            }
        }
    });
}

// Hook encodeToString to capture the encoding alphabet
function hookEncodeToString() {
    const base = Module.findBaseAddress('Lingma.exe') || ptr('0x140000000');
    const addr = base.add(0x4549e0);

    console.log('\\n=== Hooking encodeToString at ' + addr + ' ===');

    Interceptor.attach(addr, {
        onEnter: function(args) {
            console.log('\\n[encodeToString] called');
            // RCX = this pointer (encoding struct)
            const encodingPtr = this.context.rcx;
            console.log('  Encoding struct ptr: ' + encodingPtr);

            if (!encodingPtr.isNull()) {
                try {
                    // encoding struct: encode[64], decodeMap[256], padChar, strict
                    const encodeArr = encodingPtr.readByteArray(64);
                    if (encodeArr) {
                        const alphabet = Array.from(encodeArr).map(b =>
                            b >= 32 && b < 127 ? String.fromCharCode(b) : '.'
                        ).join('');
                        console.log('  Encode alphabet: ' + alphabet);
                        console.log('  Encode (hex): ' + toHex(encodeArr));
                    }

                    // Input string: RDX (ptr), R8 (len) -- varies by ABI
                    console.log('  RDX: ' + this.context.rdx);
                    console.log('  R8: ' + this.context.r8);
                    console.log('  R9: ' + this.context.r9);
                } catch (e) {
                    console.log('  Failed to read encoding struct: ' + e.message);
                }
            }
        },
        onLeave: function(retval) {
            console.log('[encodeToString] return: ' + retval);
        }
    });
}

// Hook encodeRequestBody
function hookEncodeRequestBody() {
    const base = Module.findBaseAddress('Lingma.exe') || ptr('0x140000000');
    const addr = base.add(0x881820);

    console.log('\\n=== Hooking encodeRequestBody at ' + addr + ' ===');

    Interceptor.attach(addr, {
        onEnter: function(args) {
            console.log('\\n[encodeRequestBody] called');
            console.log('  RAX: ' + this.context.rax);
            console.log('  RBX: ' + this.context.rbx);
            console.log('  RCX: ' + this.context.rcx);
        },
        onLeave: function(retval) {
            console.log('[encodeRequestBody] return: ' + retval);
        }
    });
}

// Hook encodeTo to see the alphabet in action
function hookEncodeTo() {
    const base = Module.findBaseAddress('Lingma.exe') || ptr('0x140000000');
    const addr = base.add(0x454c80);

    console.log('\\n=== Hooking encodeTo at ' + addr + ' ===');

    Interceptor.attach(addr, {
        onEnter: function(args) {
            console.log('\\n[encodeTo] called');
            const encodingPtr = this.context.rcx;
            if (!encodingPtr.isNull()) {
                try {
                    const encodeArr = encodingPtr.readByteArray(64);
                    if (encodeArr) {
                        const alphabet = Array.from(encodeArr).map(b =>
                            b >= 32 && b < 127 ? String.fromCharCode(b) : '[' + b.toString(16) + ']'
                        ).join('');
                        console.log('  Encode alphabet: ' + alphabet);
                    }
                } catch (e) {}
            }
            console.log('  RDX: ' + this.context.rdx);
            console.log('  R8: ' + this.context.r8);
            console.log('  R9: ' + this.context.r9);
        },
        onLeave: function(retval) {
            console.log('[encodeTo] return: ' + retval);
        }
    });
}

// Hook CustomDecryptParts to see decryption
function hookCustomDecrypt() {
    const base = Module.findBaseAddress('Lingma.exe') || ptr('0x140000000');
    const addr = base.add(0x455ca0);

    console.log('\\n=== Hooking CustomDecryptParts at ' + addr + ' ===');

    Interceptor.attach(addr, {
        onEnter: function(args) {
            console.log('\\n[CustomDecryptParts] called');
            console.log('  RAX: ' + this.context.rax);
            console.log('  RBX: ' + this.context.rbx);
            console.log('  RCX: ' + this.context.rcx);
        },
        onLeave: function(retval) {
            console.log('[CustomDecryptParts] return');
        }
    });
}

// Hook Md5Encode to see key derivation
function hookMd5Encode() {
    const base = Module.findBaseAddress('Lingma.exe') || ptr('0x140000000');
    const addr = base.add(0x4563c0);

    console.log('\\n=== Hooking Md5Encode at ' + addr + ' ===');

    Interceptor.attach(addr, {
        onEnter: function(args) {
            console.log('\\n[Md5Encode] called');
            const strPtr = this.context.rax;
            const strLen = this.context.rbx;
            if (!strPtr.isNull() && strLen.toInt32() < 1000) {
                try {
                    const str = strPtr.readUtf8String(strLen.toInt32());
                    console.log('  Input: ' + str);
                } catch (e) {}
            }
        },
        onLeave: function(retval) {
            console.log('[Md5Encode] return');
        }
    });
}

// Also hook the Go net/http client to capture the actual request
function hookHttpClient() {
    // Find the Do method of http.Client
    const doPattern = 'http.(*Client).do';
    const matches = Process.enumerateModules().filter(m => m.name.includes('Lingma'));

    // We'll use a broader approach - hook all crypto operations
    console.log('\\n=== HTTP Client hooks ===');
}

// Main
console.log('Starting Lingma encryption analysis...');
console.log('Process: ' + Process.arch + ' / ' + Process.platform);

hookAesEncrypt();
hookEncodeToString();
hookEncodeTo();
hookEncodeRequestBody();
hookCustomDecrypt();
hookMd5Encode();

console.log('\\nAll hooks installed. Waiting for encryption operations...');

// Keep the script alive
setInterval(() => {}, 1000);
"""

def main():
    print("Frida Lingma Encryption Analyzer")
    print("=" * 50)

    # Try to find Lingma process
    try:
        session = frida.attach("Lingma.exe")
        print("Attached to Lingma.exe")
    except frida.ProcessNotFoundError:
        print("Lingma.exe not found. Trying to start it...")
        # Try to start Lingma
        try:
            session = frida.spawn([
                "C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe"
            ])
            session = frida.attach(session)
            print(f"Started and attached to Lingma (PID: {session})")
        except Exception as e:
            print(f"Failed to start/attach Lingma: {e}")
            print("\nPlease start Lingma and run this script again.")
            return

    script = session.create_script(SCRIPT)

    def on_message(message, data):
        if message['type'] == 'send':
            print(message['payload'])
        else:
            print(message)

    script.on('message', on_message)
    script.load()

    print("Script loaded. Press Ctrl+C to exit.")

    # Resume if we spawned
    try:
        frida.resume(session.pid)
    except:
        pass

    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\nDetaching...")
        session.detach()

if __name__ == "__main__":
    main()
