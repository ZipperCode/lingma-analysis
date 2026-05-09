"""
Final approach: use Frida to hook AesEncryptWithBase64 and capture actual parameters.
This will tell us exactly:
1. What key is used
2. What IV is used
3. What the plaintext looks like
4. What the encoded output looks like
"""

import subprocess
import sys

FRIDA_SCRIPT = """
// Hook AesEncryptWithBase64 at RVA 0x455da0
const base = Module.getBaseAddress('Lingma.exe') || ptr('0x140000000');
const aesAddr = base.add(0x455da0);

console.log('[*] AesEncryptWithBase64 at: ' + aesAddr);

Interceptor.attach(aesAddr, {
    onEnter: function(args) {
        console.log('\\n[AesEncryptWithBase64] called');

        // Go function arguments on stack (x86-64 Windows)
        // AesEncryptWithBase64(key []byte, data []byte, enc *encoding)
        // Key is a Go slice: {ptr, len, cap}
        // Data is a Go slice: {ptr, len, cap}
        // Enc is a pointer

        // On Windows x64, first 4 args are in RCX, RDX, R8, R9
        // But Go has its own calling convention
        // Let's try reading from registers and stack

        // Try RAX as key slice (Go passes slices as {ptr, len, cap})
        const keyPtr = this.context.rax;
        const dataPtr = this.context.rbx || this.context.rcx;

        console.log('  RAX: ' + keyPtr);
        console.log('  RBX: ' + this.context.rbx);
        console.log('  RCX: ' + this.context.rcx);
        console.log('  RDX: ' + this.context.rdx);

        // Try to read key as Go slice from RAX
        if (!keyPtr.isNull()) {
            try {
                const arrPtr = keyPtr.readPointer();
                const arrLen = keyPtr.add(8).readUInt();
                const arrCap = keyPtr.add(16).readUInt();
                console.log('  Key slice: ptr=' + arrPtr + ' len=' + arrLen + ' cap=' + arrCap);
                if (arrLen > 0 && arrLen <= 64) {
                    const keyBytes = arrPtr.readByteArray(arrLen);
                    console.log('  Key (hex): ' + toHex(keyBytes));
                    console.log('  Key (utf8): ' + toUtf8(keyBytes));
                }
            } catch(e) {
                console.log('  Failed to read key: ' + e.message);
            }
        }

        // Try to read data from RBX or RCX
        const readPtr = this.context.rbx;
        if (readPtr && !readPtr.isNull()) {
            try {
                const arrPtr = readPtr.readPointer();
                const arrLen = readPtr.add(8).readUInt();
                console.log('  Data slice: ptr=' + arrPtr + ' len=' + arrLen);
                if (arrLen > 0 && arrLen <= 10000) {
                    const dataBytes = arrPtr.readByteArray(Math.min(arrLen, 256));
                    console.log('  Data (hex, first 256): ' + toHex(dataBytes));
                    console.log('  Data (utf8): ' + toUtf8(dataBytes));
                }
            } catch(e) {
                console.log('  Failed to read data: ' + e.message);
            }
        }
    },

    onLeave: function(retval) {
        console.log('\\n[AesEncryptWithBase64] return');
        console.log('  RAX: ' + this.context.rax);
        console.log('  RDX: ' + this.context.rdx);

        // Return value is a Go string: {ptr, len} in RAX
        if (!this.context.rax.isNull()) {
            try {
                const retPtr = this.context.rax.readPointer();
                const retLen = this.context.rdx.toUInt32();
                console.log('  Return: ptr=' + retPtr + ' len=' + retLen);
                if (retLen > 0 && retLen <= 10000) {
                    const retBytes = retPtr.readByteArray(Math.min(retLen, 512));
                    console.log('  Return (hex, first 512): ' + toHex(retBytes));
                    console.log('  Return (utf8): ' + toUtf8(retBytes));
                }
            } catch(e) {
                console.log('  Failed to read return: ' + e.message);
            }
        }
    }
});

// Also hook pkcs5Padding to see what gets padded
const pkcs5Addr = base.add(0x456280);
Interceptor.attach(pkcs5Addr, {
    onEnter: function(args) {
        console.log('\\n[pkcs5Padding] called');
    },
    onLeave: function(retval) {
        console.log('[pkcs5Padding] return');
    }
});

// Also hook the encoding.encodeToString
const encodeToStringAddr = base.add(0x4549e0);
Interceptor.attach(encodeToStringAddr, {
    onEnter: function(args) {
        console.log('\\n[encodeToString] called');
        // RCX = encoding struct
        const encPtr = this.context.rcx;
        if (!encPtr.isNull()) {
            try {
                // encoding struct has encode[64] array at offset 0
                const encodeArr = encPtr.readByteArray(64);
                if (encodeArr) {
                    const alphabet = Array.from(encodeArr).map(b =>
                        b >= 32 && b < 127 ? String.fromCharCode(b) : '.'
                    ).join('');
                    console.log('  Encode alphabet: ' + alphabet);
                }
            } catch(e) {}
        }
    },
    onLeave: function(retval) {
        console.log('[encodeToString] return');
    }
});

// Helper functions
function toHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function toUtf8(bytes) {
    try {
        return new TextDecoder('utf-8', {fatal: false}).decode(bytes);
    } catch(e) {
        return '';
    }
}

// Keep running
setInterval(() => {}, 1000);
"""

def main():
    print("Frida Lingma Encryption Capture")
    print("=" * 50)

    # Find Lingma process
    try:
        result = subprocess.run(
            ["frida-ps", "-a"],
            capture_output=True, text=True, timeout=10
        )
        print("Running processes:")
        for line in result.stdout.split('\n'):
            if 'lingma' in line.lower() or 'Lingma' in line:
                print(f"  {line}")
    except:
        pass

    # Write the script to a file
    with open('capture/frida-aes-capture.js', 'w') as f:
        f.write(FRIDA_SCRIPT)

    print(f"\nScript saved to capture/frida-aes-capture.js")
    print(f"\nTo run:")
    print(f"  frida -n Lingma.exe -l capture/frida-aes-capture.js")
    print(f"Or:")
    print(f"  frida -f 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe' -l capture/frida-aes-capture.js")

if __name__ == "__main__":
    main()
