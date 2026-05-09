"""
Direct Frida capture of AES encryption parameters.
Attach to running Lingma.exe and capture:
1. AesEncryptWithBase64: key, plaintext, ciphertext, encoded output
2. encodeToString: encoding alphabet
3. The encodeRequestBody flow
"""

try:
    import frida
except ImportError:
    print("frida package not installed. Run: pip install frida")
    exit(1)

SCRIPT = r"""
// Frida script for Lingma AES encryption capture
// x86-64 Windows: Go 1.22 uses register-based ABI

const base = Module.getBaseAddress('Lingma.exe');
console.log('[*] Lingma.exe base: ' + base);

// AesEncryptWithBase64: RVA 0x455da0
// Function signature: func AesEncryptWithBase64(key, data []byte, enc *encoding) (string, error)
// In Go 1.22, args are passed in registers:
// RAX = key slice (ptr, len, cap)
// RBX = data slice (ptr, len, cap)
// RCX = encoding pointer

const aesAddr = base.add(0x455da0);
console.log('[*] AesEncryptWithBase64 at: ' + aesAddr);

Interceptor.attach(aesAddr, {
    onEnter: function(args) {
        console.log('\n========== [AesEncryptWithBase64] ==========');

        // Save context
        this.keyPtr = this.context.rax;
        this.dataPtr = this.context.rbx;
        this.encPtr = this.context.rcx;

        console.log('  RAX (key): ' + this.keyPtr);
        console.log('  RBX (data): ' + this.dataPtr);
        console.log('  RCX (enc): ' + this.encPtr);

        // Read key (Go slice: {ptr, len, cap} at the address pointed to by RAX)
        // Actually, for []byte, RAX might directly contain the slice header
        // or RAX might be the ptr. Let's try both.

        // Method 1: RAX is the slice header address
        try {
            const keyArrPtr = this.keyPtr.readPointer();
            const keyLen = this.keyPtr.add(8).readUInt();
            if (keyLen > 0 && keyLen <= 64) {
                const keyBytes = keyArrPtr.readByteArray(keyLen);
                console.log('  KEY (hex): ' + hex(keyBytes));
                console.log('  KEY (utf8): ' + utf8(keyBytes));
            }
        } catch(e) {
            // Method 2: Try RAX directly as ptr with len from elsewhere
            console.log('  Method 1 failed, trying method 2...');
            try {
                // Maybe RAX IS the data ptr (not slice header)
                const keyBytes = this.keyPtr.readByteArray(16);
                console.log('  Possible key (direct, 16 bytes): ' + hex(keyBytes));
            } catch(e2) {}
        }

        // Read plaintext data
        try {
            const dataArrPtr = this.dataPtr.readPointer();
            const dataLen = this.dataPtr.add(8).readUInt();
            console.log('  DATA len: ' + dataLen);
            if (dataLen > 0 && dataLen <= 10000) {
                const dataBytes = dataArrPtr.readByteArray(Math.min(dataLen, 512));
                console.log('  DATA (hex, first 512): ' + hex(dataBytes));
                console.log('  DATA (utf8): ' + utf8(dataBytes));
            }
        } catch(e) {
            console.log('  Failed to read data: ' + e.message);
        }

        // Read encoding struct
        try {
            if (!this.encPtr.isNull()) {
                const encodeArr = this.encPtr.readByteArray(64);
                if (encodeArr) {
                    const alphabet = Array.from(new Uint8Array(encodeArr)).map(b =>
                        b >= 32 && b < 127 ? String.fromCharCode(b) : '.'
                    ).join('');
                    console.log('  ENCODE alphabet: ' + alphabet);
                }
            }
        } catch(e) {
            console.log('  Failed to read encoding: ' + e.message);
        }
    },

    onLeave: function(retval) {
        console.log('\n  [Return]');
        console.log('  RAX: ' + this.context.rax);
        console.log('  RDX: ' + this.context.rdx);

        // Go returns (string, error) - string is {ptr, len}
        // Return ptr in RAX, len in RDX
        try {
            const retPtr = this.context.rax.readPointer();
            const retLen = this.context.rdx.toUInt32();
            console.log('  RETURN ptr: ' + retPtr + ' len: ' + retLen);
            if (retLen > 0 && retLen <= 10000) {
                const retBytes = retPtr.readByteArray(Math.min(retLen, 1024));
                console.log('  RETURN (hex, first 1024): ' + hex(retBytes));
                console.log('  RETURN (utf8): ' + utf8(retBytes));
            }
        } catch(e) {
            console.log('  Failed to read return: ' + e.message);
        }

        console.log('==========================================\n');
    }
});

// Helper: bytes to hex
function hex(bytes) {
    return Array.from(new Uint8Array(bytes))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Helper: bytes to UTF-8 string
function utf8(bytes) {
    try {
        return new TextDecoder('utf-8', {fatal: false}).decode(bytes);
    } catch(e) {
        return '';
    }
}

console.log('[*] All hooks installed. Waiting for encryption...\n');

// Keep the script alive
setInterval(() => {}, 1000);
"""

def main():
    print("[*] Lingma AES Encryption Capture via Frida")
    print("=" * 50)

    # Try to find Lingma.exe
    try:
        session = frida.attach("Lingma.exe")
        print(f"[+] Attached to Lingma.exe (PID: {session.pid})")
    except frida.ProcessNotFoundError:
        # Try to find the process by PID or start it
        print("[-] Lingma.exe not found. Trying to find Lingma process...")
        processes = frida.enumerate_processes()
        for p in processes:
            if 'lingma' in p.name.lower():
                print(f"  Found: {p.name} (PID: {p.pid})")

        print("\nPlease start Lingma and run this script again.")
        print("Or run manually:")
        print("  frida -n Lingma.exe -l capture/frida-aes-capture.js")
        return

    # Create and load the script
    script = session.create_script(SCRIPT)

    def on_message(message, data):
        if message['type'] == 'send':
            print(message['payload'])
        elif message['type'] == 'error':
            print(f"ERROR: {message['stack']}")

    script.on('message', on_message)
    script.load()

    print("[*] Script loaded. Waiting for encryption operations...\n")
    print("(Press Ctrl+C to exit)")

    try:
        import sys
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[*] Detaching...")
        session.detach()

if __name__ == "__main__":
    main()
