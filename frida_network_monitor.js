/**
 * Lingma Network Monitor - Passive HTTP traffic capture
 * Non-invasive: only monitors network requests, no function hooking
 */

console.log('=== Lingma Network Monitor (Passive) ===\n');

// Monitor all HTTP requests
const requests = [];

// Hook WinHTTP/WinInet functions for request capture
const ws2_32 = Module.findBaseAddress('ws2_32.dll');
console.log('[*] ws2_32.dll base:', ws2_32);

// Hook send/recv to capture HTTP traffic
try {
    const send = Module.findExportByName('ws2_32.dll', 'send');
    if (send) {
        Interceptor.attach(send, {
            onEnter: function(args) {
                const buf = args[1];
                const len = args[2].toInt32();
                if (len > 0 && len < 100000) {
                    try {
                        const data = buf.readByteArray(len);
                        const str = buf.readCString(len);
                        if (str && (str.startsWith('POST') || str.startsWith('GET') || str.startsWith('HTTP'))) {
                            console.log('\n[HTTP] ' + str.split('\r\n')[0]);
                            const lines = str.split('\r\n');
                            lines.forEach(line => {
                                if (line.toLowerCase().includes('token') ||
                                    line.toLowerCase().includes('auth') ||
                                    line.toLowerCase().includes('nonce') ||
                                    line.toLowerCase().includes('pt-') ||
                                    line.toLowerCase().includes('rt-')) {
                                    console.log('  ' + line);
                                }
                            });
                            // Check body for tokens
                            const bodyStart = str.indexOf('\r\n\r\n');
                            if (bodyStart >= 0) {
                                const body = str.substring(bodyStart + 4);
                                if (body.length > 0) {
                                    console.log('  [BODY] ' + body.substring(0, 500));
                                }
                            }
                        }
                    } catch(e) {}
                }
            }
        });
        console.log('[+] Hooked ws2_32!send');
    }
} catch(e) {
    console.log('[!] Failed to hook send:', e.message);
}

// Hook recv
try {
    const recv = Module.findExportByName('ws2_32.dll', 'recv');
    if (recv) {
        Interceptor.attach(recv, {
            onLeave: function(retval) {
                if (retval.toInt32() > 0) {
                    const buf = this.context.rdx; // or get from args
                    const len = retval.toInt32();
                    // Only try if len is reasonable
                    if (len < 100000) {
                        try {
                            const str = buf.readCString(len);
                            if (str && (str.includes('token') || str.includes('pt-') || str.includes('rt-') || str.includes('auth'))) {
                                console.log('\n[RECV] ' + str.substring(0, 500));
                            }
                        } catch(e) {}
                    }
                }
            }
        });
        console.log('[+] Hooked ws2_32!recv');
    }
} catch(e) {
    console.log('[!] Failed to hook recv:', e.message);
}

console.log('\n[*] Network monitor ready.\n');
