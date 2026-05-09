/**
 * Frida script: Hook WSASend to capture HTTP requests during OAuth login flow.
 * Attach to running Lingma, then trigger auth/login via WebSocket.
 */
'use strict';

var ws2 = Process.getModuleByName('ws2_32.dll');
var ws2exports = ws2.enumerateExports();

// Hook connect to see what remote hosts Lingma talks to
var connectExp = ws2exports.filter(function(e) { return e.name === 'connect'; });
if (connectExp.length > 0) {
    Interceptor.attach(connectExp[0].address, {
        onEnter: function(args) {
            var addr = args[1];
            try {
                var family = addr.readU16();
                if (family === 2) {
                    var port = addr.add(2).readU16();
                    port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                    var ip = addr.add(4).readU8() + '.' + addr.add(5).readU8() + '.' +
                            addr.add(6).readU8() + '.' + addr.add(7).readU8();
                    if (port === 443 || port === 80) {
                        console.log('[connect] -> ' + ip + ':' + port);
                    }
                }
            } catch(e) {}
        }
    });
    console.log('[Hook] connect OK');
}

// Hook WSASend to capture plaintext HTTP data
var wsasendExp = ws2exports.filter(function(e) { return e.name === 'WSASend'; });
if (wsasendExp.length > 0) {
    Interceptor.attach(wsasendExp[0].address, {
        onEnter: function(args) {
            var lpBuffers = args[1];
            var dwBufferCount = args[2].toInt32();
            for (var i = 0; i < dwBufferCount && i < 8; i++) {
                var buf = lpBuffers.add(i * 16);
                var len = buf.readUInt();
                var ptr = buf.add(8).readPointer();
                if (len > 0 && len < 200000) {
                    try {
                        var data = ptr.readUtf8String(Math.min(len, 10000));
                        // For HTTPS, look for TLS ClientHello (SNI field)
                        if (data.indexOf('HTTP/') >= 0 || data.indexOf('POST') >= 0 ||
                            data.indexOf('GET') >= 0 || data.indexOf('Host:') >= 0) {
                            console.log('[WSASend HTTP] len=' + len);
                            console.log('---START---');
                            console.log(data.substring(0, 5000));
                            console.log('---END---');
                        }
                        // Also capture TLS ClientHello for SNI
                        if (len > 5 && data.charCodeAt(0) === 0x16 && data.charCodeAt(1) === 0x03) {
                            // TLS record - try to find SNI
                            console.log('[WSASend TLS] len=' + len + ' - looking for SNI...');
                            // SNI is usually in the ClientHello
                            for (var j = 0; j < Math.min(len, 500); j++) {
                                if (data[j] === '.' && j > 2) {
                                    // Found a dot, try to extract surrounding hostname
                                    var start = j;
                                    while (start > 0 && data[start-1].match(/[a-z0-9\.\-]/i)) start--;
                                    var end = j;
                                    while (end < len && data[end].match(/[a-z0-9\.\-]/i)) end++;
                                    var host = data.substring(start, end);
                                    if (host.indexOf('.') > 0 && host.lastIndexOf('.') > host.indexOf('.') + 1) {
                                        console.log('  SNI candidate: ' + host);
                                    }
                                }
                            }
                        }
                    } catch(e) {}
                }
            }
        }
    });
    console.log('[Hook] WSASend OK');
}

console.log('[Hook] All ready - trigger auth/login via WebSocket');
