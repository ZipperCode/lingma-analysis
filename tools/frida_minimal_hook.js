/**
 * Minimal Frida hook: capture all TCP connections and TLS SNI from Lingma.
 * Goal: See what remote hosts Lingma contacts during auth/refreshToken.
 */
'use strict';

var ws2 = Process.getModuleByName('ws2_32.dll');
var ws2exports = ws2.enumerateExports();

function findExport(name) {
    var results = ws2exports.filter(function(e) { return e.name === name; });
    return results.length > 0 ? results[0].address : null;
}

// Hook connect
var connectAddr = findExport('connect');
if (connectAddr) {
    Interceptor.attach(connectAddr, {
        onEnter: function(args) {
            var addr = args[1];
            try {
                var family = addr.readU16();
                if (family === 2) {
                    var port = addr.add(2).readU16();
                    port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                    var ip = addr.add(4).readU8() + '.' + addr.add(5).readU8() + '.' +
                            addr.add(6).readU8() + '.' + addr.add(7).readU8();
                    console.log('[CONNECT] ' + ip + ':' + port);
                    send({type: 'connect', ip: ip, port: port});
                }
            } catch(e) {}
        }
    });
}

// Hook WSASend — extract TLS SNI
var wsasendAddr = findExport('WSASend');
if (wsasendAddr) {
    Interceptor.attach(wsasendAddr, {
        onEnter: function(args) {
            var lpBuffers = args[1];
            var dwBufferCount = args[2].toInt32();
            for (var i = 0; i < dwBufferCount && i < 8; i++) {
                var buf = lpBuffers.add(i * 16);
                var len = buf.readUInt();
                var ptr = buf.add(8).readPointer();
                if (len > 0 && len < 200000) {
                    try {
                        var data = ptr.readByteArray(Math.min(len, 4096));
                        var arr = new Uint8Array(data);

                        // Check for plaintext HTTP
                        var preview = '';
                        for (var j = 0; j < Math.min(arr.length, 100); j++) {
                            var c = arr[j];
                            if (c >= 32 && c < 127) preview += String.fromCharCode(c);
                            else if (c === 10 || c === 13) preview += '\\n';
                        }
                        if (preview.indexOf('HTTP/') >= 0 || preview.indexOf('POST') >= 0 || preview.indexOf('GET') >= 0 ||
                            preview.indexOf('Host:') >= 0) {
                            var full = '';
                            for (var j = 0; j < Math.min(arr.length, 2000); j++) {
                                var c = arr[j];
                                if (c >= 32 && c < 127) full += String.fromCharCode(c);
                                else if (c === 10 || c === 13 || c === 9) full += String.fromCharCode(c);
                            }
                            console.log('[HTTP SEND] len=' + len + '\n' + full);
                            send({type: 'http', len: len, data: full.substring(0, 2000)});
                        }

                        // TLS ClientHello
                        if (arr.length > 5 && arr[0] === 0x16 && arr[1] === 0x03) {
                            // Find SNI
                            var sni = null;
                            var pos = 5 + 4 + 2 + 32; // past record+handshake hdr+version+random
                            if (pos < arr.length) {
                                var sidLen = arr[pos]; pos += 1 + sidLen;
                                if (pos + 2 < arr.length) {
                                    var csLen = (arr[pos] << 8) | arr[pos+1]; pos += 2 + csLen;
                                    if (pos + 1 < arr.length) {
                                        var compLen = arr[pos]; pos += 1 + compLen;
                                        if (pos + 2 < arr.length) {
                                            var extLen = (arr[pos] << 8) | arr[pos+1]; pos += 2;
                                            var extEnd = Math.min(pos + extLen, arr.length);
                                            while (pos + 4 < extEnd) {
                                                var extType = (arr[pos] << 8) | arr[pos+1];
                                                var extDataLen = (arr[pos+2] << 8) | arr[pos+3];
                                                pos += 4;
                                                if (extType === 0x0000 && pos + 5 < extEnd && arr[pos] === 0x00) {
                                                    var nameLen = (arr[pos+1] << 8) | arr[pos+2];
                                                    pos += 3;
                                                    if (pos + nameLen <= arr.length) {
                                                        sni = '';
                                                        for (var k = 0; k < nameLen; k++) sni += String.fromCharCode(arr[pos+k]);
                                                        break;
                                                    }
                                                }
                                                pos += extDataLen;
                                            }
                                        }
                                    }
                                }
                            }
                            if (sni) {
                                console.log('[TLS SNI] ' + sni + ' (len=' + len + ')');
                                send({type: 'sni', sni: sni, len: len});
                            }
                        }
                    } catch(e) {}
                }
            }
        }
    });
}

// Hook WSARecv — capture responses
var wsarecvAddr = findExport('WSARecv');
if (wsarecvAddr) {
    Interceptor.attach(wsarecvAddr, {
        onEnter: function(args) {
            this.lpBuffers = args[1];
            this.dwBufferCount = args[2].toInt32();
        },
        onLeave: function(retval) {
            if (retval.toInt32() !== 0) return;
            for (var i = 0; i < this.dwBufferCount && i < 8; i++) {
                var buf = this.lpBuffers.add(i * 16);
                var len = buf.readUInt();
                var ptr = buf.add(8).readPointer();
                if (len > 0 && len < 200000) {
                    try {
                        var data = ptr.readByteArray(Math.min(len, 4096));
                        var arr = new Uint8Array(data);
                        var preview = '';
                        for (var j = 0; j < Math.min(arr.length, 100); j++) {
                            var c = arr[j];
                            if (c >= 32 && c < 127) preview += String.fromCharCode(c);
                            else if (c === 10 || c === 13) preview += '\\n';
                        }
                        if (preview.indexOf('HTTP/') >= 0) {
                            var full = '';
                            for (var j = 0; j < Math.min(arr.length, 2000); j++) {
                                var c = arr[j];
                                if (c >= 32 && c < 127) full += String.fromCharCode(c);
                                else if (c === 10 || c === 13 || c === 9) full += String.fromCharCode(c);
                            }
                            console.log('[HTTP RECV] len=' + len + '\n' + full.substring(0, 2000));
                            send({type: 'http_recv', len: len, data: full.substring(0, 2000)});
                        }
                    } catch(e) {}
                }
            }
        }
    });
}

console.log('[HOOKS READY] connect + WSASend + WSARecv');
send({type: 'ready'});
