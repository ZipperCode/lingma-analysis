"""
Frida script to hook Go TLS and network I/O in Lingma.exe.

Strategy:
1. Hook Windows WriteFile/ReadFile on socket handles (Go's I/O on Windows)
2. Hook crypto/sha256 block function to capture signing data
3. Hook crypto/cipher functions (GCM encrypt/decrypt)
4. Monitor TLS handshake to identify target server connections

This works at the I/O layer, avoiding Go GC issues.
"""
import frida
import time
import json
import win32file
import win32event
import pywintypes

LINGMA_PID = 456

FRIDA_SCRIPT = r"""
'use strict';

var base = Module.getBaseAddress();
var capturedCount = 0;
var connectionLog = {};

// ============================================================
// Strategy 1: Hook WriteFile (Go uses this for socket I/O on Windows)
// ============================================================
var writeFile = Module.findExportByName('kernel32.dll', 'WriteFile');
if (writeFile) {
    Interceptor.attach(writeFile, {
        onEnter: function(args) {
            this.handle = args[0];
            this.buffer = args[1];
            this.numBytesToWrite = args[2].toInt32();
            this.numBytesWritten = args[3];

            // Only check socket-like handles
            if (this.numBytesToWrite > 0 && this.numBytesToWrite < 500000) {
                try {
                    var data = this.buffer.readUtf8String(Math.min(this.numBytesToWrite, 100000));
                    if (!data) return;

                    // Check for HTTP request
                    if ((data.indexOf('POST /') >= 0 || data.indexOf('GET /') >= 0 ||
                         data.indexOf('PUT /') >= 0 || data.indexOf('DELETE /') >= 0) &&
                        data.indexOf('HTTP/') >= 0) {
                        capturedCount++;
                        console.log('\n' + '='.repeat(80));
                        console.log('WriteFile HTTP Request #' + capturedCount + ' (' + this.numBytesToWrite + ' bytes)');
                        console.log('='.repeat(80));
                        console.log(data.substring(0, 80000));
                        console.log('='.repeat(80));
                    }
                    // Check for TLS ClientHello
                    else if (data.charCodeAt(0) === 0x16 && data.charCodeAt(1) === 0x03) {
                        console.log('[TLS] ClientHello handshake (' + this.numBytesToWrite + ' bytes)');
                    }
                    // Check for TLS Application Data
                    else if (data.charCodeAt(0) === 0x17 && data.charCodeAt(1) === 0x03) {
                        // TLS 1.2 Application Data record
                        var recordLen = (data.charCodeAt(3) << 8) | data.charCodeAt(4);
                        console.log('[TLS] Application Data record (' + recordLen + ' bytes encrypted)');
                    }
                } catch(e) {}
            }
        }
    });
    console.log('[+] WriteFile hooked at ' + writeFile);
}

// ============================================================
// Strategy 2: Hook ReadFile (for responses)
// ============================================================
var readFile = Module.findExportByName('kernel32.dll', 'ReadFile');
if (readFile) {
    Interceptor.attach(readFile, {
        onEnter: function(args) {
            this.handle = args[0];
            this.buffer = args[1];
            this.numBytesToRead = args[2].toInt32();
            this.numBytesRead = args[3];
        },
        onLeave: function(retval) {
            try {
                if (this.numBytesRead) {
                    var bytesRead = this.numBytesRead.readUInt();
                    if (bytesRead > 0 && bytesRead < 500000) {
                        var data = this.buffer.readUtf8String(Math.min(bytesRead, 100000));
                        if (data) {
                            // Check for HTTP response
                            if (data.indexOf('HTTP/1.1') >= 0 || data.indexOf('HTTP/2') >= 0) {
                                capturedCount++;
                                console.log('\n' + '='.repeat(80));
                                console.log('ReadFile HTTP Response #' + capturedCount + ' (' + bytesRead + ' bytes)');
                                console.log('='.repeat(80));
                                console.log(data.substring(0, 80000));
                                console.log('='.repeat(80));
                            }
                            // Check for TLS handshake response
                            else if (data.charCodeAt(0) === 0x16 && data.charCodeAt(1) === 0x03) {
                                console.log('[TLS] Server handshake (' + bytesRead + ' bytes)');
                            }
                            else if (data.charCodeAt(0) === 0x17 && data.charCodeAt(1) === 0x03) {
                                console.log('[TLS] Server Application Data (' + bytesRead + ' bytes encrypted)');
                            }
                        }
                    }
                }
            } catch(e) {}
        }
    });
    console.log('[+] ReadFile hooked at ' + readFile);
}

// ============================================================
// Strategy 3: Hook WSASend/WSARecv as fallback
// ============================================================
var wsasend = Module.findExportByName('ws2_32.dll', 'WSASend');
if (wsasend) {
    Interceptor.attach(wsasend, {
        onEnter: function(args) {
            this.socket = args[0].toInt32();
            this.lpBuffers = args[1];
            this.dwBufferCount = args[2].toInt32();
        },
        onLeave: function(retval) {
            try {
                for (var i = 0; i < this.dwBufferCount && i < 8; i++) {
                    var buf = this.lpBuffers.add(i * 16);
                    var len = buf.readUInt();
                    var ptr = buf.add(8).readPointer();
                    if (len > 0 && len < 500000) {
                        var data = ptr.readUtf8String(Math.min(len, 100000));
                        if (data && (data.indexOf('POST /algo') >= 0 || data.indexOf('GET /algo') >= 0 ||
                            data.indexOf('POST /api/') >= 0 || data.indexOf('Host: lingma') >= 0)) {
                            capturedCount++;
                            console.log('\n' + '='.repeat(80));
                            console.log('WSASend #' + capturedCount + ' (socket ' + this.socket + ', ' + len + ' bytes)');
                            console.log('='.repeat(80));
                            console.log(data.substring(0, 80000));
                            console.log('='.repeat(80));
                        }
                    }
                }
            } catch(e) {}
        }
    });
    console.log('[+] WSASend hooked');
}

var wsarecv = Module.findExportByName('ws2_32.dll', 'WSARecv');
if (wsarecv) {
    Interceptor.attach(wsarecv, {
        onEnter: function(args) {
            this.socket = args[0].toInt32();
            this.lpBuffers = args[1];
            this.lpdwNumberOfBytesRecvd = args[4];
        },
        onLeave: function(retval) {
            try {
                if (this.lpdwNumberOfBytesRecvd) {
                    var bytesRecvd = this.lpdwNumberOfBytesRecvd.readUInt();
                    if (bytesRecvd > 0 && bytesRecvd < 500000) {
                        var buf = this.lpBuffers.add(8).readPointer();
                        var data = buf.readUtf8String(Math.min(bytesRecvd, 100000));
                        if (data && (data.indexOf('HTTP/1.1') >= 0 || data.indexOf('{"success"') >= 0 ||
                            data.indexOf('"algo"') >= 0 || data.indexOf('Entry-Timestamp') >= 0)) {
                            capturedCount++;
                            console.log('\n' + '='.repeat(80));
                            console.log('WSARecv #' + capturedCount + ' (socket ' + this.socket + ', ' + bytesRecvd + ' bytes)');
                            console.log('='.repeat(80));
                            console.log(data.substring(0, 80000));
                            console.log('='.repeat(80));
                        }
                    }
                }
            } catch(e) {}
        }
    });
    console.log('[+] WSARecv hooked');
}

// ============================================================
// Strategy 4: Hook connect to track connections
// ============================================================
var connect = Module.findExportByName('ws2_32.dll', 'connect');
if (connect) {
    Interceptor.attach(connect, {
        onEnter: function(args) {
            var addr = args[1];
            try {
                var family = addr.readU16();
                if (family === 2) {
                    var port = addr.add(2).readU16();
                    port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                    var ip = addr.add(4).readU8() + '.' + addr.add(5).readU8() + '.' +
                            addr.add(6).readU8() + '.' + addr.add(7).readU8();
                    console.log('[connect] -> ' + ip + ':' + port);
                } else if (family === 23) {
                    // AF_INET6
                    var port = addr.add(2).readU16();
                    port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                    console.log('[connect] -> [' + 'ipv6' + ']:' + port);
                }
            } catch(e) {}
        }
    });
    console.log('[+] connect hooked');
}

// ============================================================
// Strategy 5: Hook getAppSalt (0x882760) - just log entry/exit
// No GC interaction, just console logging
// ============================================================
var getAppSalt = base.add(0x882760);
Interceptor.attach(getAppSalt, {
    onEnter: function(args) {
        console.log('\n[** getAppSalt ENTER **]');
        console.log('  Args: rcx=' + this.context.rcx + ' rdx=' + this.context.rdx +
                    ' r8=' + this.context.r8 + ' r9=' + this.context.r9);
        this.entryTime = Date.now();
    },
    onLeave: function(retval) {
        var elapsed = Date.now() - this.entryTime;
        console.log('[** getAppSalt LEAVE **] (' + elapsed + 'ms)');
        console.log('  Return: rax=' + this.context.rax + ' rcx=' + this.context.rcx);

        // Try to read return value as Go string
        try {
            var retPtr = this.context.rax;
            var retLen = ptr(this.context.rcx).toInt32();
            if (retLen > 0 && retLen < 100000) {
                var str = retPtr.readUtf8String(Math.min(retLen, 2000));
                if (str) {
                    console.log('  Return string (' + retLen + ' bytes): ' + str.substring(0, 2000));
                }
            }
        } catch(e) {
            console.log('  (could not read return value: ' + e.message + ')');
        }
    }
});
console.log('[+] getAppSalt hooked at ' + getAppSalt);

// ============================================================
// Strategy 6: Hook addBigModelSignatureHeaders (0x882ba0)
// ============================================================
var addSigHeaders = base.add(0x882ba0);
Interceptor.attach(addSigHeaders, {
    onEnter: function(args) {
        console.log('\n[** addBigModelSignatureHeaders ENTER **]');
        console.log('  Args: rcx=' + this.context.rcx + ' rdx=' + this.context.rdx);
        this.entryTime = Date.now();
    },
    onLeave: function(retval) {
        var elapsed = Date.now() - this.entryTime;
        console.log('[** addBigModelSignatureHeaders LEAVE **] (' + elapsed + 'ms)');
        console.log('  Return: rax=' + this.context.rax);
    }
});
console.log('[+] addBigModelSignatureHeaders hooked at ' + addSigHeaders);

// ============================================================
// Strategy 7: Hook MainSigning (0x8821e0)
// ============================================================
var mainSigning = base.add(0x8821e0);
Interceptor.attach(mainSigning, {
    onEnter: function(args) {
        console.log('\n[** MainSigning ENTER **]');
        console.log('  Args: rcx=' + this.context.rcx + ' rdx=' + this.context.rdx +
                    ' r8=' + this.context.r8);
        this.entryTime = Date.now();
    },
    onLeave: function(retval) {
        var elapsed = Date.now() - this.entryTime;
        console.log('[** MainSigning LEAVE **] (' + elapsed + 'ms)');
        console.log('  Return: rax=' + this.context.rax);
    }
});
console.log('[+] MainSigning hooked at ' + mainSigning);

// ============================================================
console.log('\n[*] All hooks installed!');
console.log('[*] ' + capturedCount + ' captures so far');
console.log('[*] Waiting for HTTP/TLS traffic...');
"""

def on_message(msg, data):
    payload = msg.get('payload', '')
    if payload:
        print(f"[MSG] {payload}")

def send_rpc(handle, method, params=None, msg_id=None):
    body = {"jsonrpc": "2.0", "method": method}
    if params:
        body["params"] = params
    if msg_id is not None:
        body["id"] = msg_id
    content = json.dumps(body)
    header = f"Content-Length: {len(content)}\r\n\r\n"
    win32file.WriteFile(handle, (header + content).encode('utf-8'))

def read_resp(handle, timeout_ms=5000):
    overlapped = pywintypes.OVERLAPPED()
    overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
    try:
        err, data = win32file.ReadFile(handle, 65536, overlapped)
        if err == 997:
            result = win32event.WaitForSingleObject(overlapped.hEvent, timeout_ms)
            if result == win32event.WAIT_OBJECT_0:
                data = bytes(overlapped.GetOverlappedResult())
            else:
                return None
        else:
            data = bytes(data)
    except:
        return None
    if data:
        text = data.decode('utf-8', errors='replace')
        if '\r\n\r\n' in text:
            _, body = text.split('\r\n\r\n', 1)
            return body[:500]
    return None

def main():
    device = frida.get_local_device()

    pid = LINGMA_PID
    print(f"[*] Attaching to Lingma (PID: {pid}) with I/O hooks...")

    try:
        session = device.attach(pid)
        print("[*] Attached successfully")

        script = session.create_script(FRIDA_SCRIPT)
        script.on('message', on_message)
        script.load()
        time.sleep(2)

        # Connect via named pipe to trigger LSP
        info_path = r'C:\Users\Zipper\.lingma\.info.json'
        with open(info_path, 'r') as f:
            info = json.load(f)
        pipe_path = info.get('ipcServerPath')
        print(f"[*] Pipe: {pipe_path}")

        try:
            handle = win32file.CreateFile(
                pipe_path,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING,
                win32file.FILE_FLAG_OVERLAPPED, None
            )
            print("[*] Connected to LSP pipe")

            # Initialize
            print("\n[*] Sending LSP initialize...")
            send_rpc(handle, "initialize", {
                "processId": 12345,
                "clientInfo": {"name": "vscode", "version": "1.95.0"},
                "locale": "en-US",
                "rootPath": "C:/test"
            }, 1)
            time.sleep(2)
            read_resp(handle)

            # Open document
            code = """import requests

def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)

def main():
    result = fib"""

            print("[*] Opening document...")
            send_rpc(handle, "textDocument/didOpen", {
                "textDocument": {
                    "uri": "file:///C:/test/fib.py",
                    "languageId": "python",
                    "version": 1,
                    "text": code
                }
            })
            time.sleep(1)

            # Request completion
            print("[*] Requesting completion...")
            send_rpc(handle, "textDocument/completion", {
                "textDocument": {"uri": "file:///C:/test/fib.py"},
                "position": {"line": 10, "character": 15}
            }, 2)
            time.sleep(5)
            read_resp(handle, 10000)

            print("\n[*] Waiting 45s for traffic...")
            for i in range(45):
                if i % 15 == 0:
                    print(f"  {i}s elapsed")
                time.sleep(1)

            win32file.CloseHandle(handle)
        except Exception as e:
            print(f"[*] Pipe error: {e}")
            print("[*] Waiting 45s anyway...")
            for i in range(45):
                if i % 15 == 0:
                    print(f"  {i}s elapsed")
                time.sleep(1)

        print("\n--- Done ---")
        script.unload()
        session.detach()

    except frida.ProcessNotFoundError:
        print(f"[!] Process {pid} not found")
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
