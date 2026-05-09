"""
Frida Stalker-based HTTP capture for Go 1.23 binary.

Stalker doesn't modify function prologues, so it avoids the Go GC crash issue.
Strategy:
1. Use Interceptor.attach on WSASend (safe, works at socket level)
2. When getAppSalt (0x882760) or addBigModelSignatureHeaders (0x882ba0) is called,
   use Stalker to follow execution and capture HTTP data in memory
3. Trigger LSP completion to activate the signing flow
"""
import frida
import time
import subprocess
import json
import win32file
import win32event
import pywintypes

LINGMA_PID = 456  # Running Lingma.exe PID

# Frida Stalker script
STALKER_SCRIPT = r"""
'use strict';

var base = Module.getBaseAddress();
var capturedCount = 0;
var isStalking = false;

// ============================================================
// Strategy 1: Hook WSASend at socket level (safe, always works)
// ============================================================
var wsasend = Module.findExportByName('ws2_32.dll', 'WSASend');
if (wsasend) {
    Interceptor.attach(wsasend, {
        onEnter: function(args) {
            var socket = args[0].toInt32();
            var lpBuffers = args[1];
            var dwBufferCount = args[2].toInt32();

            for (var i = 0; i < dwBufferCount && i < 8; i++) {
                var buf = lpBuffers.add(i * 16);
                var len = buf.readUInt();
                var ptr = buf.add(8).readPointer();

                if (len > 0 && len < 500000) {
                    try {
                        var data = ptr.readUtf8String(Math.min(len, 100000));
                        if (!data) continue;

                        // Check for HTTP request (headers)
                        if (data.indexOf('POST /algo') >= 0 || data.indexOf('GET /algo') >= 0 ||
                            data.indexOf('POST /api/') >= 0 || data.indexOf('GET /api/') >= 0) {
                            capturedCount++;
                            console.log('\n========== WSASend HTTP Request #' + capturedCount + ' ==========');
                            console.log(data.substring(0, 50000));
                            console.log('========== END Request #' + capturedCount + ' ==========');
                        }

                        // Check for HTTP response (headers from recv, unlikely in send but just in case)
                        if (data.indexOf('HTTP/1.1') >= 0 && (data.indexOf('200') >= 0 || data.indexOf('403') >= 0 || data.indexOf('401') >= 0)) {
                            capturedCount++;
                            console.log('\n========== WSASend HTTP Response #' + capturedCount + ' ==========');
                            console.log(data.substring(0, 50000));
                            console.log('========== END Response #' + capturedCount + ' ==========');
                        }

                        // Also capture if it contains signature-related headers
                        if (data.indexOf('Cosy-MachineToken') >= 0 || data.indexOf('Cosy-Key') >= 0 ||
                            data.indexOf('Cosy-User') >= 0 || data.indexOf('Authorization: Bearer') >= 0) {
                            if (data.indexOf('POST') < 0 && data.indexOf('GET') < 0) {
                                // This might be part of a larger request
                                console.log('\n========== WSASend Auth Headers (fragment) ==========');
                                console.log(data.substring(0, 5000));
                                console.log('========== END Fragment ==========');
                            }
                        }
                    } catch(e) {}
                }
            }
        }
    });
    console.log('[+] WSASend hooked at ' + wsasend);
}

// Hook WSARecv for responses
var wsarecv = Module.findExportByName('ws2_32.dll', 'WSARecv');
if (wsarecv) {
    Interceptor.attach(wsarecv, {
        onEnter: function(args) {
            this.socket = args[0].toInt32();
            this.lpBuffers = args[1];
            this.lpNumberOfBytesRecvd = args[4];
        },
        onLeave: function(retval) {
            try {
                if (this.lpNumberOfBytesRecvd) {
                    var bytesRecvd = this.lpNumberOfBytesRecvd.readUInt();
                    if (bytesRecvd > 0 && bytesRecvd < 500000) {
                        var buf = this.lpBuffers.add(8).readPointer();
                        var data = buf.readUtf8String(Math.min(bytesRecvd, 100000));
                        if (data && (data.indexOf('HTTP/1.1') >= 0 || data.indexOf('{"success"') >= 0 ||
                            data.indexOf('{"result"') >= 0 || data.indexOf('"algo"') >= 0)) {
                            capturedCount++;
                            console.log('\n========== WSARecv HTTP Response #' + capturedCount + ' ==========');
                            console.log(data.substring(0, 50000));
                            console.log('========== END Response #' + capturedCount + ' ==========');
                        }
                    }
                }
            } catch(e) {}
        }
    });
    console.log('[+] WSARecv hooked');
}

// ============================================================
// Strategy 2: Use Stalker on getAppSalt (0x882760)
// This follows execution of the signing function without modifying it
// ============================================================
var getAppSalt = base.add(0x882760);
var addBigModelSignatureHeaders = base.add(0x882ba0);
var buildBigModelAuthRequest = base.add(0x881000);

function stalkFunction(funcAddr, funcName) {
    Interceptor.attach(funcAddr, {
        onEnter: function(args) {
            this.funcName = funcName;
            console.log('\n[*] Entering ' + funcName);

            // Save register state
            this.savedRcx = this.context.rcx;
            this.savedRdx = this.context.rdx;
            this.savedR8 = this.context.r8;
            this.savedR9 = this.context.r9;

            // Start stalking this thread
            if (!isStalking) {
                isStalking = true;
                Stalker.follow(this.threadId, {
                    events: {
                        call: true,
                        ret: false,
                        exec: false,
                        block: false,
                        compile: false
                    },
                    onCallSummary: function(summary) {
                        // Log all calls during the stalked execution
                        for (var target in summary) {
                            var addr = ptr(target);
                            var offset = addr.sub(base);
                            var count = summary[target];

                            // Check if this is a known interesting function
                            var interesting = false;
                            var name = '';

                            var interestingFuncs = {
                                '0x4563c0': 'SHA256',
                                '0x2dd360': 'mapassign_faststr',
                                '0x25c7e0': 'time.Format',
                                '0x882760': 'getAppSalt',
                                '0x882ba0': 'addBigModelSignatureHeaders',
                                '0x8821e0': 'MainSigning',
                            };

                            var offsetStr = '0x' + offset.toString(16);
                            if (offsetStr in interestingFuncs) {
                                interesting = true;
                                name = interestingFuncs[offsetStr];
                            }

                            if (interesting || count > 10) {
                                console.log('  Call -> ' + (name || offsetStr) + ' (count: ' + count + ')');
                            }
                        }
                    }
                });
            }
        },

        onLeave: function(retval) {
            console.log('[*] Leaving ' + this.funcName);

            // Try to read return value as Go string
            try {
                var retPtr = this.context.rax;
                var retLen = this.context.rcx.toInt32();
                if (retLen > 0 && retLen < 100000) {
                    var str = retPtr.readUtf8String(Math.min(retLen, 5000));
                    if (str && (str.indexOf('algo') >= 0 || str.indexOf('Signature') >= 0 ||
                        str.indexOf('HTTP') >= 0 || str.indexOf('Bearer') >= 0)) {
                        console.log('  RETURN: ' + str.substring(0, 5000));
                    }
                }
            } catch(e) {}

            // Stop stalking
            if (isStalking) {
                Stalker.unfollow(this.threadId);
                Stalker.garbageCollect();
                isStalking = false;
            }
        }
    });
    console.log('[+] ' + funcName + ' hooked at ' + funcAddr);
}

stalkFunction(buildBigModelAuthRequest, 'BuildBigModelAuthRequest');
stalkFunction(getAppSalt, 'getAppSalt');
stalkFunction(addBigModelSignatureHeaders, 'addBigModelSignatureHeaders');

// ============================================================
// Strategy 3: Hook connect to track connections to Lingma server
// ============================================================
var connect = Module.findExportByName('ws2_32.dll', 'connect');
if (connect) {
    Interceptor.attach(connect, {
        onEnter: function(args) {
            var addr = args[1];
            try {
                var family = addr.readU16();
                if (family === 2) { // AF_INET
                    var port = addr.add(2).readU16();
                    port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                    var ip = addr.add(4).readU8() + '.' + addr.add(5).readU8() + '.' +
                            addr.add(6).readU8() + '.' + addr.add(7).readU8();

                    // Check if connecting to Lingma servers
                    if (port === 443 || port === 80) {
                        console.log('[connect] -> ' + ip + ':' + port);
                    }
                }
            } catch(e) {}
        }
    });
    console.log('[+] connect hooked');
}

console.log('\n[*] All hooks installed. Waiting for HTTP traffic...');
console.log('[*] Trigger a completion or chat request to activate signing flow');
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
    print(f"[*] Attaching to Lingma (PID: {pid}) with Stalker...")

    try:
        session = device.attach(pid)
        print("[*] Attached successfully")

        script = session.create_script(STALKER_SCRIPT)
        script.on('message', on_message)
        script.load()
        time.sleep(2)

        # Connect via named pipe to trigger LSP requests
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
                "rootPath": "C:/test",
                "capabilities": {
                    "textDocument": {
                        "completion": {
                            "completionItem": {"snippetSupport": True}
                        }
                    }
                }
            }, 1)
            time.sleep(2)
            read_resp(handle)

            # Open a document
            code = """import requests

def fetch_user_data(user_id):
    url = f"https://api.example.com/users/{user_id}"
    headers = {"Authorization": "Bearer token"}
    response = requests.get(url, headers=headers)
    return response.json()

def main():
    user_id = 12345
    data = fetch_user_data(user_id)
    print(data)

if __name__ == "__main__":
    main()
"""
            print("[*] Opening document...")
            send_rpc(handle, "textDocument/didOpen", {
                "textDocument": {
                    "uri": "file:///C:/test/example.py",
                    "languageId": "python",
                    "version": 1,
                    "text": code
                }
            })
            time.sleep(1)

            # Request completion
            print("[*] Requesting completion...")
            send_rpc(handle, "textDocument/completion", {
                "textDocument": {"uri": "file:///C:/test/example.py"},
                "position": {"line": 9, "character": 11}
            }, 2)
            time.sleep(5)
            read_resp(handle, 10000)

            # Wait for any HTTP traffic
            print("\n[*] Waiting 30s for HTTP traffic captured by hooks...")
            print("[*] (Stalker is watching signing functions)")
            for i in range(30):
                if i % 10 == 0:
                    print(f"  {i}s elapsed")
                time.sleep(1)

            win32file.CloseHandle(handle)
        except Exception as e:
            print(f"[*] Pipe error: {e}")
            print("[*] Waiting 30s anyway, traffic may come from other sources...")
            for i in range(30):
                if i % 10 == 0:
                    print(f"  {i}s elapsed")
                time.sleep(1)

        print("\n--- Done ---")
        script.unload()
        session.detach()

    except frida.ProcessNotFoundError:
        print(f"[!] Process {pid} not found. Is Lingma running?")
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
