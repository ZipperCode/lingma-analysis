"""
Hook Go HTTP 客户端来捕获明文请求
在 net/http 的 writeHeader 或 crypto/tls 的 writeRecordLocked 处 hook
方法: 搜索 Go 函数名模式
"""
import frida
import time
import subprocess
import json
import win32file
import win32event
import pywintypes

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def get_pipe_path():
    import os
    info_path = os.path.expandvars(r'C:\Users\Zipper\.lingma\.info.json')
    with open(info_path, 'r') as f:
        info = json.load(f)
    return info.get('ipcServerPath')

# Hook approach: hook at the buffer level where HTTP data is assembled
# before TLS encryption
HOOK_SCRIPT = r"""
'use strict';

var base = Module.getBaseAddress();

// We'll hook WriteFile on socket handles (which catches SSL_write)
// But more importantly, we'll hook Go's internal write functions

// Strategy 1: Hook crypto/tls (*Conn).writeRecordLocked
// This function is called before encryption with the plaintext record
// The plaintext data for Application Data type (0x17) is already encrypted
// BUT for handshake records we can see the clear text

// Strategy 2: Hook net/http (*Request).Write
// This writes the HTTP request to the underlying connection (pre-TLS)
// In Go, this is typically (*persistConn).roundTrip -> writeHeader

// Strategy 3: Since we know the binary has these Go functions,
// let's find them by scanning for string references

// crypto/tls contains strings like:
// "tls: ", "ClientHello", "ServerHello", "handshake", "alert"
// net/http contains strings like:
// "HTTP/", "Content-Type", "Content-Length", "POST ", "GET "

// Let's hook functions that reference these strings

// First, let's try the most direct approach:
// Hook at the point where the HTTP request body + headers are in memory
// This is typically in net/textproto.(*Writer).Flush or similar

console.log('[Hook] Starting scan for HTTP-related functions...');

// Hook known offsets and any that touch HTTP-like data
var candidates = [
    0x882ba0, 0x882c80, 0x882e40,
    0x883a40, 0x883b60, 0x883d80, 0x883f40,
    0x884040, 0x884080, 0x8840e0, 0x8841a0,
    0x884200, 0x8843c0, 0x884880, 0x884a80,
    0x884c00, 0x884d20, 0x884e80, 0x884f80,
    0x885340, 0x885620, 0x8856a0, 0x885860,
    0x885e40, 0x886040, 0x890140, 0x890380,
];

var hookedCount = 0;
candidates.forEach(function(offset) {
    try {
        var addr = base.add(offset);
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.offset = offset;
                // On function entry, try to read string from return area
                console.log('>>> 0x' + offset.toString(16));
            },
            onLeave: function(retval) {
                // Go string return: RAX = ptr, RCX = len
                try {
                    var ptr = this.context.rax;
                    var len = this.context.rcx.toInt32();
                    if (len > 0 && len < 10000) {
                        var str = ptr.readUtf8String(Math.min(len, 2000));
                        if (str.indexOf('POST') >= 0 || str.indexOf('Signature') >= 0 ||
                            str.indexOf('algo') >= 0 || str.indexOf('HTTP/') >= 0 ||
                            str.indexOf('dashscope') >= 0 || str.indexOf('Authorization') >= 0 ||
                            str.indexOf('Timestamp') >= 0 || str.indexOf('sign') >= 0 ||
                            str.indexOf('Content-Type') >= 0) {
                            console.log('<<< 0x' + this.offset.toString(16) + ' RETURNS HTTP-like data:');
                            console.log(str.substring(0, 2000));
                        }
                    }
                } catch(e) {}
            }
        });
        hookedCount++;
    } catch(e) {}
});

console.log('[Hook] ' + hookedCount + ' functions hooked');

// Also hook WSASend for good measure
var ws2 = Process.getModuleByName('ws2_32.dll');
var ws2exports = ws2.enumerateExports();
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
                        var data = ptr.readUtf8String(Math.min(len, 50000));
                        // Check for ANY HTTP-like content (not just signature)
                        var isHttp = data.indexOf('POST') >= 0 || data.indexOf('GET') >= 0 ||
                            data.indexOf('HTTP/') >= 0 || data.indexOf('Host:') >= 0 ||
                            data.indexOf('Content-Length') >= 0 || data.indexOf('User-Agent') >= 0;
                        if (isHttp) {
                            console.log('[WSASend HTTP] len=' + len);
                            console.log('---START---');
                            console.log(data.substring(0, 10000));
                            console.log('---END---');
                        }
                    } catch(e) {}
                }
            }
        }
    });
    console.log('[Hook] WSASend HTTP capture OK');
}

// Hook connect
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
                    console.log('[connect] -> ' + ip + ':' + port);
                }
            } catch(e) {}
        }
    });
}

console.log('[Hook] All ready');
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

def read_resp(handle, timeout_ms=3000):
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

    # Attach to ALREADY RUNNING Lingma (don't kill/restart, preserve login state)
    processes = device.enumerate_processes()
    lingma_procs = [p for p in processes if 'lingma' in p.name.lower()]
    if not lingma_procs:
        print("Lingma not running!")
        return

    pid = lingma_procs[0].pid
    print(f"Attaching to running Lingma (PID: {pid})...")

    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()
    time.sleep(2)

    pipe_path = get_pipe_path()
    print(f"Pipe: {pipe_path}")

    try:
        handle = win32file.CreateFile(
            pipe_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING,
            win32file.FILE_FLAG_OVERLAPPED, None
        )
        print("Connected!")

        send_rpc(handle, "initialize", {
            "processId": 12345, "clientInfo": {"name": "vscode", "version": "1.95.0"},
            "locale": "en-US", "rootPath": "C:/test"
        }, 1)
        time.sleep(1)
        read_resp(handle)

        # Try various methods
        methods = [
            ("textDocument/completion", {"textDocument": {"uri": "file:///C:/test/hello.py"}, "position": {"line": 0, "character": 0}}, 2),
            ("chat/ask", {"sessionId": "t1", "chatId": "c1", "message": "hello", "stream": False}, 3),
        ]
        for method, params, msg_id in methods:
            send_rpc(handle, method, params, msg_id)
            time.sleep(3)
            read_resp(handle, 10000)

        print("\nWaiting 30s...")
        for i in range(30):
            if i % 5 == 0:
                print(f"  {i}s")
            time.sleep(1)

        win32file.CloseHandle(handle)
    except Exception as e:
        print(f"Pipe error: {e}")

    print("--- Done ---")
    script.unload()
    session.detach()

if __name__ == '__main__':
    main()
