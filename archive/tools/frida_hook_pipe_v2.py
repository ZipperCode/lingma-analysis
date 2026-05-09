"""
Frida Hook + Named Pipe v2: 多种协议格式尝试
同时尝试: 纯JSON+换行, LSP风格(Content-Length), 二进制帧
"""
import frida
import time
import subprocess
import json
import win32file
import win32event
import pywintypes
import struct

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

# Read info.json to get the pipe path
def get_pipe_path():
    import os
    info_path = os.path.expandvars(r'C:\Users\Zipper\.lingma\.info.json')
    with open(info_path, 'r') as f:
        info = json.load(f)
    return info.get('ipcServerPath')

HOOK_SCRIPT = r"""
var ws2 = Process.getModuleByName('ws2_32.dll');
var exports = ws2.enumerateExports();

var wsasendExp = exports.filter(function(e) { return e.name === 'WSASend'; });
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
                        // Show ALL HTTP-like content
                        if (data.indexOf('POST') >= 0 || data.indexOf('GET') >= 0 ||
                            data.indexOf('HTTP/') >= 0 || data.indexOf('Signature') >= 0 ||
                            data.indexOf('algo') >= 0 || data.indexOf('dashscope') >= 0 ||
                            data.indexOf('Authorization') >= 0 || data.indexOf('Timestamp') >= 0 ||
                            data.indexOf('sign') >= 0) {
                            console.log('[WSASend] len=' + len);
                            console.log('---DATA---');
                            console.log(data.substring(0, 50000));
                            console.log('---END---');
                        }
                    } catch(e) {
                        // Try binary
                        var bytes = ptr.readByteArray(Math.min(len, 200));
                        console.log('[WSASend] len=' + len + ' (hex preview):');
                        console.log(hexdump(bytes));
                    }
                }
            }
        }
    });
    console.log('[Hook] WSASend OK');
}

// Also hook send/recv for good measure
var sendExp = exports.filter(function(e) { return e.name === 'send'; });
if (sendExp.length > 0) {
    Interceptor.attach(sendExp[0].address, {
        onEnter: function(args) {
            var len = args[2].toInt32();
            if (len > 0 && len < 10000) {
                try {
                    var data = args[1].readUtf8String(len);
                    if (data.indexOf('Signature') >= 0 || data.indexOf('algo') >= 0 ||
                        data.indexOf('dashscope') >= 0) {
                        console.log('[send] len=' + len);
                        console.log(data.substring(0, 5000));
                    }
                } catch(e) {}
            }
        }
    });
    console.log('[Hook] send OK');
}

// Hook connect to see destinations
var connectExp = exports.filter(function(e) { return e.name === 'connect'; });
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
    console.log('[Hook] connect OK');
}

console.log('[Hook] All ready');
"""

def on_message(msg, data):
    payload = msg.get('payload', '')
    if payload:
        print(f"[MSG] {payload}")

def read_pipe_with_timeout(handle, timeout_ms=3000):
    """Non-blocking pipe read with timeout"""
    overlapped = pywintypes.OVERLAPPED()
    overlapped.hEvent = win32event.CreateEvent(None, True, False, None)

    try:
        err, data = win32file.ReadFile(handle, 65536, overlapped)
        # If it returned immediately
        return data
    except pywintypes.error as e:
        if e.args[0] == 997:  # ERROR_IO_PENDING
            result = win32event.WaitForSingleObject(overlapped.hEvent, timeout_ms)
            if result == win32event.WAIT_OBJECT_0:
                return overlapped.GetOverlappedResult()
            else:
                return b''
        else:
            raise

def try_send(handle, msg_bytes, label):
    """Send and try to read response"""
    print(f"\n[{label}] Sending {len(msg_bytes)} bytes...")
    try:
        win32file.WriteFile(handle, msg_bytes)
        time.sleep(0.5)
        data = read_pipe_with_timeout(handle)
        if data:
            print(f"[{label}] Response: {data[:500]}")
        else:
            print(f"[{label}] No response (timeout or empty)")
        return data
    except Exception as e:
        print(f"[{label}] Error: {e}")
        return None

def main():
    device = frida.get_local_device()

    for p in device.enumerate_processes():
        if 'lingma' in p.name.lower():
            device.kill(p.pid)

    print("Starting Lingma...")
    proc = subprocess.Popen([LINGMA, "start"])
    time.sleep(10)

    processes = device.enumerate_processes()
    lingma_procs = [p for p in processes if 'lingma' in p.name.lower()]
    if not lingma_procs:
        print("Not found!")
        proc.kill()
        return

    pid = lingma_procs[0].pid
    print(f"PID: {pid}")

    # Get pipe path
    pipe_path = get_pipe_path()
    print(f"Pipe: {pipe_path}")

    # Attach Frida first (before any pipe activity)
    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()

    # Connect via named pipe
    print("\nConnecting via named pipe...")
    try:
        handle = win32file.CreateFile(
            pipe_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING,
            win32file.FILE_FLAG_OVERLAPPED,  # Use overlapped for async
            None
        )
        print("Connected to pipe!")

        # Method 1: Pure JSON-RPC with newline (LSP-style)
        print("\n=== Method 1: JSON-RPC + newline ===")

        # Initialize
        init_msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "processId": 12345,
                "clientInfo": {"name": "vscode", "version": "1.95.0"},
                "locale": "en-US",
            },
            "id": 1
        }) + "\n"
        try_send(handle, init_msg.encode('utf-8'), "init")

        # Try several methods that might trigger remote calls
        methods_to_try = [
            ("ide/update", {"type": "online"}),
            ("chat/send", {"message": "hello", "model": "qwen-coder"}),
            ("extension/sendRequest", {"method": "chat/ask", "params": {"message": "What is Python?"}}),
            ("initialize", {"processId": 99999, "clientInfo": {"name": "test"}, "id": 99}),
        ]

        for method, params in methods_to_try:
            msg = json.dumps({
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
            }) + "\n"
            try_send(handle, msg.encode('utf-8'), method)
            time.sleep(1)

        # Method 2: LSP-style with Content-Length header
        print("\n=== Method 2: Content-Length header ===")
        content = json.dumps({
            "jsonrpc": "2.0",
            "method": "chat/sendMessage",
            "params": {"message": "explain quantum computing", "stream": True}
        })
        lsp_msg = f"Content-Length: {len(content)}\r\n\r\n{content}"
        try_send(handle, lsp_msg.encode('utf-8'), "lsp")

        time.sleep(2)

        # Method 3: Try a notification-style message
        print("\n=== Method 3: Various notifications ===")
        notifications = [
            {"jsonrpc": "2.0", "method": "$/cancelRequest", "params": {"id": 1}},
            {"jsonrpc": "2.0", "method": "initialized", "params": {}},
            {"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
                "textDocument": {
                    "uri": "file:///test.py",
                    "languageId": "python",
                    "version": 1,
                    "text": "def hello():\n    print('world')"
                }
            }},
        ]
        for notif in notifications:
            msg = json.dumps(notif) + "\n"
            try_send(handle, msg.encode('utf-8'), notif.get('method', 'unknown'))
            time.sleep(1)

        # Wait for any delayed traffic
        print("\nWaiting 30s for any triggered traffic...")
        for i in range(30):
            if i % 5 == 0:
                print(f"  {i}s elapsed")
            time.sleep(1)

        win32file.CloseHandle(handle)
    except Exception as e:
        print(f"Pipe error: {e}")
        import traceback
        traceback.print_exc()

    print("--- Done ---")
    try:
        script.unload()
    except:
        pass
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
