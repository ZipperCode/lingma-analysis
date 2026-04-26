"""
Frida Hook + Named Pipe v4: 使用从 VS Code 扩展提取的真实方法名
关键方法: chat/ask, textDocument/completion, codebase/recommendation
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

HOOK_SCRIPT = r"""
var ws2 = Process.getModuleByName('ws2_32.dll');
var ws2exports = ws2.enumerateExports();

// Hook WSASend
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
                        if (data.indexOf('Signature') >= 0 || data.indexOf('algo') >= 0 ||
                            data.indexOf('dashscope') >= 0 || data.indexOf('Authorization') >= 0 ||
                            data.indexOf('Timestamp') >= 0 || data.indexOf('sign') >= 0 ||
                            data.indexOf('POST') >= 0 || data.indexOf('GET') >= 0) {
                            console.log('[WSASend] len=' + len);
                            console.log('---DATA START---');
                            console.log(data.substring(0, 50000));
                            console.log('---DATA END---');
                        }
                    } catch(e) {}
                }
            }
        }
    });
    console.log('[Hook] WSASend OK');
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
    console.log('[Hook] connect OK');
}

console.log('[Hook] Ready');
"""

def on_message(msg, data):
    payload = msg.get('payload', '')
    if payload:
        print(f"[MSG] {payload}")

def send_rpc(handle, method, params=None, msg_id=None):
    """Send JSON-RPC with Content-Length header"""
    body = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        body["params"] = params
    if msg_id is not None:
        body["id"] = msg_id
    content = json.dumps(body)
    header = f"Content-Length: {len(content)}\r\n\r\n"
    full_msg = header + content
    win32file.WriteFile(handle, full_msg.encode('utf-8'))
    print(f"  Sent: {method} ({len(content)} bytes)")

def read_response(handle, timeout_ms=3000):
    overlapped = pywintypes.OVERLAPPED()
    overlapped.hEvent = win32event.CreateEvent(None, True, False, None)

    try:
        err, data = win32file.ReadFile(handle, 65536, overlapped)
        if err == 997:
            result = win32event.WaitForSingleObject(overlapped.hEvent, timeout_ms)
            if result != win32event.WAIT_OBJECT_0:
                return None
            try:
                data = bytes(overlapped.GetOverlappedResult())
            except:
                return None
        else:
            data = bytes(data)
    except pywintypes.error as e:
        if e.args[0] == 997:
            result = win32event.WaitForSingleObject(overlapped.hEvent, timeout_ms)
            if result != win32event.WAIT_OBJECT_0:
                return None
            try:
                data = bytes(overlapped.GetOverlappedResult())
            except:
                return None
        else:
            return None

    if not data:
        return None

    text = data.decode('utf-8', errors='replace')
    # Parse Content-Length
    if '\r\n\r\n' in text:
        header_part, body = text.split('\r\n\r\n', 1)
        for line in header_part.split('\r\n'):
            if line.startswith('Content-Length:'):
                cl = int(line.split(':')[1].strip())
                if cl > 0:
                    return body[:cl]
        return body[:2000]
    return text[:2000]

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

    pipe_path = get_pipe_path()
    print(f"Pipe: {pipe_path}")

    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()

    print("\nConnecting via named pipe...")
    try:
        handle = win32file.CreateFile(
            pipe_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING,
            win32file.FILE_FLAG_OVERLAPPED, None
        )
        print("Connected!")

        # 1. Initialize
        print("\n[1] initialize")
        send_rpc(handle, "initialize", {
            "processId": 12345,
            "clientInfo": {"name": "vscode", "version": "1.95.0"},
            "locale": "en-US",
            "rootPath": "C:/test"
        }, msg_id=1)
        time.sleep(1)
        resp = read_response(handle)
        print(f"  Resp: {str(resp)[:200]}")

        # 2. initialized notification
        print("\n[2] initialized")
        send_rpc(handle, "initialized", {})
        time.sleep(0.5)

        # 3. ide/update (set online mode)
        print("\n[3] ide/update")
        send_rpc(handle, "ide/update", {"type": "online"})
        time.sleep(1)

        # 4. textDocument/didOpen (simulate opening a file)
        print("\n[4] textDocument/didOpen")
        send_rpc(handle, "textDocument/didOpen", {
            "textDocument": {
                "uri": "file:///C:/test/hello.py",
                "languageId": "python",
                "version": 1,
                "text": "def fibonacci(n):\n    if n <= 1:\n        return n\n    return fibonacci(n-1) + fibonacci(n-2)\n\n# Calculate\nresult = fibonacci(10)\nprint(result)"
            }
        })
        time.sleep(1)

        # 5. textDocument/completion - THIS should trigger remote API!
        print("\n[5] textDocument/completion")
        send_rpc(handle, "textDocument/completion", {
            "textDocument": {"uri": "file:///C:/test/hello.py"},
            "position": {"line": 7, "character": 0}
        }, msg_id=5)
        time.sleep(3)
        resp = read_response(handle, timeout_ms=10000)
        print(f"  Resp: {str(resp)[:500]}")
        time.sleep(2)

        # 6. chat/ask - This definitely triggers remote API!
        print("\n[6] chat/ask")
        send_rpc(handle, "chat/ask", {
            "message": "What is the difference between Python and JavaScript?",
            "model": "qwen-coder-plus-latest",
            "sessionId": "test-session-1",
            "chatId": "test-chat-1"
        }, msg_id=6)
        time.sleep(5)
        resp = read_response(handle, timeout_ms=15000)
        print(f"  Resp: {str(resp)[:500]}")
        time.sleep(2)

        # 7. codebase/recommendation
        print("\n[7] codebase/recommendation")
        send_rpc(handle, "codebase/recommendation", {
            "uri": "file:///C:/test/hello.py",
            "content": "def fibonacci(n):\n    pass"
        }, msg_id=7)
        time.sleep(3)
        resp = read_response(handle)
        print(f"  Resp: {str(resp)[:500]}")

        # 8. commitMsg/generate
        print("\n[8] commitMsg/generate")
        send_rpc(handle, "commitMsg/generate", {
            "diff": "diff --git a/hello.py b/hello.py\n+def fibonacci(n):\n+    return n if n <= 1 else fibonacci(n-1) + fibonacci(n-2)",
            "repoPath": "C:/test"
        }, msg_id=8)
        time.sleep(5)
        resp = read_response(handle, timeout_ms=15000)
        print(f"  Resp: {str(resp)[:500]}")

        # Wait for any delayed traffic
        print("\nWaiting 30s for remote traffic...")
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
