"""
Frida Hook + Named Pipe v3: 正确使用 Content-Length 协议格式
同时 hook Go 的 http.RoundTrip 获取明文 HTTP 请求
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

# Hook both WSASend AND try to find Go http client functions
HOOK_SCRIPT = r"""
// ========== WSASend (catches TLS records) ==========
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

// ========== connect (see where it connects) ==========
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

// ========== Try to intercept Go HTTP client =========
// Go net/http uses net/textproto which uses (*Writer).WriteString
// and (*Reader).ReadString - but hard to find in stripped binary
// Instead, let's try to find crypto/tls Conn.Write to catch pre-encrypted data

console.log('[Hook] Ready');
"""

def on_message(msg, data):
    payload = msg.get('payload', '')
    if payload:
        print(f"[MSG] {payload}")

def send_jsonrpc(handle, method, params=None, msg_id=None):
    """Send JSON-RPC message with proper Content-Length header"""
    body = {"jsonrpc": "2.0"}
    if params is not None:
        body["params"] = params
    if msg_id is not None:
        body["id"] = msg_id
    body["method"] = method

    content = json.dumps(body)
    header = f"Content-Length: {len(content)}\r\n\r\n"
    full_msg = header + content
    win32file.WriteFile(handle, full_msg.encode('utf-8'))

def send_notification(handle, method, params=None):
    """Send JSON-RPC notification (no id)"""
    send_jsonrpc(handle, method, params)

def read_response(handle, timeout_ms=5000):
    """Read Content-Length delimited response"""
    overlapped = pywintypes.OVERLAPPED()
    overlapped.hEvent = win32event.CreateEvent(None, True, False, None)

    # Read in small chunks to get headers first
    try:
        err, data = win32file.ReadFile(handle, 4096, overlapped)
    except pywintypes.error as e:
        if e.args[0] == 997:  # IO_PENDING
            result = win32event.WaitForSingleObject(overlapped.hEvent, timeout_ms)
            if result == win32event.WAIT_OBJECT_0:
                try:
                    data = overlapped.GetOverlappedResult()
                except:
                    return None
            else:
                return None
        else:
            return None

    if not data:
        return None

    # Convert memoryview to bytes
    data = bytes(data)

    # Parse Content-Length header
    text = data.decode('utf-8', errors='replace')
    if '\r\n\r\n' in text:
        header_part, body = text.split('\r\n\r\n', 1)
        cl = 0
        for line in header_part.split('\r\n'):
            if line.startswith('Content-Length:'):
                cl = int(line.split(':')[1].strip())
        if cl > 0 and len(body) >= cl:
            return body[:cl]
        elif cl > 0:
            # Need to read more
            remaining = cl - len(body)
            try:
                err2, data2 = win32file.ReadFile(handle, remaining, overlapped)
                body += data2.decode('utf-8', errors='replace')
            except:
                pass
            return body[:cl] if cl <= len(body) else body
        return body
    return text[:500]

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

    # Attach Frida
    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()

    # Connect via named pipe with proper protocol
    print("\nConnecting via named pipe...")
    try:
        handle = win32file.CreateFile(
            pipe_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING,
            win32file.FILE_FLAG_OVERLAPPED,
            None
        )
        print("Connected!")

        # 1. Initialize (must be first)
        print("\n[1] initialize")
        send_jsonrpc(handle, "initialize", {
            "processId": 12345,
            "clientInfo": {"name": "vscode", "version": "1.95.0"},
            "locale": "en-US",
            "rootPath": "C:/test"
        }, msg_id=1)
        time.sleep(1)
        resp = read_response(handle)
        print(f"  Response: {resp}")
        time.sleep(1)

        # 2. initialized notification
        print("\n[2] initialized")
        send_notification(handle, "initialized", {})
        time.sleep(1)

        # 3. Send a chat message - should trigger remote API call
        print("\n[3] chat/sendMessage")
        send_jsonrpc(handle, "chat/sendMessage", {
            "message": "What is Python?",
            "model": "qwen-coder-plus-latest",
            "stream": False
        }, msg_id=2)
        time.sleep(2)
        resp = read_response(handle)
        print(f"  Response: {resp}")
        time.sleep(1)

        # 4. Try completion
        print("\n[4] completion/complete")
        send_jsonrpc(handle, "completion/complete", {
            "prompt": "def fibonacci(n):\n    ",
            "suffix": "",
            "model": "qwen-coder-plus-latest"
        }, msg_id=3)
        time.sleep(2)
        resp = read_response(handle)
        print(f"  Response: {resp}")
        time.sleep(1)

        # 5. Try algo endpoint directly
        print("\n[5] algo/model/info")
        send_jsonrpc(handle, "algo/model/info", {}, msg_id=4)
        time.sleep(2)
        resp = read_response(handle)
        print(f"  Response: {resp}")
        time.sleep(1)

        # 6. Try workspace/symbol (might trigger search API)
        print("\n[6] workspace/symbol")
        send_jsonrpc(handle, "workspace/symbol", {
            "query": "authentication"
        }, msg_id=5)
        time.sleep(2)
        resp = read_response(handle)
        print(f"  Response: {resp}")

        # Wait for any delayed traffic (chat responses take time)
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
