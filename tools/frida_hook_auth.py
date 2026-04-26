"""
Hook Go 标准库的 TLS 和 HTTP 函数，在加密前捕获明文数据
方法: 扫描 .text 段寻找 Go 函数特征模式
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

# Hook Go TLS write function to capture plaintext before encryption
HOOK_SCRIPT = r"""
var base = Module.getBaseAddress();

// We know from analysis:
// - trimQueryPath is at offset 0x882c80 from base
// - getAuthSignature is at 0x890140
// - getAuthPayload is at 0x890380
// - getAppSalt is nearby

// Let's hook the known auth functions
var offsets = [
    0x882c80,  // trimQueryPath (verified)
    0x890140,  // getAuthSignature
    0x890380,  // getAuthPayload
    0x882ba0,  // func before trimQueryPath
    0x882e40,  // func after trimQueryPath
];

offsets.forEach(function(offset) {
    try {
        var addr = base.add(offset);
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.entry = offset;
                // Read Go string from RAX/RCX (return value area)
                console.log('[func] entering 0x' + offset.toString(16));
            },
            onLeave: function(retval) {
                console.log('[func] leaving 0x' + this.entry.toString(16) + ' retval=' + retval);
            }
        });
        console.log('[Hook] 0x' + offset.toString(16) + ' OK');
    } catch(e) {
        console.log('[Hook] 0x' + offset.toString(16) + ' FAILED: ' + e.message);
    }
});

// Also try to find crypto/tls functions by scanning
// Go's (*Conn).Write has pattern: writes to internal buffer then encrypts
// Look for the string "TLS" or "encrypt" or "WriteRecord" near code

// Hook common Go runtime functions that deal with HTTP
// net/http.(*Client).do
// net/http.(*Request).Write
// crypto/tls.(*Conn).writeRecordLocked

console.log('[Hook] Auth functions setup complete');
console.log('[Hook] Waiting for calls...');
"""

def on_message(msg, data):
    payload = msg.get('payload', '')
    if payload:
        print(f"[MSG] {payload}")

def send_rpc(handle, method, params=None, msg_id=None):
    body = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        body["params"] = params
    if msg_id is not None:
        body["id"] = msg_id
    content = json.dumps(body)
    header = f"Content-Length: {len(content)}\r\n\r\n"
    full_msg = header + content
    win32file.WriteFile(handle, full_msg.encode('utf-8'))
    print(f"  Sent: {method}")

def read_response(handle, timeout_ms=3000):
    overlapped = pywintypes.OVERLAPPED()
    overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
    try:
        err, data = win32file.ReadFile(handle, 65536, overlapped)
        if err == 997:
            result = win32event.WaitForSingleObject(overlapped.hEvent, timeout_ms)
            if result != win32event.WAIT_OBJECT_0:
                return None
            data = bytes(overlapped.GetOverlappedResult())
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
    if '\r\n\r\n' in text:
        _, body = text.split('\r\n\r\n', 1)
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

    # Attach Frida and install hooks FIRST
    print("Attaching Frida...")
    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()

    # Wait a bit for hooks to be ready
    time.sleep(2)

    # Now connect via pipe and trigger traffic
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

        # Initialize
        print("\n[1] initialize")
        send_rpc(handle, "initialize", {
            "processId": 12345,
            "clientInfo": {"name": "vscode", "version": "1.95.0"},
            "locale": "en-US",
            "rootPath": "C:/test"
        }, msg_id=1)
        time.sleep(1)
        read_response(handle)

        # Chat/ask with proper params
        print("\n[2] chat/ask")
        send_rpc(handle, "chat/ask", {
            "sessionId": "test-1",
            "chatId": "chat-1",
            "message": "test",
            "stream": False,
            "chatContext": {
                "languageId": "python",
                "fileContent": "print('hello')"
            }
        }, msg_id=2)
        time.sleep(3)
        read_response(handle, timeout_ms=10000)

        # Wait for any auth/heartbeat calls
        print("\nWaiting 30s...")
        for i in range(30):
            if i % 5 == 0:
                print(f"  {i}s")
            time.sleep(1)

        win32file.CloseHandle(handle)
    except Exception as e:
        print(f"Pipe error: {e}")

    print("--- Done ---")
    try:
        script.unload()
    except:
        pass
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
