"""
Frida v4: Load JS from separate file, use Interceptor.replace
"""
import frida
import time
import subprocess
import json
import win32file
import win32event
import pywintypes
import os

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def load_js():
    with open(os.path.join(SCRIPT_DIR, 'hook_getappsalt.js'), 'r', encoding='utf-8') as f:
        return f.read()

def send_rpc(handle, method, params=None, msg_id=None):
    body = {"jsonrpc": "2.0", "method": method}
    if params:
        body["params"] = params
    if msg_id is not None:
        body["id"] = msg_id
    content = json.dumps(body)
    header = "Content-Length: {}\r\n\r\n".format(len(content))
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

    # Kill existing
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
    print("PID: {}".format(pid))

    print("Loading hook script from file...")
    hook_script = load_js()
    print("Script size: {} bytes".format(len(hook_script)))

    print("Installing hooks...")
    session = device.attach(pid)
    script = session.create_script(hook_script)

    call_count = [0]
    def on_message(msg, data):
        payload = msg.get('payload', msg)
        if isinstance(payload, dict):
            msg_type = payload.get('type', '')
            if msg_type == 'log':
                print("[FRIDA] {}".format(payload.get('msg', '')))
                if 'ENTER' in payload.get('msg', '') or 'SALT' in payload.get('msg', ''):
                    call_count[0] += 1
            elif msg_type == 'error':
                print("[FRIDA ERROR] {}".format(payload.get('msg', '')))
        else:
            print("[FRIDA] {}".format(payload))

    script.on('message', on_message)
    script.load()
    time.sleep(3)

    # Try RPC
    info_path = 'C:/Users/Zipper/.lingma/.info.json'
    try:
        with open(info_path, 'r') as f:
            info = json.load(f)
        pipe_path = info.get('ipcServerPath')
        print("Pipe: {}".format(pipe_path))

        handle = win32file.CreateFile(
            pipe_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING,
            win32file.FILE_FLAG_OVERLAPPED, None
        )
        print("Connected!")

        # Initialize
        print("\nSending initialize...")
        send_rpc(handle, "initialize", {
            "processId": 12345,
            "clientInfo": {"name": "vscode", "version": "1.95.0"},
            "locale": "en-US", "rootPath": "C:/test"
        }, 1)
        time.sleep(2)
        resp = read_resp(handle)
        if resp:
            print("  Response: {}".format(resp[:200]))

        # Completion
        print("Sending textDocument/completion...")
        send_rpc(handle, "textDocument/completion", {
            "textDocument": {"uri": "file:///C:/test/hello.py"},
            "position": {"line": 0, "character": 0}
        }, 2)
        time.sleep(5)
        resp = read_resp(handle, 5000)
        if resp:
            print("  Response: {}".format(resp[:200]))

        # Chat
        print("Sending chat/ask...")
        send_rpc(handle, "chat/ask", {
            "sessionId": "t1", "chatId": "c1",
            "message": "hello", "stream": False
        }, 3)
        time.sleep(10)
        resp = read_resp(handle, 10000)
        if resp:
            print("  Response: {}".format(resp[:200]))

        print("\nWaiting 30s for getAppSalt calls...")
        print("Calls captured so far: {}".format(call_count[0]))
        for i in range(30):
            time.sleep(1)
            if i % 10 == 0:
                print("  {}s elapsed, calls: {}".format(i, call_count[0]))

        # Get captured results
        try:
            results = script.exports_sync.get_captured()
            print("\nCaptured results: {}".format(results))
        except Exception as e:
            print("Error getting captured: {}".format(e))

        win32file.CloseHandle(handle)
    except Exception as e:
        import traceback
        print("Pipe error: {}".format(e))
        traceback.print_exc()

    print("--- Done ---")
    script.unload()
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
