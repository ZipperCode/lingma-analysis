"""Trigger signing by sending LSP requests that require authentication/signing."""
import json, time, win32file, pywintypes, win32event, os

def send_rpc(handle, method, params=None, msg_id=None):
    body = {"jsonrpc": "2.0", "method": method}
    if params: body["params"] = params
    if msg_id is not None: body["id"] = msg_id
    content = json.dumps(body)
    header = "Content-Length: {}\r\n\r\n".format(len(content))
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
            return body[:1000]
    return None

def main():
    # Find pipe
    info_path = 'C:/Users/Zipper/.lingma/.info.json'
    if not os.path.exists(info_path):
        print("No .info.json found")
        return

    with open(info_path, 'r') as f:
        info = json.load(f)
    pipe_path = info.get('ipcServerPath')
    if not pipe_path:
        print("No pipe path found")
        return

    print(f"Connecting to {pipe_path}")

    handle = win32file.CreateFile(
        pipe_path,
        win32file.GENERIC_READ | win32file.GENERIC_WRITE,
        0, None, win32file.OPEN_EXISTING,
        win32file.FILE_FLAG_OVERLAPPED, None
    )
    print("Connected!")

    # 1. Initialize
    print("\n1. Sending initialize...")
    send_rpc(handle, "initialize", {
        "processId": os.getpid(),
        "clientInfo": {"name": "vscode", "version": "1.95.0"},
        "locale": "en-US",
        "rootPath": "C:/test",
        "rootUri": "file:///C:/test",
        "capabilities": {}
    }, 1)
    time.sleep(3)
    resp = read_resp(handle, 5000)
    print(f"  Response: {resp[:200] if resp else 'None'}")

    # 2. Send initialized notification
    print("\n2. Sending initialized notification...")
    send_rpc(handle, "initialized", {})
    time.sleep(1)

    # 3. Try textDocument/completion (might trigger signing if configured)
    print("\n3. Sending textDocument/completion...")
    send_rpc(handle, "textDocument/completion", {
        "textDocument": {"uri": "file:///C:/test/hello.py"},
        "position": {"line": 0, "character": 0}
    }, 2)
    time.sleep(5)
    resp = read_resp(handle, 5000)
    print(f"  Response: {resp[:200] if resp else 'None'}")

    # 4. Try inline completion (Lingma-specific, might trigger signing)
    print("\n4. Sending lingma/inlineCompletion...")
    send_rpc(handle, "lingma/inlineCompletion", {
        "textDocument": {"uri": "file:///C:/test/hello.py"},
        "position": {"line": 0, "character": 0},
        "context": {"triggerKind": 1}
    }, 3)
    time.sleep(5)
    resp = read_resp(handle, 5000)
    print(f"  Response: {resp[:200] if resp else 'None'}")

    # 5. Try workspace/executeCommand with a signing-related command
    print("\n5. Trying to trigger remote API calls...")
    # Lingma might have commands that trigger /algo/* API calls
    send_rpc(handle, "workspace/executeCommand", {
        "command": "lingma.checkLoginStatus"
    }, 4)
    time.sleep(3)
    resp = read_resp(handle, 5000)
    print(f"  Response: {resp[:200] if resp else 'None'}")

    # 6. Check if there's a login-related method
    print("\n6. Checking login status...")
    send_rpc(handle, "lingma/auth/status", {}, 5)
    time.sleep(2)
    resp = read_resp(handle, 5000)
    print(f"  Response: {resp[:200] if resp else 'None'}")

    # 7. Try various Lingma-specific methods
    for method in ["lingma/getConfig", "lingma/getEndpoint", "$/cancelRequest"]:
        print(f"\n7. Trying {method}...")
        send_rpc(handle, method, {}, 100)
        time.sleep(2)
        resp = read_resp(handle, 3000)
        print(f"  Response: {resp[:150] if resp else 'None'}")

    win32file.CloseHandle(handle)
    print("\nDone!")

if __name__ == '__main__':
    main()
