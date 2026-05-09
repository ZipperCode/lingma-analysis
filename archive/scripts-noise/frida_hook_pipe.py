"""
通过命名管道连接 Lingma + WSASend hook
命名管道是 VS Code 扩展的实际通信方式
"""
import frida
import time
import subprocess
import json
import win32file
import win32event
import pywintypes

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
                        var data = ptr.readUtf8String(Math.min(len, 20000));
                        if (data.indexOf('POST') >= 0 || data.indexOf('Signature') >= 0 ||
                            data.indexOf('algo') >= 0 || data.indexOf('heartbeat') >= 0 ||
                            data.indexOf('dashscope') >= 0 || data.indexOf('Authorization') >= 0 ||
                            data.indexOf('Timestamp') >= 0 || data.indexOf('sign') >= 0) {
                            console.log('[WSASend] len=' + len);
                            console.log('  ' + data.substring(0, 20000));
                        }
                    } catch(e) {}
                }
            }
        }
    });
    console.log('[Hook] WSASend OK');
}

console.log('[Hook] Ready');
"""

def on_message(msg, data):
    payload = msg.get('payload', '')
    if payload:
        print(f"[MSG] {payload}")

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

    # Attach Frida
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
            0, None, win32file.OPEN_EXISTING, 0, None
        )
        print("Connected to pipe!")

        # Send initialize request
        init_msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "processId": 12345,
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
                "locale": "en-US",
                "rootPath": "C:/test",
            },
            "id": 1
        }) + "\n"

        win32file.WriteFile(handle, init_msg.encode('utf-8'))
        print(f"Sent initialize")

        # Read response
        _, data = win32file.ReadFile(handle, 65536)
        print(f"Response: {data.decode('utf-8', errors='replace')[:500]}")

        time.sleep(1)

        # Send ping
        ping_msg = json.dumps({"jsonrpc": "2.0", "method": "ping", "params": {}}) + "\n"
        win32file.WriteFile(handle, ping_msg.encode('utf-8'))
        print("Sent ping")

        try:
            _, data = win32file.ReadFile(handle, 65536)
            print(f"Response: {data.decode('utf-8', errors='replace')[:500]}")
        except:
            print("No response to ping")

        time.sleep(1)

        # Send ide/update - this might trigger heartbeat with signature
        ide_msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "ide/update",
            "params": {"type": "online"},
        }) + "\n"
        win32file.WriteFile(handle, ide_msg.encode('utf-8'))
        print("Sent ide/update")

        try:
            _, data = win32file.ReadFile(handle, 65536)
            print(f"Response: {data.decode('utf-8', errors='replace')[:500]}")
        except:
            pass

        win32file.CloseHandle(handle)
    except Exception as e:
        print(f"Pipe error: {e}")

    # Wait for remote traffic
    print("\nWaiting 30s...")
    time.sleep(30)

    print("--- Done ---")
    try:
        script.unload()
    except:
        pass
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
