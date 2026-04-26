"""
调试: 确认 hook 是否真的被触发
先测试 hook 是否工作，再等待网络活动
"""
import frida
import time
import subprocess
import urllib.request

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

# Test hook on our own HTTP request
HOOK_SCRIPT = r"""
// Hook send
var ws2 = Process.getModuleByName('ws2_32.dll');
var exports = ws2.enumerateExports();

var sendExp = exports.filter(function(e) { return e.name === 'send'; });
if (sendExp.length > 0) {
    console.log('[Hook] send at ' + sendExp[0].address);
    Interceptor.attach(sendExp[0].address, {
        onEnter: function(args) {
            var len = args[2].toInt32();
            console.log('[send] len=' + len);
            if (len > 0 && len < 10000) {
                try {
                    var data = args[1].readUtf8String(Math.min(len, 5000));
                    console.log('  ' + data.substring(0, 1000));
                } catch(e) {
                    console.log('  read error: ' + e.message);
                }
            }
        }
    });
    console.log('[Hook] send installed');
}

// Hook WSASend
var wsasendExp = exports.filter(function(e) { return e.name === 'WSASend'; });
if (wsasendExp.length > 0) {
    console.log('[Hook] WSASend at ' + wsasendExp[0].address);
    Interceptor.attach(wsasendExp[0].address, {
        onEnter: function(args) {
            console.log('[WSASend] called');
        }
    });
    console.log('[Hook] WSASend installed');
}

// Hook WriteFile (for named pipes and possibly sockets)
var kernel32 = Process.getModuleByName('kernel32.dll');
var kernelExports = kernel32.enumerateExports();
var writeFileExp = kernelExports.filter(function(e) { return e.name === 'WriteFile'; });
if (writeFileExp.length > 0) {
    console.log('[Hook] WriteFile at ' + writeFileExp[0].address);
    Interceptor.attach(writeFileExp[0].address, {
        onEnter: function(args) {
            console.log('[WriteFile] called');
        }
    });
    console.log('[Hook] WriteFile installed');
}

console.log('[Hook] Done');
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
    time.sleep(8)

    processes = device.enumerate_processes()
    lingma_procs = [p for p in processes if 'lingma' in p.name.lower()]
    if not lingma_procs:
        print("Not found!")
        proc.kill()
        return

    pid = lingma_procs[0].pid
    print(f"PID: {pid}")

    session = device.attach(pid)
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()

    # Make an HTTP request FROM WITHIN the process
    # We'll use curl to send a request to the Lingma HTTP server
    # This should trigger socket send/recv within Lingma

    print("\nMaking HTTP request to Lingma...")
    try:
        req = urllib.request.Request('http://127.0.0.1:37510/')
        resp = urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"HTTP request: {e}")

    # Wait
    print("Waiting 5s...")
    time.sleep(5)

    print("--- Done ---")
    try:
        script.unload()
    except:
        pass
    session.detach()
    proc.kill()

if __name__ == '__main__':
    main()
