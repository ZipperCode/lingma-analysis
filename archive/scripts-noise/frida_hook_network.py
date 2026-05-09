"""
Frida Hook: 通过 hook send() 捕获网络流量
"""
import frida
import time
import subprocess

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

HOOK_SCRIPT = r"""
var ws2 = Process.getModuleByName('ws2_32.dll');
var exports = ws2.enumerateExports();

// Find send
var sendExp = exports.filter(function(e) { return e.name === 'send'; });
if (sendExp.length > 0) {
    var sendAddr = sendExp[0].address;
    console.log('[Hook] send at ' + sendAddr);

    Interceptor.attach(sendAddr, {
        onEnter: function(args) {
            var socket = args[0].toInt32();
            var len = args[2].toInt32();
            var buf = args[1];

            if (len > 0 && len < 100000) {
                try {
                    var data = buf.readUtf8String(Math.min(len, 5000));
                    if (data.indexOf('POST') >= 0 || data.indexOf('Signature') >= 0 ||
                        data.indexOf('Timestamp') >= 0 || data.indexOf('algo') >= 0 ||
                        data.indexOf('HTTP') >= 0) {
                        console.log('[send] socket=' + socket + ' len=' + len);
                        console.log('  ' + data.substring(0, 5000));
                    }
                } catch(e) {}
            }
        }
    });
    console.log('[Hook] send hook installed');
}

// Hook connect
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
                    var ip = addr.add(4).readU8() + '.' +
                            addr.add(5).readU8() + '.' +
                            addr.add(6).readU8() + '.' +
                            addr.add(7).readU8();
                    console.log('[connect] ' + ip + ':' + port);
                }
            } catch(e) {}
        }
    });
    console.log('[Hook] connect hook installed');
}

console.log('[Hook] Setup complete');
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

    print("Waiting 30s for network activity...")
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
