#!/usr/bin/env python3
"""
Two-phase approach:
Phase 1: Start Lingma normally, wait for WebSocket to be ready
Phase 2: Attach Frida, hook Md5Encode, then send device_login via WebSocket

This avoids Frida interfering with Lingma startup.
"""
import frida
import sys
import time
import json
import os
import subprocess
import websocket

LINGMA_EXE = r"C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe"
WORKDIR = os.path.join(os.environ.get("TEMP", "C:/temp"), "lingma-twophase")
SOCKET_PORT = 37099
HTTP_PORT = 37599

FRIDA_SCRIPT = r"""
'use strict';

var MD5ENCODE_RVA = ptr(0x4563c0);

function readGoStr(addr, len) {
    if (addr.isNull() || len === 0 || len > 4096) return '';
    try { return addr.readUtf8String(Math.min(len, 1024)); }
    catch (e) { return '<err>'; }
}

var lingmaMod = null;
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase().indexOf('lingma') !== -1) {
        lingmaMod = mods[i];
        break;
    }
}

if (!lingmaMod) {
    send(JSON.stringify({type: 'error', msg: 'Lingma module not found'}));
} else {
    var base = lingmaMod.base;
    send(JSON.stringify({type: 'info', msg: 'Base: ' + base}));

    // Read .data runtime values
    var COSY_PTR_RVA = ptr(0x5fa7cc0);
    var COSY_LEN_RVA = ptr(0x5fa7cc8);
    try {
        var cosyPtr = base.add(COSY_PTR_RVA).readPointer();
        var cosyLen = base.add(COSY_LEN_RVA).readU64();
        send(JSON.stringify({
            type: 'runtime',
            cosy_ptr: cosyPtr.toString(),
            cosy_len: cosyLen.toNumber(),
            cosy_str: readGoStr(cosyPtr, cosyLen.toNumber()),
        }));
    } catch (e) {
        send(JSON.stringify({type: 'error', msg: 'Read .data: ' + e}));
    }

    // Hook Md5Encode
    Interceptor.attach(base.add(MD5ENCODE_RVA), {
        onEnter: function(args) {
            var arrPtr = this.context.rax;
            var count = this.context.rbx.toInt32();
            if (count <= 0 || count > 100) return;

            var parts = [];
            for (var i = 0; i < count; i++) {
                var ptr = arrPtr.add(i * 16).readPointer();
                var len = arrPtr.add(i * 16 + 8).readU64().toNumber();
                parts.push(readGoStr(ptr, Math.min(len, 1024)));
            }

            var preimage = parts.join('');
            send(JSON.stringify({
                type: 'md5encode',
                count: count,
                parts: parts,
                preimage: preimage,
                preimageLen: preimage.length,
                ts: new Date().toISOString(),
            }));
            this.parts = parts;
        },
        onLeave: function(retval) {
            if (!this.parts) return;
            var ptr = this.context.rax;
            var len = this.context.rbx.toInt32();
            send(JSON.stringify({
                type: 'md5encode_output',
                output: readGoStr(ptr, Math.min(len, 64)),
                outputLen: len,
            }));
        }
    });
    send(JSON.stringify({type: 'info', msg: 'Md5Encode hooked. Ready for device_login.'}));
}
"""

captured = []

def on_message(message, data):
    if message['type'] == 'send':
        try:
            obj = json.loads(message['payload'])
            t = obj.get('type', '')
            if t == 'runtime':
                print(f'\n*** RUNTIME: cosy_str={repr(obj["cosy_str"])} len={obj["cosy_len"]}')
            elif t == 'md5encode':
                print(f'\n{"="*60}')
                print(f'*** Md5Encode CAPTURED! count={obj["count"]}')
                for i, p in enumerate(obj['parts']):
                    print(f'    Part[{i}] (len={len(p)}): {repr(p)}')
                print(f'    FULL PREIMAGE: {repr(obj["preimage"])}')
                print(f'{"="*60}')
                captured.append(obj)
            elif t == 'md5encode_output':
                print(f'    MD5 OUTPUT: {obj["output"]}')
            elif t == 'info':
                print(f'  [*] {obj["msg"]}')
            elif t == 'error':
                print(f'  [!] {obj["msg"]}')
        except Exception as e:
            print(f'  [raw] {message["payload"][:300]}')
    elif message['type'] == 'error':
        print(f'  [FERR] {message.get("description", message)}')

def main():
    os.makedirs(WORKDIR, exist_ok=True)

    # Kill any existing Lingma
    print('[*] Phase 0: Killing existing Lingma...')
    device = frida.get_local_device()
    for proc in device.enumerate_processes():
        if 'Lingma' in proc.name or 'lingma' in proc.name.lower():
            try:
                device.kill(proc.pid)
                print(f'  Killed PID {proc.pid}')
            except:
                pass
    time.sleep(2)

    # Phase 1: Start Lingma normally
    print(f'[*] Phase 1: Starting Lingma...')
    lingma_proc = subprocess.Popen(
        [LINGMA_EXE, 'start',
         f'--workDir={WORKDIR}',
         f'--socketPort={SOCKET_PORT}',
         f'--httpPort={HTTP_PORT}'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f'[*] Lingma PID: {lingma_proc.pid}')

    # Wait for WebSocket to be ready
    print(f'[*] Waiting for WebSocket on port {SOCKET_PORT}...')
    ws_ready = False
    for i in range(60):
        time.sleep(1)
        if lingma_proc.poll() is not None:
            print(f'[!] Lingma exited with code {lingma_proc.returncode}')
            return
        try:
            ws = websocket.create_connection(f'ws://127.0.0.1:{SOCKET_PORT}', timeout=2)
            ws.close()
            ws_ready = True
            print(f'[*] WebSocket ready after {i+1}s')
            break
        except:
            if i % 10 == 0:
                print(f'  Still waiting... ({i+1}s)')

    if not ws_ready:
        print('[!] WebSocket never became ready')
        lingma_proc.terminate()
        return

    # Phase 2: Attach Frida
    print('[*] Phase 2: Attaching Frida...')
    try:
        session = device.attach(lingma_proc.pid)
    except Exception as e:
        print(f'[!] Attach failed: {e}')
        lingma_proc.terminate()
        return

    script = session.create_script(FRIDA_SCRIPT)
    script.on('message', on_message)
    script.load()
    print('[*] Frida attached and hooks installed.')
    time.sleep(1)

    # Phase 3: Send device_login via WebSocket
    print('[*] Phase 3: Sending device_login...')
    ws = websocket.create_connection(f'ws://127.0.0.1:{SOCKET_PORT}')

    # Read config for params
    cfg = json.load(open(r'C:/Users/Zipper/.lingma/portable_config.json'))

    # Initialize
    init_msg = {
        'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
        'params': {
            'processId': None,
            'clientInfo': {'name': 'frida-twophase', 'version': '1.0'},
            'rootUri': 'file:///tmp/frida',
            'capabilities': {},
            'workspaceFolders': [{'uri': 'file:///tmp/frida', 'name': 'frida'}],
        },
    }
    init_data = json.dumps(init_msg)
    ws.send(f'Content-Length: {len(init_data)}\r\n\r\n{init_data}')
    print('[*] Initialize sent')
    time.sleep(1)

    try:
        ws.settimeout(2)
        resp = ws.recv()
        print(f'[*] Init response: {resp[:200]}')
    except:
        print('[*] No init response (OK)')

    # Send device_login
    login_msg = {
        'jsonrpc': '2.0', 'id': 4, 'method': 'auth/device_login',
        'params': {
            'token': cfg.get('security_oauth_token', ''),
            'refreshToken': cfg.get('refresh_token', ''),
            'expiresIn': '',
            'expireTime': str(cfg.get('expire_time', '0')),
            'userId': cfg.get('user_id', ''),
            'username': cfg.get('user_name', ''),
        },
    }
    login_data = json.dumps(login_msg)
    ws.send(f'Content-Length: {len(login_data)}\r\n\r\n{login_data}')
    print('[*] device_login sent! Waiting for Md5Encode...')

    # Wait for captures
    for i in range(30):
        time.sleep(2)
        try:
            ws.settimeout(1)
            resp = ws.recv()
            if '"result"' in resp or '"error"' in resp:
                print(f'[*] device_login response: {resp[:500]}')
        except:
            pass
        if captured:
            print(f'\n[!!!] SUCCESS: {len(captured)} Md5Encode calls captured!')
            break

    ws.close()

    # Wait more for any late captures
    if not captured:
        print('[*] Waiting 10s more for late captures...')
        time.sleep(10)

    # Results
    if captured:
        print('\n' + '=' * 60)
        print('RESULTS:')
        for i, cap in enumerate(captured):
            print(f'\nCapture #{i+1}:')
            print(f'  Parts: {cap["parts"]}')
            print(f'  Preimage: {repr(cap["preimage"])}')
            # Verify against known oracle
            import hashlib
            md5 = hashlib.md5(cap['preimage'].encode()).hexdigest()
            print(f'  MD5: {md5}')
            # Check if it matches any oracle
            from tools.exhaustive_oracle_test import ORACLES
            for oracle_date, oracle_sig in ORACLES:
                if md5 == oracle_sig:
                    print(f'  *** MATCHES ORACLE: {oracle_date}')
    else:
        print('\n[!] No Md5Encode calls captured.')

    # Cleanup
    print('[*] Cleaning up...')
    session.detach()
    try:
        lingma_proc.terminate()
        time.sleep(2)
        if lingma_proc.poll() is None:
            lingma_proc.kill()
    except:
        pass

    # Restore config
    bak = r'C:/Users/Zipper/.lingma/portable_config.json.bak3'
    if os.path.exists(bak):
        import shutil
        shutil.copy(bak, r'C:/Users/Zipper/.lingma/portable_config.json')
        print('[*] Config restored')

    print('[*] Done')

if __name__ == '__main__':
    main()
