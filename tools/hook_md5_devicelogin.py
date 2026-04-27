#!/usr/bin/env python3
"""
Frida hook Md5Encode + WebSocket device_login trigger.
Forces Lingma to call /user/login (old Signature flow) and captures Md5Encode inputs.

Strategy:
1. Wipe cosy_key from config
2. Spawn Lingma with --socketPort
3. Hook Md5Encode
4. Send device_login via WebSocket
5. Lingma calls /user/login → triggers Md5Encode
6. Capture exact preimage!
"""
import frida
import sys
import time
import json
import asyncio
import websocket

LINGMA_BIN = r"C:\Users\Zipper\.lingma\bin\2.11.2\x86_64_windows\Lingma.exe"
CFG_PATH = r"C:/Users/Zipper/.lingma/portable_config.json"

SCRIPT = r"""
function readGoStr(addr, len) {
    if (addr.isNull() || len === 0 || len > 4096) return '';
    try {
        return addr.readUtf8String(Math.min(len, 512));
    } catch (e) {
        return '<err:' + e + '>';
    }
}

function hookMd5Encode() {
    var mod = null;
    var attempts = 0;
    while (!mod && attempts < 300) {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            if (mods[i].name.toLowerCase().indexOf('lingma') !== -1) {
                mod = mods[i];
                break;
            }
        }
        if (!mod) Thread.sleep(0.1);
        attempts++;
    }

    if (!mod) {
        send(JSON.stringify({type: 'error', msg: 'Lingma module not found after ' + attempts + ' attempts'}));
        return;
    }

    var base = mod.base;
    send(JSON.stringify({type: 'info', msg: 'Lingma base: ' + base}));

    var addr = base.add(0x4563c0);
    send(JSON.stringify({type: 'info', msg: 'Hooking Md5Encode at ' + addr}));

    Interceptor.attach(addr, {
        onEnter: function(args) {
            var arrPtr = this.context.rax;
            var count = this.context.rbx.toInt32();
            if (count <= 0 || count > 100) return;

            var parts = [];
            for (var i = 0; i < count; i++) {
                var ptr = arrPtr.add(i * 16).readPointer();
                var len = arrPtr.add(i * 16 + 8).readU64().toNumber();
                var s = readGoStr(ptr, Math.min(len, 512));
                parts.push(s);
            }

            var preimage = parts.join('');
            send(JSON.stringify({
                type: 'md5encode',
                count: count,
                parts: parts,
                preimage: preimage,
                preimageLen: preimage.length,
            }));

            this.parts = parts;
        },
        onLeave: function(retval) {
            if (!this.parts) return;
            var ptr = retval;
            var len = this.context.rbx.toInt32();
            var output = readGoStr(ptr, Math.min(len, 64));
            send(JSON.stringify({
                type: 'md5encode_output',
                output: output,
                outputLen: len,
            }));
        }
    });

    send(JSON.stringify({type: 'info', msg: 'Md5Encode hook installed'}));
}

// Also hook the POST /user/login call to capture request details
function hookHttpSend() {
    var mod = null;
    var attempts = 0;
    while (!mod && attempts < 300) {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            if (mods[i].name.toLowerCase().indexOf('lingma') !== -1) {
                mod = mods[i];
                break;
            }
        }
        if (!mod) Thread.sleep(0.1);
        attempts++;
    }
    if (!mod) return;

    // Hook WinHttpSendRequest to see the actual HTTP headers
    var winhttp = Module.findExportByName('winhttp.dll', 'WinHttpSendRequest');
    if (winhttp) {
        Interceptor.attach(winhttp, {
            onEnter: function(args) {
                var headers = args[2].isNull() ? '' : args[2].readUtf8String();
                if (headers && headers.indexOf('Signature') !== -1) {
                    send(JSON.stringify({
                        type: 'http_headers',
                        headers: headers,
                    }));
                }
            }
        });
        send(JSON.stringify({type: 'info', msg: 'WinHttpSendRequest hook installed'}));
    }
}

hookMd5Encode();
hookHttpSend();
"""

def main():
    # 1. Backup and modify config
    with open(CFG_PATH, 'r') as f:
        config = json.load(f)

    # Save backup
    with open(CFG_PATH + '.bak', 'w') as f:
        json.dump(config, f)

    # Remove cosy_key and encrypt_user_info to force /user/login
    config.pop('cosy_key', None)
    config.pop('encrypt_user_info', None)
    # But KEEP security_oauth_token for device_login

    with open(CFG_PATH, 'w') as f:
        json.dump(config, f)
    print('[*] Config: wiped cosy_key/encrypt_user_info, kept security_oauth_token')

    # 2. Kill any existing Lingma processes
    device = frida.get_local_device()
    for proc in device.enumerate_processes():
        if 'Lingma' in proc.name or 'lingma' in proc.name.lower():
            try:
                device.kill(proc.pid)
                print(f'[*] Killed Lingma PID {proc.pid}')
            except:
                pass
    time.sleep(1)

    # 3. Spawn Lingma with start command
    import tempfile, os
    workdir = os.path.join(tempfile.gettempdir(), 'lingma-frida-' + str(int(time.time())))
    os.makedirs(workdir, exist_ok=True)

    cmd = [LINGMA_BIN, 'start', f'--workDir={workdir}', '--socketPort=37099', '--httpPort=37599']
    print(f'[*] Spawning: {cmd}')
    pid = device.spawn(cmd)
    print(f'[*] Spawned PID {pid}')

    session = device.attach(pid)
    script = session.create_script(SCRIPT)

    captured = []

    def on_message(message, data):
        if message['type'] == 'send':
            payload = message['payload']
            try:
                obj = json.loads(payload)
                msg_type = obj.get('type', '')
                if msg_type == 'md5encode':
                    print('\n========== [Md5Encode CAPTURED] ==========')
                    print(f"Count: {obj['count']}")
                    for i, p in enumerate(obj['parts']):
                        print(f"  Part[{i}] (len={len(p)}): {repr(p[:200])}")
                    print(f"  PREIMAGE ({obj['preimageLen']} chars): {repr(obj['preimage'][:300])}")
                    captured.append(obj)
                elif msg_type == 'md5encode_output':
                    print(f"  MD5 OUTPUT: {obj['output']} (len={obj['outputLen']})")
                    print('==========================================')
                elif msg_type == 'http_headers':
                    print(f'\n[HTTP Headers with Signature]\n{obj["headers"]}')
                elif msg_type == 'info':
                    print(f'[*] {obj["msg"]}')
                elif msg_type == 'error':
                    print(f'[!] {obj["msg"]}')
                else:
                    print(f'[MSG] {payload[:200]}')
            except:
                print(f'[MSG] {payload[:200]}')
        elif message['type'] == 'error':
            print(f'[ERR] {message.get("description", message)}')

    script.on('message', on_message)
    script.load()
    device.resume(pid)
    print('[*] Lingma resumed. Waiting for it to become ready...')

    # 4. Wait for WebSocket to become available
    ws_ready = False
    for i in range(60):
        time.sleep(1)
        try:
            ws = websocket.create_connection('ws://127.0.0.1:37099', timeout=2)
            ws.close()
            ws_ready = True
            print(f'[*] WebSocket ready after {i+1}s')
            break
        except:
            if i % 5 == 0:
                print(f'[*] Waiting for WebSocket... ({i+1}s)')

    if not ws_ready:
        print('[!] WebSocket never became ready')
        session.detach()
        return

    time.sleep(2)

    # 5. Send device_login via WebSocket
    print('[*] Sending device_login...')
    ws = websocket.create_connection('ws://127.0.0.1:37099')

    # Send initialize first
    init_msg = {
        'jsonrpc': '2.0',
        'id': 1,
        'method': 'initialize',
        'params': {
            'processId': None,
            'clientInfo': {'name': 'frida-oracle', 'version': '1.0'},
            'rootUri': 'file:///tmp/frida',
            'capabilities': {},
            'workspaceFolders': [{'uri': 'file:///tmp/frida', 'name': 'frida'}],
        },
    }
    init_data = json.dumps(init_msg)
    frame = f'Content-Length: {len(init_data)}\r\n\r\n{init_data}'
    ws.send(frame)
    time.sleep(1)

    # Read initialize response
    try:
        ws.settimeout(2)
        resp = ws.recv()
        print(f'[*] Init response: {resp[:200]}')
    except:
        print('[*] No init response (may be OK)')

    # Send device_login
    config = json.load(open(CFG_PATH, 'r'))
    login_msg = {
        'jsonrpc': '2.0',
        'id': 4,
        'method': 'auth/device_login',
        'params': {
            'token': config.get('security_oauth_token', ''),
            'refreshToken': config.get('refresh_token', ''),
            'expiresIn': '',
            'expireTime': str(config.get('expire_time', '0')),
            'userId': config.get('user_id', ''),
            'username': config.get('user_name', ''),
        },
    }
    login_data = json.dumps(login_msg)
    frame = f'Content-Length: {len(login_data)}\r\n\r\n{login_data}'
    ws.send(frame)
    print('[*] device_login sent, waiting for Md5Encode captures...')

    # 6. Wait for captures
    for i in range(30):
        time.sleep(2)
        try:
            ws.settimeout(1)
            resp = ws.recv()
            if '"result"' in resp or '"error"' in resp:
                print(f'[*] device_login response: {resp[:300]}')
        except:
            pass
        if captured:
            print(f'\n[!!!] CAPTURED {len(captured)} Md5Encode calls!')

    ws.close()

    # 7. Wait a bit more for late captures
    print('[*] Waiting 10s for late captures...')
    time.sleep(10)

    if captured:
        print('\n' + '=' * 60)
        print('ALL Md5Encode CAPTURES:')
        print('=' * 60)
        for i, cap in enumerate(captured):
            print(f'\nCapture #{i+1}:')
            print(f"  Parts: {cap['parts']}")
            print(f"  Full preimage: {repr(cap['preimage'])}")
    else:
        print('\n[!] No Md5Encode calls captured. The device_login flow may not use old Signature.')
        print('[!] Lingma might be using a cached cosy_key from another source.')

    session.detach()

    # 8. Restore config
    import shutil
    shutil.copy(CFG_PATH + '.bak', CFG_PATH)
    print('[*] Config restored')

if __name__ == '__main__':
    main()
