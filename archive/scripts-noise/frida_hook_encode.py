"""
Frida hook script: capture encodeRequestBody input/output
Hook encodeRequestBody to capture pre/post encoding data

Usage:
  python3 tools/frida_hook_encode.py
  Then trigger a chat request via 37010 API
"""

import frida
import sys
import json
import time
import threading

JS_HOOK = """
'use strict';

const MODULE_NAME = 'Lingma.exe';

// Offsets from GoReSym (subtract image base 0x140000000)
const OFFSETS = {
    encodeRequestBody: 0x881820,
    shouldEncryptBody: 0x882680,
    addBigModelAuthorizationHeaders: 0x882ba0,
    buildRequest: 0x880da0,
};

let moduleBase = null;

function getModuleBase() {
    if (!moduleBase) {
        const mod = Process.findModuleByName(MODULE_NAME);
        if (mod) moduleBase = mod.base;
    }
    return moduleBase;
}

function hookEncodeRequestBody() {
    const base = getModuleBase();
    if (!base) {
        send({error: 'Module not found: ' + MODULE_NAME});
        return;
    }

    const addr = base.add(OFFSETS.encodeRequestBody);
    send({info: 'Hooking encodeRequestBody at ' + addr});

    Interceptor.attach(addr, {
        onEnter(args) {
            // encodeRequestBody signature (from GoReSym analysis):
            // func encodeRequestBody(method string, url string, body []byte) []byte
            // Go calling convention: args[0]=method.ptr, args[1]=method.len,
            //   args[2]=url.ptr, args[3]=url.len, args[4]=body.ptr, args[5]=body.len
            this.methodPtr = args[0];
            this.methodLen = args[1].toInt32();
            this.urlPtr = args[2];
            this.urlLen = args[3].toInt32();
            this.bodyPtr = args[4];
            this.bodyLen = args[5].toInt32();

            try {
                const method = this.methodPtr.readUtf8String(this.methodLen);
                const url = this.urlPtr.readUtf8String(this.urlLen);
                let bodyHex = '';
                let bodyUtf8 = '';
                if (this.bodyLen > 0 && this.bodyLen < 100000) {
                    const bodyBytes = this.bodyPtr.readByteArray(this.bodyLen);
                    bodyHex = Array.from(new Uint8Array(bodyBytes)).slice(0, 100).map(b => b.toString(16).padStart(2, '0')).join('');
                    bodyUtf8 = new TextDecoder('utf-8', {fatal: false}).decode(bodyBytes);
                }

                send({
                    event: 'encodeRequestBody.enter',
                    method: method,
                    url: url,
                    bodyLen: this.bodyLen,
                    bodyHexPreview: bodyHex,
                    bodyUtf8Preview: bodyUtf8.slice(0, 500),
                });
            } catch(e) {
                send({event: 'encodeRequestBody.enter.error', error: e.message});
            }
        },
        onLeave(retval) {
            // Return value might be the encoded body (Go slice: ptr, len, cap)
            try {
                // Check rax (return value) - Go returns multiple values
                // The encoded body might be in a stack location
                send({
                    event: 'encodeRequestBody.leave',
                    retval: retval.toString(),
                });
            } catch(e) {
                send({event: 'encodeRequestBody.leave.error', error: e.message});
            }
        }
    });
}

function hookShouldEncryptBody() {
    const base = getModuleBase();
    if (!base) return;

    const addr = base.add(OFFSETS.shouldEncryptBody);
    send({info: 'Hooking shouldEncryptBody at ' + addr});

    Interceptor.attach(addr, {
        onEnter(args) {
            try {
                const url = args[0].readUtf8String();
                send({
                    event: 'shouldEncryptBody.enter',
                    url: url,
                });
            } catch(e) {}
        },
        onLeave(retval) {
            send({
                event: 'shouldEncryptBody.leave',
                result: retval.toInt32(),
            });
        }
    });
}

function hookBuildRequest() {
    const base = getModuleBase();
    if (!base) return;

    const addr = base.add(OFFSETS.buildRequest);
    send({info: 'Hooking buildRequest at ' + addr});

    Interceptor.attach(addr, {
        onEnter(args) {
            try {
                // buildRequest(method, url, body, headers...)
                const method = args[0].readUtf8String(args[1].toInt32());
                const url = args[2].readUtf8String(args[3].toInt32());
                const bodyLen = args[5].toInt32();

                send({
                    event: 'buildRequest.enter',
                    method: method,
                    url: url,
                    bodyLen: bodyLen,
                });

                if (bodyLen > 0 && bodyLen < 100000) {
                    const bodyBytes = args[4].readByteArray(bodyLen);
                    const bodyUtf8 = new TextDecoder('utf-8', {fatal: false}).decode(bodyBytes);
                    send({
                        event: 'buildRequest.body',
                        bodyUtf8Preview: bodyUtf8.slice(0, 500),
                        bodyLen: bodyLen,
                    });
                }
            } catch(e) {
                send({event: 'buildRequest.error', error: e.message});
            }
        }
    });
}

// Main
try {
    hookEncodeRequestBody();
    hookShouldEncryptBody();
    hookBuildRequest();
    send({info: 'All hooks installed. Trigger a chat request now.'});
} catch(e) {
    send({error: 'Hook installation failed: ' + e.message});
}
"""

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if isinstance(payload, dict):
            event = payload.get('event', payload.get('info', payload.get('error', '')))
            print(f'[{time.strftime("%H:%M:%S")}] {json.dumps(payload, ensure_ascii=False)[:500]}')
    elif message['type'] == 'error':
        print(f'[ERROR] {message["description"]}')

def main():
    print('Attaching to Lingma.exe...')
    try:
        session = frida.attach('Lingma.exe')
    except Exception as e:
        print(f'Failed to attach: {e}')
        print('Make sure Lingma.exe is running')
        return

    print('Injecting hooks...')
    script = session.create_script(JS_HOOK)
    script.on('message', on_message)
    script.load()

    print('\nHooks installed! Trigger a chat request via 37010 API now.')
    print('Press Ctrl+C to stop.\n')

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('\nDetaching...')
        session.detach()

if __name__ == '__main__':
    main()
