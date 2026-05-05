"""
Frida hook: capture encodeRequestBody full I/O
Captures the body BEFORE and AFTER encoding for each request
"""
import frida
import json
import time
import sys

JS = '''
const mod = Process.findModuleByName('Lingma.exe');
const base = mod.base;

// Function offsets (from GoReSym, relative to image base 0x140000000)
const ENCODE_BODY_OFFSET = 0x881820;
const SHOULD_ENCRYPT_OFFSET = 0x882680;
const BUILD_REQUEST_OFFSET = 0x880da0;
const ADD_AUTH_HEADERS_OFFSET = 0x882ba0;

send({info: `Module base: ${base}, size: ${mod.size}`});

// Store request context per thread
const threadContexts = {};

// Hook encodeRequestBody
Interceptor.attach(base.add(ENCODE_BODY_OFFSET), {
    onEnter(args) {
        const tid = this.threadId;
        try {
            const method = args[0].readUtf8String(args[1].toInt32());
            const url = args[2].readUtf8String(args[3].toInt32());
            const bodyLen = args[5].toInt32();

            let bodyPreview = '';
            let bodyFull = '';
            if (bodyLen > 0 && bodyLen < 200000) {
                const bodyBytes = args[4].readByteArray(bodyLen);
                bodyFull = new TextDecoder('utf-8', {fatal: false}).decode(bodyBytes);
                bodyPreview = bodyFull.slice(0, 500);
            }

            threadContexts[tid] = {method, url, bodyLen, bodyFull};

            send({
                event: 'encode.enter',
                tid,
                method,
                url: url.slice(0, 200),
                bodyLen,
                bodyPreview,
            });
        } catch(e) {
            send({event: 'encode.enter.error', tid, error: e.message});
        }
    },
    onLeave(retval) {
        const tid = this.threadId;
        const ctx = threadContexts[tid];
        if (ctx) {
            send({
                event: 'encode.leave',
                tid,
                method: ctx.method,
                url: ctx.url.slice(0, 200),
                inputLen: ctx.bodyLen,
            });
        }
    }
});

// Hook shouldEncryptBody
Interceptor.attach(base.add(SHOULD_ENCRYPT_OFFSET), {
    onEnter(args) {
        try {
            const url = args[0].readUtf8String();
            send({event: 'encrypt.check', url: url.slice(0, 200)});
        } catch(e) {}
    },
    onLeave(retval) {
        send({event: 'encrypt.result', value: retval.toInt32()});
    }
});

// Hook buildRequest to capture the final outgoing request
Interceptor.attach(base.add(BUILD_REQUEST_OFFSET), {
    onEnter(args) {
        const tid = this.threadId;
        try {
            // buildRequest(method, methodLen, url, urlLen, body, bodyLen, ...)
            const method = args[0].readUtf8String(args[1].toInt32());
            const url = args[2].readUtf8String(args[3].toInt32());
            const bodyLen = args[5].toInt32();

            let bodyPreview = '';
            if (bodyLen > 0 && bodyLen < 200000) {
                const bodyBytes = args[4].readByteArray(Math.min(bodyLen, 1000));
                bodyPreview = new TextDecoder('utf-8', {fatal: false}).decode(bodyBytes);
            }

            send({
                event: 'build.enter',
                tid,
                method,
                url: url.slice(0, 200),
                bodyLen,
                bodyPreview: bodyPreview.slice(0, 500),
            });
        } catch(e) {
            send({event: 'build.error', tid, error: e.message});
        }
    }
});

send({info: 'All hooks installed. Waiting for requests...'});
'''

events = []
def on_message(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']
        events.append(p)
        event = p.get('event', p.get('info', ''))
        print(f'[{time.strftime("%H:%M:%S")}] {json.dumps(p, ensure_ascii=False)[:500]}')
    elif msg['type'] == 'error':
        print(f'[ERROR] {msg.get("description","")}')

# Attach to fresh Lingma process
print('Attaching to Lingma.exe...')
session = frida.attach('Lingma.exe')
script = session.create_script(JS)
script.on('message', on_message)
script.load()
print('Hooks installed! Now trigger a chat request.')
print('Use: python3 tools/lingma_probe.py --do-chat --question "test" --chat-overall-timeout 30')
print()
print('Waiting for events... (Ctrl+C to stop)')
print()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print(f'\nCollected {len(events)} events')
    session.detach()
