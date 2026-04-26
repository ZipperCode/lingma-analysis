const mod = Process.findModuleByName('Lingma.exe');
const base = mod.base;

function toHex(bytes, maxLen) {
    const arr = new Uint8Array(bytes);
    const len = Math.min(arr.length, maxLen || 100);
    let hex = '';
    for (let i = 0; i < len; i++) hex += arr[i].toString(16).padStart(2, '0');
    return hex;
}

function toSafeUtf8(bytes, maxLen) {
    const arr = new Uint8Array(bytes);
    const len = Math.min(arr.length, maxLen || 2000);
    let result = '';
    for (let i = 0; i < len; i++) {
        const b = arr[i];
        if (b >= 32 && b < 127) result += String.fromCharCode(b);
        else if (b === 10 || b === 13 || b === 9) result += String.fromCharCode(b);
        else result += '|' + b.toString(16).padStart(2, '0') + '|';
    }
    return result;
}

Interceptor.attach(base.add(0x881820), {
    onEnter(args) {
        try {
            const method = args[0].readUtf8String(args[1].toInt32());
            const url = args[2].readUtf8String(args[3].toInt32());
            const bodyLen = args[5].toInt32();
            let bodyHex = '';
            let bodyUtf8 = '';
            if (bodyLen > 0 && bodyLen < 200000) {
                const bodyBytes = args[4].readByteArray(bodyLen);
                bodyHex = toHex(bodyBytes, 100);
                bodyUtf8 = toSafeUtf8(bodyBytes, 500);
            }
            send({event: 'encode', method, url: url.slice(0,100), bodyLen, bodyHex, bodyUtf8});
        } catch(e) { send({err: 'encode: ' + e.message}); }
    },
});

Interceptor.attach(base.add(0x880da0), {
    onEnter(args) {
        try {
            const method = args[0].readUtf8String(args[1].toInt32());
            const url = args[2].readUtf8String(args[3].toInt32());
            const bodyLen = args[5].toInt32();
            let bodyHex = '';
            let bodyUtf8 = '';
            if (bodyLen > 0 && bodyLen < 500000) {
                const bodyBytes = args[4].readByteArray(Math.min(bodyLen, 5000));
                bodyHex = toHex(bodyBytes, 200);
                bodyUtf8 = toSafeUtf8(bodyBytes, 2000);
            }
            send({event: 'build', method, url: url.slice(0,100), bodyLen, bodyHex, bodyUtf8});
        } catch(e) { send({err: 'build: ' + e.message}); }
    }
});

send({info: 'hooks ready'});
