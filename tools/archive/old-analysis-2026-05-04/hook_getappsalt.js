'use strict';

var mods = Process.enumerateModules().filter(function(m) { return m.name.includes('Lingma'); });
if (mods.length === 0) {
    send({type: 'error', msg: 'Lingma module not found!'});
} else {
    var baseAddr = mods[0].base;
    send({type: 'log', msg: 'Lingma base: ' + baseAddr});

    var getAppSaltAddr = baseAddr.add(0x882760);
    send({type: 'log', msg: 'getAppSalt target: ' + getAppSaltAddr});

    var firstByte = getAppSaltAddr.readU8();
    send({type: 'log', msg: 'First byte at getAppSalt: 0x' + firstByte.toString(16)});

    var capturedResults = [];

    // Use Interceptor.replace instead of attach
    // Replace entirely, call original via NativeFunction
    send({type: 'log', msg: 'Installing getAppSalt replace hook...'});

    Interceptor.replace(getAppSaltAddr, new NativeCallback(function () {
        send({type: 'log', msg: 'GETAPPSALT REPLACED (called)'});

        // Call original
        var orig = new NativeFunction(getAppSaltAddr, 'pointer', []);
        var ret = orig();

        send({type: 'log', msg: 'Original returned: RAX=' + ret});

        // Go string return: RAX=ptr, RCX=len (in Go 1.22+ register calling conv)
        // But after NativeFunction return, we can read registers from context
        // Actually NativeFunction returns the first return value
        // For Go strings, we need len from RCX which was set by the call

        // Try reading as Go string (ptr + len stored together after return)
        try {
            var len = Process.arch === 'x64' ? 0 : 0; // We need to get this differently
            // Try reading as C string first
            var str = ret.readUtf8String(200);
            send({type: 'log', msg: '>>> SALT STRING: ' + str});
        } catch(e) {
            send({type: 'log', msg: 'Not a simple string: ' + e.message});
        }

        // Try reading as Go slice header: [ptr(8), len(8), cap(8)]
        try {
            var sliceData = ret.readPointer();
            var sliceLen = ret.add(8).readUInt();
            var sliceCap = ret.add(16).readUInt();
            send({type: 'log', msg: 'Slice: data=' + sliceData + ' len=' + sliceLen + ' cap=' + sliceCap});

            if (sliceLen > 0 && sliceLen < 100) {
                var bytes = sliceData.readByteArray(Math.min(sliceLen, 500));
                send({type: 'log', msg: 'Slice bytes: ' + bytesToHex(bytes)});

                // Try as []string (each element = ptr + len = 16 bytes)
                if (sliceLen > 0 && sliceLen < 20) {
                    for (var i = 0; i < sliceLen; i++) {
                        var elemPtr = sliceData.add(i * 16).readPointer();
                        var elemLen = sliceData.add(i * 16 + 8).readUInt();
                        if (elemLen > 0 && elemLen < 500) {
                            try {
                                var elemStr = elemPtr.readUtf8String(elemLen);
                                send({type: 'log', msg: '  [' + i + '] = "' + elemStr + '"'});
                            } catch(e) {}
                        }
                    }
                }
            }
        } catch(e) {
            send({type: 'log', msg: 'Not a slice: ' + e.message});
        }

        capturedResults.push({
            rax: ret.toString(),
            time: Date.now()
        });

        return ret;
    }, 'pointer', []));

    send({type: 'log', msg: 'getAppSalt replace hook installed!'});

    // Also hook the caller to see when getAppSalt is invoked
    var callerAddr = baseAddr.add(0x880da0);
    Interceptor.attach(callerAddr, {
        onEnter: function(args) {
            send({type: 'log', msg: 'CALLER 0x880da0 ENTER (will call getAppSalt)'});
        },
        onLeave: function(retval) {
            send({type: 'log', msg: 'CALLER 0x880da0 LEAVE'});
        }
    });
    send({type: 'log', msg: 'Caller hook installed'});

    send({type: 'log', msg: 'All hooks installed. Waiting...'});

    rpc.exports = {
        getCaptured: function() {
            return JSON.stringify(capturedResults);
        }
    };
}

function bytesToHex(bytes) {
    var hex = '';
    var arr = new Uint8Array(bytes);
    for (var i = 0; i < arr.length; i++) {
        var h = arr[i].toString(16);
        if (h.length < 2) h = '0' + h;
        hex += h;
    }
    return hex;
}
