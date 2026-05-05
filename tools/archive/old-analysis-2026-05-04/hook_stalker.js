'use strict';

// Stalker-based tracing - no code patching on target function
var mods = Process.enumerateModules().filter(function(m) { return m.name.includes('Lingma'); });
if (mods.length === 0) {
    send({type: 'error', msg: 'Lingma module not found'});
    throw new Error('Lingma not found');
}

var baseAddr = mods[0].base;
send({type: 'log', msg: 'Lingma base: ' + baseAddr});

var getAppSaltAddr = baseAddr.add(0x882760);
send({type: 'log', msg: 'getAppSalt target: ' + getAppSaltAddr});

var capturedResults = [];
var stalking = false;

// Hook caller to trigger Stalker
var callerAddr = baseAddr.add(0x880da0);
send({type: 'log', msg: 'Hooking caller at 0x880da0'});

Interceptor.attach(callerAddr, {
    onEnter: function(args) {
        send({type: 'log', msg: 'CALLER ENTER - starting Stalker'});
        stalking = true;

        var self = this;
        Stalker.follow({
            events: { call: true },
            transform: function(iterator) {
                var instruction = iterator.next();
                while (instruction !== null) {
                    if (instruction.address.equals(getAppSaltAddr)) {
                        send({type: 'log', msg: 'Stalker: found call to getAppSalt'});
                        iterator.putInstruction(instruction);
                        iterator.putCallout(function(context) {
                            var ret = context.rax;
                            send({type: 'stalker', msg: 'RAX after getAppSalt: ' + ret});
                            try {
                                var str = ret.readUtf8String(100);
                                send({type: 'stalker', msg: 'STRING: ' + str});
                            } catch (e) {
                                send({type: 'stalker', msg: 'Not a string: ' + e.message});
                            }
                            try {
                                var sliceData = ret.readPointer();
                                var sliceLen = ret.add(8).readUInt();
                                send({type: 'stalker', msg: 'Slice: len=' + sliceLen + ' data=' + sliceData});
                                if (sliceLen > 0 && sliceLen < 20) {
                                    var bytes = sliceData.readByteArray(sliceLen * 16);
                                    send({type: 'stalker', msg: 'Bytes: ' + bytesToHex(bytes)});
                                    for (var i = 0; i < sliceLen; i++) {
                                        var p = sliceData.add(i * 16).readPointer();
                                        var l = sliceData.add(i * 16 + 8).readUInt();
                                        if (l > 0 && l < 500) {
                                            try {
                                                var s = p.readUtf8String(l);
                                                send({type: 'stalker', msg: 'elem[' + i + ']: ' + s});
                                            } catch (e2) {}
                                        }
                                    }
                                }
                            } catch (e) {
                                send({type: 'stalker', msg: 'Not a slice: ' + e.message});
                            }
                            capturedResults.push({rax: ret.toString(), time: Date.now()});
                        });
                    } else {
                        iterator.putInstruction(instruction);
                    }
                    instruction = iterator.next();
                }
            }
        });
    },
    onLeave: function(retval) {
        send({type: 'log', msg: 'CALLER LEAVE'});
        if (stalking) {
            Stalker.unfollow();
            stalking = false;
            send({type: 'log', msg: 'Stalker stopped'});
        }
    }
});

send({type: 'log', msg: 'Hooks installed, waiting...'});

rpc.exports = {
    getCaptured: function() {
        return JSON.stringify(capturedResults);
    }
};

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
