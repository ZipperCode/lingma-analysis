'use strict';

// Hook runtime.mapassign_faststr to capture getAppSalt's map construction
// This avoids modifying getAppSalt's code entirely

var mods = Process.enumerateModules().filter(function(m) { return m.name.includes('Lingma'); });
if (mods.length === 0) {
    send({type: 'error', msg: 'Lingma module not found'});
    throw new Error('Lingma not found');
}

var baseAddr = mods[0].base;
send({type: 'log', msg: 'Lingma base: ' + baseAddr});

// Find runtime.mapassign_faststr
// In Go 1.23, this is at a known RVA. Let's search for it.
var mapassignAddr = baseAddr.add(0x2dd360);
send({type: 'log', msg: 'runtime.mapassign_faststr at: ' + mapassignAddr});

var firstByte = mapassignAddr.readU8();
send({type: 'log', msg: 'First byte at mapassign_faststr: 0x' + firstByte.toString(16)});

// getAppSalt range
var getAppSaltStart = baseAddr.add(0x882760);
var getAppSaltEnd = getAppSaltStart.add(0x882b8a - 0x882760 + 5); // function end

var capturedResults = [];

// Track which threads are inside getAppSalt
var inGetAppSalt = {};

// Hook the caller to set tracking flag
var callerAddr = baseAddr.add(0x880da0);
Interceptor.attach(callerAddr, {
    onEnter: function() {
        send({type: 'log', msg: '=== CALLER 0x880da0 ENTER ==='});
        inGetAppSalt[this.threadId] = true;
    },
    onLeave: function() {
        send({type: 'log', msg: '=== CALLER 0x880da0 LEAVE, captured ' + capturedResults.length + ' map entries ==='});
        delete inGetAppSalt[this.threadId];
    }
});

// Hook mapassign_faststr
// Signature: func mapassign_faststr(t *maptype, h *hmap, key string, val unsafe.Pointer) *unsafe.Pointer
// Go register calling convention: RCX=maptype, RDX=hmap, R8=key.ptr, R9=key.len
// Stack: val.ptr, val.len (or similar)
Interceptor.attach(mapassignAddr, {
    onEnter: function(args) {
        var tid = this.threadId;
        if (inGetAppSalt[tid]) {
            // Check if return address is within getAppSalt range
            var retAddr = this.returnAddress;
            if (retAddr.greaterOrEqual(getAppSaltStart) && retAddr.lessOrEqual(getAppSaltEnd)) {
                // This call originated from getAppSalt!
                try {
                    var keyPtr = this.context.r8;
                    var keyLen = this.context.r9.toUInt32();
                    if (keyLen > 0 && keyLen < 200) {
                        var keyStr = keyPtr.readUtf8String(keyLen);
                        send({type: 'mapassign', msg: 'KEY: "' + keyStr + '" (len=' + keyLen + ')'});
                        capturedResults.push({type: 'key', value: keyStr});
                    }
                } catch(e) {}

                try {
                    // Value is likely on the stack
                    var valPtr = this.context.rsp.add(8).readPointer();
                    var valLen = this.context.rsp.add(16).readUInt();
                    if (valLen > 0 && valLen < 500) {
                        var valStr = valPtr.readUtf8String(valLen);
                        send({type: 'mapassign', msg: 'VAL: "' + valStr + '" (len=' + valLen + ')'});
                        capturedResults.push({type: 'val', value: valStr});
                    }
                } catch(e) {}
            }
        }
    }
});

send({type: 'log', msg: 'All hooks installed. Waiting for getAppSalt calls...'});

rpc.exports = {
    getCaptured: function() {
        return JSON.stringify(capturedResults);
    }
};
