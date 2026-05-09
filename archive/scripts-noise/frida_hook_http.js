/**
 * Frida script: Hook Go HTTP Transport to capture remote OAuth calls.
 * Targets: net/http.(*Transport).RoundTrip
 */
'use strict';

// The Go symbol for Transport.RoundTrip
// Go 1.22 uses register ABI - we hook via RVA or symbol name
var mod = Process.getModuleByName('Lingma.exe');
var exports = mod.enumerateExports();

// Look for the HTTP transport's RoundTrip
var targetRva = null;
for (var i = 0; i < exports.length; i++) {
    var e = exports[i];
    if (e.name.indexOf('RoundTrip') >= 0 && e.name.indexOf('Transport') >= 0) {
        console.log('Found:', e.name, '@', e.address);
        targetRva = e.address;
    }
}

if (!targetRva) {
    console.log('RoundTrip not in exports, trying to find via module base + known offset...');
    console.log('Module base:', mod.base);
    console.log('Module size:', mod.size);
    // Fallback: try to find via pattern scan or known RVA
    send({type: 'error', msg: 'RoundTrip not found in exports'});
} else {
    Interceptor.attach(targetRva, {
        onEnter: function(args) {
            // args[0] = *Transport, args[1] = *Request
            try {
                var req = args[1];
                // Go *Request: URL is at offset depending on struct layout
                // We'll capture the Method and URL from the request
                this.reqAddr = req;
            } catch(e) {}
        },
        onLeave: function(retval) {
            try {
                // Try to read what we can from the request
                send({type: 'roundtrip', addr: this.reqAddr.toString()});
            } catch(e) {}
        }
    });
    console.log('Hook installed on RoundTrip');
}
