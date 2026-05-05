/**
 * Lingma OAuth Token Extractor v9 - Duktape runtime (more stealthy)
 * Ultra-minimal: only console.log on function entry/exit
 */

const IDA_BASE = ptr('0x140000000');
const mod = Process.findModuleByName('Lingma.exe');
if (!mod) { console.log('[!] Lingma.exe not found'); Process.exit(1); }

const OFFSET = mod.base.sub(IDA_BASE);
function addr(a) { return ptr(a).add(OFFSET); }
function gstr(p) {
    try {
        var s = p.readPointer();
        var n = p.add(8).readUInt();
        if (n > 0 && n < 50000 && !s.isNull()) return s.readUtf8String(n);
    } catch(e) {}
    return null;
}

console.log('[*] PID:', Process.id, 'Base:', mod.base);

// Hook 1: genPKCE - minimal
Interceptor.attach(addr('0x141a197a0'), {
    onEnter: function() { this.pkceEnter = Date.now(); },
    onLeave: function() {
        var sp = this.context.sp;
        // Read return values from stack (Go strings at known offsets)
        for (var i = 0; i < 0x80; i += 8) {
            try {
                var p = sp.add(i).readPointer();
                if (p.compare(ptr('0x7ff000000000')) < 0) continue;
                var s = gstr(p);
                if (s && s.length === 32 && /^[a-f0-9]+$/.test(s)) {
                    send({type: 'pkce_verifier', value: s});
                }
                if (s && s.length > 30 && !s.includes('/') && !s.includes('.')) {
                    send({type: 'pkce_candidate', value: s.substring(0, 60)});
                }
            } catch(e) {}
        }
    }
});

// Hook 2: handleAuth
Interceptor.attach(addr('0x141a18dc0'), {
    onEnter: function() { send({type: 'handleAuth'}); },
    onLeave: function() { send({type: 'handleAuth_return'}); }
});

// Hook 3: parseToken - capture input/output
Interceptor.attach(addr('0x141a213e0'), {
    onEnter: function() {
        var sp = this.context.sp;
        for (var i = 0; i < 0x100; i += 8) {
            try {
                var p = sp.add(i).readPointer();
                if (p.compare(ptr('0x7ff000000000')) < 0) continue;
                var s = gstr(p);
                if (s && s.length > 20 && (s.startsWith('Y3') || s.startsWith('cn') || s.includes('==') || s.includes('pt-') || s.includes('rt-'))) {
                    send({type: 'token_input', value: s.substring(0, 80)});
                }
            } catch(e) {}
        }
    },
    onLeave: function() {
        var sp = this.context.sp;
        for (var i = 0; i < 0x100; i += 8) {
            try {
                var p = sp.add(i).readPointer();
                if (p.compare(ptr('0x7ff000000000')) < 0) continue;
                var s = gstr(p);
                if (s && s.startsWith('pt-')) send({type: 'pt_token', value: s});
                if (s && s.startsWith('rt-')) send({type: 'rt_token', value: s});
            } catch(e) {}
        }
    }
});

// Hook 4: saveUser
Interceptor.attach(addr('0x14088e260'), {
    onEnter: function() {
        var sp = this.context.sp;
        for (var i = 0; i < 0x100; i += 8) {
            try {
                var p = sp.add(i).readPointer();
                if (p.compare(ptr('0x7ff000000000')) < 0) continue;
                var s = gstr(p);
                if (s && s.startsWith('pt-')) send({type: 'save_pt', value: s});
                if (s && s.startsWith('rt-')) send({type: 'save_rt', value: s});
            } catch(e) {}
        }
    }
});

console.log('[*] Hooks set. Waiting...');
