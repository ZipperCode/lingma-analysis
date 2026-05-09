"""Frida memory scanner to find client_id in Lingma process.

Strategy: Scan readable memory regions for strings that look like OAuth client_ids.
Go stores strings inline in data sections or on heap.
"""
import frida
import sys
import re
import time

SCRIPT = r"""
'use strict';

// Scan memory for strings that look like client_ids
function findClientIdPatterns() {
    var results = [];
    var ranges = Process.enumerateRanges('r--');

    console.log('[Scanner] Scanning ' + ranges.length + ' readable regions...');

    var patterns = [
        // UUID pattern
        /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/gi,
        // Long hex strings (32-64 chars)
        /[a-f0-9]{32,64}/gi,
        // Alphanumeric with dots (common Alibaba format)
        /[a-z]{4,20}\.[a-z]{4,20}\.[a-z0-9]{4,30}/gi,
    ];

    var seen = {};
    var count = 0;

    ranges.forEach(function(range) {
        if (range.size > 50 * 1024 * 1024) return; // Skip huge regions
        if (!range.protection.includes('r')) return;

        try {
            var bytes = range.base.readByteArray(range.size);
            if (!bytes) return;

            var text = '';
            var arr = new Uint8Array(bytes);
            // Convert to string (only printable chars)
            for (var i = 0; i < arr.length; i++) {
                var b = arr[i];
                text += (b >= 32 && b < 127) ? String.fromCharCode(b) : '\n';
            }

            patterns.forEach(function(pattern) {
                var match;
                while ((match = pattern.exec(text)) !== null) {
                    var val = match[0];
                    if (!seen[val]) {
                        seen[val] = true;
                        results.push(val);
                        count++;
                        if (count <= 50) {
                            console.log('  [MATCH] ' + val);
                            send({type: 'candidate', value: val});
                        }
                    }
                }
            });
        } catch(e) {
            // Skip unreadable regions
        }
    });

    console.log('[Scanner] Found ' + count + ' unique candidates');
    send({type: 'scan_done', total: count});
}

// Also specifically look for OAuth config strings
function findOAuthContext() {
    var ranges = Process.enumerateRanges('r--');

    ranges.forEach(function(range) {
        if (range.size > 50 * 1024 * 1024) return;
        try {
            var bytes = range.base.readByteArray(Math.min(range.size, 1024 * 1024));
            if (!bytes) return;
            var arr = new Uint8Array(bytes);
            var text = '';
            for (var i = 0; i < arr.length; i++) {
                var b = arr[i];
                text += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
            }

            // Find "client_id" or "ClientID" and show surrounding context
            var idx = text.indexOf('client_id');
            if (idx < 0) idx = text.indexOf('ClientID');
            if (idx >= 0) {
                var ctx = text.substring(Math.max(0, idx - 50), idx + 100);
                console.log('[OAUTH CONTEXT] ' + ctx);
                send({type: 'oauth_context', text: ctx});
            }
        } catch(e) {}
    });
}

// Run scans
try {
    findOAuthContext();
    findClientIdPatterns();
} catch(e) {
    console.log('[Error] ' + e);
}

send({type: 'done'});
"""


def main():
    print("[*] Attaching Frida to Lingma...")
    device = frida.get_local_device()
    processes = [p for p in device.enumerate_processes()
                 if p.name and 'lingma' in p.name.lower()]

    if not processes:
        print("[!] Lingma not running")
        sys.exit(1)

    pid = processes[0].pid
    print(f"[*] PID: {pid}")

    session = device.attach(pid)
    script = session.create_script(SCRIPT)

    candidates = []
    oauth_contexts = []

    def on_msg(msg, data):
        if msg['type'] == 'send':
            p = msg['payload']
            t = p.get('type', '?')
            if t == 'candidate':
                candidates.append(p['value'])
            elif t == 'oauth_context':
                oauth_contexts.append(p['text'])
            elif t == 'scan_done':
                print(f"\n[*] Scan complete: {p['total']} candidates found")
            elif t == 'done':
                print("[*] All scans complete")
        elif msg['type'] == 'log':
            print(f"[Frida] {msg['payload'][:300]}")

    script.on('message', on_msg)
    script.load()

    # Wait for scans to complete
    time.sleep(30)

    print(f"\n=== OAuth Contexts ===")
    for ctx in oauth_contexts:
        print(f"  {ctx[:200]}")

    print(f"\n=== Unique Candidates ({len(candidates)}) ===")
    # Filter for likely client_ids
    for c in candidates:
        # Client IDs are typically alphanumeric with some structure
        if len(c) >= 20 and len(c) <= 80:
            if any(ch.isdigit() for ch in c) and any(ch.isalpha() for ch in c):
                print(f"  {c}")

    script.unload()
    session.detach()


if __name__ == '__main__':
    main()
