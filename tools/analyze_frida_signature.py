"""
分析 Frida 签名追踪数据

从 frida-signature-trace-37017-login.jsonl:
1. trimQueryPath: /algo/api/v2/model/list → /api/v2/model/list
2. getAuthPayload: 664 bytes base64 → 1040 bytes base64 (JSON)
3. getAuthSignature:
   - Input: payload (1040 chars), path (18 chars), timestamp (10 chars), secret (172 chars)
   - Output: 32 hex chars (MD5!)

目标: 解码这些值并理解签名算法
"""
import json
import base64

# Load the Frida trace
trace_entries = []
with open('capture/frida-signature-trace-37017-login.jsonl', 'r') as f:
    for line in f:
        line = line.strip()
        if line:
            trace_entries.append(json.loads(line))

# Find getAuthSignature.enter entry
print("=== getAuthSignature.enter ===")
for entry in trace_entries:
    payload = entry.get('message', {}).get('payload', {})
    event = payload.get('event', '')
    if 'getAuthSignature.enter' in event:
        regs = payload.get('regs', {})
        print("Registers:")
        for reg_name, reg_data in regs.items():
            if isinstance(reg_data, dict):
                ok = reg_data.get('ok')
                if ok:
                    text = reg_data.get('text', '')
                    ptr = reg_data.get('ptr', '')
                    length = reg_data.get('len', 0)
                    print(f"  {reg_name}: ptr={ptr}, len={length}, text={text[:100]}{'...' if len(text) > 100 else ''}")
                else:
                    print(f"  {reg_name}: ERROR - {reg_data.get('error', 'unknown')}")

# Decode getAuthPayload output (the JSON payload)
print("\n\n=== getAuthPayload.leave (output JSON) ===")
for entry in trace_entries:
    payload = entry.get('message', {}).get('payload', {})
    event = payload.get('event', '')
    if 'getAuthPayload.leave' in event:
        regs = payload.get('regs', {})
        for reg_name, reg_data in regs.items():
            if isinstance(reg_data, dict) and reg_data.get('ok'):
                text = reg_data.get('text', '')
                print(f"  {reg_name}: {text[:100]}{'...' if len(text) > 100 else ''}")

                # This is base64-encoded JSON
                try:
                    decoded = base64.b64decode(text)
                    decoded_json = json.loads(decoded)
                    print(f"\n  Decoded JSON:")
                    for k, v in decoded_json.items():
                        val_preview = str(v)[:80]
                        print(f"    {k}: {val_preview}{'...' if len(str(v)) > 80 else ''}")
                except Exception as e:
                    print(f"\n  Decode error: {e}")

# Decode getAuthPayload input
print("\n\n=== getAuthPayload.enter (input) ===")
for entry in trace_entries:
    payload = entry.get('message', {}).get('payload', {})
    event = payload.get('event', '')
    if 'getAuthPayload.enter' in event:
        regs = payload.get('regs', {})
        for reg_name, reg_data in regs.items():
            if isinstance(reg_data, dict) and reg_data.get('ok'):
                text = reg_data.get('text', '')
                ptr = reg_data.get('ptr', '')
                length = reg_data.get('len', 0)
                print(f"  {reg_name}: ptr={ptr}, len={length}, text={text[:80]}{'...' if len(text) > 80 else ''}")

# The input (664 bytes) is also base64
# Let's try to decode it
for entry in trace_entries:
    payload = entry.get('message', {}).get('payload', {})
    event = payload.get('event', '')
    if 'getAuthPayload.enter' in event:
        regs = payload.get('regs', {})
        rax_data = regs.get('rax_rbx', {})
        if rax_data.get('ok'):
            text = rax_data.get('text', '')
            try:
                decoded = base64.b64decode(text)
                print(f"\n  Decoded input: {len(decoded)} bytes")
                print(f"  First 50 hex: {decoded[:50].hex()}")
                # Try to decode as JSON
                try:
                    j = json.loads(decoded)
                    print(f"  JSON: {j}")
                except:
                    # Try as latin-1 text
                    txt = decoded.decode('latin-1')
                    printable = ''.join(c if 32 <= ord(c) < 127 else '.' for c in txt)
                    print(f"  Text: {printable[:100]}")
            except Exception as e:
                print(f"\n  Input decode error: {e}")

# Now analyze the signature computation
print("\n\n=== Signature computation analysis ===")
# We have:
# - Payload: base64 JSON with cosyVersion, info (encrypted data), requestId, version
# - Path: /api/v2/model/list
# - Timestamp: 1777038686
# - Secret: 172 bytes of base64 data
# - Output: a0c8bb3de47a955df4f786b4000faa0d

# The signature is 32 hex chars = MD5
# What's being hashed?
# Candidates:
# 1. MD5(payload + path + timestamp + secret)
# 2. MD5(payload_body + path + timestamp + secret_key)
# 3. HMAC-MD5(secret, payload + path + timestamp)

# Let's try all combinations
import hashlib
import hmac

# Extract values from the trace
payload_b64 = ""  # Will be set from the trace
path = "/api/v2/model/list"
timestamp = "1777038686"
secret_b64 = ""
expected_sig = "a0c8bb3de47a955df4f786b4000faa0d"

for entry in trace_entries:
    payload_data = entry.get('message', {}).get('payload', {})
    event = payload_data.get('event', '')
    if 'getAuthSignature.enter' in event:
        regs = payload_data.get('regs', {})
        # Get payload (rax_rbx)
        rax = regs.get('rax_rbx', {})
        if rax.get('ok'):
            payload_b64 = rax.get('text', '')
        # Get timestamp (r9_r10)
        r9 = regs.get('r9_r10', {})
        if r9.get('ok'):
            timestamp = r9.get('text', '')
        # Get secret (stack_08_10)
        stack = regs.get('stack_08_10', {})
        if stack.get('ok'):
            secret_b64 = stack.get('text', '')
        # Get path (rcx_rdi)
        rcx = regs.get('rcx_rdi', {})
        if rcx.get('ok'):
            path = rcx.get('text', '')

print(f"Payload (b64): {payload_b64[:50]}... (len={len(payload_b64)})")
print(f"Path: {path}")
print(f"Timestamp: {timestamp}")
print(f"Secret (b64): {secret_b64[:50]}... (len={len(secret_b64)})")
print(f"Expected sig: {expected_sig}")

# Try different combinations
print("\n=== Testing signature combinations ===")

# Decode the secret
secret_raw = base64.b64decode(secret_b64)
print(f"Secret raw: {len(secret_raw)} bytes, hex: {secret_raw[:32].hex()}...")

# Test 1: MD5 of various string combinations
tests = [
    ("payload + path + timestamp", (payload_b64 + path + timestamp).encode()),
    ("payload + path", (payload_b64 + path).encode()),
    ("path + timestamp", (path + timestamp).encode()),
    ("path + payload + timestamp", (path + payload_b64 + timestamp).encode()),
    ("timestamp + path + payload", (timestamp + path + payload_b64).encode()),
    ("decoded_payload + path + timestamp", (base64.b64decode(payload_b64) + path.encode() + timestamp.encode())),
]

for name, data in tests:
    sig = hashlib.md5(data).hexdigest()
    match = sig == expected_sig
    print(f"  MD5({name}): {sig} {'*** MATCH ***' if match else ''}")

# Test 2: HMAC-MD5
print("\n=== Testing HMAC-MD5 ===")
hmac_tests = [
    ("secret_raw, payload + path + timestamp", secret_raw, (payload_b64 + path + timestamp).encode()),
    ("secret_raw, payload_b64 + path", secret_raw, (payload_b64 + path).encode()),
    ("secret_raw, path + timestamp", secret_raw, (path + timestamp).encode()),
    ("secret_raw, payload only", secret_raw, payload_b64.encode()),
    ("secret_b64, payload + path + timestamp", secret_b64.encode(), (payload_b64 + path + timestamp).encode()),
    ("decoded_payload, path + timestamp", base64.b64decode(payload_b64), (path + timestamp).encode()),
    ("secret_raw, decoded_payload + path + timestamp", secret_raw, base64.b64decode(payload_b64) + path.encode() + timestamp.encode()),
]

for name, key, data in hmac_tests:
    sig = hmac.new(key if isinstance(key, bytes) else key.encode(), data, hashlib.md5).hexdigest()
    match = sig == expected_sig
    print(f"  HMAC-MD5({name}): {sig} {'*** MATCH ***' if match else ''}")

# Test 3: Maybe the secret key is the raw bytes, not base64
print("\n=== Testing with raw secret as key ===")
# The secret might be an AES key or derived key
secret_decoded = base64.b64decode(secret_b64)
print(f"Secret decoded length: {len(secret_decoded)}")
print(f"Secret hex: {secret_decoded.hex()[:64]}...")

# Try with the decoded secret as HMAC key
for name, data in [
    ("decoded_secret, payload+path+timestamp", base64.b64decode(payload_b64) + path.encode() + timestamp.encode()),
    ("decoded_secret, payload_b64+path+timestamp", payload_b64.encode() + path.encode() + timestamp.encode()),
]:
    sig = hmac.new(secret_decoded, data, hashlib.md5).hexdigest()
    match = sig == expected_sig
    print(f"  HMAC-MD5({name}): {sig} {'*** MATCH ***' if match else ''}")
