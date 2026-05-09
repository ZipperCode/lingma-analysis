#!/usr/bin/env python3
"""
Online oracle attack: test Signature formulas against real Lingma server.
Implements Encode=1 AES encryption in Python, bypassing the need for Lingma binary.
"""
import hashlib
import json
import time
import base64
import math
import urllib.request
import ssl
from Crypto.Cipher import AES

# ===== Encode=1 Implementation =====
ENCODE1_ALPHA = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"
ENCODE1_STDB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# Build translation tables
_alpha_to_std = {}
_std_to_alpha = {}
for i, c in enumerate(ENCODE1_ALPHA):
    _std_to_alpha[ENCODE1_STDB64[i]] = c
    _alpha_to_std[c] = ENCODE1_STDB64[i]

def lingma_encode(data: bytes) -> str:
    """Custom base64 + block reordering."""
    std = base64.b64encode(data).decode()
    std = std.rstrip('=')

    # Custom alphabet substitution
    custom = ''.join(_std_to_alpha.get(c, c) for c in std)

    # Block reordering
    e = len(custom)
    bs = math.ceil(e / 3)
    pad = (4 - e % 4) % 4

    b0 = custom[:bs]
    b1 = custom[bs:2*bs] if 2*bs <= e else custom[bs:] if bs < e else ''
    b2 = custom[2*bs:] if 2*bs <= e else ''

    return b2 + '$' * pad + b1 + b0

def lingma_encode_aes(plaintext: bytes, aes_key: bytes) -> str:
    """AES-128-CBC encrypt + custom encode."""
    # PKCS7 padding
    pad_len = 16 - len(plaintext) % 16
    padded = plaintext + bytes([pad_len] * pad_len)

    # AES-128-CBC with key as IV
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_key)
    encrypted = cipher.encrypt(padded)

    return lingma_encode(encrypted)

# ===== Config and Oracle Testing =====
CFG_PATH = r"C:/Users/Zipper/.lingma/portable_config.json"
AES_KEY = b"QbgzpWzN7tfe43gf"
LOGIN_URL = "https://lingma.alibabacloud.com/algo/api/v3/user/login?Encode=1"

# Keys from static analysis
LONG_KEY = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"
SHORT_KEY = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="

def load_config():
    with open(CFG_PATH, 'r') as f:
        return json.load(f)

def build_login_body(config):
    """Build the JSON body for /user/login."""
    req = {
        "token": config.get("security_oauth_token", ""),
        "refreshToken": config.get("refresh_token", ""),
        "userId": config.get("user_id", ""),
        "username": config.get("user_name", ""),
        "machineId": config.get("machine_id", ""),
        "expireTime": str(config.get("expire_time", "0")),
    }
    return json.dumps(req).encode()

def make_signature(date_str, key, formula="cosy+key+date"):
    """Compute MD5 signature based on formula."""
    if formula == "cosy+key+date":
        preimage = "cosy" + key + date_str
    elif formula == "key+date":
        preimage = key + date_str
    elif formula == "date+key":
        preimage = date_str + key
    elif formula == "cosy+date+key":
        preimage = "cosy" + date_str + key
    elif formula == "date+cosy+key":
        preimage = date_str + "cosy" + key
    elif formula == "key+cosy+date":
        preimage = key + "cosy" + date_str
    elif formula == "cosy|key|date":
        preimage = "cosy|" + key + "|" + date_str
    elif formula == "cosy\nkey\ndate":
        preimage = "cosy\n" + key + "\n" + date_str
    elif formula == "key|date":
        preimage = key + "|" + date_str
    elif formula == "date|key":
        preimage = date_str + "|" + key
    else:
        preimage = formula  # Direct preimage string
    return hashlib.md5(preimage.encode()).hexdigest()

def try_login(config, date_str, signature, encoded_body):
    """Try a POST to /user/login with given Signature."""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(LOGIN_URL, data=encoded_body.encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Appcode", "cosy")
    req.add_header("User-Agent", "Go-http-client/1.1")
    req.add_header("Date", date_str)
    if signature:
        req.add_header("Signature", signature)

    try:
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        body = resp.read().decode()
        return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return e.code, body
    except Exception as e:
        return 0, str(e)

def main():
    config = load_config()
    print(f"Config loaded: user={config.get('user_name')}, machine_id={config.get('machine_id')}")
    print(f"security_oauth_token present: {bool(config.get('security_oauth_token'))}")

    body = build_login_body(config)
    print(f"Login body: {body.decode()}")
    encoded_body = lingma_encode_aes(body, AES_KEY)
    print(f"Encoded body ({len(encoded_body)} chars)")

    # Current time in RFC1123
    from email.utils import formatdate
    date_str = formatdate(time.time(), usegmt=True)
    print(f"Date: {date_str}")

    # Test formulas in order of likelihood
    formulas = [
        # Direct from static analysis
        ("cosy+key+date", lambda d, k: "cosy" + k + d),
        ("cosy+key+date (short)", lambda d, k: "cosy" + SHORT_KEY + d),
        ("key+date (long)", lambda d, k: LONG_KEY + d),
        ("key+date (short)", lambda d, k: SHORT_KEY + d),
        ("date+key (long)", lambda d, k: d + LONG_KEY),
        ("date+key (short)", lambda d, k: d + SHORT_KEY),
        # With separators
        ("cosy\\nkey\\ndate", lambda d, k: "cosy\n" + k + "\n" + d),
        ("cosy|key|date", lambda d, k: "cosy|" + k + "|" + d),
        ("key\\ndate", lambda d, k: k + "\n" + d),
        ("key|date", lambda d, k: k + "|" + d),
        ("date\\nkey", lambda d, k: d + "\n" + k),
        # Different cosy cases
        ("COSY+key+date", lambda d, k: "COSY" + k + d),
        # No prefix
        ("date only", lambda d, k: d),
        ("key only", lambda d, k: k),
    ]

    print(f"\nTesting {len(formulas)} formulas against real server...")
    print("=" * 70)

    results = []
    for name, formula_fn in formulas:
        # Determine which key to use
        key = LONG_KEY
        if "short" in name:
            key = SHORT_KEY

        preimage = formula_fn(date_str, key)
        sig = hashlib.md5(preimage.encode()).hexdigest()

        status, body_text = try_login(config, date_str, sig, encoded_body)
        result = f"HTTP {status}"
        if status == 200:
            result += " *** SUCCESS ***"
            try:
                resp_json = json.loads(body_text)
                if resp_json.get("key"):
                    result += f" (got cosy_key!)"
            except:
                pass
        elif status != 0:
            # Show error message from server
            try:
                err = json.loads(body_text)
                result += f" error={err.get('errorMessage', body_text[:80])}"
            except:
                result += f" body={body_text[:80]}"
        else:
            result += f" error={body_text[:80]}"

        print(f"  [{name}] -> {sig[:16]}... -> {result}")
        results.append((name, status, sig, preimage[:100]))

        if status == 200:
            print(f"\n*** FOUND WORKING FORMULA: {name} ***")
            print(f"Preimage: {preimage[:120]}")
            break

        time.sleep(0.5)  # Rate limiting

    print("\n" + "=" * 70)
    print("All results:")
    for name, status, sig, preimg in results:
        status_str = "OK" if status == 200 else f"ERR({status})"
        print(f"  [{status_str}] {name}: preimage={preimg[:80]}...")

    # Also test: what if the key is something else?
    # Try MD5 of just the date string (no key) to check
    print("\n--- Sanity check: no-signature strategy ---")
    status, body_text = try_login(config, date_str, None, encoded_body)
    print(f"  No signature: HTTP {status}")
    if status != 200:
        try:
            err = json.loads(body_text)
            print(f"  Error: {err.get('errorMessage', body_text[:100])}")
        except:
            print(f"  Body: {body_text[:100]}")

if __name__ == "__main__":
    main()
