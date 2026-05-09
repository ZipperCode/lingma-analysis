"""Try GET requests and different endpoints."""
import hashlib
import hmac
import time
import json
from datetime import datetime, timezone
import urllib.request

def get_http_date():
    return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

SECRET_FULL = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTed2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==9f1dff714a390b20aeb19175ecc496e6"
SECRET_PREFIX = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"

ENDPOINTS = [
    "https://lingma.alibabacloud.com/algo/api/v1/ping",
    "https://lingma-api.tongyi.aliyun.com/algo/api/v1/ping",
    "https://lingma.alibabacloud.com/algo/api/v1/service/next_edit_predict",
]

def compute_sig(date_str, endpoint, secret, use_hmac=True):
    to_sign = f"{date_str}{endpoint}"
    if use_hmac:
        return hmac.new(secret.encode(), to_sign.encode(), hashlib.sha256).hexdigest()
    else:
        return hashlib.sha256((secret + to_sign).encode()).hexdigest()

def try_request(url, date_str, sig, method="GET"):
    headers = {
        "Date": date_str,
        "Signature": sig,
        "Appcode": "cosy",
    }

    req = urllib.request.Request(url, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode('utf-8', errors='replace')[:1000]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='replace')[:1000]
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"

def main():
    date_str = get_http_date()

    print("=" * 70)
    print("GET Request Tests")
    print("=" * 70)

    for url in ENDPOINTS:
        print(f"\n{'='*60}")
        print(f"URL: {url}")
        print(f"{'='*60}")

        for secret_name, secret, use_hmac in [
            ("full_secret HMAC", SECRET_FULL, True),
            ("full_secret SHA", SECRET_FULL, False),
            ("prefix HMAC", SECRET_PREFIX, True),
            ("prefix SHA", SECRET_PREFIX, False),
        ]:
            sig = compute_sig(date_str, url, secret, use_hmac)
            status, body = try_request(url, date_str, sig)
            print(f"\n  [{secret_name}] Status: {status}")
            if status != 404:
                print(f"    Body: {body[:300]}")

            time.sleep(0.5)

        # Also try without any signature
        print(f"\n  [no signature]")
        status, body = try_request(url, date_str, "")
        print(f"    Status: {status}")
        print(f"    Body: {body[:300]}")

        # Try with just Date header
        print(f"\n  [Date only, no Signature]")
        req_headers = {"Date": date_str, "Appcode": "cosy"}
        req = urllib.request.Request(url, headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                print(f"    Status: {resp.status}")
                print(f"    Body: {resp.read().decode('utf-8', errors='replace')[:300]}")
        except urllib.error.HTTPError as e:
            print(f"    Status: {e.code}")
            print(f"    Body: {e.read().decode('utf-8', errors='replace')[:300]}")
        except Exception as e:
            print(f"    Error: {e}")

        time.sleep(1)

if __name__ == '__main__':
    main()
