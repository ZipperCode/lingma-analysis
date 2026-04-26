"""Forge authenticated API requests using extracted auth tokens."""
import hashlib
import hmac
import base64
import json
import time
import requests
from urllib.parse import urlparse

# Auth tokens from HTML
SECURITY_OAUTH_TOKEN = "pt-SpgVj8cEmNKy09m8cXUpGpwg"
REFRESH_TOKEN = "rt-J6C5hybLMOeykNndfoJOn9bo"
USER_ID = "5930676910898027"
MACHINE_ID = "35346164-3866-492d-a339-30773a32652d"

# Signing secrets
SECRET_FULL = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTed2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==9f1dff714a390b20aeb19175ecc496e6"
SECRET_PREFIX = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"

BASE_URL = "https://lingma.alibabacloud.com"

def get_timestamp():
    """Format time as Go requires: Mon, 02 Jan 2006 15:04:05 GMT"""
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def compute_signature_variants(date_str: str, endpoint: str):
    """Compute signature using different possible string-to-sign formats."""
    variants = {}

    # Variant 1: secret + date + endpoint (concatenation)
    s1 = SECRET_FULL + date_str + endpoint
    variants['concat_full'] = sha256_hex(s1)

    # Variant 2: prefix + date + endpoint
    s2 = SECRET_PREFIX + date_str + endpoint
    variants['concat_prefix'] = sha256_hex(s2)

    # Variant 3: HMAC-SHA256 with secret as key, date+endpoint as message
    msg3 = (date_str + endpoint).encode('utf-8')
    variants['hmac_full'] = hmac.new(SECRET_FULL.encode(), msg3, hashlib.sha256).hexdigest()
    variants['hmac_prefix'] = hmac.new(SECRET_PREFIX.encode(), msg3, hashlib.sha256).hexdigest()

    # Variant 4: date first
    s4 = date_str + SECRET_FULL + endpoint
    variants['date_first'] = sha256_hex(s4)

    # Variant 5: endpoint + date + secret
    s5 = endpoint + date_str + SECRET_FULL
    variants['endpoint_first'] = sha256_hex(s5)

    return variants

def try_auth_headers(session, method, url, date_str, signature):
    """Try various authentication header combinations."""
    headers_base = {
        "Date": date_str,
        "Signature": signature,
        "Appcode": "cosy",
        "Content-Type": "application/json",
        "User-Agent": "Lingma/2.11.1",
    }

    auth_variants = [
        {"name": "Bearer + Sign", "headers": {
            **headers_base,
            "Authorization": f"Bearer {SECURITY_OAUTH_TOKEN}",
        }},
        {"name": "Cosy-Machine-Token", "headers": {
            **headers_base,
            "Cosy-Machine-Token": SECURITY_OAUTH_TOKEN,
        }},
        {"name": "X-Security-Token", "headers": {
            **headers_base,
            "X-Security-Token": SECURITY_OAUTH_TOKEN,
        }},
        {"name": "Token + Machine-Token", "headers": {
            **headers_base,
            "Token": SECURITY_OAUTH_TOKEN,
            "Cosy-Machine-Token": MACHINE_ID,
        }},
        {"name": "Machine-ID header", "headers": {
            **headers_base,
            "X-Machine-Id": MACHINE_ID,
            "X-User-Id": USER_ID,
        }},
        {"name": "Cookie style", "headers": {
            **headers_base,
            "Cookie": f"security_oauth_token={SECURITY_OAUTH_TOKEN}",
        }},
        {"name": "AppAuth style", "headers": {
            **headers_base,
            "Authorization": f"AppAuth {SECURITY_OAUTH_TOKEN}:{MACHINE_ID}",
        }},
    ]

    results = []
    for variant in auth_variants:
        if method == "GET":
            resp = session.get(url, headers=variant["headers"], timeout=10)
        else:
            resp = session.post(url, headers=variant["headers"], json={}, timeout=10)

        results.append({
            "name": variant["name"],
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:200],
        })

        if resp.status_code == 200:
            print(f"  [SUCCESS] {variant['name']} - HTTP {resp.status_code}")
            print(f"  Response: {resp.text[:300]}")
            return results, True

    return results, False

def main():
    session = requests.Session()

    endpoints_to_test = [
        ("GET", f"{BASE_URL}/algo/api/v1/ping"),
        ("POST", f"{BASE_URL}/algo/api/v1/heartbeat"),
        ("POST", f"{BASE_URL}/algo/api/v1/tracking"),
        ("GET", f"{BASE_URL}/algo/api/v1/user/quota"),
        ("GET", f"{BASE_URL}/algo/api/v1/user/info"),
    ]

    for method, url in endpoints_to_test:
        print(f"\n{'='*70}")
        print(f"{method} {url}")
        print(f"{'='*70}")

        endpoint_path = url.replace(BASE_URL, "")
        date_str = get_timestamp()
        sig_variants = compute_signature_variants(date_str, endpoint_path)

        found_success = False
        for sig_name, signature in sig_variants.items():
            results, success = try_auth_headers(session, method, url, date_str, signature)
            if success:
                found_success = True
                break

            # Print the best result (highest status or most informative)
            if not found_success and sig_name == 'concat_full':
                for r in results:
                    detail = ""
                    if r['status'] == 403:
                        detail = " (403 Forbidden)"
                    elif r['status'] == 401:
                        detail = " (401 Unauthorized)"
                    elif r['status'] == 404:
                        detail = " (404 Not Found)"
                    print(f"  [{r['status']}] {r['name']}{detail}")
                    if r['status'] not in (403, 401, 404, 200):
                        print(f"    Body: {r['body'][:150]}")

    # Also try without any signature, just auth tokens
    print(f"\n{'='*70}")
    print("Testing auth tokens WITHOUT signature")
    print(f"{'='*70}")

    for method, url in endpoints_to_test:
        print(f"\n{method} {url}")
        date_str = get_timestamp()
        headers_no_sign = {
            "Date": date_str,
            "Content-Type": "application/json",
            "User-Agent": "Lingma/2.11.1",
            "Authorization": f"Bearer {SECURITY_OAUTH_TOKEN}",
        }

        if method == "GET":
            resp = session.get(url, headers=headers_no_sign, timeout=10)
        else:
            resp = session.post(url, headers=headers_no_sign, json={}, timeout=10)

        print(f"  Status: {resp.status_code}")
        if resp.status_code == 200:
            print(f"  Response: {resp.text[:300]}")
        elif resp.status_code not in (403, 401, 404):
            print(f"  Body: {resp.text[:200]}")

if __name__ == "__main__":
    main()
