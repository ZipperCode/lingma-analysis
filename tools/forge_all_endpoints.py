"""Test all discovered endpoints with the discovered header format."""
import requests
import time
import json

# Auth tokens from HTML
SECURITY_OAUTH_TOKEN = "pt-SpgVj8cEmNKy09m8cXUpGpwg"
REFRESH_TOKEN = "rt-J6C5hybLMOeykNndfoJOn9bo"
USER_ID = "5930676910898027"
MACHINE_ID = "35346164-3866-492d-a339-30773a32652d"

BASE_URL = "https://lingma.alibabacloud.com"

def get_timestamp():
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

def make_request(session, method, url, extra_headers=None, body=None):
    """Make request with discovered headers."""
    date_str = get_timestamp()

    headers = {
        "Date": date_str,
        "Content-Type": "application/json",
        "User-Agent": "Lingma/2.11.1",
        "Accept": "application/json",
        "Cosy-User": USER_ID,
        "Authorization": f"Bearer {SECURITY_OAUTH_TOKEN}",
    }
    if extra_headers:
        headers.update(extra_headers)

    try:
        if method == "GET":
            resp = session.get(url, headers=headers, timeout=10)
        elif method == "POST":
            if body is None:
                body = {}
            resp = session.post(url, headers=headers, json=body, timeout=10)

        # Parse response
        info = {
            "status": resp.status_code,
            "headers": {},
            "body": resp.text[:500] if resp.text else "",
        }
        for h in ["entry-timestamp", "entry-signature", "x-request-id", "content-type", "set-cookie"]:
            if h in resp.headers:
                info["headers"][h] = resp.headers[h]

        return info
    except Exception as e:
        return {"status": 0, "error": str(e)}

def main():
    session = requests.Session()

    # All discovered endpoints
    endpoints = [
        # /algo API endpoints
        ("GET", f"{BASE_URL}/algo/api/v1/ping"),
        ("POST", f"{BASE_URL}/algo/api/v1/heartbeat"),
        ("POST", f"{BASE_URL}/algo/api/v1/tracking"),
        ("GET", f"{BASE_URL}/algo/api/v1/organizations"),

        # Service endpoints
        ("GET", f"{BASE_URL}/algo/api/v1/service/stilla"),
        ("POST", f"{BASE_URL}/algo/api/v1/service/next_edit_predict"),
        ("GET", f"{BASE_URL}/algo/api/v1/service/feedback"),
        ("GET", f"{BASE_URL}/algo/api/v1/service/back_flow"),
        ("GET", f"{BASE_URL}/algo/api/v1/service/network/diagnosis"),
        ("GET", f"{BASE_URL}/algo/api/v1/service/sync/definition"),

        # Direct completion endpoint
        ("POST", f"{BASE_URL}/algo/api/v1/complete/messages"),
        ("POST", f"{BASE_URL}/algo/api/v1/inlineEdit"),
        ("POST", f"{BASE_URL}/algo/api/v1/next_edit"),
        ("POST", f"{BASE_URL}/algo/api/v1/next_edit_predict"),

        # Qoder endpoints (found in config)
        ("GET", f"{BASE_URL}/algo/api/v1/user/info"),
        ("GET", f"{BASE_URL}/algo/api/v1/user/quota"),
    ]

    # First try without signature
    print("=" * 80)
    print("TEST 1: With Cosy-User + Authorization Bearer, NO signature")
    print("=" * 80)

    for method, url in endpoints:
        info = make_request(session, method, url)
        status_str = "OK" if info["status"] == 200 else f'HTTP {info["status"]}'
        print(f"  [{status_str}] {method} {url.replace(BASE_URL, '')}")
        if info["status"] == 200:
            print(f"    Body: {info['body'][:200]}")
        elif info["status"] == 403 and "entry-timestamp" in info.get("headers", {}):
            print(f"    Entry-Timestamp: {info['headers']['entry-timestamp']}")
        elif info["status"] == 0:
            print(f"    Error: {info.get('error', 'unknown')}")

    # Now try with Cosy-MachineToken
    print()
    print("=" * 80)
    print("TEST 2: With Cosy-MachineToken header")
    print("=" * 80)

    for method, url in endpoints:
        info = make_request(session, method, url, extra_headers={
            "Cosy-MachineToken": SECURITY_OAUTH_TOKEN,
        })
        status_str = "OK" if info["status"] == 200 else f'HTTP {info["status"]}'
        if info["status"] == 200:
            print(f"  [SUCCESS] {method} {url.replace(BASE_URL, '')}")
            print(f"    Body: {info['body'][:300]}")
            return

    print("  All endpoints returned non-200")

    # Try with Cookie-based auth
    print()
    print("=" * 80)
    print("TEST 3: With cookie-based auth")
    print("=" * 80)

    session2 = requests.Session()
    session2.cookies.set("security_oauth_token", SECURITY_OAUTH_TOKEN, domain=".alibabacloud.com")

    for method, url in endpoints:
        info = make_request(session2, method, url)
        status_str = "OK" if info["status"] == 200 else f'HTTP {info["status"]}'
        if info["status"] == 200:
            print(f"  [SUCCESS] {method} {url.replace(BASE_URL, '')}")
            print(f"    Body: {info['body'][:300]}")
            return

    print("  All endpoints returned non-200")

if __name__ == "__main__":
    main()
