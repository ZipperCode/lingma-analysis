"""Try to exchange OAuth tokens for API access via login flow endpoints."""
import requests
import json
import time

SECURITY_OAUTH_TOKEN = "pt-SpgVj8cEmNKy09m8cXUpGpwg"
REFRESH_TOKEN = "rt-J6C5hybLMOeykNndfoJOn9bo"
USER_ID = "5930676910898027"
MACHINE_ID = "35346164-3866-492d-a339-30773a32652d"

# Try the web-based API endpoints
WEB_BASE = "https://lingma.alibabacloud.com"

def test_web_endpoints():
    session = requests.Session()

    # First, get a session cookie from the web
    print("[1] Getting web session...")
    resp = session.get(f"{WEB_BASE}/lingma/login", timeout=10)
    print(f"  Status: {resp.status_code}")
    print(f"  Cookies: {dict(session.cookies)}")

    # Try to use the securityOauthToken directly
    print("\n[2] Testing web API endpoints with Bearer token...")

    web_endpoints = [
        ("GET", f"{WEB_BASE}/lingma/api/v1/user/info"),
        ("GET", f"{WEB_BASE}/api/v1/user/info"),
        ("GET", f"{WEB_BASE}/lingma/api/user/info"),
        ("POST", f"{WEB_BASE}/lingma/api/v1/chat"),
        ("GET", f"{WEB_BASE}/api/v1/auth/check"),
    ]

    headers = {
        "Authorization": f"Bearer {SECURITY_OAUTH_TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }

    for method, url in web_endpoints:
        try:
            if method == "GET":
                resp = session.get(url, headers=headers, timeout=10)
            else:
                resp = session.post(url, headers=headers, json={"test": True}, timeout=10)
            print(f"  [{resp.status_code}] {method} {url.replace(WEB_BASE, '')}")
            if resp.status_code == 200:
                print(f"    Response: {resp.text[:300]}")
        except Exception as e:
            print(f"  [Error] {method} {url.replace(WEB_BASE, '')}: {e}")

    # Try to refresh the token
    print("\n[3] Trying token refresh...")
    try:
        resp = session.post(f"{WEB_BASE}/lingma/api/v1/token/refresh",
                          headers=headers,
                          json={"refreshToken": REFRESH_TOKEN},
                          timeout=10)
        print(f"  Status: {resp.status_code}")
        print(f"  Body: {resp.text[:300]}")
    except Exception as e:
        print(f"  Error: {e}")

    # Try the heartbeat with session cookies
    print("\n[4] Testing /heartbeat with web session cookies...")
    date_str = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    heartbeat_headers = {
        "Date": date_str,
        "Content-Type": "application/json",
        "User-Agent": "Lingma/2.11.1",
        "Authorization": f"Bearer {SECURITY_OAUTH_TOKEN}",
    }
    try:
        resp = session.post(f"{WEB_BASE}/algo/api/v1/heartbeat",
                          headers=heartbeat_headers, json={}, timeout=10)
        print(f"  Status: {resp.status_code}")
        print(f"  Headers: {dict(resp.headers)}")
        print(f"  Body: {resp.text[:200]}")
    except Exception as e:
        print(f"  Error: {e}")

if __name__ == "__main__":
    test_web_endpoints()
