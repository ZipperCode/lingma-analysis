#!/usr/bin/env python3
"""Test if machine_id serves as OAuth client_id by constructing authorize URL."""
import secrets, base64, hashlib, urllib.parse, webbrowser
import urllib3
urllib3.disable_warnings()
import requests

machine_id = "35346164-3866-492d-a339-30773a32652d"

# Generate PKCE
verifier = secrets.token_urlsafe(32)[:43]
digest = hashlib.sha256(verifier.encode()).digest()
challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

state = "test-" + secrets.token_hex(8)

print("=== Testing OAuth Authorize Endpoint with machine_id as client_id ===\n")

# Test 1: machine_id as client_id
test_urls = {
    "machine_id": f"https://signin.alibabacloud.com/oauth2/v1/auth?response_type=code&client_id={machine_id}&redirect_uri=http://localhost:37510&scope=openid+aliuid+profile&state={state}&code_challenge={challenge}&code_challenge_method=S256",
}

for label, url in test_urls.items():
    print(f"--- {label} ---")
    print(f"URL: {url[:180]}...")
    r = requests.get(url, allow_redirects=False, timeout=15, verify=False)
    print(f"Status: {r.status_code}")
    loc = r.headers.get("Location", "")
    if loc:
        print(f"Location: {loc[:200]}")
    # Check if it's redirecting to login (valid client) or showing error
    content = r.text[:500] if r.text else ""
    if "error" in content.lower() or "invalid" in content.lower():
        error_lines = [l for l in content.split("\n") if "error" in l.lower() or "invalid" in l.lower()]
        print(f"ERROR: {' | '.join(error_lines[:3])}")
    elif r.status_code == 302:
        print("REDIRECT — client_id ACCEPTED!")
    elif r.status_code == 200:
        # Check if it's a login page (valid) or error page
        if "login" in content.lower() or "sign" in content.lower():
            print("Login page — client_id seems valid!")
        else:
            print(f"Page content: {content[:200]}")
    print()

# Also construct the Lingma-correct authorize URL format
print("=== Constructed Authorize URL for Browser ===")
auth_url = f"https://signin.alibabacloud.com/oauth2/v1/auth?response_type=code&client_id={machine_id}&redirect_uri=http://localhost:37510&scope=openid+aliuid+profile&state={state}&code_challenge={challenge}&code_challenge_method=S256"
print(auth_url)
print()
print("You can open this URL in browser to test if machine_id is the client_id.")
print("If redirected to login page → machine_id IS the client_id")
print("If error page → machine_id is NOT the client_id")
