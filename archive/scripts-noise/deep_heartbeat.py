"""Deep analysis of the 403 response from /heartbeat."""
import requests
import json
import time

SECURITY_OAUTH_TOKEN = "pt-SpgVj8cEmNKy09m8cXUpGpwg"
REFRESH_TOKEN = "rt-J6C5hybLMOeykNndfoJOn9bo"
USER_ID = "5930676910898027"
MACHINE_ID = "35346164-3866-492d-a339-30773a32652d"

def test_heartbeat(session, headers, name):
    """Test /heartbeat with specific headers."""
    url = "https://lingma.alibabacloud.com/algo/api/v1/heartbeat"
    date_str = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

    base_headers = {
        "Date": date_str,
        "Content-Type": "application/json",
        "User-Agent": "Lingma/2.11.1",
    }
    base_headers.update(headers)

    body = json.dumps({})

    try:
        resp = session.post(url, headers=base_headers, data=body, timeout=10)
        print(f"\n{'='*60}")
        print(f"[{name}] Status: {resp.status_code}")
        print(f"Request headers:")
        for k, v in base_headers.items():
            if k.lower() in ('date', 'content-type', 'user-agent', 'cosy-user',
                           'authorization', 'cosy-machinetoken', 'cosy-key',
                           'cosy-date', 'x-machine-id', 'cookie', 'token'):
                print(f"  {k}: {v}")
        print(f"Response headers:")
        for k, v in resp.headers.items():
            if k.lower() in ('entry-timestamp', 'entry-signature', 'x-request-id',
                           'content-type', 'set-cookie', 'www-authenticate'):
                print(f"  {k}: {v}")
        print(f"Response body: {resp.text[:300]}")
        return resp.status_code
    except Exception as e:
        print(f"\n[{name}] Error: {e}")
        return 0

def main():
    session = requests.Session()

    # Test various header combinations
    variants = [
        # Variant 1: Bearer only
        {"Authorization": f"Bearer {SECURITY_OAUTH_TOKEN}"},

        # Variant 2: Bearer + Cosy-User
        {"Authorization": f"Bearer {SECURITY_OAUTH_TOKEN}",
         "Cosy-User": USER_ID},

        # Variant 3: Bearer + Cosy-MachineToken
        {"Authorization": f"Bearer {SECURITY_OAUTH_TOKEN}",
         "Cosy-MachineToken": SECURITY_OAUTH_TOKEN},

        # Variant 4: Bearer + Cosy-MachineToken (machine_id)
        {"Authorization": f"Bearer {SECURITY_OAUTH_TOKEN}",
         "Cosy-MachineToken": MACHINE_ID},

        # Variant 5: Cosy-MachineToken only
        {"Cosy-MachineToken": SECURITY_OAUTH_TOKEN},

        # Variant 6: Bearer + Cosy-User + Cosy-MachineToken
        {"Authorization": f"Bearer {SECURITY_OAUTH_TOKEN}",
         "Cosy-User": USER_ID,
         "Cosy-MachineToken": SECURITY_OAUTH_TOKEN},

        # Variant 7: All headers
        {"Authorization": f"Bearer {SECURITY_OAUTH_TOKEN}",
         "Cosy-User": USER_ID,
         "Cosy-MachineToken": SECURITY_OAUTH_TOKEN,
         "Cosy-Date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())},

        # Variant 8: Token header style
        {"Token": SECURITY_OAUTH_TOKEN},

        # Variant 9: X-Token
        {"X-Token": SECURITY_OAUTH_TOKEN},

        # Variant 10: Cookie with session
        {"Cookie": f"security_oauth_token={SECURITY_OAUTH_TOKEN}"},
    ]

    for i, headers in enumerate(variants):
        test_heartbeat(session, headers, f"V{i+1}")

    # Also try with proper heartbeat body
    print(f"\n{'='*60}")
    print("Trying with proper heartbeat body")
    print(f"{'='*60}")

    url = "https://lingma.alibabacloud.com/algo/api/v1/heartbeat"
    date_str = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

    # Try various body formats
    bodies = [
        json.dumps({"machineId": MACHINE_ID, "userId": USER_ID}),
        json.dumps({"token": SECURITY_OAUTH_TOKEN}),
        json.dumps({"type": "heartbeat"}),
        json.dumps({"ping": True}),
        "{}",
    ]

    for j, body in enumerate(bodies):
        headers = {
            "Date": date_str,
            "Content-Type": "application/json",
            "User-Agent": "Lingma/2.11.1",
            "Authorization": f"Bearer {SECURITY_OAUTH_TOKEN}",
            "Cosy-User": USER_ID,
            "Cosy-MachineToken": SECURITY_OAUTH_TOKEN,
        }
        try:
            resp = session.post(url, headers=headers, data=body, timeout=10)
            print(f"\nBody {j+1}: {body[:80]}")
            print(f"  Status: {resp.status_code}")
            if resp.status_code == 200:
                print(f"  Response: {resp.text[:300]}")
        except Exception as e:
            print(f"\nBody {j+1} Error: {e}")

if __name__ == "__main__":
    main()
