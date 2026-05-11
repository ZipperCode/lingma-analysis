"""Test v3 SIGN mode API — correct HttpPayload body format from IDA analysis.

KEY FINDING: v3 API body is NOT raw AuthQueryParam JSON.
It's wrapped in HttpPayload: {"RequestId":"","Payload":"<escaped JSON>","EncodeVersion":"1"}
Then the whole thing is Encode=1 encoded.

SIGN mode: MD5("cosy&" + COSY_KEY + "&" + RFC1123_date)
URL: /algo/api/v3/user/status?Encode=1
"""
import base64
import hashlib
import json
import math
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

# Constants from IDA
COSY_KEY = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="

# Encode=1 alphabet and helpers (from lingma_remote_api.py)
ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def _custom_b64_encode(data: bytes) -> str:
    std = base64.b64encode(data).decode().rstrip('=')
    return ''.join(ALPHA[STD_B64.index(c)] for c in std)


def lingma_encode(data: bytes) -> str:
    encoded = _custom_b64_encode(data)
    E = len(encoded)
    BS = math.ceil(E / 3)
    pad = (4 - E % 4) % 4
    b0, b1, b2 = encoded[:BS], encoded[BS:2*BS], encoded[2*BS:]
    return b2 + '$' * pad + b1 + b0


def rfc1123_date() -> str:
    """RFC1123 date in English (avoid locale issues on Windows)."""
    days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
              'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    now = datetime.now(timezone.utc)
    return f'{days[now.weekday()]}, {now.day:02d} {months[now.month-1]} {now.year} {now.hour:02d}:{now.minute:02d}:{now.second:02d} GMT'


def make_sign_signature(date_str: str) -> str:
    """SIGN mode: MD5("cosy&" + COSY_KEY + "&" + date)"""
    preimage = f"cosy&{COSY_KEY}&{date_str}"
    return hashlib.md5(preimage.encode()).hexdigest()


def load_credentials():
    """Load credentials from local cache."""
    lingma_dir = Path.home() / '.lingma'
    cache_id = lingma_dir / 'cache' / 'id'
    cache_user = lingma_dir / 'cache' / 'user'

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    with open(cache_id, 'r') as f:
        machine_id = f.read().strip()

    with open(cache_user, 'rb') as f:
        encrypted = base64.b64decode(f.read().strip())

    key = machine_id[:16].encode('utf-8')
    cipher = Cipher(algorithms.AES(key), modes.CBC(key))
    dec = cipher.decryptor()
    decrypted = dec.update(encrypted) + dec.finalize()
    decrypted = decrypted[:-decrypted[-1]]
    user_data = json.loads(decrypted.decode('utf-8'))

    config_path = lingma_dir / 'portable_config.json'
    with open(config_path, 'r') as f:
        config = json.load(f)

    return {
        'machine_id': machine_id,
        'user_id': str(user_data['uid']),
        'cosy_key': user_data['key'],
        'encrypt_user_info': user_data['encrypt_user_info'],
        'pt_token': config.get('security_oauth_token', ''),
        'rt_token': config.get('refresh_token', ''),
    }


def build_auth_query_param(creds: dict) -> str:
    """Build AuthQueryParam JSON (inner payload for HttpPayload).
    Fields from IDA: fetchAuthStatusWithUri @ 0x141a1f260
    AuthInfo struct has UserName and OrgId (not CustomAuthType/CustomAuthData).
    """
    obj = {
        "Ak": "",
        "Sk": "",
        "SecurityToken": "",
        "UserId": creds['user_id'],
        "OrgId": "",
        "Token": "",
        "PersonalToken": "",
        "SecurityOauthToken": creds['pt_token'],
        "RefreshToken": creds['rt_token'],
        "NeedRefresh": False,
        "AuthInfo": {"UserName": "", "OrgId": ""},
    }
    return json.dumps(obj, separators=(',', ':'), ensure_ascii=False)


def build_http_payload(auth_query_json: str) -> bytes:
    """Build HttpPayload JSON body (outer wrapper).
    From IDA: HttpPayload struct {RequestId, Payload, EncodeVersion}
    encodeRequestBody marshals this to JSON, then Encode=1 encodes it.
    """
    payload_obj = {
        "RequestId": "",
        "Payload": auth_query_json,
        "EncodeVersion": "1",
    }
    return json.dumps(payload_obj, separators=(',', ':'), ensure_ascii=False).encode()


def test_v3_user_status():
    """Test /algo/api/v3/user/status with SIGN mode + HttpPayload body."""
    creds = load_credentials()
    date_str = rfc1123_date()
    sig = make_sign_signature(date_str)

    print(f"Date: {date_str}")
    print(f"Signature: {sig}")
    print(f"Machine ID: {creds['machine_id']}")
    print(f"User ID: {creds['user_id']}")
    print(f"PT Token: {creds['pt_token'][:20]}...")
    print()

    # Build the correct body: AuthQueryParam -> HttpPayload -> Encode=1
    auth_query_json = build_auth_query_param(creds)
    print(f"AuthQueryParam JSON:\n  {auth_query_json[:200]}...")
    print()

    http_payload_json = build_http_payload(auth_query_json)
    print(f"HttpPayload JSON length: {len(http_payload_json)} bytes")
    print(f"HttpPayload JSON:\n  {http_payload_json.decode()[:300]}...")
    print()

    # Encode=1 the HttpPayload JSON
    encoded_body = lingma_encode(http_payload_json)
    print(f"Encoded body length: {len(encoded_body)}")
    print()

    url = "https://lingma.alibabacloud.com/algo/api/v3/user/status?Encode=1"

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Accept-Encoding': 'gzip',
        'Cosy-MachineId': creds['machine_id'],
        'Cosy-MachineToken': '',
        'Cosy-MachineType': '',
        'Cosy-MachineCode': '',
        'Cosy-MachineOS': 'x86_64_windows',
        'Cosy-ClientType': '2',
        'Cosy-Data-Policy': '',
        'Date': date_str,
        'Signature': sig,
        'Appcode': 'cosy',
    }

    cmd = ['curl', '-s', '--compressed', '--max-time', '30', '-X', 'POST']
    for k, v in headers.items():
        cmd.extend(['-H', f'{k}: {v}'])
    cmd.extend(['-d', encoded_body, url])

    print("=== Test 1: POST /api/v3/user/status (SIGN + HttpPayload + Encode=1) ===")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
    print(f"Exit code: {result.returncode}")
    print(f"Response: {result.stdout[:1000]}")
    if result.stderr:
        print(f"Stderr: {result.stderr[:200]}")
    print()

    # Test 2: user/login with same body format
    url2 = "https://lingma.alibabacloud.com/algo/api/v3/user/login?Encode=1"
    cmd2 = ['curl', '-s', '--compressed', '--max-time', '30', '-X', 'POST']
    for k, v in headers.items():
        cmd2.extend(['-H', f'{k}: {v}'])
    cmd2.extend(['-d', encoded_body, url2])

    print("=== Test 2: POST /api/v3/user/login (SIGN + HttpPayload + Encode=1) ===")
    result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=40)
    print(f"Exit code: {result2.returncode}")
    print(f"Response: {result2.stdout[:1000]}")
    print()

    # Test 3: grantAuthInfos
    url3 = "https://lingma.alibabacloud.com/algo/api/v3/user/grantAuthInfos?Encode=1"
    cmd3 = ['curl', '-s', '--compressed', '--max-time', '30', '-X', 'POST']
    for k, v in headers.items():
        cmd3.extend(['-H', f'{k}: {v}'])
    cmd3.extend(['-d', encoded_body, url3])

    print("=== Test 3: POST /api/v3/user/grantAuthInfos (SIGN + HttpPayload + Encode=1) ===")
    result3 = subprocess.run(cmd3, capture_output=True, text=True, timeout=40)
    print(f"Exit code: {result3.returncode}")
    print(f"Response: {result3.stdout[:1000]}")
    print()

    # Test 4: Without Encode=1 wrapper (raw HttpPayload JSON, no encoding)
    url4 = "https://lingma.alibabacloud.com/algo/api/v3/user/status"
    cmd4 = ['curl', '-s', '--compressed', '--max-time', '30', '-X', 'POST']
    for k, v in headers.items():
        cmd4.extend(['-H', f'{k}: {v}'])
    cmd4.extend(['-d', http_payload_json.decode(), url4])

    print("=== Test 4: POST /api/v3/user/status (SIGN + raw HttpPayload JSON, no Encode=1) ===")
    result4 = subprocess.run(cmd4, capture_output=True, text=True, timeout=40)
    print(f"Exit code: {result4.returncode}")
    print(f"Response: {result4.stdout[:1000]}")


if __name__ == '__main__':
    test_v3_user_status()
