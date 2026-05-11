"""
Lingma V3 API Client — 完全独立的 SIGN 模式客户端.

IDA 逆向分析结果:
- SIGN 签名: MD5("cosy&" + COSY_KEY + "&" + RFC1123_date)
- Body 格式: HttpPayload({RequestId, Payload, EncodeVersion}) 包装 AuthQueryParam
- JSON 字段名: snake_case (重要!)
- Encode=1: 自定义 base64 + 3-block 反转
- COSY 凭据本地生成: RSA-1024 (PKCS1v15) 加密随机 AES key, AES-128-CBC 加密用户 JSON

Usage:
    python lingma_v3_api.py status
    python lingma_v3_api.py login
    python lingma_v3_api.py grants
    python lingma_v3_api.py generate-credentials
    python lingma_v3_api.py test-chat
"""
import base64
import hashlib
import json
import math
import os
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# IDA constants
COSY_KEY = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="

RSA_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----"""

# Encode=1 alphabet
ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


# ─── Encode=1 helpers ───

def _custom_b64_encode(data: bytes) -> str:
    std = base64.b64encode(data).decode().rstrip('=')
    return ''.join(ALPHA[STD_B64.index(c)] for c in std)


def _custom_b64_decode(encoded: str) -> bytes:
    converted = ''.join(STD_B64[ALPHA.index(c)] for c in encoded if c in ALPHA)
    pad = (4 - len(converted) % 4) % 4
    return base64.b64decode(converted + '=' * pad)


def lingma_encode(data: bytes) -> str:
    """Encode=1: custom base64 → 3-block reversal → $ padding"""
    encoded = _custom_b64_encode(data)
    E = len(encoded)
    BS = math.ceil(E / 3)
    pad = (4 - E % 4) % 4
    b0, b1, b2 = encoded[:BS], encoded[BS:2*BS], encoded[2*BS:]
    return b2 + '$' * pad + b1 + b0


def lingma_decode(body: str) -> bytes:
    """Decode Encode=1 body"""
    dollar_start = body.find('$')
    if dollar_start < 0:
        rev = body
        E = len(body)
    else:
        pad = 0
        pos = dollar_start
        while pos < len(body) and body[pos] == '$':
            pad += 1
            pos += 1
        rev = body[:dollar_start] + body[dollar_start + pad:]
        E = len(rev)
    BS = math.ceil(E / 3)
    lb = E - 2 * BS
    b2 = rev[:lb]
    b1 = rev[lb:lb + BS]
    b0 = rev[lb + BS:]
    return _custom_b64_decode(b0 + b1 + b2)


# ─── SIGN mode ───

def rfc1123_date() -> str:
    days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
              'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    now = datetime.now(timezone.utc)
    return f'{days[now.weekday()]}, {now.day:02d} {months[now.month-1]} {now.year} {now.hour:02d}:{now.minute:02d}:{now.second:02d} GMT'


def make_sign_signature(date_str: str) -> str:
    return hashlib.md5(f"cosy&{COSY_KEY}&{date_str}".encode()).hexdigest()


# ─── Credential loading ───

def load_credentials():
    """Load all credentials from local cache + portable config."""
    lingma_dir = Path(os.environ.get('LINGMA_HOME', str(Path.home() / '.lingma')))
    cache_id = lingma_dir / 'cache' / 'id'
    cache_user = lingma_dir / 'cache' / 'user'

    machine_id = ''
    user_data = {}

    if cache_id.exists():
        with open(cache_id, 'r') as f:
            machine_id = f.read().strip()

    if cache_user.exists() and machine_id:
        try:
            with open(cache_user, 'rb') as f:
                encrypted = base64.b64decode(f.read().strip())
            key = machine_id[:16].encode('utf-8')
            cipher = Cipher(algorithms.AES(key), modes.CBC(key))
            dec = cipher.decryptor()
            decrypted = dec.update(encrypted) + dec.finalize()
            decrypted = decrypted[:-decrypted[-1]]
            user_data = json.loads(decrypted.decode('utf-8'))
        except Exception:
            pass

    config = {}
    config_path = lingma_dir / 'portable_config.json'
    if config_path.exists():
        with open(config_path, 'r') as f:
            config = json.load(f)

    return {
        'machine_id': machine_id or config.get('machine_id', ''),
        'user_id': str(user_data.get('uid', config.get('user_id', ''))),
        'name': user_data.get('name', config.get('name', '')),
        'aid': str(user_data.get('aid', config.get('aid', ''))),
        'yx_uid': user_data.get('yx_uid', ''),
        'organization_id': user_data.get('organization_id', ''),
        'organization_name': user_data.get('organization_name', ''),
        'user_type': user_data.get('user_type', 'personal_standard'),
        'cosy_key': user_data.get('key', config.get('cosy_key', '')),
        'encrypt_user_info': user_data.get('encrypt_user_info', config.get('encrypt_user_info', '')),
        'pt_token': user_data.get('security_oauth_token', config.get('security_oauth_token', '')),
        'rt_token': user_data.get('refresh_token', config.get('refresh_token', '')),
        'expire_time': user_data.get('expire_time', config.get('expire_time', 0)),
        'email': user_data.get('email', config.get('email', '')),
        'data_policy_agreed': user_data.get('data_policy_agreed', False),
    }


# ─── V3 API request ───

def build_auth_query_param(creds: dict) -> str:
    """Build AuthQueryParam JSON with snake_case field names (IDA confirmed)."""
    obj = {
        "ak": "",
        "sk": "",
        "security_token": "",
        "user_id": creds['user_id'],
        "org_id": "",
        "token": "",
        "personal_token": "",
        "security_oauth_token": creds['pt_token'],
        "refresh_token": creds['rt_token'],
        "need_refresh": False,
        "auth_info": {"user_name": "", "org_id": ""},
    }
    return json.dumps(obj, separators=(',', ':'), ensure_ascii=False)


def build_http_payload(auth_query_json: str) -> bytes:
    """Build HttpPayload wrapper (IDA: RequestId, Payload, EncodeVersion)."""
    payload_obj = {
        "RequestId": "",
        "Payload": auth_query_json,
        "EncodeVersion": "1",
    }
    return json.dumps(payload_obj, separators=(',', ':'), ensure_ascii=False).encode()


def v3_request(endpoint: str, creds: dict = None, body_modifier=None) -> dict:
    """Send a v3 SIGN mode API request."""
    if creds is None:
        creds = load_credentials()

    date_str = rfc1123_date()
    sig = make_sign_signature(date_str)

    auth_json = build_auth_query_param(creds)
    if body_modifier:
        auth_json = body_modifier(auth_json)

    http_payload = build_http_payload(auth_json)
    encoded_body = lingma_encode(http_payload)

    url = f"https://lingma.alibabacloud.com/algo/api/v3/{endpoint}?Encode=1"

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

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
    try:
        return json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return {'raw': result.stdout, 'error': result.stderr}


# ─── COSY credential generation (SaveUserInfo path) ───

def generate_cosy_credentials(creds: dict):
    """
    Generate COSY credentials locally using SaveUserInfo logic (IDA: 0x14088e260).

    Steps:
    1. Build inner CosyUserInfo JSON (basic fields only, no key/encrypt_user_info)
    2. Generate random UUID → remove hyphens → first 16 chars = AES-128 key
    3. RSA-1024 (PKCS1v15) encrypt the AES key → base64 → cosy_key
    4. AES-128-CBC encrypt the inner JSON with AES key → encrypt_user_info
    """
    # Load RSA public key
    public_key = serialization.load_pem_public_key(RSA_PUBLIC_KEY_PEM.encode())

    # Generate random AES key (UUID without hyphens, first 16 chars)
    aes_key_str = uuid.uuid4().hex[:16]
    aes_key_bytes = aes_key_str.encode('utf-8')

    # Step 1: Build inner CosyUserInfo JSON (matching SaveUserInfo v118)
    # Only the fields that are copied in SaveUserInfo (zeroed first, then 9 fields set)
    inner_user = {
        "name": creds.get('name', ''),
        "aid": creds.get('aid', creds.get('user_id', '')),
        "uid": creds.get('user_id', ''),
        "yx_uid": creds.get('yx_uid', ''),
        "organization_id": creds.get('organization_id', ''),
        "organization_name": creds.get('organization_name', ''),
        "user_type": creds.get('user_type', 'personal_standard'),
        "security_oauth_token": creds.get('pt_token', ''),
        "refresh_token": creds.get('rt_token', ''),
    }
    inner_json = json.dumps(inner_user, separators=(',', ':'), ensure_ascii=False)

    # Step 2: RSA-encrypt the AES key
    encrypted_key = public_key.encrypt(
        aes_key_bytes,
        padding.PKCS1v15()
    )
    cosy_key = base64.b64encode(encrypted_key).decode()

    # Step 3: AES-128-CBC encrypt the inner JSON
    # Go's AesEncryptWithBase64 uses key[:16] as both key and IV
    iv = aes_key_bytes[:16]
    plaintext = inner_json.encode('utf-8')
    # PKCS7 padding
    pad_len = 16 - len(plaintext) % 16
    padded = plaintext + bytes([pad_len] * pad_len)
    cipher = Cipher(algorithms.AES(iv), modes.CBC(iv))
    enc = cipher.encryptor()
    encrypted_user_info = enc.update(padded) + enc.finalize()
    encrypt_user_info = base64.b64encode(encrypted_user_info).decode()

    return {
        'cosy_key': cosy_key,
        'encrypt_user_info': encrypt_user_info,
        'aes_key': aes_key_str,
    }


# ─── Chat API (v2 AUTH mode) ───

def test_chat_with_credentials(cosy_key: str, encrypt_user_info: str, user_id: str, machine_id: str):
    """Test v2 Chat API with given COSY credentials."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from lingma_remote_api import LingmaRemoteAPI

    api = LingmaRemoteAPI(
        cosy_key=cosy_key,
        encrypt_user_info=encrypt_user_info,
        user_id=user_id,
        machine_id=machine_id,
    )

    print("Testing model list...")
    models = api.get_models()
    print(f"  Models: {len(models)}")
    for m in models[:3]:
        print(f"    - {m.get('display_name', '?')} ({m.get('key', '?')})")

    print("Testing chat...")
    response = api.chat('Reply with just the word: Success')
    print(f"  Response: {response[:200]}")

    return models, response


# ─── CLI ───

if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python lingma_v3_api.py [status|login|grants|generate-credentials|test-chat]")
        sys.exit(1)

    cmd = sys.argv[1]
    creds = load_credentials()

    print(f"Machine ID: {creds['machine_id']}")
    print(f"User ID:    {creds['user_id']}")
    print(f"Name:       {creds['name']}")
    print(f"PT Token:   {creds['pt_token'][:20]}...")
    print()

    if cmd == 'status':
        result = v3_request('user/status', creds)
        print("=== User Status ===")
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif cmd == 'login':
        result = v3_request('user/login', creds)
        print("=== User Login ===")
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif cmd == 'grants':
        result = v3_request('user/grantAuthInfos', creds)
        print("=== Grant Auth Infos ===")
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif cmd == 'generate-credentials':
        print("=== Generating COSY Credentials Locally ===")
        gen = generate_cosy_credentials(creds)
        print(f"AES Key (random UUID[:16]): {gen['aes_key']}")
        print(f"cosy_key length: {len(gen['cosy_key'])}")
        print(f"encrypt_user_info length: {len(gen['encrypt_user_info'])}")
        print(f"cosy_key: {gen['cosy_key'][:50]}...")
        print()

        # Verify by decrypting
        print("=== Verification: Decrypting generated credentials ===")
        private_key = serialization.load_pem_public_key(RSA_PUBLIC_KEY_PEM.encode())
        # We can't decrypt without the private key, but we can verify the format
        cosy_key_bytes = base64.b64decode(gen['cosy_key'])
        print(f"RSA encrypted key size: {len(cosy_key_bytes)} bytes (expected 128 for RSA-1024)")
        eui_bytes = base64.b64decode(gen['encrypt_user_info'])
        print(f"AES encrypted user info size: {len(eui_bytes)} bytes")

        # Decrypt with our known AES key to verify
        iv = gen['aes_key'].encode('utf-8')[:16]
        cipher = Cipher(algorithms.AES(iv), modes.CBC(iv))
        dec = cipher.decryptor()
        decrypted = dec.update(eui_bytes) + dec.finalize()
        decrypted = decrypted[:-decrypted[-1]]
        inner = json.loads(decrypted.decode('utf-8'))
        print(f"Decrypted inner JSON: {json.dumps(inner, ensure_ascii=False)}")
        print()

        # Test with Chat API
        print("=== Testing with v2 Chat API ===")
        test_chat_with_credentials(
            gen['cosy_key'], gen['encrypt_user_info'],
            creds['user_id'], creds['machine_id']
        )

    elif cmd == 'test-chat':
        print("=== Testing v2 Chat API with existing credentials ===")
        test_chat_with_credentials(
            creds['cosy_key'], creds['encrypt_user_info'],
            creds['user_id'], creds['machine_id']
        )

    else:
        print(f"Unknown command: {cmd}")
        print("Available: status, login, grants, generate-credentials, test-chat")
