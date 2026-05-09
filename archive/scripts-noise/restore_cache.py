"""Restore Lingma cache/user file for logged-in state."""
import json
import base64
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

CACHE_DIR = os.path.expandvars(r"C:\Users\Zipper\.lingma\cache")

# Read machine_id
with open(os.path.join(CACHE_DIR, "id"), 'r') as f:
    machine_id = f.read().strip()
print(f"[*] machine_id: {machine_id}")

# Construct user data from known credentials
user_data = {
    "uid": "5930676910898027",
    "security_oauth_token": "pt-QoxY0qTLwr0iWoDKMlp8c8gs",
    "refresh_token": "rt-wXpF3nnbryRWQXadBQUWG6aD",
    "expire_time": 1782390753307,
    "key": "WowHsKF0eZROKgQxGhk4",  # cosy_key
    "encrypt_user_info": {
        "name": "zhang640@blny.de",
        "email": "zhang640@blny.de"
    }
}

# Encrypt and write
key = machine_id[:16].encode('utf-8')
plaintext = json.dumps(user_data, ensure_ascii=False).encode('utf-8')
cipher = AES.new(key, AES.MODE_CBC, iv=key)
encrypted = cipher.encrypt(pad(plaintext, 16))
encoded = base64.b64encode(encrypted)

user_path = os.path.join(CACHE_DIR, "user")
with open(user_path, 'wb') as f:
    f.write(encoded)

print(f"[*] Written {len(encoded)} bytes to {user_path}")
print(f"[*] Tokens restored!")
