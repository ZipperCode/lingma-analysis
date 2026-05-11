"""
Lingma Token Refresh Module — 三路径 Token 刷新.

IDA 逆向: doRefreshToken (0x14088d660) 使用 v3 SIGN 模式发送
AuthQueryParam → HttpPayload → Encode=1 → POST /api/v3/user/refresh_token

路径:
  A. v3 SIGN 远程刷新 (首选, 完全独立)
  B. OAuth 标准端点 (回退, 需 client_id)
  C. LSP WebSocket 代理 (最后手段, 需 Lingma 运行)

Usage:
    python lingma_token_refresh.py v3          # 路径 A
    python lingma_token_refresh.py v3-domestic # 路径 A 国内版
    python lingma_token_refresh.py oauth       # 路径 B
    python lingma_token_refresh.py lsp         # 路径 C
    python lingma_token_refresh.py auto        # 自动选择
    python lingma_token_refresh.py auto-update # 自动 + 更新凭据文件
"""

import base64
import hashlib
import json
import math
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
import requests

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Re-export from lingma_v3_api
sys.path.insert(0, str(Path(__file__).parent))
from lingma_v3_api import (
    COSY_KEY,
    RSA_PUBLIC_KEY_PEM,
    lingma_encode,
    lingma_decode,
    rfc1123_date,
    make_sign_signature,
    build_auth_query_param,
    build_http_payload,
    load_credentials,
    generate_cosy_credentials,
)

# Endpoints
INTERNATIONAL_URL = "https://lingma.alibabacloud.com/algo/api/v3/user/refresh_token?Encode=1"
DOMESTIC_URL = "https://lingma.cn/algo/api/v3/user/refresh_token?Encode=1"

# LSP WebSocket
LSP_WS_URL = "ws://127.0.0.1:37010"


# ─── Path A: v3 SIGN remote refresh ───

def _v3_build_request(creds: dict, endpoint: str, body_modifier=None,
                      encode: bool = True, method: str = 'POST',
                      extra_headers: dict = None) -> dict:
    """Build v3 SIGN request components (shared by refresh and diagnose)."""
    import requests as req_lib

    date_str = rfc1123_date()
    sig = make_sign_signature(date_str)

    auth_json = build_auth_query_param(creds)
    if body_modifier:
        auth_json = body_modifier(auth_json, creds)

    http_payload = build_http_payload(auth_json)

    if encode:
        body = lingma_encode(http_payload)
        query = '?Encode=1'
    else:
        body = http_payload
        query = ''

    url = f"https://lingma.alibabacloud.com/algo/api/v3/{endpoint}{query}"

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
    if extra_headers:
        headers.update(extra_headers)

    return {
        'url': url, 'headers': headers, 'body': body,
        'method': method, 'date_str': date_str, 'sig': sig,
        'auth_json': auth_json, 'encode': encode,
    }


def _v3_send_request(built: dict, timeout: int = 30) -> dict:
    """Send a built v3 request and return full diagnostics."""
    import requests as req_lib

    url = built['url']
    headers = built['headers']
    body = built['body']
    method = built['method']

    try:
        resp = getattr(req_lib, method.lower())(
            url, data=body.encode('utf-8') if isinstance(body, str) else body,
            headers=headers, timeout=timeout, allow_redirects=False,
        )
    except req_lib.RequestException as e:
        return {
            'success': False, 'error': str(e),
            'status_code': None, 'headers': {}, 'raw': '',
            'parsed': None,
        }

    raw = resp.text
    parsed = None

    # Try Encode=1 decode
    try:
        decoded_bytes = lingma_decode(raw)
        parsed = json.loads(decoded_bytes)
    except Exception:
        pass

    # Try raw JSON
    if parsed is None:
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            pass

    return {
        'status_code': resp.status_code,
        'resp_headers': dict(resp.headers),
        'raw': raw,
        'raw_length': len(raw),
        'parsed': parsed,
        'success': parsed is not None and resp.status_code == 200 and (
            (isinstance(parsed, dict) and (
                parsed.get('Code', '') == '200' or
                parsed.get('success', False) is True or
                'id' in parsed
            )) or isinstance(parsed, list)
        ),
    }


def refresh_token_v3(creds: dict, domestic: bool = False,
                      verbose: bool = True, **kwargs) -> dict:
    """
    v3 SIGN 模式远程刷新 token (IDA: doRefreshToken 0x14088d660).
    使用 Python requests 获取完整 HTTP 诊断信息。
    """
    built = _v3_build_request(creds, 'user/refresh_token', **kwargs)
    if domestic:
        built['url'] = DOMESTIC_URL

    if verbose:
        print(f"[v3] POST {built['url']}")
        print(f"[v3] Date: {built['date_str']}")
        print(f"[v3] Signature: {built['sig']}")
        print(f"[v3] Body length: {len(built['body'])}")
        print(f"[v3] Encode: {built['encode']}")

    result = _v3_send_request(built)

    if verbose:
        print(f"[v3] HTTP {result.get('status_code')}")
        if result.get('resp_headers'):
            for k, v in result['resp_headers'].items():
                print(f"[v3]   {k}: {v}")
        if result.get('raw'):
            print(f"[v3] Body ({result.get('raw_length', 0)} chars): {result['raw'][:300]}")

    return result


# ─── Path B: OAuth standard refresh ───

def refresh_token_oauth(creds: dict, client_id: str = '') -> dict:
    """
    OAuth 标准端点刷新 (POST /v1/token).
    BLOCKED: client_id 由服务端注入, 无法自动获取.
    """
    if not client_id:
        print("[oauth] BLOCKED: client_id is required (server-side secret)")
        print("[oauth] Get it from browser DevTools: Network tab → filter 'oauth'")
        return {'success': False, 'error': 'client_id required'}

    if not creds.get('rt_token'):
        return {'success': False, 'error': 'no refresh_token available'}

    url = "https://oauth.alibabacloud.com/v1/token"
    body = {
        'grant_type': 'refresh_token',
        'refresh_token': creds['rt_token'],
        'client_id': client_id,
    }

    print(f"[oauth] POST {url}")
    print(f"[oauth] grant_type=refresh_token, client_id={client_id[:8]}...")

    cmd = [
        'curl', '-s', '--compressed', '--max-time', '30',
        '-X', 'POST',
        '-H', 'Content-Type: application/x-www-form-urlencoded',
        '-d', f'grant_type=refresh_token&refresh_token={creds["rt_token"]}&client_id={client_id}',
        url,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=40)

    try:
        parsed = json.loads(result.stdout)
        success = 'access_token' in parsed or 'security_oauth_token' in parsed
        return {'raw': result.stdout, 'parsed': parsed, 'success': success}
    except (json.JSONDecodeError, TypeError):
        return {'raw': result.stdout, 'stderr': result.stderr, 'success': False}


# ─── Path C: LSP WebSocket proxy ───

def refresh_token_lsp(creds: dict) -> dict:
    """
    LSP WebSocket 代理刷新 (JSON-RPC auth/refreshToken).
    Requires Lingma to be running on localhost:37010.
    """
    try:
        import websocket
    except ImportError:
        print("[lsp] python-websocket not installed, try: pip install websocket-client")
        return {'success': False, 'error': 'websocket-client not installed'}

    print(f"[lsp] Connecting to {LSP_WS_URL}...")

    try:
        ws = websocket.create_connection(LSP_WS_URL, timeout=10)
    except Exception as e:
        print(f"[lsp] Connection failed: {e}")
        return {'success': False, 'error': str(e)}

    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "auth/refreshToken",
        "params": {
            "uid": creds.get('user_id', ''),
        }
    }

    print(f"[lsp] Sending auth/refreshToken for uid={creds.get('user_id', '')[:8]}...")
    ws.send(json.dumps(request))

    try:
        response = ws.recv()
        ws.close()
    except Exception as e:
        return {'success': False, 'error': f'ws recv failed: {e}'}

    try:
        parsed = json.loads(response)
        result = parsed.get('result', {})
        success = result.get('success', False)
        print(f"[lsp] Response: success={success}")
        if success:
            return {
                'success': True,
                'parsed': result,
                'new_token': result.get('tokenExpireTime', ''),
            }
        return {'success': False, 'parsed': result, 'error': result.get('message', 'unknown')}
    except json.JSONDecodeError:
        return {'raw': response, 'success': False}


# ─── Auto refresh (fallback chain) ───

def auto_refresh(creds: dict = None) -> dict:
    """
    自动刷新: 尝试所有路径, 返回第一个成功的结果.
    """
    if creds is None:
        creds = load_credentials()

    print("=" * 50)
    print("Auto Refresh — trying all paths")
    print("=" * 50)

    # Path A: v3 SIGN (international)
    print("\n--- Path A1: v3 SIGN (international) ---")
    result = refresh_token_v3(creds, domestic=False)
    if result['success']:
        print("[A1] SUCCESS")
        return _finalize(result, 'v3-sign-international', creds)

    print(f"[A1] Failed: {result.get('parsed', result.get('raw', ''))[:200]}")

    # Path A: v3 SIGN (domestic)
    print("\n--- Path A2: v3 SIGN (domestic) ---")
    result = refresh_token_v3(creds, domestic=True)
    if result['success']:
        print("[A2] SUCCESS")
        return _finalize(result, 'v3-sign-domestic', creds)

    print(f"[A2] Failed: {result.get('parsed', result.get('raw', ''))[:200]}")

    # Path C: LSP WebSocket
    print("\n--- Path C: LSP WebSocket proxy ---")
    result = refresh_token_lsp(creds)
    if result['success']:
        print("[C] SUCCESS")
        return _finalize(result, 'lsp-ws', creds)

    print(f"[C] Failed: {result.get('error', 'unknown')}")

    # All paths failed
    print("\n" + "=" * 50)
    print("ALL PATHS FAILED")
    print("Options:")
    print("  1. Re-login: python lingma_oauth_complete.py login")
    print("  2. Get client_id for OAuth refresh from browser DevTools")
    print("  3. Start Lingma for LSP proxy refresh")
    print("=" * 50)

    return {
        'success': False,
        'creds': creds,
        'results': {},
    }


def _finalize(result: dict, method: str, creds: dict) -> dict:
    """Extract new tokens from refresh result."""
    parsed = result.get('parsed', {})

    # v3 SIGN response: {Code, Data: {RefreshToken, SecurityOauthToken, ExpireTime}}
    data = parsed.get('Data', parsed)
    new_rt = data.get('RefreshToken', data.get('refresh_token', ''))
    new_pt = data.get('SecurityOauthToken', data.get('security_oauth_token', ''))
    expire = data.get('ExpireTime', data.get('expire_time', 0))

    # LSP response: {success, uid, name, tokenExpireTime}
    if method.startswith('lsp'):
        # LSP doesn't return tokens directly, need to re-read from cache
        print("[lsp] Refresh triggered locally, re-reading credentials from cache...")
        time.sleep(2)
        new_creds = load_credentials()
        new_pt = new_creds.get('pt_token', '')
        new_rt = new_creds.get('rt_token', '')

    new_tokens = {
        'refresh_token': new_rt,
        'security_oauth_token': new_pt,
        'expire_time': expire,
        'method': method,
    }

    # Regenerate COSY credentials with new tokens
    if new_pt:
        creds_copy = dict(creds)
        creds_copy['pt_token'] = new_pt
        if new_rt:
            creds_copy['rt_token'] = new_rt
        cosy = generate_cosy_credentials(creds_copy)
        new_tokens['cosy_key'] = cosy['cosy_key']
        new_tokens['encrypt_user_info'] = cosy['encrypt_user_info']

    new_tokens['success'] = True
    new_tokens['creds'] = creds
    return new_tokens


# ─── Post-refresh: update config files ───

def update_portable_config(new_tokens: dict, creds: dict) -> bool:
    """Update portable_config.json with new tokens and COSY credentials."""
    lingma_dir = Path(os.environ.get('LINGMA_HOME', str(Path.home() / '.lingma')))
    config_path = lingma_dir / 'portable_config.json'

    config = {}
    if config_path.exists():
        with open(config_path, 'r') as f:
            config = json.load(f)

    if new_tokens.get('security_oauth_token'):
        config['security_oauth_token'] = new_tokens['security_oauth_token']
    if new_tokens.get('refresh_token'):
        config['refresh_token'] = new_tokens['refresh_token']
    if new_tokens.get('expire_time'):
        config['expire_time'] = new_tokens['expire_time']
    if new_tokens.get('cosy_key'):
        config['cosy_key'] = new_tokens['cosy_key']
    if new_tokens.get('encrypt_user_info'):
        config['encrypt_user_info'] = new_tokens['encrypt_user_info']

    config['last_refresh_time'] = datetime.now(timezone.utc).isoformat()
    config['last_refresh_method'] = new_tokens.get('method', 'unknown')

    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print(f"[config] Updated {config_path}")
    return True


def auto_refresh_and_update(creds: dict = None) -> dict:
    """Auto refresh + update portable_config.json."""
    result = auto_refresh(creds)
    if result.get('success'):
        update_portable_config(result, result.get('creds', {}))
    return result


# ─── Diagnose & Variants ───

def diagnose_refresh(creds: dict):
    """Compare user/status (works) vs user/refresh_token (404) side by side."""
    # 1. Status request (baseline, known working)
    print("── [1] user/status (baseline) ──")
    status_built = _v3_build_request(creds, 'user/status')
    status_result = _v3_send_request(status_built)
    print(f"  HTTP {status_result.get('status_code')}")
    print(f"  Body: {status_result.get('raw', '')[:200]}")
    print()

    # 2. Refresh request
    print("── [2] user/refresh_token ──")
    refresh_built = _v3_build_request(creds, 'user/refresh_token')
    refresh_result = _v3_send_request(refresh_built)
    print(f"  HTTP {refresh_result.get('status_code')}")
    print(f"  Body: {refresh_result.get('raw', '')[:200]}")
    print()

    # 3. Compare headers
    print("── [3] Request differences ──")
    print(f"  URL status:  {status_built['url']}")
    print(f"  URL refresh: {refresh_built['url']}")
    print(f"  Same body?   {status_built['body'] == refresh_built['body']}")
    print(f"  Same headers? {status_built['headers'] == refresh_built['headers']}")
    print()

    # 4. Try Encode=1 decode on refresh response
    print("── [4] Decode refresh response ──")
    raw = refresh_result.get('raw', '')
    if raw:
        try:
            decoded = lingma_decode(raw)
            print(f"  Encode=1 decoded: {decoded[:300]}")
        except Exception as e:
            print(f"  Encode=1 decode failed: {e}")
            print(f"  Raw (first 500): {raw[:500]}")
    print()

    # 5. Response headers comparison
    print("── [5] Response headers ──")
    for label, r in [("status", status_result), ("refresh", refresh_result)]:
        print(f"  [{label}]")
        for k, v in r.get('resp_headers', {}).items():
            print(f"    {k}: {v}")
    print()

    return {
        'status': status_result,
        'refresh': refresh_result,
    }


def test_variants(creds: dict):
    """Try request variants to probe why refresh_token returns 404."""
    results = []

    # Variant 1: need_refresh=true
    print("── V1: need_refresh=true ──")
    def set_need_refresh(auth_json, c):
        obj = json.loads(auth_json)
        obj['need_refresh'] = True
        return json.dumps(obj, separators=(',', ':'), ensure_ascii=False)
    r = _v3_send_request(_v3_build_request(creds, 'user/refresh_token', body_modifier=set_need_refresh))
    print(f"  HTTP {r.get('status_code')} | Body: {r.get('raw', '')[:150]}")
    results.append(('need_refresh=true', r))
    print()

    # Variant 2: No Encode=1 (raw JSON body)
    print("── V2: No Encode=1 ──")
    r = _v3_send_request(_v3_build_request(creds, 'user/refresh_token', encode=False))
    print(f"  HTTP {r.get('status_code')} | Body: {r.get('raw', '')[:150]}")
    results.append(('no-encode', r))
    print()

    # Variant 3: PUT method
    print("── V3: PUT method ──")
    r = _v3_send_request(_v3_build_request(creds, 'user/refresh_token', method='PUT'))
    print(f"  HTTP {r.get('status_code')} | Body: {r.get('raw', '')[:150]}")
    results.append(('PUT', r))
    print()

    # Variant 4: Content-Type octet-stream
    print("── V4: Content-Type: application/octet-stream ──")
    r = _v3_send_request(_v3_build_request(
        creds, 'user/refresh_token',
        extra_headers={'Content-Type': 'application/octet-stream'},
    ))
    print(f"  HTTP {r.get('status_code')} | Body: {r.get('raw', '')[:150]}")
    results.append(('octet-stream', r))
    print()

    # Variant 5: Without Cosy-ClientType header
    print("── V5: No Cosy-ClientType ──")
    built = _v3_build_request(creds, 'user/refresh_token')
    built['headers'].pop('Cosy-ClientType', None)
    r = _v3_send_request(built)
    print(f"  HTTP {r.get('status_code')} | Body: {r.get('raw', '')[:150]}")
    results.append(('no-client-type', r))
    print()

    # Variant 6: GET method (some APIs respond differently)
    print("── V6: GET method ──")
    r = _v3_send_request(_v3_build_request(creds, 'user/refresh_token', method='GET'))
    print(f"  HTTP {r.get('status_code')} | Body: {r.get('raw', '')[:150]}")
    results.append(('GET', r))
    print()

    # Variant 7: Try without Encode=1 query param but with encoded body
    print("── V7: Encoded body, no ?Encode=1 query ──")
    built = _v3_build_request(creds, 'user/refresh_token')
    built['url'] = built['url'].replace('?Encode=1', '')
    r = _v3_send_request(built)
    print(f"  HTTP {r.get('status_code')} | Body: {r.get('raw', '')[:150]}")
    results.append(('no-query-encode', r))
    print()

    # Summary
    print("=" * 50)
    print("VARIANT SUMMARY")
    print("=" * 50)
    for name, r in results:
        code = r.get('status_code', 'ERR')
        body_preview = r.get('raw', '')[:80].replace('\n', ' ')
        print(f"  {name:25s} → HTTP {code} | {body_preview}")

    return results


# ─── CLI ───

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python lingma_token_refresh.py [v3|v3-domestic|oauth|lsp|auto|auto-update]")
        sys.exit(1)

    cmd = sys.argv[1]
    creds = load_credentials()

    print(f"Machine ID: {creds['machine_id']}")
    print(f"User ID:    {creds['user_id']}")
    print(f"PT Token:   {creds['pt_token'][:20]}...")
    print(f"RT Token:   {creds['rt_token'][:20]}...")
    print()

    if cmd == 'v3':
        result = refresh_token_v3(creds, domestic=False)
        print("\n=== Result ===")
        if result.get('parsed'):
            print(json.dumps(result['parsed'], indent=2, ensure_ascii=False))
        else:
            print(f"Raw: {result.get('raw', '')[:500]}")
            if result.get('stderr'):
                print(f"Stderr: {result['stderr']}")

    elif cmd == 'v3-domestic':
        result = refresh_token_v3(creds, domestic=True)
        print("\n=== Result ===")
        if result.get('parsed'):
            print(json.dumps(result['parsed'], indent=2, ensure_ascii=False))
        else:
            print(f"Raw: {result.get('raw', '')[:500]}")
            if result.get('stderr'):
                print(f"Stderr: {result['stderr']}")

    elif cmd == 'oauth':
        client_id = sys.argv[2] if len(sys.argv) > 2 else ''
        result = refresh_token_oauth(creds, client_id)
        print("\n=== Result ===")
        print(json.dumps(result, indent=2, ensure_ascii=False) if isinstance(result, dict) else result)

    elif cmd == 'lsp':
        result = refresh_token_lsp(creds)
        print("\n=== Result ===")
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif cmd == 'auto':
        result = auto_refresh(creds)
        print("\n=== Final Result ===")
        # Remove creds from output for brevity
        display = {k: v for k, v in result.items() if k != 'creds'}
        print(json.dumps(display, indent=2, ensure_ascii=False))

    elif cmd == 'auto-update':
        result = auto_refresh_and_update(creds)
        print("\n=== Final Result ===")
        display = {k: v for k, v in result.items() if k != 'creds'}
        print(json.dumps(display, indent=2, ensure_ascii=False))

    elif cmd == 'diagnose':
        print("=== Diagnose: Compare status vs refresh_token ===\n")
        diagnose_refresh(creds)

    elif cmd == 'variants':
        print("=== Testing request variants ===\n")
        test_variants(creds)

    else:
        print(f"Unknown command: {cmd}")
        print("Available: v3, v3-domestic, oauth, lsp, auto, auto-update, diagnose, variants")
