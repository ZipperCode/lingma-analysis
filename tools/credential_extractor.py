#!/usr/bin/env python3
"""
Lingma 便携凭据导出器 — 从本地缓存提取凭据，导出为可移植格式.

Usage:
    python credential_extractor.py                    # 显示凭据
    python credential_extractor.py --save             # 保存到 ~/.lingma/portable_config.json
    python credential_extractor.py --env              # 输出 shell 环境变量格式
    python credential_extractor.py --save --env       # 同时保存并输出 env 格式

导出的凭据可在任何机器上使用 LingmaRemoteAPI，无需安装 Lingma 程序.
"""
import base64
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def decrypt_cache_user(lingma_dir: Path) -> dict:
    """解密 cache/user 文件"""
    with open(lingma_dir / 'cache' / 'id', 'r') as f:
        machine_id = f.read().strip()

    with open(lingma_dir / 'cache' / 'user', 'rb') as f:
        encrypted = base64.b64decode(f.read().strip())

    key = machine_id[:16].encode('utf-8')
    cipher = Cipher(algorithms.AES(key), modes.CBC(key))
    dec = cipher.decryptor()
    decrypted = dec.update(encrypted) + dec.finalize()
    decrypted = decrypted[:-decrypted[-1]]

    user_data = json.loads(decrypted.decode('utf-8'))
    user_data['_machine_id'] = machine_id
    return user_data


def export_portable(user_data: dict) -> dict:
    """提取便携凭据"""
    return {
        'machine_id': user_data['_machine_id'],
        'user_id': user_data['uid'],
        'user_name': user_data.get('name', ''),
        'cosy_key': user_data['key'],
        'encrypt_user_info': user_data['encrypt_user_info'],
        'security_oauth_token': user_data.get('security_oauth_token', ''),
        'refresh_token': user_data.get('refresh_token', ''),
        'expire_time': user_data.get('expire_time', ''),
    }


def print_env_format(creds: dict):
    """输出 shell 环境变量格式"""
    print('# Lingma portable credentials — add to ~/.bashrc or use with:')
    print('#   eval "$(python credential_extractor.py --env)"')
    print(f'export LINGMA_MACHINE_ID="{creds["machine_id"]}"')
    print(f'export LINGMA_USER_ID="{creds["user_id"]}"')
    print(f'export LINGMA_COSY_KEY="{creds["cosy_key"]}"')
    print(f'export LINGMA_ENCRYPT_USER_INFO="{creds["encrypt_user_info"]}"')


def main():
    lingma_dir = Path.home() / '.lingma'
    cache_user = lingma_dir / 'cache' / 'user'
    cache_id = lingma_dir / 'cache' / 'id'

    if not cache_user.exists() or not cache_id.exists():
        print(f'错误: 未找到 Lingma 缓存文件喵～')
        print(f'  需要: {cache_user}')
        print(f'  需要: {cache_id}')
        sys.exit(1)

    user_data = decrypt_cache_user(lingma_dir)
    creds = export_portable(user_data)

    args = set(sys.argv[1:])

    if '--env' in args:
        print_env_format(creds)
        if '--save' not in args:
            return

    # 显示凭据摘要
    print('=== Lingma 便携凭据 ===')
    print(f'  Machine ID:     {creds["machine_id"]}')
    print(f'  User ID:        {creds["user_id"]}')
    print(f'  User Name:      {creds["user_name"]}')
    print(f'  COSY Key:       {creds["cosy_key"][:40]}... ({len(creds["cosy_key"])} chars)')
    print(f'  Encrypt Info:   {creds["encrypt_user_info"][:40]}... ({len(creds["encrypt_user_info"])} chars)')
    print(f'  OAuth Token:    {creds["security_oauth_token"][:20]}...' if creds["security_oauth_token"] else '  OAuth Token:    (none)')
    print(f'  Refresh Token:  {creds["refresh_token"][:20]}...' if creds["refresh_token"] else '  Refresh Token:  (none)')
    print(f'  Expire Time:    {creds["expire_time"]}')

    if '--save' in args:
        config_path = lingma_dir / 'portable_config.json'
        with open(config_path, 'w') as f:
            json.dump(creds, f, indent=2, ensure_ascii=False)
        print(f'\n[*] 已保存到: {config_path}')
        print(f'[*] 使用方式:')
        print(f'    from lingma_remote_api import LingmaRemoteAPI')
        print(f'    api = LingmaRemoteAPI(config_file="{config_path}")')
        print(f'    api.chat("你好")')

    print(f'\n[*] 环境变量方式 (无需配置文件):')
    print(f'    export LINGMA_MACHINE_ID="{creds["machine_id"]}"')
    print(f'    export LINGMA_USER_ID="{creds["user_id"]}"')
    print(f'    export LINGMA_COSY_KEY="{creds["cosy_key"]}"')
    print(f'    export LINGMA_ENCRYPT_USER_INFO="{creds["encrypt_user_info"]}"')

    print(f'\n[*] 完成！凭据可移植到任意机器使用，无需安装 Lingma 喵~ o(*￣︶￣*)o')


if __name__ == '__main__':
    main()
