#!/usr/bin/env python3
"""
灵码 Token Refresh 测试辅助脚本
快速从灵码缓存文件提取凭证并测试 refresh

日期：2026-04-30
"""

import sys
import json
from pathlib import Path

try:
    from Crypto.Cipher import AES
    import base64
except ImportError:
    print("❌ 需要安装 pycryptodome：pip install pycryptodome")
    sys.exit(1)

def extract_lingma_credentials():
    """
    从灵码缓存文件提取所有必要凭证
    """
    lingma_dir = Path.home() / '.lingma'
    cache_dir = lingma_dir / 'cache'

    # 1. 读取 machine_id（明文）
    machine_id_file = cache_dir / 'id'
    if not machine_id_file.exists():
        print(f"❌ Machine ID 文件不存在：{machine_id_file}")
        return None

    machine_id = machine_id_file.read_text().strip()
    print(f"✅ Machine ID：{machine_id}")

    # 2. 读取用户缓存（AES 加密）
    user_cache_file = cache_dir / 'user'
    if not user_cache_file.exists():
        print(f"❌ 用户缓存文件不存在：{user_cache_file}")
        return None

    try:
        # AES-128-CBC 解密
        aes_key = machine_id[:16].encode()  # key = machine_id 前 16 字符
        encrypted_data = base64.b64decode(user_cache_file.read_text())

        cipher = AES.new(aes_key, AES.MODE_CBC, aes_key)  # IV = key
        decrypted = cipher.decrypt(encrypted_data)

        # 去除 padding，转换为字符串
        user_info_str = decrypted.rstrip(b'\x00').decode('utf-8')

        # 关键修复：处理多个 JSON 对象拼接的情况
        # 使用正则表达式找到第一个完整的 JSON 对象
        import re
        json_pattern = r'\{[^{}]*\}'
        first_json_match = re.search(json_pattern, user_info_str)

        if first_json_match:
            first_json_str = first_json_match.group(0)
            user_info = json.loads(first_json_str)
            print(f"✅ 用户缓存解密成功（提取第一个 JSON 对象）")
        else:
            print(f"❌ 未找到有效 JSON 对象")
            print(f"   解密后数据长度: {len(user_info_str)}")
            print(f"   前 200 字符: {user_info_str[:200]}")
            return None

        print(f"✅ 用户缓存解密成功")
        return {
            'machine_id': machine_id,
            'user_id': user_info.get('uid', user_info.get('aid', '')),  # 使用 uid 或 aid
            'org_id': user_info.get('organization_id', ''),  # 使用 organization_id
            'security_oauth_token': user_info.get('security_oauth_token', ''),
            'refresh_token': user_info.get('refresh_token', ''),
            'cosy_key': user_info.get('key', ''),
            'encrypt_user_info': user_info.get('encrypt_user_info', ''),
        }

    except Exception as e:
        print(f"❌ 解密用户缓存失败：{e}")
        print(f"   可能原因：")
        print(f"   1. AES key 不正确（machine_id 格式错误）")
        print(f"   2. 缓存文件格式不正确")
        print(f"   3. 缓存文件未加密（直接读取 JSON）")

        # 尝试直接读取 JSON（未加密情况）
        try:
            print(f"\n尝试直接读取 JSON...")
            with open(user_cache_file, 'r', encoding='utf-8') as f:
                content = f.read()
                user_info = json.loads(content)
                print(f"✅ 直接读取 JSON 成功")
                return {
                    'machine_id': machine_id,
                    'user_id': user_info.get('user_id', ''),
                    'org_id': user_info.get('org_id', ''),
                    'security_oauth_token': user_info.get('security_oauth_token', ''),
                    'refresh_token': user_info.get('refresh_token', ''),
                }
        except Exception as e2:
            print(f"❌ 直接读取也失败：{e2}")
            return None

def main():
    print("\n" + "="*60)
    print("灵码 Token Refresh 测试辅助工具")
    print("="*60)

    creds = extract_lingma_credentials()
    if not creds:
        sys.exit(1)

    print(f"\n📦 提取的凭证信息：")
    print(f"   Machine ID：{creds['machine_id']}")
    print(f"   User ID：{creds['user_id']}")
    print(f"   Org ID：{creds['org_id']}")
    print(f"   Security Token：{creds['security_oauth_token'][:20]}...")
    print(f"   Refresh Token：{creds['refresh_token'][:20]}...")

    print(f"\n💡 使用以下命令测试 refresh：")
    print(f"\npython tools/lingma_refresh_token_direct.py \\")
    print(f"  --machine-id '{creds['machine_id']}' \\")
    print(f"  --user-id '{creds['user_id']}' \\")
    print(f"  --org-id '{creds['org_id']}' \\")
    print(f"  --security-token '{creds['security_oauth_token']}' \\")
    print(f"  --refresh-token '{creds['refresh_token']}'")

    # 可选：直接调用 refresh 测试
    print(f"\n是否立即测试 refresh？（y/n）")
    choice = input(">>> ").strip().lower()

    if choice == 'y':
        import subprocess
        cmd = [
            'python', 'tools/lingma_refresh_token_direct.py',
            '--machine-id', creds['machine_id'],
            '--user-id', creds['user_id'],
            '--org-id', creds['org_id'],
            '--security-token', creds['security_oauth_token'],
            '--refresh-token', creds['refresh_token'],
        ]
        print(f"\n🚀 执行命令...")
        subprocess.run(cmd)
    else:
        print(f"\n退出。请手动运行上述命令。")

if __name__ == '__main__':
    main()