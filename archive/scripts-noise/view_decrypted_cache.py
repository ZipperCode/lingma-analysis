#!/usr/bin/env python3
"""
查看灵码缓存解密后的完整数据结构
找出 user_id 和 org_id 在哪里
"""

import sys
import json
import base64
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:
    print("❌ 需要安装 pycryptodome：pip install pycryptodome")
    sys.exit(1)

def main():
    lingma_dir = Path.home() / '.lingma'
    cache_dir = lingma_dir / 'cache'

    # 1. 读取 machine_id
    machine_id_file = cache_dir / 'id'
    if not machine_id_file.exists():
        print(f"❌ Machine ID 文件不存在")
        sys.exit(1)

    machine_id = machine_id_file.read_text().strip()
    print(f"✅ Machine ID：{machine_id}")

    # 2. 读取用户缓存（加密）
    user_cache_file = cache_dir / 'user'
    if not user_cache_file.exists():
        print(f"❌ 用户缓存文件不存在")
        sys.exit(1)

    # 3. AES-128-CBC 解密
    aes_key = machine_id[:16].encode()
    encrypted_data = base64.b64decode(user_cache_file.read_text())

    cipher = AES.new(aes_key, AES.MODE_CBC, aes_key)
    decrypted = cipher.decrypt(encrypted_data)

    # 4. 去除 padding，转换为字符串
    user_info_str = decrypted.rstrip(b'\x00').decode('utf-8')

    print(f"\n📦 解密后的完整数据（长度={len(user_info_str)}）：")
    print("="*60)
    print(user_info_str)
    print("="*60)

    # 5. 尝试找到所有 JSON 对象
    import re
    json_objects = []

    # 匹配所有 {...} 模式
    depth = 0
    start = None
    for i, c in enumerate(user_info_str):
        if c == '{':
            if depth == 0:
                start = i
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0 and start is not None:
                json_str = user_info_str[start:i+1]
                try:
                    json_obj = json.loads(json_str)
                    json_objects.append(json_obj)
                except:
                    pass
                start = None

    print(f"\n🔍 找到 {len(json_objects)} 个 JSON 对象：")

    for idx, obj in enumerate(json_objects):
        print(f"\n--- JSON 对象 {idx+1} ---")
        print(json.dumps(obj, indent=2, ensure_ascii=False))

        # 检查关键字段
        if 'user_id' in obj or 'userId' in obj:
            print(f"✅ 包含 user_id/userId 字段")

        if 'org_id' in obj or 'orgId' in obj:
            print(f"✅ 包含 org_id/orgId 字段")

        if 'security_oauth_token' in obj:
            print(f"✅ 包含 security_oauth_token 字段")

        if 'refresh_token' in obj:
            print(f"✅ 包含 refresh_token 字段")

if __name__ == '__main__':
    main()