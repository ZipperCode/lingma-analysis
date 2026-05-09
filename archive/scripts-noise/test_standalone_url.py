#!/usr/bin/env python3
"""
验证独立生成的登录 URL 结构是否正确
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import urllib.parse
import re
from lingma_oauth_capture import generate_login_url_standalone


def verify_url_structure():
    """验证生成的 URL 结构是否与 callback.html 一致"""

    # 生成新 URL
    info = generate_login_url_standalone(port=35710, region='intl')

    print("=== URL 结构验证 ===\n")

    # 1. 验证最外层 URL
    full_url = info['login_url']
    assert full_url.startswith('https://account.alibabacloud.com/logout/logout.htm?oauth_callback='), \
        "最外层 URL 格式错误"
    print("✓ 最外层 URL 格式正确 (logout.htm)")

    # 2. 解码第一层，验证中间层
    decoded1 = urllib.parse.unquote(full_url)
    assert 'account.alibabacloud.com/login/login.htm?oauth_callback=' in decoded1, \
        "中间层 URL 格式错误"
    print("✓ 中间层 URL 格式正确 (login.htm)")

    # 3. 解码第二层，验证最内层
    decoded2 = urllib.parse.unquote(decoded1)
    assert 'lingma.alibabacloud.com/lingma/login?' in decoded2, \
        "最内层 URL 格式错误"
    print("✓ 最内层 URL 格式正确 (lingma/login)")

    # 4. 提取并验证最内层参数
    match = re.search(r'lingma\.alibabacloud\.com/lingma/login\?(.+?)(?:\s|$)', decoded2)
    assert match, "无法提取最内层参数"

    inner_url = f"https://lingma.alibabacloud.com/lingma/login?{match.group(1)}"
    params = urllib.parse.urlparse(inner_url)
    query_params = urllib.parse.parse_qs(params.query)

    required_params = ['state', 'challenge', 'challenge_method', 'machine_id', 'nonce', 'port']
    for param in required_params:
        assert param in query_params, f"缺少参数: {param}"
        print(f"✓ 参数 {param}: {query_params[param][0][:50]}...")

    # 5. 验证 state 格式
    state = query_params['state'][0]
    assert state.startswith('1-') or state.startswith('2-'), \
        f"state 格式错误: {state}"
    print(f"\n✓ state 格式正确: {state[:10]}...")

    # 6. 验证 nonce 长度（32 字符）
    nonce = query_params['nonce'][0]
    assert len(nonce) == 32, f"nonce 长度错误: {len(nonce)} (应为 32)"
    print(f"✓ nonce 长度正确: {len(nonce)} 字符")

    # 7. 验证 PKCE challenge 方法
    method = query_params['challenge_method'][0]
    assert method == 'S256', f"challenge_method 错误: {method}"
    print(f"✓ challenge_method 正确: {method}")

    # 8. 与 callback.html 中的 URL 对比
    print("\n=== 与 callback.html 对比 ===")
    callback_inner = "https://lingma.alibabacloud.com/lingma/login?state=2-15c913e5ced04c2a99aa784e0f77d746&challenge=Te6UY8blXOZR1AYFUUCnICaEvs-1KlKixqWvsFiBYGE&challenge_method=S256&machine_id=43303747-3630-492d-8151-366d4e59432d&nonce=15c913e5ced04c2a99aa784e0f77d746&port=37510"
    callback_params = urllib.parse.urlparse(callback_inner)
    callback_query = urllib.parse.parse_qs(callback_params.query)

    print(f"callback.html 参数: {list(callback_query.keys())}")
    print(f"生成 URL 参数:      {list(query_params.keys())}")

    # 验证参数列表一致
    assert set(query_params.keys()) == set(callback_query.keys()), \
        "参数列表与 callback.html 不一致"
    print("✓ 参数列表与 callback.html 完全一致")

    print("\n=== 所有验证通过！ ===")
    print(f"\n完整 URL (可用于浏览器打开):")
    print(full_url)

    return True


if __name__ == '__main__':
    verify_url_structure()
