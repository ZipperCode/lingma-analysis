#!/usr/bin/env python3
"""调试：对比 LSP URL 和 Standalone URL 的差异"""
import json, re, time, urllib.parse, uuid, secrets, base64, hashlib

from lingma_full_auth import (
    generate_nonce, generate_pkce, build_oauth_url,
    get_login_url_via_lsp, OAUTH_BASE_URL
)

print("=" * 70)
print("URL 对比工具 — LSP vs Standalone")
print("=" * 70)

# ── LSP 方式 ──
print(f"\n{'─'*70}")
print("[1] 通过 LSP 获取 URL (需 Lingma 运行)")
print(f"{'─'*70}")

lsp_info = get_login_url_via_lsp()
if lsp_info.get("login_url"):
    lsp_url = lsp_info["login_url"]
    print(f"\n  LSP URL ({len(lsp_url)} chars):")
    print(f"  {lsp_url}")
    print()
    # 解析参数
    parsed = urllib.parse.urlparse(lsp_url)
    lsp_params = urllib.parse.parse_qs(parsed.query)
    print(f"  Base: {parsed.scheme}://{parsed.netloc}{parsed.path}")
    print(f"  参数:")
    for k, v in sorted(lsp_params.items()):
        val = v[0] if isinstance(v, list) else v
        print(f"    {k}: {val[:80]}{'...' if len(val) > 80 else ''}")
else:
    print("\n  [!] 获取 LSP URL 失败")
    lsp_params = {}

# ── Standalone 方式 ──
print(f"\n{'─'*70}")
print("[2] Standalone 生成 URL")
print(f"{'─'*70}")

nonce = generate_nonce()
verifier, challenge = generate_pkce()
machine_id = str(uuid.uuid4())
port = 37510

url2 = build_oauth_url(nonce, port, challenge, machine_id)
print(f"\n  Standalone URL ({len(url2)} chars):")
print(f"  {url2}")
print()
parsed2 = urllib.parse.urlparse(url2)
sa_params = urllib.parse.parse_qs(parsed2.query)
print(f"  Base: {parsed2.scheme}://{parsed2.netloc}{parsed2.path}")
print(f"  参数:")
for k, v in sorted(sa_params.items()):
    val = v[0] if isinstance(v, list) else v
    print(f"    {k}: {val[:80]}{'...' if len(val) > 80 else ''}")

# ── 对比差异 ──
print(f"\n{'─'*70}")
print("[3] 差异分析")
print(f"{'─'*70}")

if lsp_params:
    lsp_keys = set(lsp_params.keys())
    sa_keys = set(sa_params.keys())

    only_lsp = lsp_keys - sa_keys
    only_sa = sa_keys - lsp_keys
    common = lsp_keys & sa_keys

    if only_lsp:
        print(f"\n  LSP 有但 Standalone 没有的参数: {only_lsp}")
    if only_sa:
        print(f"\n  Standalone 有但 LSP 没有的参数: {only_sa}")

    print(f"\n  共同参数对比:")
    for k in sorted(common):
        lv = lsp_params.get(k, [""])[0][:60]
        sv = sa_params.get(k, [""])[0][:60]
        match = "✅" if lv == sv else "❌"
        print(f"    {k}: LSP={lv} | SA={sv} {match}")

    # 比较 base URL
    lsp_base = f"{urllib.parse.urlparse(lsp_url).scheme}://{urllib.parse.urlparse(lsp_url).netloc}{urllib.parse.urlparse(lsp_url).path}"
    sa_base = f"{parsed2.scheme}://{parsed2.netloc}{parsed2.path}"
    if lsp_base != sa_base:
        print(f"\n  ⚠️ Base URL 不同!")
        print(f"    LSP: {lsp_base}")
        print(f"    SA:  {sa_base}")
    else:
        print(f"\n  ✅ Base URL 相同: {lsp_base}")
else:
    print("\n  ⚠️ 无法对比 (LSP 未获取到 URL)")

print()
