"""
mitmproxy 拦截脚本：抓取灵码 refresh token 请求

使用方法：
mitmdump -s mitmproxy_capture_refresh.py -p 8083

然后启动灵码：
HTTP_PROXY=http://127.0.0.1:8083 HTTPS_PROXY=http://127.0.0.1:8083 \
  ~/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe start
"""

from mitmproxy import http, ctx
import json
import time
from pathlib import Path

# 保存目录
SAVE_DIR = Path("/tmp/lingma_refresh_captures")
SAVE_DIR.mkdir(exist_ok=True)

def request(flow: http.HTTPFlow) -> None:
    """
    拦截所有请求，重点关注 refresh_token 端点
    """

    # 检查 URL 是否包含 refresh_token
    url = flow.request.pretty_url

    if "refresh_token" in url or "refresh" in url.lower():
        ctx.log.info("\n" + "="*60)
        ctx.log.info("[!] Refresh Token Request Detected")
        ctx.log.info("="*60)
        ctx.log.info(f"URL: {url}")
        ctx.log.info(f"Method: {flow.request.method}")

        # 记录请求头
        ctx.log.info("\nHeaders:")
        for key, value in flow.request.headers.items():
            ctx.log.info(f"  {key}: {value}")

        # 记录请求体
        ctx.log.info("\nBody (raw):")
        ctx.log.info(f"  {flow.request.text}")

        # 保存到文件
        timestamp = int(time.time())
        filename = SAVE_DIR / f"refresh_{timestamp}.json"

        data = {
            "timestamp": timestamp,
            "url": url,
            "method": flow.request.method,
            "headers": dict(flow.request.headers),
            "body": flow.request.text,
            "body_size": len(flow.request.content),
        }

        filename.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        ctx.log.info(f"\n✅ Saved to: {filename}")

    # 也记录其他认证相关请求
    auth_keywords = ["oauth", "login", "token", "auth", "user/status"]
    if any(kw in url.lower() for kw in auth_keywords):
        ctx.log.info(f"\n[Auth] {flow.request.method} {url}")

        if flow.request.method == "POST":
            ctx.log.info(f"Body: {flow.request.text[:200]}")

def response(flow: http.HTTPFlow) -> None:
    """
    拦截响应
    """

    url = flow.request.pretty_url

    if "refresh_token" in url:
        ctx.log.info("\n" + "="*60)
        ctx.log.info("[!] Refresh Token Response")
        ctx.log.info("="*60)
        ctx.log.info(f"Status: {flow.response.status_code}")
        ctx.log.info(f"Headers: {dict(flow.response.headers)}")
        ctx.log.info(f"\nBody:")
        ctx.log.info(f"  {flow.response.text}")

        # 保存响应
        timestamp = int(time.time())
        filename = SAVE_DIR / f"refresh_response_{timestamp}.json"

        data = {
            "timestamp": timestamp,
            "url": url,
            "status_code": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "body": flow.response.text,
        }

        filename.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        ctx.log.info(f"\n✅ Response saved to: {filename}")

# 启动提示
ctx.log.info("\n" + "="*60)
ctx.log.info("mitmproxy Lingma Refresh Token Capture")
ctx.log.info("="*60)
ctx.log.info(f"Save directory: {SAVE_DIR}")
ctx.log.info("Monitoring...\n")