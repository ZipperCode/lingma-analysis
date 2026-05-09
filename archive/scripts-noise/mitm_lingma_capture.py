"""Mitmproxy addon to capture and log Lingma HTTP traffic."""
from mitmproxy import http, ctx
import json
import time

class LingmaCapture:
    """Capture and log all Lingma-related HTTP traffic."""

    def __init__(self):
        self.request_count = 0
        self.hosts = [
            'lingma.alibabacloud.com',
            'lingma-api.tongyi.aliyun.com',
            'account.alibabacloud.com',
            'account.aliyun.com',
            'dashscope.aliyuncs.com',
            'dashscope.alibabacloud.com',
            'qts2.qoder.sh',
            'center.qoder.sh',
        ]

    def is_lingma(self, flow):
        host = flow.request.pretty_host
        return any(h in host for h in self.hosts)

    def request(self, flow):
        if not self.is_lingma(flow):
            return

        self.request_count += 1
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        ctx.log.info(f"\n{'='*80}")
        ctx.log.info(f"#{self.request_count} [{timestamp}]")
        ctx.log.info(f"{flow.request.method} {flow.request.pretty_url}")
        ctx.log.info(f"Host: {flow.request.pretty_host}")

        # Log all headers
        ctx.log.info("Headers:")
        for name, value in flow.request.headers.items():
            marker = " <-- INTERESTING" if name.lower() in [
                'date', 'signature', 'authorization', 'appcode',
                'cosy-machinetoken', 'cosy-key', 'cosy-date', 'cosy-user',
                'x-security-token', 'token', 'cookie', 'x-machine-id',
                'user-agent', 'content-type'
            ] else ""
            ctx.log.info(f"  {name}: {value}{marker}")

        # Log body
        if flow.request.content:
            try:
                body = flow.request.content.decode('utf-8')
                size = len(body)
                ctx.log.info(f"Body ({size} bytes):")
                if size > 5000:
                    ctx.log.info(body[:5000])
                    ctx.log.info(f"... (truncated, {size} total)")
                else:
                    try:
                        parsed = json.loads(body)
                        ctx.log.info(json.dumps(parsed, indent=2, ensure_ascii=False)[:5000])
                    except:
                        ctx.log.info(body[:5000])
            except:
                ctx.log.info(f"[binary body, {len(flow.request.content)} bytes]")

    def response(self, flow):
        if not self.is_lingma(flow):
            return

        ctx.log.info(f"  <- Status: {flow.response.status_code}")
        ctx.log.info("Response Headers:")
        for name, value in flow.response.headers.items():
            if name.lower() in [
                'entry-timestamp', 'entry-signature', 'x-request-id',
                'set-cookie', 'content-type', 'www-authenticate',
                'x-cosy-request-id'
            ]:
                ctx.log.info(f"  {name}: {value}")

        if flow.response.content:
            try:
                body = flow.response.content.decode('utf-8')
                size = len(body)
                if flow.response.status_code != 200 or 'algo' in flow.request.path:
                    ctx.log.info(f"Response Body ({size} bytes):")
                    if size > 3000:
                        ctx.log.info(body[:3000])
                        ctx.log.info(f"... (truncated)")
                    else:
                        try:
                            parsed = json.loads(body)
                            ctx.log.info(json.dumps(parsed, indent=2, ensure_ascii=False)[:3000])
                        except:
                            ctx.log.info(body[:3000])
            except:
                ctx.log.info(f"[binary response, {len(flow.response.content)} bytes]")


addons = [LingmaCapture()]
