"""Mitmproxy addon to capture Lingma HTTP requests with full headers and body."""
import json
import sys
from datetime import datetime

class LingmaCapture:
    """Capture and log Lingma HTTP requests."""

    def __init__(self):
        self.request_count = 0

    def request(self, flow):
        """Capture outgoing request."""
        self.request_count += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Only capture Lingma-related requests
        host = flow.request.pretty_host
        if 'lingma' in host or 'alibabacloud' in host or 'aliyun' in host or 'tongyi' in host or 'dashscope' in host:
            print(f"\n{'='*80}")
            print(f"#{self.request_count} [{timestamp}]")
            print(f"{flow.request.method} {flow.request.pretty_url}")
            print(f"Host: {host}")

            # Print interesting headers
            interesting = ['date', 'signature', 'authorization', 'appcode',
                          'cosy-machine-token', 'x-security-token', 'token',
                          'cookie', 'x-machine-id', 'x-user-id', 'content-type',
                          'user-agent', 'accept', 'x-timestamp', 'entry-timestamp']
            for h in interesting:
                if h in flow.request.headers:
                    print(f"  {h}: {flow.request.headers[h]}")

            # Print body if present
            if flow.request.content and len(flow.request.content) > 0:
                try:
                    body = flow.request.content.decode('utf-8')
                    print(f"\n  Body ({len(body)} bytes):")
                    # Truncate but show enough to see structure
                    if len(body) > 3000:
                        print(body[:3000])
                        print(f"  ... (truncated, {len(body)} total bytes)")
                    else:
                        print(body)
                except:
                    print(f"  [binary body, {len(flow.request.content)} bytes]")

    def response(self, flow):
        """Capture incoming response."""
        host = flow.request.pretty_host
        if 'lingma' in host or 'alibabacloud' in host or 'aliyun' in host or 'tongyi' in host or 'dashscope' in host:
            print(f"  -> {flow.response.status_code}")
            interesting_resp = ['entry-timestamp', 'entry-signature', 'x-request-id',
                               'set-cookie', 'content-type']
            for h in interesting_resp:
                if h in flow.response.headers:
                    print(f"  {h}: {flow.response.headers[h]}")
            if flow.response.content and len(flow.response.content) > 0:
                try:
                    body = flow.response.content.decode('utf-8')
                    if flow.response.status_code != 200 or 'algo' in flow.request.path:
                        preview = body[:500]
                        print(f"  Response body: {preview}")
                except:
                    print(f"  [binary response, {len(flow.response.content)} bytes]")

addons = [LingmaCapture()]
