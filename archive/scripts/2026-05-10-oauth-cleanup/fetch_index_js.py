#!/usr/bin/env python3
"""Fetch the cosy-client-assets index.js"""
import ssl
import urllib.request

url = "https://lingma.alibabacloud.com/static/yunxiao-fe/cosy-client-assets/0.1.12/index.js"
output = "D:\\Project\\lingma\\cosy_client_index.js"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

req = urllib.request.Request(url, headers={
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
})

try:
    resp = urllib.request.urlopen(req, context=ctx, timeout=30)
    data = resp.read()
    with open(output, 'wb') as f:
        f.write(data)
    print(f"Downloaded {len(data)} bytes to {output}")
except Exception as e:
    print(f"Error: {e}")
    # Try alternative URL patterns
    for alt_url in [
        "https://lingma.alibabacloud.com/static/yunxiao-fe/cosy-client-assets/0.1.12/index.js",
    ]:
        try:
            print(f"Trying: {alt_url}")
            resp = urllib.request.urlopen(urllib.request.Request(alt_url, headers={
                "User-Agent": "Mozilla/5.0"
            }), context=ctx, timeout=30)
            data = resp.read()
            with open(output, 'wb') as f:
                f.write(data)
            print(f"Downloaded {len(data)} bytes")
            break
        except Exception as e2:
            print(f"  Failed: {e2}")
