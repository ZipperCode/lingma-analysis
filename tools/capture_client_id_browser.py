#!/usr/bin/env python3
"""Capture OAuth client_id from Lingma login redirect chain using Playwright.
Uses persistent Chrome profile to reuse existing Alibaba Cloud session if available.
"""
import asyncio, json, os, sys, time
from playwright.async_api import async_playwright

LOGIN_URL = "https://devops.aliyun.com/lingma/login?state=2-test123&challenge=test&challenge_method=S256&machine_id=test&nonce=test&port=37599"
OUTPUT_FILE = os.path.join(os.path.dirname(__file__) or ".", "captured_client_id.json")

async def main():
    captured_urls = []

    chrome_user_dir = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data")
    if not os.path.isdir(chrome_user_dir):
        chrome_user_dir = r"C:\Users\Zipper\AppData\Local\Google\Chrome\User Data"

    use_persistent = os.path.isdir(chrome_user_dir)

    async with async_playwright() as p:
        if use_persistent:
            print(f"[*] Using Chrome profile: {chrome_user_dir}")
            try:
                context = await p.chromium.launch_persistent_context(
                    user_data_dir=chrome_user_dir,
                    channel="chrome",
                    headless=False,
                    viewport={"width": 1280, "height": 800},
                )
            except Exception as e:
                print(f"[!] Persistent context failed ({e}), launching fresh")
                browser = await p.chromium.launch(headless=False)
                context = await browser.new_context(viewport={"width": 1280, "height": 800})
        else:
            print("[*] No Chrome profile found, using fresh context")
            browser = await p.chromium.launch(headless=False)
            context = await browser.new_context(viewport={"width": 1280, "height": 800})

        page = await context.new_page()

        # Intercept ALL redirect responses
        async def on_response(response):
            url = response.url
            status = response.status
            if status in (301, 302, 303, 307, 308):
                location = response.headers.get("location", "")
                full = url + " -> " + location
                if any(k in full for k in ["client_id", "oauth2/v1/auth", "signin", "lingma/login", "oauth_callback"]):
                    print(f"[REDIR {status}] {url[:200]}")
                    print(f"         -> {location[:300]}")
                    captured_urls.append({"type": "redirect", "status": status, "from": url, "to": location})
                    if "client_id=" in location:
                        import re
                        m = re.search(r"client_id=([^&\s]+)", location)
                        if m:
                            cid = m.group(1)
                            print(f"\n{'='*60}")
                            print(f"*** FOUND client_id: {cid} ***")
                            print(f"{'='*60}")
                            captured_urls.append({"type": "CLIENT_ID_FOUND", "client_id": cid, "url": location})

        async def on_request(request):
            url = request.url
            if "client_id" in url or "oauth2/v1/auth" in url:
                print(f"[REQ] {request.method} {url[:300]}")
                captured_urls.append({"type": "request_with_cid", "url": url})

        page.on("response", on_response)
        page.on("request", on_request)

        print(f"[*] Navigating to Lingma login URL...")
        print(f"[*] If login is required, please complete it in the browser window.")
        print(f"[*] The redirect chain will be captured automatically.")
        print()

        try:
            await page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            print(f"[*] Initial navigation: {e}")

        current_url = page.url
        print(f"[*] Current URL: {current_url[:200]}")

        # Wait up to 3 minutes for redirect chain
        for i in range(180):
            await asyncio.sleep(1)
            new_url = page.url
            if new_url != current_url:
                print(f"[{i}s] URL: {new_url[:200]}")
                current_url = new_url
                if "client_id=" in current_url:
                    import re
                    m = re.search(r"client_id=([^&\s]+)", current_url)
                    if m:
                        print(f"\n*** client_id = {m.group(1)} ***")
                        captured_urls.append({"type": "FOUND", "client_id": m.group(1), "url": current_url})
            if "code=" in current_url or "/callback" in current_url:
                print(f"[*] Callback received! OAuth flow complete.")
                break

        print(f"[*] Final URL: {page.url[:400]}")

        # Save results
        with open(OUTPUT_FILE, "w") as f:
            json.dump({
                "final_url": page.url,
                "captured_urls": captured_urls,
            }, f, indent=2, ensure_ascii=False)

        print(f"[*] Results saved to {OUTPUT_FILE}")
        print(f"[*] Browser will stay open for 10 seconds, then close.")
        await asyncio.sleep(10)

        try:
            await context.close()
        except:
            pass

if __name__ == "__main__":
    asyncio.run(main())
