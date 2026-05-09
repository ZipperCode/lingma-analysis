
import asyncio, json, os, sys, time
from playwright.async_api import async_playwright

LOGIN_URL = "https://devops.aliyun.com/lingma/login?state=2-dac01f411fd841eeb50a9c47739c7f90&challenge=nhjeWu-Js0FONWkWQ2BQH5m6IAIodpYuGqcGq1XM2YI&challenge_method=S256&machine_id=35346164-3866-492d-a339-30773a32652d&nonce=dac01f411fd841eeb50a9c47739c7f90&port=37599"
OUTPUT = r"D:/Project/lingma/tools/captured_redirects.jsonl"

captured_urls = []

async def main():
    async with async_playwright() as p:
        # Use persistent context to reuse existing browser session
        browser = await p.chromium.launch(
            headless=False,
            args=['--disable-blink-features=AutomationControlled']
        )
        
        context = await browser.new_context(
            viewport={'width': 1280, 'height': 800},
        )
        page = await context.new_page()
        
        # Intercept ALL requests and responses
        async def on_request(request):
            url = request.url
            if any(t in url for t in ['client_id', 'oauth2/v1/auth', 'signin', 'lingma/login', 'oauth_callback']):
                captured_urls.append({'type': 'request', 'url': url, 'method': request.method, 'headers': dict(request.headers)})
                print(f'[REQ] {request.method} {url[:200]}', flush=True)
        
        async def on_response(response):
            url = response.url
            status = response.status
            if status in (301, 302, 303, 307, 308):
                location = response.headers.get('location', '')
                if any(t in (url + location) for t in ['client_id', 'oauth2/v1/auth', 'signin', 'lingma/login', 'oauth_callback']):
                    print(f'[REDIR {status}] {url[:150]} -> {location[:200]}', flush=True)
                    captured_urls.append({'type': 'redirect', 'status': status, 'from': url, 'to': location})
        
        page.on('request', on_request)
        page.on('response', on_response)
        
        print(f'[*] Navigating to login URL...', flush=True)
        print(f'[*] URL: {LOGIN_URL[:120]}...', flush=True)
        
        try:
            await page.goto(LOGIN_URL, wait_until='domcontentloaded', timeout=15000)
        except Exception as e:
            print(f'[*] Navigation result: {e}', flush=True)
        
        print(f'[*] Current URL: {page.url[:200]}', flush=True)
        
        # Take a snapshot
        title = await page.title()
        print(f'[*] Page title: {title}', flush=True)
        
        # Keep browser open for manual login
        print(f'[*] ========================================', flush=True)
        print(f'[*] BROWSER IS OPEN - PLEASE LOG IN', flush=True)
        print(f'[*] After login, the redirect chain will be captured automatically', flush=True)
        print(f'[*] Waiting 120 seconds for login...', flush=True)
        print(f'[*] ========================================', flush=True)
        
        # Wait for redirect to complete (callback or auth page)
        for i in range(120):
            await asyncio.sleep(1)
            current_url = page.url
            if 'client_id' in current_url:
                print(f'[*] CAPTURED client_id URL: {current_url}', flush=True)
                captured_urls.append({'type': 'client_id_capture', 'url': current_url})
            if 'callback' in current_url or 'code=' in current_url:
                print(f'[*] Callback received! URL has auth code', flush=True)
                captured_urls.append({'type': 'callback', 'url': current_url})
            if i % 10 == 0:
                print(f'  [{i}s] Current: {current_url[:150]}', flush=True)
        
        print(f'[*] Final URL: {page.url}', flush=True)
        
        # Save captured URLs
        with open(OUTPUT, 'w') as f:
            for entry in captured_urls:
                f.write(json.dumps(entry) + '
')
        
        print(f'[*] Saved {len(captured_urls)} captured entries to {OUTPUT}', flush=True)
        
        await browser.close()

asyncio.run(main())
