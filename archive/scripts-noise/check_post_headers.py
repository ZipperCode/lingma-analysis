import json

# Let's look at the request headers to understand the encoding
captures = [
    'capture/lingma-http-capture-body-20260424-222313.jsonl',
]

for cap_file in captures:
    with open(f'D:/Project/lingma/{cap_file}', 'r') as f:
        for line in f:
            obj = json.loads(line)
            path = obj.get('path', '')
            method = obj.get('method', '')
            headers = obj.get('headers', {})
            body_len = obj.get('body_len', 0)
            body = obj.get('body_utf8', '')

            if method == 'POST' and body:
                print(f'=== {method} {path} ===')
                print(f'Body length (encoded): {body_len}')
                print(f'Body length (utf8 field): {len(body)}')

                # Show ALL headers
                for k, v in headers.items():
                    print(f'  {k}: {v}')

                # Check content-type
                ct = headers.get('Content-Type', '')
                print(f'\nContent-Type: {ct}')

                # Check if there's a custom header indicating encoding
                for k in headers:
                    if 'encode' in k.lower() or 'compress' in k.lower() or 'encoding' in k.lower():
                        print(f'  Encoding header: {k}: {headers[k]}')

                # Check if body is the ENCODED text or the decoded bytes
                print(f'\nBody preview (first 100 chars):')
                print(f'  {body[:100]}')

                # Does the body look like it's in the custom alphabet?
                CUSTOM_ALPHABET = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
                alpha_set = set(CUSTOM_ALPHABET)
                in_alpha = sum(1 for ch in body if ch in alpha_set)
                print(f'\nIn custom alphabet: {in_alpha}/{len(body)} ({in_alpha/len(body)*100:.0f}%)')

                print()

            # Only show first 3 POST requests
            if method == 'POST':
                break
