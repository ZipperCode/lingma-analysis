import json

CUSTOM_ALPHABET = "!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz"
ALPHABET_INDEX = {c: i for i, c in enumerate(CUSTOM_ALPHABET)}

with open('capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl') as f:
    for line in f:
        d = json.loads(line)
        path = d.get('path', '')
        if 'user/status' in path:
            body = d.get('body_base64_preview', '')
            print(f"Body ({len(body)} chars):")
            print(f"  First 100 chars: {body[:100]}")
            print(f"  Last 50 chars: {body[-50:]}")

            # Show positions of non-alphabet chars
            print(f"\nNon-alphabet char positions:")
            for i, ch in enumerate(body):
                if ch not in ALPHABET_INDEX:
                    print(f"  [{i}] '{ch}' (surrounding: ...{body[max(0,i-5):i+6]}...)")
                    if i > 50:  # Only show first few
                        break

            # Also check the full body
            print(f"\n  Full body:")
            # Highlight non-alpha chars
            highlighted = ""
            for ch in body:
                if ch in ALPHABET_INDEX:
                    highlighted += ch
                else:
                    highlighted += f"[{ch}]"
            print(f"  {highlighted[:200]}")

            break
