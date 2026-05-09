"""Trigger real AI completion request through LSP to make Lingma call the API."""
import asyncio
import websockets
import json
import sys
import time

async def read_lsp_response(ws, timeout=15):
    """Read LSP response with Content-Length parsing."""
    try:
        raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
        if '\r\n\r\n' in raw:
            headers, body = raw.split('\r\n\r\n', 1)
            for line in headers.split('\r\n'):
                if line.startswith('Content-Length:'):
                    length = int(line.split(':')[1].strip())
                    return json.loads(body[:length])
            return json.loads(body)
        return json.loads(raw)
    except asyncio.TimeoutError:
        return None
    except Exception as e:
        return None

async def main():
    try:
        async with websockets.connect('ws://127.0.0.1:37010/', open_timeout=3, close_timeout=3) as ws:
            print("[*] Connected to Lingma LSP server")

            # Initialize
            msg = json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "processId": 0,
                    "rootUri": None,
                    "clientInfo": {"name": "vscode", "version": "1.95.0"},
                    "capabilities": {
                        "textDocument": {
                            "completion": {
                                "completionItem": {"snippetSupport": True},
                                "completionList": {"itemDefaults": ["commitCharacters"]}
                            }
                        }
                    }
                }
            })
            await ws.send(f"Content-Length: {len(msg)}\r\n\r\n{msg}")
            resp = await read_lsp_response(ws)
            print(f"Initialize: {json.dumps(resp, indent=2)[:200]}")

            # Initialized notification
            msg = json.dumps({"jsonrpc": "2.0", "method": "initialized", "params": {}})
            await ws.send(f"Content-Length: {len(msg)}\r\n\r\n{msg}")

            # Open document with REAL code context
            code = '''import requests

def fetch_user_data(user_id):
    """Fetch user data from the API."""
    url = f"https://api.example.com/users/{user_id}"
    headers = {"Authorization": "Bearer token"}
    response = requests.get(url, headers=headers, timeout=10)
    return response.json()

def process_data(data):
    """Process the fetched data."""
    result = []
    for item in data.get("items", []):
        if item.get("status") == "active":
            result.append({
                "name": item["name"],
                "email": item["email"],
                "score": item.get("score", 0)
            })
    return result

def main():
    user_id = 12345
    data = fetch_user_data(user_id)
    processed = process_data(data)
    print(f"Found {len(processed)} active users")
    for user in processed:
        print(f"  {user['name']}: {user['email']}")

if __name__ == "__main__":
    main()
'''

            msg = json.dumps({
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": "file:///C:/test/example.py",
                        "languageId": "python",
                        "version": 1,
                        "text": code
                    }
                }
            })
            await ws.send(f"Content-Length: {len(msg)}\r\n\r\n{msg}")

            # Wait for any server processing
            await asyncio.sleep(1)

            # Request completion at the end of process_data function
            # Position after "    return " on line 17
            msg = json.dumps({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "textDocument/completion",
                "params": {
                    "textDocument": {"uri": "file:///C:/test/example.py"},
                    "position": {"line": 16, "character": 11}  # After "return "
                }
            })
            await ws.send(f"Content-Length: {len(msg)}\r\n\r\n{msg}")

            # Wait longer for AI completion
            print("[*] Waiting for AI completion...")
            for i in range(20):
                resp = await read_lsp_response(ws, timeout=3)
                if resp:
                    if resp.get("id") == 2:
                        result = resp.get("result", {})
                        if isinstance(result, dict):
                            items = result.get("items", result)
                            if isinstance(items, list):
                                print(f"  Got {len(items)} completion items")
                                for item in items[:5]:
                                    label = item.get("label", "")
                                    detail = item.get("detail", "")
                                    kind = item.get("kind", "")
                                    print(f"    - {label} (kind={kind}, detail={detail[:50]})")
                            else:
                                print(f"  Result: {json.dumps(items, indent=2)[:500]}")
                        else:
                            print(f"  Result: {result}")
                        break
                    else:
                        print(f"  Other response: {json.dumps(resp, indent=2)[:200]}")

            # Also try completion/resolve for the first item
            await asyncio.sleep(2)

            # Collect any remaining responses
            for _ in range(3):
                resp = await read_lsp_response(ws, timeout=2)
                if resp:
                    method = resp.get("method", "")
                    if method:
                        print(f"  Notification: {method}")
                        params = resp.get("params", {})
                        if isinstance(params, dict):
                            content = params.get("content", "")
                            if content:
                                print(f"    Content: {content[:300]}")

            print("\n[*] Done!")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
