"""Try to use Lingma's chat capabilities through LSP protocol."""
import asyncio
import websockets
import json
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

async def send_lsp(ws, method, params=None, msg_id=None):
    """Send an LSP message."""
    body = {"jsonrpc": "2.0", "method": method}
    if params:
        body["params"] = params
    if msg_id is not None:
        body["id"] = msg_id
    content = json.dumps(body)
    msg = f"Content-Length: {len(content)}\r\n\r\n{content}"
    await ws.send(msg)

async def main():
    try:
        async with websockets.connect('ws://127.0.0.1:37010/', open_timeout=3, close_timeout=3) as ws:
            print("[*] Connected to Lingma LSP server")

            # Step 1: Initialize
            print("\n[1] Initialize...")
            await send_lsp(ws, "initialize", {
                "processId": 0,
                "rootUri": "file:///C:/test",
                "clientInfo": {"name": "vscode", "version": "1.95.0"},
                "capabilities": {
                    "textDocument": {
                        "completion": {"completionItem": {"snippetSupport": True}}
                    }
                }
            }, 1)
            resp = await read_lsp_response(ws)
            caps = resp.get('result', {}).get('capabilities', {})
            print(f"    Commands: {caps.get('executeCommandProvider', {}).get('commands', [])}")

            # Step 2: Initialized notification
            await send_lsp(ws, "initialized", {})

            # Step 3: Open document
            code = """def calculate_fibonacci(n):
    \"\"\"Calculate the nth Fibonacci number.\"\"\"
    if n <= 1:
        return n
    return calculate_fibonacci(n-1) + calculate_fibonacci(n-2)

def """
            print("\n[2] Open document...")
            await send_lsp(ws, "textDocument/didOpen", {
                "textDocument": {
                    "uri": "file:///C:/test/fib.py",
                    "languageId": "python",
                    "version": 1,
                    "text": code
                }
            })

            # Step 4: Request completion right after "def " - should trigger inline completion
            print("\n[3] Request completion after 'def '...")
            await send_lsp(ws, "textDocument/completion", {
                "textDocument": {"uri": "file:///C:/test/fib.py"},
                "position": {"line": 7, "character": 4}
            }, 2)

            resp = await read_lsp_response(ws, timeout=20)
            if resp:
                result = resp.get('result', {})
                if isinstance(result, dict):
                    items = result.get('items', [])
                    print(f"    Got {len(items)} completion items")
                    for item in items[:3]:
                        label = item.get('label', '')
                        kind = item.get('kind', '')
                        detail = item.get('detail', '')
                        insert_text = item.get('insertText', '')
                        print(f"    - '{label}' (kind={kind})")
                        if insert_text:
                            print(f"      Insert: {insert_text[:100]}")
                else:
                    print(f"    Result: {json.dumps(result, indent=2)[:500]}")

            # Step 5: Wait for any server notifications
            print("\n[4] Waiting for server notifications...")
            for i in range(10):
                resp = await read_lsp_response(ws, timeout=5)
                if resp:
                    method = resp.get('method', resp.get('id', ''))
                    if method:
                        params = resp.get('params', {})
                        print(f"    [{i}] {method}: {json.dumps(params, indent=2)[:300]}")
                    else:
                        print(f"    [{i}] Response: {json.dumps(resp, indent=2)[:200]}")
                else:
                    break

            # Step 6: Try textDocument/didChange to trigger re-analysis
            print("\n[5] Send document change...")
            await send_lsp(ws, "textDocument/didChange", {
                "textDocument": {"uri": "file:///C:/test/fib.py", "version": 2},
                "contentChanges": [{"text": code + "main():"}]
            })
            time.sleep(2)

            # Step 7: Request completion again
            await send_lsp(ws, "textDocument/completion", {
                "textDocument": {"uri": "file:///C:/test/fib.py"},
                "position": {"line": 7, "character": 10}
            }, 3)

            resp = await read_lsp_response(ws, timeout=10)
            if resp:
                print(f"    After change: {json.dumps(resp, indent=2)[:300]}")

            # Step 8: Try resolve completion item
            print("\n[6] Try completion/resolve...")
            await send_lsp(ws, "completionItem/resolve", {
                "label": "main",
                "kind": 3
            }, 4)
            resp = await read_lsp_response(ws, timeout=5)
            if resp:
                print(f"    Resolved: {json.dumps(resp, indent=2)[:300]}")

            # Collect remaining
            print("\n[7] Collect remaining...")
            for i in range(5):
                resp = await read_lsp_response(ws, timeout=3)
                if resp:
                    print(f"    [{i}] {json.dumps(resp, indent=2)[:200]}")
                else:
                    break

            print("\n[*] Done!")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
