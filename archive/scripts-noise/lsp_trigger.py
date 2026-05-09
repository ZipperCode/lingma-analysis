"""Use LSP protocol to trigger Lingma AI requests and capture signatures."""
import asyncio
import websockets
import json
import sys

async def lsp_request(method, params=None, msg_id=None):
    """Send an LSP request and return response."""
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": msg_id or 1,
        "method": method,
        "params": params or {}
    })
    msg = f"Content-Length: {len(body)}\r\n\r\n{body}"
    return msg

async def lsp_notification(method, params=None):
    """Send an LSP notification (no response expected)."""
    body = json.dumps({
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {}
    })
    msg = f"Content-Length: {len(body)}\r\n\r\n{body}"
    return msg

async def read_lsp_response(ws, timeout=10):
    """Read LSP response with Content-Length parsing."""
    try:
        raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
        # Parse Content-Length header
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
        print(f"Read error: {e}")
        return None

async def main():
    try:
        async with websockets.connect('ws://127.0.0.1:37010/', open_timeout=3, close_timeout=3) as ws:
            print("[*] Connected to Lingma LSP server")

            # Step 1: Initialize
            print("\n[1] Sending initialize...")
            msg = await lsp_request("initialize", {
                "processId": 0,
                "rootUri": None,
                "clientInfo": {"name": "lingma-ctf", "version": "1.0"},
                "capabilities": {
                    "textDocument": {
                        "completion": {"completionItem": {"snippetSupport": True}}
                    }
                }
            }, 1)
            await ws.send(msg)
            resp = await read_lsp_response(ws)
            print(f"    Capabilities: {json.dumps(resp.get('result', {}).get('capabilities', {}), indent=2)[:300]}")

            # Step 2: Send initialized notification
            print("\n[2] Sending initialized notification...")
            msg = await lsp_notification("initialized", {})
            await ws.send(msg)

            # Step 3: Open a text document
            print("\n[3] Opening text document...")
            msg = await lsp_notification("textDocument/didOpen", {
                "textDocument": {
                    "uri": "file:///test.py",
                    "languageId": "python",
                    "version": 1,
                    "text": "def hello_world():\n    print('Hello, "
                }
            })
            await ws.send(msg)

            # Step 4: Request completion
            print("\n[4] Requesting completion...")
            msg = await lsp_request("textDocument/completion", {
                "textDocument": {"uri": "file:///test.py"},
                "position": {"line": 1, "character": 20}
            }, 2)
            await ws.send(msg)
            resp = await read_lsp_response(ws)
            if resp:
                print(f"    Completion response: {json.dumps(resp, indent=2)[:500]}")

            # Step 5: Request code lens (may trigger backend calls)
            print("\n[5] Requesting code lens...")
            msg = await lsp_request("textDocument/codeLens", {
                "textDocument": {"uri": "file:///test.py"}
            }, 3)
            await ws.send(msg)
            resp = await read_lsp_response(ws)
            if resp:
                print(f"    CodeLens response: {json.dumps(resp, indent=2)[:300]}")

            # Step 6: Try execute command for Lingma-specific features
            print("\n[6] Checking executeCommandProvider...")
            msg = await lsp_request("workspace/executeCommand", {
                "command": "lingma.checkStatus",
                "arguments": []
            }, 4)
            await ws.send(msg)
            resp = await read_lsp_response(ws, timeout=5)
            if resp:
                print(f"    Response: {json.dumps(resp, indent=2)[:300]}")

            # Step 7: Try lingma-specific commands
            print("\n[7] Trying lingma.getAuthStatus...")
            msg = await lsp_request("workspace/executeCommand", {
                "command": "lingma.getAuthStatus",
                "arguments": []
            }, 5)
            await ws.send(msg)
            resp = await read_lsp_response(ws, timeout=5)
            if resp:
                print(f"    Response: {json.dumps(resp, indent=2)[:500]}")

            # Step 8: Collect all remaining responses
            print("\n[8] Collecting remaining responses...")
            for i in range(3):
                resp = await read_lsp_response(ws, timeout=2)
                if resp:
                    print(f"    [{i}] {json.dumps(resp, indent=2)[:300]}")
                else:
                    break

            print("\n[*] Done!")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
