"""Trigger Lingma chat request via LSP to capture signing flow."""
import asyncio
import websockets
import json
import time

async def read_lsp(ws, timeout=10):
    try:
        raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
        if '\r\n\r\n' in raw:
            headers, body = raw.split('\r\n\r\n', 1)
            length = 0
            for line in headers.split('\r\n'):
                if line.startswith('Content-Length:'):
                    length = int(line.split(':')[1].strip())
            return json.loads(body[:length] if length else body)
        return json.loads(raw)
    except:
        return None

async def send(ws, method, params=None, msg_id=None):
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
            print("[1] Initialize...")
            await send(ws, "initialize", {
                "processId": 0,
                "rootUri": "file:///C:/test",
                "clientInfo": {"name": "vscode", "version": "1.95.0"},
                "capabilities": {}
            }, 1)
            await read_lsp(ws, 5)
            await send(ws, "initialized", {})

            # Open a file with a real coding question
            print("[2] Open document with question context...")
            code = """# TODO: Implement a function to sort a list of dictionaries by a specific key
def sort_dicts(dict_list, key):
    pass
"""
            await send(ws, "textDocument/didOpen", {
                "textDocument": {
                    "uri": "file:///C:/test/sort.py",
                    "languageId": "python",
                    "version": 1,
                    "text": code
                }
            })

            # Try executeCommand for chat - various command names
            print("[3] Try executeCommand for chat/request...")
            commands_to_try = [
                "lingma.chat",
                "lingma.chat.new",
                "lingma.chat.send",
                "cosy.chat",
                "cosy.chat.new",
                "cosy.chat.send",
                "lingma.requestCompletion",
                "cosy.requestCompletion",
                "lingma.triggerAgent",
                "cosy.triggerAgent",
                "lingma.chatWithAI",
                "cosy.chatWithAI",
                "lingma/sendMessage",
                "cosy/sendMessage",
            ]
            for cmd in commands_to_try:
                await send(ws, "workspace/executeCommand", {
                    "command": cmd,
                    "arguments": [{"question": "how to implement sort_dicts?"}]
                }, 100)
                resp = await read_lsp(ws, 3)
                if resp:
                    print(f"  {cmd}: {json.dumps(resp, indent=2)[:200]}")

            # Try Lingma-specific methods that might trigger AI calls
            print("\n[4] Try custom LSP methods...")
            custom_methods = [
                "lingma/chat",
                "cosy/chat",
                "lingma/request",
                "cosy/request",
                "textDocument/aiCompletion",
                "textDocument/inlineCompletion",
                "lingma/triggerCompletion",
                "cosy/triggerCompletion",
            ]
            for method in custom_methods:
                await send(ws, method, {
                    "textDocument": {"uri": "file:///C:/test/sort.py"},
                    "position": {"line": 2, "character": 4},
                    "prompt": "implement sort_dicts"
                }, 200)
                resp = await read_lsp(ws, 3)
                if resp:
                    print(f"  {method}: {json.dumps(resp, indent=2)[:200]}")

            # Wait for any traffic
            print("\n[5] Collect remaining...")
            for i in range(5):
                resp = await read_lsp(ws, 5)
                if resp:
                    print(f"  [{i}] {json.dumps(resp, indent=2)[:200]}")
                else:
                    break

            print("\n[*] Done!")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
