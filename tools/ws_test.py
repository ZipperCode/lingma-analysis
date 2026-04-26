"""
通过 WebSocket 连接 Lingma 本地服务器
发送请求来触发签名计算，同时用 Frida 捕获
"""
import websocket
import json
import time
import threading

def on_message(ws, message):
    print(f"[WS] <<< {message[:500]}")

def on_error(ws, error):
    print(f"[WS ERROR] {error}")

def on_close(ws, close_code, close_msg):
    print(f"[WS CLOSED] {close_code} {close_msg}")

def on_open(ws):
    print("[WS] Connected!")

    # Send initialization request
    init_msg = {
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "processId": 12345,
            "clientInfo": {"name": "test", "version": "1.0"},
            "locale": "en-US",
            "rootPath": "C:/",
        },
        "id": 1
    }
    ws.send(json.dumps(init_msg))
    print(f"[WS] >>> initialize")

    # Send ping
    time.sleep(1)
    ping_msg = {"jsonrpc": "2.0", "method": "ping", "params": {}}
    ws.send(json.dumps(ping_msg))
    print(f"[WS] >>> ping")

    # Wait for response
    time.sleep(3)
    ws.close()

def main():
    ws_url = "ws://127.0.0.1:37010"
    print(f"Connecting to {ws_url}...")

    ws = websocket.WebSocketApp(ws_url,
                                 on_open=on_open,
                                 on_message=on_message,
                                 on_error=on_error,
                                 on_close=on_close)

    ws.run_forever()

if __name__ == '__main__':
    main()
