import argparse
import json
import pathlib
import time
import uuid

import websocket


def encode_lsp(message: dict) -> str:
    body = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    return f"Content-Length: {len(body.encode('utf-8'))}\r\n\r\n{body}"


def parse_lsp(payload: bytes) -> list[dict]:
    messages: list[dict] = []
    offset = 0
    marker = b"\r\n\r\n"

    while offset < len(payload):
        header_end = payload.find(marker, offset)
        if header_end < 0:
            break

        header = payload[offset:header_end].decode("ascii", errors="replace")
        content_length = None
        for line in header.split("\r\n"):
            if line.lower().startswith("content-length:"):
                content_length = int(line.split(":", 1)[1].strip())
                break

        if content_length is None:
            break

        body_start = header_end + len(marker)
        body_end = body_start + content_length
        if body_end > len(payload):
            break

        raw_json = payload[body_start:body_end].decode("utf-8", errors="replace")
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            data = None

        messages.append({"rawJson": raw_json, "data": data})
        offset = body_end

    return messages


def read_available(ws: websocket.WebSocket, idle_timeout: float, overall_timeout: float) -> list[dict]:
    messages: list[dict] = []
    deadline = time.monotonic() + overall_timeout
    ws.settimeout(idle_timeout)

    while time.monotonic() < deadline:
        try:
            frame = ws.recv()
        except websocket.WebSocketTimeoutException:
            break
        except (websocket.WebSocketConnectionClosedException, ConnectionResetError, OSError) as exc:
            messages.append({"transportError": f"{type(exc).__name__}: {exc}"})
            break

        if isinstance(frame, str):
            frame_bytes = frame.encode("utf-8")
        else:
            frame_bytes = frame

        messages.extend(parse_lsp(frame_bytes))

    return messages


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--uri", default="ws://127.0.0.1:37010")
    parser.add_argument("--idle-timeout", type=float, default=1.2)
    parser.add_argument("--overall-timeout", type=float, default=10.0)
    parser.add_argument("--do-chat", action="store_true")
    parser.add_argument("--question", default="Say hello in one short sentence.")
    parser.add_argument("--chat-task", default="FREE_INPUT")
    parser.add_argument("--mode", default="normal")
    parser.add_argument("--workspace-uri", default=pathlib.Path.cwd().as_uri())
    parser.add_argument("--chat-idle-timeout", type=float, default=10.0)
    parser.add_argument("--chat-overall-timeout", type=float, default=30.0)
    parser.add_argument("--do-device-login", action="store_true")
    parser.add_argument("--login-token", default="")
    parser.add_argument("--login-refresh-token", default="")
    parser.add_argument("--login-user-id", default="")
    parser.add_argument("--login-username", default="")
    parser.add_argument("--login-expire-time", default="")
    args = parser.parse_args()

    ws = websocket.create_connection(args.uri, timeout=args.idle_timeout)
    steps: list[dict] = []

    try:
        initialize = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": None,
                "clientInfo": {"name": "codex", "version": "1.0"},
                "rootUri": args.workspace_uri,
                "capabilities": {},
                "workspaceFolders": [{"uri": args.workspace_uri, "name": pathlib.Path.cwd().name}],
            },
        }
        ws.send(encode_lsp(initialize))
        steps.append({"request": initialize, "response": read_available(ws, args.idle_timeout, args.overall_timeout)})

        auth_status = {"jsonrpc": "2.0", "id": 2, "method": "auth/status", "params": {}}
        ws.send(encode_lsp(auth_status))
        steps.append({"request": auth_status, "response": read_available(ws, args.idle_timeout, args.overall_timeout)})

        query_models = {"jsonrpc": "2.0", "id": 3, "method": "config/queryModels", "params": {}}
        ws.send(encode_lsp(query_models))
        steps.append({"request": query_models, "response": read_available(ws, args.idle_timeout, args.overall_timeout)})

        if args.do_device_login:
            device_login = {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "auth/device_login",
                "params": {
                    "token": args.login_token,
                    "refreshToken": args.login_refresh_token,
                    "expiresIn": "",
                    "expireTime": args.login_expire_time,
                    "userId": args.login_user_id,
                    "username": args.login_username,
                },
            }
            ws.send(encode_lsp(device_login))
            steps.append(
                {
                    "request": device_login,
                    "response": read_available(ws, args.idle_timeout, args.chat_overall_timeout),
                }
            )

            auth_status_after_login = {"jsonrpc": "2.0", "id": 5, "method": "auth/status", "params": {}}
            ws.send(encode_lsp(auth_status_after_login))
            steps.append(
                {
                    "request": auth_status_after_login,
                    "response": read_available(ws, args.idle_timeout, args.overall_timeout),
                }
            )

            query_models_after_login = {"jsonrpc": "2.0", "id": 6, "method": "config/queryModels", "params": {}}
            ws.send(encode_lsp(query_models_after_login))
            steps.append(
                {
                    "request": query_models_after_login,
                    "response": read_available(ws, args.idle_timeout, args.overall_timeout),
                }
            )

        if args.do_chat:
            chat_ask = {
                "jsonrpc": "2.0",
                "id": 7 if args.do_device_login else 4,
                "method": "chat/ask",
                "params": {
                    "requestId": uuid.uuid4().hex,
                    "chatTask": args.chat_task,
                    "chatContext": None,
                    "sessionId": "",
                    "codeLanguage": "",
                    "isReply": False,
                    "source": 1,
                    "questionText": args.question,
                    "stream": True,
                    "taskDefinitionType": "",
                    "extra": None,
                    "sessionType": "chat",
                    "targetAgent": "",
                    "pluginPayloadConfig": None,
                    "mode": args.mode,
                    "shellType": "",
                    "customModel": None,
                },
            }
            ws.send(encode_lsp(chat_ask))
            steps.append(
                {
                    "request": chat_ask,
                    "response": read_available(ws, args.chat_idle_timeout, args.chat_overall_timeout),
                }
            )
    finally:
        ws.close()

    print(json.dumps({"uri": args.uri, "steps": steps}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
