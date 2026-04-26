import argparse
import base64
import http.client
import hashlib
import json
import pathlib
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def safe_text(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode("utf-8", errors="replace")


def body_preview(body: bytes, limit: int = 512) -> str:
    if not body:
        return ""
    preview = base64.b64encode(body[:limit]).decode("ascii")
    if len(body) > limit:
        preview += "...(truncated)"
    return preview


class CaptureHandler(BaseHTTPRequestHandler):
    server_version = "LingmaCapture/1.0"

    def log_message(self, format: str, *args) -> None:
        return

    def _record(self, body: bytes) -> dict:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "method": self.command,
            "path": self.path,
            "headers": {k: v for k, v in self.headers.items()},
            "body_len": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_utf8": safe_text(body),
            "body_base64_preview": body_preview(body),
        }

        with self.server.log_lock:
            self.server.log_file.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self.server.log_file.flush()

        print(f"[capture] {entry['method']} {entry['path']} len={entry['body_len']}")
        return entry

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_sse(self, lines: list[str]) -> None:
        body = "".join(lines).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _choose_upstream(self) -> str:
        if "/service/pro/sse/agent_chat_generation" in self.path and self.server.chat_upstream_base:
            return self.server.chat_upstream_base
        return self.server.upstream_base

    def _proxy_upstream(self, body: bytes) -> bool:
        upstream = self._choose_upstream()
        if not upstream:
            return False

        parts = urlsplit(upstream)
        conn_cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(parts.hostname, parts.port, timeout=60)

        upstream_path = self.path
        if parts.path and parts.path != "/":
            base_path = parts.path.rstrip("/")
            request_path = self.path if self.path.startswith("/") else f"/{self.path}"
            upstream_path = f"{base_path}{request_path}"

        headers = {k: v for k, v in self.headers.items() if k.lower() != "host"}
        if body:
            headers["Content-Length"] = str(len(body))
        else:
            headers.pop("Content-Length", None)

        try:
            conn.request(self.command, upstream_path, body=body if body else None, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            self.send_response(resp.status, resp.reason)
            for key, value in resp.getheaders():
                lower = key.lower()
                if lower in {"transfer-encoding", "connection", "keep-alive", "content-length"}:
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
            return True
        finally:
            conn.close()

    def do_GET(self) -> None:
        self._record(b"")
        if self.path.startswith("/algo/api/v1/ping"):
            self._send_json(200, {"code": "200", "message": "pong"})
            return
        if self._proxy_upstream(b""):
            return
        if "/config/getDataPolicy" in self.path:
            self._send_json(200, {"code": "200", "message": "ok", "data": {"signStatus": "AGREE"}})
            return
        self._send_json(200, {"code": "200", "message": "captured"})

    def do_POST(self) -> None:
        body = self._read_body()
        self._record(body)

        if self._proxy_upstream(body):
            return

        if "/service/pro/sse/agent_chat_generation" in self.path:
            self._send_sse(
                [
                    'event: message\n',
                    'data: {"code":"10500","message":"capture stub"}\n\n',
                ]
            )
            return

        if "/algo/api/v1/heartbeat" in self.path:
            self._send_json(200, {"code": "200", "message": "heartbeat captured"})
            return

        if "/algo/api/v3/user/status" in self.path:
            self._send_json(200, {"code": "200", "message": "status captured", "data": {}})
            return

        if "/algo/api/v3/user/login" in self.path:
            self._send_json(200, {"code": "200", "message": "login captured", "data": {}})
            return

        if "/algo/api/v3/user/grantAuthInfos" in self.path:
            self._send_json(200, {"code": "200", "message": "grant captured", "data": {}})
            return

        self._send_json(200, {"code": "200", "message": "captured"})


class CaptureServer(ThreadingHTTPServer):
    def __init__(self, addr: tuple[str, int], handler: type[BaseHTTPRequestHandler], log_path: pathlib.Path):
        super().__init__(addr, handler)
        self.log_lock = threading.Lock()
        self.log_path = log_path
        self.upstream_base = ""
        self.chat_upstream_base = ""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_path.open("a", encoding="utf-8")

    def server_close(self) -> None:
        try:
            self.log_file.close()
        finally:
            super().server_close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--log", default="capture/lingma-http-capture.jsonl")
    parser.add_argument("--upstream-base", default="")
    parser.add_argument("--chat-upstream-base", default="")
    args = parser.parse_args()

    log_path = pathlib.Path(args.log).resolve()
    server = CaptureServer((args.host, args.port), CaptureHandler, log_path)
    server.upstream_base = args.upstream_base.rstrip("/")
    server.chat_upstream_base = args.chat_upstream_base.rstrip("/")
    print(f"[capture] listening on http://{args.host}:{args.port}")
    print(f"[capture] logging to {log_path}")
    if server.upstream_base:
        print(f"[capture] proxy upstream {server.upstream_base}")
    if server.chat_upstream_base:
        print(f"[capture] proxy chat upstream {server.chat_upstream_base}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
