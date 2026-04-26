"""
Lingma 独立聊天客户端
绕过 plugin，直接通过本地 37010 WebSocket API 与大模型交互

使用方法:
    python lingma_client.py --question "你好"
    python lingma_client.py --interactive
"""

import argparse
import json
import pathlib
import sys
import time
import uuid

import websocket


class LingmaClient:
    """Lingma 本地 API 客户端，通过 ws://127.0.0.1:37010 通信"""

    def __init__(self, uri="ws://127.0.0.1:37010", workspace=None):
        self.uri = uri
        self.workspace = workspace or pathlib.Path.cwd().as_uri()
        self.ws = None
        self._request_id = 0
        self._initialized = False
        self._auth_info = None

    def connect(self):
        """建立 WebSocket 连接并初始化"""
        self.ws = websocket.create_connection(self.uri, timeout=5)
        self._initialize()
        self._check_auth()
        self._initialized = True

    def ask(self, question, task="FREE_INPUT", mode="normal", timeout=45):
        """
        发送单次提问并获取回答

        采用 "real + (wait step_end) + trigger" 方法解决服务端 off-by-one 延迟：
        1. 发送真正的问题
        2. 等待 step_end（模型生成完成）
        3. 发送 trigger 获取回答

        Args:
            question: 用户提问
            task: 聊天任务类型
            mode: 模式 (normal, agent)
            timeout: 响应超时时间(秒)

        Returns:
            str: 完整的响应文本
        """
        # 关闭旧连接，创建新连接
        if self._initialized:
            self.close()

        self.ws = websocket.create_connection(self.uri, timeout=5)
        self._initialize()
        self._check_auth()

        # Step 1: 发送真正的问题
        request_id = uuid.uuid4().hex
        self._send("chat/ask", self._make_chat_params(question, request_id, task, mode))

        # Step 2: 等待 step_end（模型生成完成）
        deadline = time.monotonic() + timeout
        self.ws.settimeout(10)
        got_step_end = False
        while time.monotonic() < deadline and not got_step_end:
            try:
                frame = self.ws.recv()
            except websocket.WebSocketTimeoutException:
                continue
            except (websocket.WebSocketConnectionClosedException, ConnectionResetError, OSError):
                break
            frame_bytes = frame.encode("utf-8") if isinstance(frame, str) else frame
            for msg in self._parse_lsp(frame_bytes):
                if msg and msg.get("method") == "chat/process_step_callback":
                    params = msg.get("params", {})
                    if params.get("requestId") == request_id and params.get("step") == "step_end":
                        got_step_end = True

        if not got_step_end:
            self.close()
            self._initialized = False
            return ""

        # Step 3: 发送 trigger 获取真正问题的回答
        trigger_id = uuid.uuid4().hex
        self._send("chat/ask", self._make_chat_params("OK", trigger_id, task, mode))

        # 收集 trigger 的回答 = 真正问题的回答
        answer = self._collect_answer(trigger_id, timeout=timeout)

        self.close()
        self._initialized = False
        return answer

    def _make_chat_params(self, question, request_id, task="FREE_INPUT", mode="normal"):
        """构造 chat/ask 请求参数"""
        return {
            "requestId": request_id,
            "chatTask": task,
            "chatContext": None,
            "sessionId": "",
            "codeLanguage": "",
            "isReply": False,
            "source": 1,
            "questionText": question,
            "stream": True,
            "taskDefinitionType": "",
            "extra": None,
            "sessionType": "chat",
            "targetAgent": "",
            "pluginPayloadConfig": None,
            "mode": mode,
            "shellType": "",
            "customModel": None,
        }

    def _collect_answer(self, request_id, timeout=45):
        """收集指定 requestId 的回答"""
        full_text = []
        deadline = time.monotonic() + timeout
        self.ws.settimeout(10)
        last_answer_time = None

        while time.monotonic() < deadline:
            try:
                frame = self.ws.recv()
            except websocket.WebSocketTimeoutException:
                if last_answer_time and time.monotonic() - last_answer_time > 3:
                    break
                continue
            except (websocket.WebSocketConnectionClosedException, ConnectionResetError, OSError):
                break

            frame_bytes = frame.encode("utf-8") if isinstance(frame, str) else frame
            messages = self._parse_lsp(frame_bytes)

            for msg in messages:
                if not msg:
                    continue
                method = msg.get("method", "")
                params = msg.get("params", {})
                if method == "chat/answer" and params.get("requestId") == request_id:
                    text = params.get("text", "")
                    if text:
                        full_text.append(text)
                        last_answer_time = time.monotonic()

        return "".join(full_text)

    def close(self):
        """关闭连接"""
        if self.ws:
            self.ws.close()
            self.ws = None
        self._initialized = False

    def _next_id(self):
        self._request_id += 1
        return self._request_id

    def _send(self, method, params=None):
        """发送 LSP-framed JSON-RPC 请求"""
        msg = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
            "params": params or {},
        }
        body = json.dumps(msg, ensure_ascii=False, separators=(",", ":"))
        frame = f"Content-Length: {len(body.encode('utf-8'))}\r\n\r\n{body}"
        self.ws.send(frame)
        return msg

    def _recv_all(self, idle_timeout=1.5, overall_timeout=10):
        """接收所有可用的 LSP-framed 响应"""
        messages = []
        deadline = time.monotonic() + overall_timeout
        self.ws.settimeout(idle_timeout)

        while time.monotonic() < deadline:
            try:
                frame = self.ws.recv()
            except websocket.WebSocketTimeoutException:
                break
            except (websocket.WebSocketConnectionClosedException, ConnectionResetError, OSError):
                break

            frame_bytes = frame.encode("utf-8") if isinstance(frame, str) else frame
            messages.extend(self._parse_lsp(frame_bytes))

        return messages

    def _parse_lsp(self, payload):
        """解析 LSP framing 协议"""
        messages = []
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
            messages.append(data)
            offset = body_end

        return messages

    def _initialize(self):
        """发送 initialize 请求"""
        self._send("initialize", {
            "processId": None,
            "clientInfo": {"name": "lingma-client", "version": "1.0"},
            "rootUri": self.workspace,
            "capabilities": {},
            "workspaceFolders": [{"uri": self.workspace, "name": "workspace"}],
        })
        return self._recv_all()

    def _check_auth(self):
        """检查认证状态"""
        self._send("auth/status", {})
        responses = self._recv_all()
        for resp in responses:
            if resp and "result" in resp and isinstance(resp["result"], dict):
                if "status" in resp["result"]:
                    self._auth_info = resp["result"]
                    return resp["result"]
        return None

    @property
    def is_authenticated(self):
        """是否已认证"""
        return self._auth_info is not None and self._auth_info.get("status") == 2

    @property
    def user_name(self):
        """当前用户名"""
        return self._auth_info.get("name", "") if self._auth_info else ""

    def chat(self, question, task="FREE_INPUT", mode="normal", timeout=30):
        """Backward-compatible alias for the corrected ask() flow."""
        return self.ask(question, task=task, mode=mode, timeout=timeout)

    def query_models(self):
        """查询可用模型列表"""
        self._send("config/queryModels", {})
        responses = self._recv_all()
        for resp in responses:
            if resp and "result" in resp:
                return resp["result"]
        return None


def main():
    parser = argparse.ArgumentParser(description="Lingma 独立聊天客户端")
    parser.add_argument("--uri", default="ws://127.0.0.1:37010", help="WebSocket URI")
    parser.add_argument("--question", "-q", help="单次提问")
    parser.add_argument("--interactive", "-i", action="store_true", help="交互模式")
    parser.add_argument("--timeout", type=int, default=30, help="响应超时(秒)")
    parser.add_argument("--mode", default="normal", help="聊天模式")
    args = parser.parse_args()

    client = LingmaClient(uri=args.uri)

    try:
        print("正在连接 Lingma 服务...", file=sys.stderr)
        client.connect()
        print(f"已连接! 用户: {client.user_name}", file=sys.stderr)

        if args.question:
            # 单次提问模式
            response = client.ask(args.question, timeout=args.timeout, mode=args.mode)
            print(response)
        else:
            # 交互模式
            print("进入交互模式 (输入 'quit' 退出)", file=sys.stderr)
            while True:
                try:
                    question = input("\n> ").strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if not question or question.lower() == "quit":
                    break
                response = client.ask(question, timeout=args.timeout, mode=args.mode)
                print(response)

    finally:
        client.close()
        print("\n连接已关闭", file=sys.stderr)


if __name__ == "__main__":
    main()
