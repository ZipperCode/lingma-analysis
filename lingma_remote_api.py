"""
Lingma Remote API Client — 完全脱离本地 Lingma 的独立客户端.

Chat API 直接发送原始 JSON，无需 Encode=1 编码.
支持多种凭据来源，无需本地安装 Lingma 程序.

Usage:
    # 方式 1: 环境变量 (推荐，完全脱离本地环境)
    export LINGMA_MACHINE_ID="..."
    export LINGMA_USER_ID="..."
    export LINGMA_COSY_KEY="..."
    export LINGMA_ENCRYPT_USER_INFO="..."
    api = LingmaRemoteAPI()

    # 方式 2: 便携配置文件
    api = LingmaRemoteAPI(config_file="~/.lingma/portable_config.json")

    # 方式 3: 直接传参
    api = LingmaRemoteAPI(cosy_key="...", encrypt_user_info="...",
                          user_id="...", machine_id="...")

    # 方式 4: 本地 Lingma 缓存 (需要安装 Lingma)
    api = LingmaRemoteAPI()

    api.chat("你好")
"""
import base64
import hashlib
import json
import math
import os
import subprocess
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


ALPHA = '_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def _custom_b64_encode(data: bytes) -> str:
    std = base64.b64encode(data).decode().rstrip('=')
    return ''.join(ALPHA[STD_B64.index(c)] for c in std)


def _custom_b64_decode(encoded: str) -> bytes:
    converted = ''.join(STD_B64[ALPHA.index(c)] for c in encoded if c in ALPHA)
    pad = (4 - len(converted) % 4) % 4
    return base64.b64decode(converted + '=' * pad)


def lingma_encode(data: bytes) -> str:
    """Encode=1: 自定义base64 → 3块反转 → $填充"""
    encoded = _custom_b64_encode(data)
    E = len(encoded)
    BS = math.ceil(E / 3)
    pad = (4 - E % 4) % 4
    b0, b1, b2 = encoded[:BS], encoded[BS:2*BS], encoded[2*BS:]
    return b2 + '$' * pad + b1 + b0


def lingma_decode(body: str) -> bytes:
    """Encode=1 解码: 去$ → 反转恢复 → 自定义base64解码"""
    dollar_start = body.find('$')
    if dollar_start < 0:
        rev = body
        E = len(body)
    else:
        pad = 0
        pos = dollar_start
        while pos < len(body) and body[pos] == '$':
            pad += 1
            pos += 1
        rev = body[:dollar_start] + body[dollar_start + pad:]
        E = len(rev)
    BS = math.ceil(E / 3)
    lb = E - 2 * BS
    b2 = rev[:lb]
    b1 = rev[lb:lb + BS]
    b0 = rev[lb + BS:]
    return _custom_b64_decode(b0 + b1 + b2)


def aes_encrypt(data: bytes, key_str: str) -> bytes:
    """AES-128-CBC 加密 (key=IV, PKCS7 padding) — 用于本地缓存，非远端API"""
    key = key_str.encode('utf-8')
    pad_len = 16 - len(data) % 16
    padded = data + bytes([pad_len] * pad_len)
    cipher = Cipher(algorithms.AES(key), modes.CBC(key))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def aes_decrypt(data: bytes, key_str: str) -> bytes:
    """AES-128-CBC 解密 (key=IV)"""
    key = key_str.encode('utf-8')
    cipher = Cipher(algorithms.AES(key), modes.CBC(key))
    dec = cipher.decryptor()
    decrypted = dec.update(data) + dec.finalize()
    return decrypted[:-decrypted[-1]]


class LingmaRemoteAPI:
    """Lingma 远端 API 客户端 — 支持多种凭据来源"""

    BASE_URL = 'https://lingma.alibabacloud.com'
    CHAT_PATH = '/algo/api/v2/service/pro/sse/agent_chat_generation'
    FINISH_PATH = '/algo/api/v2/service/business/finish'
    EMBEDDING_PATH = '/algo/api/v2/service/codebase/embedding_k2'
    MODEL_LIST_PATH = '/algo/api/v2/model/list'

    def __init__(self, lingma_dir=None, config_file=None,
                 cosy_key=None, encrypt_user_info=None,
                 user_id=None, machine_id=None):
        self.lingma_dir = Path(lingma_dir or Path.home() / '.lingma')
        self._config_file = config_file
        # 直接传入的凭据 (最高优先级)
        self._cosy_key = cosy_key
        self._encrypt_user_info = encrypt_user_info
        self._user_id = user_id
        self._machine_id = machine_id

    def _read_credentials(self):
        """按优先级加载凭据: 直接传入 > 环境变量 > 本地缓存 > 配置文件"""
        if self._cosy_key is not None and self._encrypt_user_info is not None:
            return  # 已有凭据

        # 1. 环境变量
        if (os.environ.get('LINGMA_COSY_KEY') and
                os.environ.get('LINGMA_ENCRYPT_USER_INFO')):
            self._cosy_key = os.environ['LINGMA_COSY_KEY']
            self._encrypt_user_info = os.environ['LINGMA_ENCRYPT_USER_INFO']
            self._user_id = os.environ.get('LINGMA_USER_ID', '')
            self._machine_id = os.environ.get('LINGMA_MACHINE_ID', '')
            return

        # 2. 本地 Lingma 缓存 (最可靠，Lingma 客户端实时写入)
        try:
            cache_id = self.lingma_dir / 'cache' / 'id'
            cache_user = self.lingma_dir / 'cache' / 'user'
            if cache_id.exists() and cache_user.exists():
                with open(cache_id, 'r') as f:
                    self._machine_id = f.read().strip()
                with open(cache_user, 'rb') as f:
                    encrypted = base64.b64decode(f.read().strip())

                key = self._machine_id[:16].encode('utf-8')
                cipher = Cipher(algorithms.AES(key), modes.CBC(key))
                dec = cipher.decryptor()
                decrypted = dec.update(encrypted) + dec.finalize()
                decrypted = decrypted[:-decrypted[-1]]
                user_data = json.loads(decrypted.decode('utf-8'))
                self._cosy_key = user_data['key']
                self._encrypt_user_info = user_data['encrypt_user_info']
                self._user_id = str(user_data['uid'])
                return
        except Exception:
            pass

        # 3. 便携配置文件 (fallback，可能过期)
        config_path = self._config_file or (self.lingma_dir / 'portable_config.json')
        if isinstance(config_path, str):
            config_path = Path(config_path)
        if config_path.exists():
            with open(config_path, 'r') as f:
                cfg = json.load(f)
            self._cosy_key = cfg['cosy_key']
            self._encrypt_user_info = cfg['encrypt_user_info']
            self._user_id = cfg.get('user_id', '')
            self._machine_id = cfg.get('machine_id', '')

    def _make_bearer(self, path: str, body: str = '', date: str = None):
        """生成 COSY Bearer token

        POST: slot4 = body (用于 MD5 签名)
        GET:  slot4 = empty
        """
        self._read_credentials()

        if date is None:
            date = str(int(time.time()))

        # trimQueryPath (IDA: 0x14087eb00): strip query → strip prefixes
        sig_path = path.split('?')[0]          # 1. strip query string
        if sig_path.startswith('/algo'):       # 2. strip "/algo" prefix (unk_1424ADCF6)
            sig_path = sig_path[5:]

        payload_obj = {
            'cosyVersion': '2.11.2',
            'ideVersion': '',
            'info': self._encrypt_user_info,
            'requestId': str(uuid.uuid4()),
            'version': 'v1',
        }
        payload_b64 = base64.b64encode(
            json.dumps(payload_obj, separators=(',', ':')).encode()
        ).decode()

        slot4 = body if body else ''
        preimage = f'{payload_b64}\n{self._cosy_key}\n{date}\n{slot4}\n{sig_path}'
        sig = hashlib.md5(preimage.encode()).hexdigest()

        return f'COSY.{payload_b64}.{sig}', date, sig_path

    def _make_headers(self, path: str, body: str = '', date: str = None):
        """生成请求头（匹配 IDA 逆向的 AuthToken 函数）"""
        self._read_credentials()
        bearer, date, sig_path = self._make_bearer(path, body, date)

        body_hash = hashlib.md5(body.encode()).hexdigest() if body else hashlib.md5(b'').hexdigest()
        body_length = str(len(body.encode())) if body else '0'

        # addBasicHeaders (IDA: 0x14087ef20) — 发送在 AuthToken headers 之前
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip',
            'Cosy-Version': '2.11.2',
            'Cosy-ClientIp': '',
            'Cosy-MachineId': self._machine_id,
            'Cosy-MachineToken': '',
            'Cosy-MachineType': '',
            'Cosy-MachineCode': '',
            'Cosy-MachineOS': 'x86_64_windows',
            'Cosy-ClientType': '2',
        }

        # AuthToken (IDA: 0x14088b740) — Bearer + COSY 签名头
        headers.update({
            'Authorization': f'Bearer {bearer}',
            'Appcode': 'cosy',
            'Cosy-Date': date,
            'Cosy-Key': self._cosy_key,
            'Cosy-User': self._user_id,
            'Cosy-BodyHash': body_hash,
            'Cosy-BodyLength': body_length,
            'Cosy-SigPath': sig_path,
            'Cosy-Data-Policy': 'AGREE',
            'Cosy-Organization-Tags': '',
            'Cosy-Organization-Id': '',
        })

        if body:
            headers['Cache-Control'] = 'no-cache'
            headers['Accept'] = 'text/event-stream'

        return headers

    def _build_chat_body(self, question: str, system_prompt: str = None,
                         task_id: str = 'question_refine', model: str = '',
                         tools: list = None, tool_choice: str = None,
                         messages: list = None, image_urls: list = None,
                         is_vl: bool = False) -> str:
        """构造 chat POST body (原始 JSON，无需 Encode=1 编码)"""
        self._read_credentials()

        request_id = uuid.uuid4().hex
        begin_at = int(time.time() * 1000)

        if system_prompt is None:
            system_prompt = 'You are a helpful AI coding assistant.'

        if messages is None:
            messages = [
                {
                    'role': 'system',
                    'content': system_prompt,
                    'response_meta': {'id': '', 'usage': {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0}},
                    'reasoning_content_signature': '',
                },
                {
                    'role': 'user',
                    'content': question,
                    'response_meta': {'id': '', 'usage': {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0}},
                    'reasoning_content_signature': '',
                },
            ]

        payload = {
            'request_id': request_id,
            'request_set_id': '',
            'chat_record_id': request_id,
            'stream': True,
            'image_urls': image_urls,
            'is_reply': False,
            'is_retry': False,
            'session_id': '',
            'code_language': '',
            'source': 0,
            'version': '3',
            'chat_prompt': '',
            'parameters': {'temperature': 0.1},
            'aliyun_user_type': 'personal_standard',
            'agent_id': 'agent_common',
            'task_id': task_id,
            'model_config': {
                'key': model, 'display_name': '', 'model': model, 'format': '',
                'is_vl': is_vl, 'is_reasoning': False, 'api_key': '', 'url': '',
                'source': '', 'max_input_tokens': 0, 'enable': False,
                'price_factor': 0, 'original_price_factor': 0,
                'is_default': False, 'is_new': False,
                'exclude_tags': None, 'tags': None, 'icon': None, 'strategies': None,
            },
            'messages': messages,
            'business': {
                'product': 'jb_plugin',
                'version': '2.11.2',
                'type': 'memory',
                'id': str(uuid.uuid4()),
                'begin_at': begin_at,
                'stage': 'start',
                'name': f'memory_intent_recognition_{request_id}',
            },
        }

        if tools:
            payload['tools'] = tools
            payload['tool_choice'] = tool_choice or 'auto'

        return json.dumps(payload, separators=(',', ':'), ensure_ascii=False)

    def _parse_sse(self, raw: str) -> dict:
        """解析 SSE 响应，提取 content + tool_calls

        Returns:
            {
                'content': str,
                'tool_calls': list[{id, type, function:{name, arguments}}],
                'finish_reason': str,
                'usage': dict | None,
            }
        """
        contents = []
        tool_calls_map = {}  # index -> {id, type, function:{name, arguments}}
        finish_reason = ''
        usage = None

        for line in raw.split('\n'):
            if not line.startswith('data:'):
                continue
            try:
                outer = json.loads(line[5:])
                body_text = outer.get('body', '')
                if not body_text or body_text == '[DONE]':
                    continue
                inner = json.loads(body_text)

                usage = inner.get('usage') or usage
                for c in inner.get('choices', []):
                    fr = c.get('finish_reason', '')
                    if fr:
                        finish_reason = fr

                    delta = c.get('delta', {})
                    # Content
                    text = delta.get('content', '')
                    if text:
                        contents.append(text)

                    # Tool calls (OpenAI streaming format)
                    for tc in delta.get('tool_calls', []):
                        idx = tc.get('index', 0)
                        if idx not in tool_calls_map:
                            tool_calls_map[idx] = {
                                'id': '', 'type': 'function',
                                'function': {'name': '', 'arguments': ''},
                            }
                        entry = tool_calls_map[idx]
                        if tc.get('id'):
                            entry['id'] = tc['id']
                        if tc.get('type'):
                            entry['type'] = tc['type']
                        fn = tc.get('function', {})
                        if fn.get('name'):
                            entry['function']['name'] += fn['name']
                        if fn.get('arguments'):
                            entry['function']['arguments'] += fn['arguments']

                    # Some responses use delta.tool_call_id (non-standard)
                    tc_id = delta.get('tool_call_id')
                    if tc_id and 0 not in tool_calls_map:
                        tool_calls_map[0] = {
                            'id': tc_id, 'type': 'function',
                            'function': {'name': '', 'arguments': ''},
                        }
            except (json.JSONDecodeError, KeyError):
                pass

        # Sort by index
        tool_calls = [tool_calls_map[i] for i in sorted(tool_calls_map)]

        return {
            'content': ''.join(contents),
            'tool_calls': tool_calls,
            'finish_reason': finish_reason,
            'usage': usage,
        }

    def chat(self, question: str, system_prompt: str = None, timeout: int = 60,
             task_id: str = 'question_refine', model: str = '',
             tools: list = None, tool_choice: str = None,
             messages: list = None, image_urls: list = None,
             is_vl: bool = False) -> str:
        """发送聊天请求并获取回复（向后兼容，仅返回文本）

        Args:
            question: 用户提问
            system_prompt: 系统提示词
            timeout: 超时秒数
            task_id: 任务类型
            model: 模型 key (空=auto)
            tools: OpenAI 格式工具定义列表
            tool_choice: "auto" | "none" | {"type":"function","function":{"name":"xxx"}}
            messages: 自定义消息列表
            image_urls: 图片 URL 列表
            is_vl: 是否为视觉模型

        Returns:
            模型回复文本
        """
        result = self.chat_raw(
            question, system_prompt=system_prompt, timeout=timeout,
            task_id=task_id, model=model,
            tools=tools, tool_choice=tool_choice, messages=messages,
            image_urls=image_urls, is_vl=is_vl,
        )
        return result['content']

    def chat_raw(self, question: str, system_prompt: str = None, timeout: int = 60,
                 task_id: str = 'question_refine', model: str = '',
                 tools: list = None, tool_choice: str = None,
                 messages: list = None, image_urls: list = None,
                 is_vl: bool = False) -> dict:
        """发送聊天请求，返回完整解析结果（含 tool_calls）

        Returns:
            {'content': str, 'tool_calls': list, 'finish_reason': str, 'usage': dict|None}
        """
        path = self.CHAT_PATH
        query = '?FetchKeys=llm_model_result&AgentId=agent_common'
        full_path = path + query

        body = self._build_chat_body(
            question, system_prompt=system_prompt,
            task_id=task_id, model=model,
            tools=tools, tool_choice=tool_choice, messages=messages,
            image_urls=image_urls, is_vl=is_vl,
        )
        headers = self._make_headers(path, body)

        cmd = ['curl', '-s', '--compressed', '--max-time', str(timeout)]
        for k, v in headers.items():
            cmd.extend(['-H', f'{k}: {v}'])
        cmd.extend(['-d', body, f'{self.BASE_URL}{full_path}'])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
        return self._parse_sse(result.stdout)

    UPLOAD_PATH = '/api/v2/image/upload'

    def upload_image(self, image_path: str) -> dict:
        """上传图片到 Lingma CDN，返回 URL

        Args:
            image_path: 本地图片文件路径 (JPEG/PNG/WebP)

        Returns:
            {'success': bool, 'image_url': str, 'request_id': str}
        """
        import mimetypes

        path = Path(image_path)
        if not path.exists():
            return {'success': False, 'image_url': '', 'request_id': '',
                    'error': f'File not found: {image_path}'}

        ext = path.suffix.lower()
        if ext not in ('.jpg', '.jpeg', '.png', '.webp'):
            return {'success': False, 'image_url': '', 'request_id': '',
                    'error': f'Unsupported format: {ext}. Use JPEG, PNG, or WebP'}

        request_id = uuid.uuid4().hex
        full_path = f'{self.UPLOAD_PATH}?request_id={request_id}'

        # Read and base64 encode the image
        with open(path, 'rb') as f:
            image_data = base64.b64encode(f.read()).decode()

        mime_type = mimetypes.guess_type(str(path))[0] or 'image/png'
        data_uri = f'data:{mime_type};base64,{image_data}'

        body_obj = json.dumps({
            'ImageUri': data_uri,
            'RequestId': request_id,
        }, separators=(',', ':'))

        headers = self._make_headers(self.UPLOAD_PATH, body_obj)

        cmd = ['curl', '-s', '--compressed', '--max-time', '60']
        for k, v in headers.items():
            cmd.extend(['-H', f'{k}: {v}'])
        cmd.extend(['-d', body_obj, f'{self.BASE_URL}{full_path}'])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=70)
        try:
            resp = json.loads(result.stdout)
            detail = resp.get('Data', {})
            return {
                'success': detail.get('Success', False),
                'image_url': detail.get('ImageUrl', ''),
                'request_id': detail.get('RequestId', request_id),
            }
        except (json.JSONDecodeError, KeyError):
            return {'success': False, 'image_url': '', 'request_id': request_id,
                    'error': result.stdout[:500]}

    def chat_with_image(self, question: str, image_path: str = None,
                        image_url: str = None, model: str = '',
                        timeout: int = 120) -> dict:
        """发送带图片的聊天请求

        Args:
            question: 关于图片的提问
            image_path: 本地图片文件路径 (会自动上传)
            image_url: 图片 URL (二选一)
            model: 模型 key (空=auto)
            timeout: 超时秒数

        Returns:
            {'content': str, 'tool_calls': list, 'finish_reason': str, 'usage': dict|None}
        """
        import mimetypes

        urls = []

        # 本地文件先上传
        if image_path:
            result = self.upload_image(image_path)
            if not result['success']:
                return {
                    'content': f"图片上传失败: {result.get('error', 'unknown')}",
                    'tool_calls': [], 'finish_reason': 'error', 'usage': None,
                }
            urls.append(result['image_url'])

        if image_url:
            urls.append(image_url)

        # 构建 parts 消息 (OpenAI multimodal format)
        parts = [{'type': 'text', 'text': question}]
        for url in urls:
            parts.append({
                'type': 'image_url',
                'image_url': {'url': url, 'detail': 'auto'},
            })

        messages = [
            {
                'role': 'system',
                'content': 'You are a helpful AI coding assistant with vision capabilities.',
                'response_meta': {'id': '', 'usage': {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0}},
                'reasoning_content_signature': '',
            },
            {
                'role': 'user',
                'content': question,
                'parts': parts,
                'response_meta': {'id': '', 'usage': {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0}},
                'reasoning_content_signature': '',
            },
        ]

        return self.chat_raw(
            question='', messages=messages,
            image_urls=urls if urls else None,
            is_vl=True, model=model, timeout=timeout,
        )

    def get_models(self) -> list:
        """获取可用模型列表"""
        self._read_credentials()

        path = self.MODEL_LIST_PATH
        headers = self._make_headers(path)

        cmd = ['curl', '-s', '--compressed', '--max-time', '30']
        for k, v in headers.items():
            cmd.extend(['-H', f'{k}: {v}'])
        cmd.append(f'{self.BASE_URL}{path}')

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        try:
            data = json.loads(result.stdout)
            return data.get('chat', []) + data.get('inline', [])
        except json.JSONDecodeError:
            return []


if __name__ == '__main__':
    import sys

    api = LingmaRemoteAPI()
    api._read_credentials()

    print('=== Lingma Remote API Client ===')
    print(f'Machine ID: {api._machine_id}')
    print(f'User ID:    {api._user_id}')

    mode = sys.argv[1] if len(sys.argv) > 1 else 'basic'

    if mode == 'models':
        print('\n=== Models ===')
        models = api.get_models()
        for m in models:
            vl = ' [VL]' if m.get('multiModalSupported') or m.get('is_vl') else ''
            print(f'  {m.get("display_name", "?")} ({m.get("key", "?")}){vl}')

    elif mode == 'tool':
        print('\n=== Tool Call Test ===')
        tools = [
            {
                'type': 'function',
                'function': {
                    'name': 'get_current_time',
                    'description': 'Get the current date and time',
                    'parameters': {
                        'type': 'object',
                        'properties': {
                            'timezone': {
                                'type': 'string',
                                'description': 'Timezone (e.g. UTC, Asia/Shanghai)',
                            },
                        },
                        'required': [],
                    },
                },
            },
        ]
        result = api.chat_raw(
            'What time is it now?',
            tools=tools, tool_choice='auto',
        )
        print(f'Content:       {result["content"]}')
        print(f'Finish reason: {result["finish_reason"]}')
        print(f'Tool calls:    {len(result["tool_calls"])}')
        for tc in result['tool_calls']:
            fn = tc['function']
            print(f'  [{tc["id"]}] {fn["name"]}({fn["arguments"]})')
        if result['usage']:
            print(f'Usage: {result["usage"]}')

    elif mode == 'upload':
        if len(sys.argv) < 3:
            print('Usage: python lingma_remote_api.py upload <image_path>')
            sys.exit(1)
        print(f'\n=== Upload Image ===')
        result = api.upload_image(sys.argv[2])
        print(f'Success:    {result["success"]}')
        print(f'Image URL:  {result["image_url"]}')
        print(f'Request ID: {result["request_id"]}')
        if result.get('error'):
            print(f'Error:      {result["error"]}')

    elif mode == 'vision':
        if len(sys.argv) < 3:
            print('Usage: python lingma_remote_api.py vision <question> [--url URL] [--file PATH]')
            sys.exit(1)
        question = sys.argv[2]
        img_url = None
        img_file = None
        i = 3
        while i < len(sys.argv):
            if sys.argv[i] == '--url' and i + 1 < len(sys.argv):
                img_url = sys.argv[i + 1]
                i += 2
            elif sys.argv[i] == '--file' and i + 1 < len(sys.argv):
                img_file = sys.argv[i + 1]
                i += 2
            else:
                i += 1

        print(f'\n=== Vision Test ===')
        print(f'Question: {question}')
        if img_file:
            print(f'File:     {img_file}')
        if img_url:
            print(f'URL:      {img_url}')

        result = api.chat_with_image(question, image_path=img_file, image_url=img_url)
        print(f'\nResponse: {result["content"]}')
        if result['usage']:
            print(f'Usage: {result["usage"]}')

    else:
        print('\n=== Chat Test ===')
        response = api.chat('Reply with just the word: Success')
        print(f'Response: {response}')
