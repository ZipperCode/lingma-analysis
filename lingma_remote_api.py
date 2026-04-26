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
        """按优先级加载凭据: 直接传入 > 环境变量 > 配置文件 > 本地缓存"""
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

        # 2. 便携配置文件
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
            return

        # 3. 本地 Lingma 缓存 (需要安装 Lingma)
        with open(self.lingma_dir / 'cache' / 'id', 'r') as f:
            self._machine_id = f.read().strip()
        with open(self.lingma_dir / 'cache' / 'user', 'rb') as f:
            encrypted = base64.b64decode(f.read().strip())

        key = self._machine_id[:16].encode('utf-8')
        cipher = Cipher(algorithms.AES(key), modes.CBC(key))
        dec = cipher.decryptor()
        decrypted = dec.update(encrypted) + dec.finalize()
        decrypted = decrypted[:-decrypted[-1]]
        user_data = json.loads(decrypted.decode('utf-8'))
        self._cosy_key = user_data['key']
        self._encrypt_user_info = user_data['encrypt_user_info']
        self._user_id = user_data['uid']

    def _make_bearer(self, path: str, body: str = '', date: str = None):
        """生成 COSY Bearer token

        POST: slot4 = body (用于 MD5 签名)
        GET:  slot4 = empty
        """
        self._read_credentials()

        if date is None:
            date = str(int(time.time()))

        normalized = path[5:] if path.startswith('/algo/') else path

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
        preimage = f'{payload_b64}\n{self._cosy_key}\n{date}\n{slot4}\n{normalized}'
        sig = hashlib.md5(preimage.encode()).hexdigest()

        return f'COSY.{payload_b64}.{sig}', date

    def _make_headers(self, path: str, body: str = '', date: str = None):
        """生成请求头"""
        self._read_credentials()
        bearer, date = self._make_bearer(path, body, date)

        headers = {
            'Authorization': f'Bearer {bearer}',
            'Content-Type': 'application/json',
            'Appcode': 'cosy',
            'Cosy-Date': date,
            'Cosy-Key': self._cosy_key,
            'Cosy-Machineid': self._machine_id,
            'Cosy-User': self._user_id,
            'Cosy-Clientip': '198.18.0.1',
            'Cosy-Clienttype': '2',
            'Cosy-Machineos': 'x86_64_windows',
            'Cosy-Machinetoken': '',
            'Cosy-Machinetype': '',
            'Cosy-Version': '2.11.2',
            'Login-Version': 'v2',
            'User-Agent': 'Go-http-client/1.1',
        }

        if body:
            headers['Cache-Control'] = 'no-cache'
            headers['Accept'] = 'text/event-stream'
        else:
            headers['Accept'] = 'application/json'

        return headers

    def _build_chat_body(self, question: str, system_prompt: str = None,
                         task_id: str = 'question_refine', model: str = '') -> str:
        """构造 chat POST body (原始 JSON，无需 Encode=1 编码)"""
        self._read_credentials()

        request_id = uuid.uuid4().hex
        begin_at = int(time.time() * 1000)

        if system_prompt is None:
            system_prompt = 'You are a helpful AI coding assistant.'

        payload = {
            'request_id': request_id,
            'request_set_id': '',
            'chat_record_id': request_id,
            'stream': True,
            'image_urls': None,
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
                'is_vl': False, 'is_reasoning': False, 'api_key': '', 'url': '',
                'source': '', 'max_input_tokens': 0, 'enable': False,
                'price_factor': 0, 'original_price_factor': 0,
                'is_default': False, 'is_new': False,
                'exclude_tags': None, 'tags': None, 'icon': None, 'strategies': None,
            },
            'messages': [
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
            ],
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

        return json.dumps(payload, separators=(',', ':'), ensure_ascii=False)

    def chat(self, question: str, system_prompt: str = None, timeout: int = 60,
             task_id: str = 'question_refine', model: str = '') -> str:
        """发送聊天请求并获取回复

        Args:
            question: 用户提问
            system_prompt: 系统提示词
            timeout: 超时秒数
            task_id: 任务类型
            model: 模型 key (空=auto)

        Returns:
            模型回复文本
        """
        path = self.CHAT_PATH
        query = '?FetchKeys=llm_model_result&AgentId=agent_common'
        full_path = path + query

        body = self._build_chat_body(question, system_prompt=system_prompt,
                                     task_id=task_id, model=model)
        headers = self._make_headers(path, body)

        cmd = ['curl', '-s', '--max-time', str(timeout)]
        for k, v in headers.items():
            cmd.extend(['-H', f'{k}: {v}'])
        cmd.extend(['-d', body, f'{self.BASE_URL}{full_path}'])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)

        # 解析 SSE 响应: data:{"body":"<JSON>","statusCodeValue":200}
        contents = []
        for line in result.stdout.split('\n'):
            if line.startswith('data:'):
                try:
                    outer = json.loads(line[5:])
                    body_text = outer.get('body', '')
                    if not body_text or body_text == '[DONE]':
                        continue
                    inner = json.loads(body_text)
                    for c in inner.get('choices', []):
                        delta = c.get('delta', {}).get('content', '')
                        if delta:
                            contents.append(delta)
                except (json.JSONDecodeError, KeyError):
                    pass

        return ''.join(contents)

    def get_models(self) -> list:
        """获取可用模型列表"""
        self._read_credentials()

        path = self.MODEL_LIST_PATH
        headers = self._make_headers(path)

        cmd = ['curl', '-s', '--max-time', '30']
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
    api = LingmaRemoteAPI()
    api._read_credentials()

    print('=== Lingma Remote API Client ===')
    print(f'Machine ID: {api._machine_id}')
    print(f'User ID:    {api._user_id}')

    print()
    print('=== Models ===')
    models = api.get_models()
    for m in models[:5]:
        print(f'  {m.get("display_name", "?")} ({m.get("key", "?")})')

    print()
    print('=== Chat Test ===')
    response = api.chat('Reply with just the word: Success')
    print(f'Response: {response}')
