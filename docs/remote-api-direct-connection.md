# Lingma 远端 API 直连 - 当前实现说明

更新时间：2026-04-30

## 这份文档负责什么

这份文档只回答一件事：

- 当前仓库里的远端 HTTP 直连，到底已经落地成了什么代码、什么请求和什么边界。

对应实现：

- [../lingma_remote_api.py](../lingma_remote_api.py)

## 核心结论

### 1. 远端 Chat API 已经可以独立工作

当前仓库已经通过 [../lingma_remote_api.py](../lingma_remote_api.py) 打通：

- `GET /algo/api/v2/model/list`
- `POST /algo/api/v2/service/pro/sse/agent_chat_generation`

其中最关键的确认是：

- Chat POST body 发送的是原始 JSON
- 不需要 `Encode=1`
- 不需要模板重放
- 不需要额外二进制分片

### 2. 当前“能不能直连”已经不是问题，真正问题是“凭据从哪里来”

当前实现已经证明：

- Bearer 可以独立生成
- 请求头可以独立生成
- 聊天 body 可以独立构造
- SSE 可以独立解析

因此真正剩下的约束是：

- 有效 `cosy_key`
- 有效 `encrypt_user_info`
- 对应的 `user_id`
- 对应的 `machine_id`
- TLS 指纹兼容传输层

## 当前实现和代码入口

### 1. 凭据读取

`LingmaRemoteAPI._read_credentials()` 按下面优先级读取材料：

1. 构造函数直接传参
2. 环境变量
3. `portable_config.json`
4. 本地 `~/.lingma/cache/id` + `~/.lingma/cache/user`

当走本地缓存时，当前代码已明确实现：

- 读取 `cache/id` 得到 `machine_id`
- base64 解码 `cache/user`
- 用 `machine_id[:16]` 做 AES-128-CBC 的 key 和 IV
- 解密后提取：
  - `key`
  - `encrypt_user_info`
  - `uid`

### 2. Bearer 签名

`LingmaRemoteAPI._make_bearer()` 当前实现的公式是：

```text
payload_b64 = base64(json({
  cosyVersion,
  ideVersion,
  info,
  requestId,
  version
}))

GET:  md5(payload_b64 + "\n" + cosy_key + "\n" + date + "\n" + ""   + "\n" + normalized_path)
POST: md5(payload_b64 + "\n" + cosy_key + "\n" + date + "\n" + body + "\n" + normalized_path)

bearer = "COSY." + payload_b64 + "." + md5hex
```

`normalized_path` 的处理规则也已经写死在实现里：

- 如果 path 以 `/algo/` 开头，就去掉前缀 `/algo/`
- 否则使用原 path

### 3. 请求头构造

`LingmaRemoteAPI._make_headers()` 当前会生成：

- `Authorization: Bearer COSY...`
- `Appcode: cosy`
- `Cosy-Date`
- `Cosy-Key`
- `Cosy-Machineid`
- `Cosy-User`
- `Cosy-Clientip`
- `Cosy-Clienttype`
- `Cosy-Machineos`
- `Cosy-Version`
- `Login-Version`
- `User-Agent`

同时：

- 有 body 时走 `Accept: text/event-stream`
- 无 body 时走 `Accept: application/json`

### 4. Chat body 构造

`LingmaRemoteAPI._build_chat_body()` 当前已经把最小 chat 请求落到了代码里，核心点包括：

- `messages` 数组
- `system` + `user` 两条消息
- `stream: true`
- `task_id`
- `model_config.key`
- `business` 元信息

这意味着当前仓库已经不再停留在“知道端点是什么”，而是已经把可运行的 body 形状固定成实现。

### 5. SSE 响应解析

`LingmaRemoteAPI.chat()` 当前按下面结构解析响应：

1. 按行读取 `curl` 标准输出
2. 只处理 `data:` 开头的 SSE 行
3. 外层 JSON 读取 `body`
4. 内层 JSON 读取 `choices[*].delta.content`
5. 按顺序拼接文本

当前口径应统一为：

- 外层是 Lingma 的包装
- 内层结构已经足够接近 OpenAI chat chunk，可直接抽取增量文本

## 与 `Encode=1` / AES 的边界

当前实现里虽然还保留了：

- `lingma_encode()`
- `lingma_decode()`
- `aes_encrypt()`
- `aes_decrypt()`

但它们在远端直连主线里的职责已经明确变化：

- `Encode=1`：
  - 作为已解析能力保留
  - 当前不是远端 Chat API 的前置条件
- AES：
  - 当前用于本地缓存处理
  - 不是远端 Chat body 的发送前置

## 当前限制

1. 仍依赖有效凭据

- 当前没有把 OAuth 登录和刷新独立成这份脚本里的默认能力

2. 仍依赖 `curl`

- 当前实现显式通过 `subprocess.run(["curl", ...])` 发请求
- 这是为了兼容服务器的 TLS 指纹要求

3. 当前只把“聊天 + 模型列表”做成主实现

- 其他端点仍属于专项分析范围
- 是否需要 `Encode=1`、是否需要不同签名链，仍应以专项文档为准

## 推荐配套阅读

- [lingma-analysis-final-status.md](./lingma-analysis-final-status.md)
- [lingma-analysis-overview.md](./lingma-analysis-overview.md)
- [topics/encode1-complete-analysis.md](./topics/encode1-complete-analysis.md)
- [topics/session-key-analysis.md](./topics/session-key-analysis.md)
