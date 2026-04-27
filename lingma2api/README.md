# lingma2api

`lingma2api` 是一个最小 OpenAI 兼容代理，对外暴露 `/v1/models` 与 `/v1/chat/completions`，对内复用当前仓库已经验证的 Lingma 远端 HTTP/SSE 契约。

## 当前能力

- `GET /v1/models`
- `POST /v1/chat/completions`
- `stream=true` 与 `stream=false`
- `extra_body.session_id` / `X-Session-Id`
- `GET /admin/status`
- `POST /admin/refresh`
- `GET /admin/sessions`
- `DELETE /admin/sessions/{id}`

## 运行态认证边界

运行态只读取当前项目内的认证文件：

1. `auth/credentials.json`

不再支持以下运行态来源：

1. `~/.lingma/*`
2. `portable_config.json`
3. 环境变量凭据注入

`~/.lingma/*` 只允许用于测试、研究或一次性迁移工具。

## 认证文件

请参考：

1. `auth/credentials.example.json`

当前推荐路径由 `config.yaml` 中的 `credential.auth_file` 指定，默认值为：

```text
./auth/credentials.json
```

文件中至少要包含：

1. `auth.cosy_key`
2. `auth.encrypt_user_info`
3. `auth.user_id`
4. `auth.machine_id`

## Bootstrap 说明

当前设计采用“一次性本地回调授权 + 项目内落盘”方案。

当前已提供 `cmd/lingma-auth-bootstrap` 骨架，可完成：

1. 生成 OAuth 链接
2. 捕获浏览器回调
3. 将回调内容保存为项目内 artifact

当前尚未完成的部分：

1. 基于回调参数完成最终 token exchange
2. 自动整理并写出可直接运行的 `auth/credentials.json`

在 bootstrap 完整链路落地前，运行态不会尝试自动登录，也不会回退读取 `.lingma`。

## 一次性迁移工具

当前已提供可用的初始化命令：

```bash
cd lingma2api
go run ./cmd/lingma-import-cache --lingma-dir ~/.lingma --output ./auth/credentials.json
```

这个命令只用于一次性初始化：

1. 读取本机 `~/.lingma/cache/user`
2. 读取 `cache/id` 或 `lingma.log` 中的 machine id
3. 生成项目内 `auth/credentials.json`

它不改变主服务运行态边界。

## 一次性 `client_id` 候选验证

如果要复用仓库里已有的 [callback.html](/Users/Zipper/Github/lingma-analysis/callback.html) 线索，验证“`machine_id` 是否可作为 `client_id` 候选”，可运行：

```bash
cd lingma2api
go run ./cmd/lingma-auth-bootstrap \
  --seed-callback-html ../callback.html \
  --use-machine-id-as-client-id \
  --listen-addr 127.0.0.1:37510 \
  --output ./auth/bootstrap-callback.json
```

这个命令当前会：

1. 从 `callback.html` 提取 `machine_id` 和历史回调提示
2. 用 `machine_id` 作为一次性 `client_id` 候选生成 OAuth URL
3. 等待浏览器回调
4. 将回调结果保存到 `auth/bootstrap-callback.json`

它当前不会自动完成最终 token exchange。

## 启动

```bash
cd lingma2api
go run . -config ./config.yaml
```

## 请求示例

```bash
curl -s http://127.0.0.1:8080/v1/models
```

```bash
curl -N http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "auto",
    "stream": true,
    "messages": [
      {"role": "user", "content": "Hello"}
    ]
  }'
```

## 管理接口

如果 `server.admin_token` 非空，则管理接口需要携带以下任一认证头：

- `Authorization: Bearer <admin_token>`
- `X-Admin-Token: <admin_token>`

## 限制

- 当前远端传输依赖本机可执行的 `curl`
- 当前实现仅覆盖最小 OpenAI Chat Completions 子集
- `/admin/refresh` 当前返回 `501`，提示重新执行 bootstrap
