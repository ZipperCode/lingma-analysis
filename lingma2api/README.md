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

`cmd/lingma-auth-bootstrap` 是完整的一次性授权引导工具，负责生成 OAuth 链接、监听回调、交换 token、派生 Lingma 凭据，最终写出可被主服务直接使用的 `auth/credentials.json`。

### 完整授权流程

```bash
cd lingma2api
go run ./cmd/lingma-auth-bootstrap --output ./auth/credentials.json
```

流程：

1. 自动生成 `machine_id` (用作 OAuth `client_id`)
2. 生成 PKCE(state + verifier + challenge)
3. 构造浏览器 OAuth 链接
4. 在本地 `127.0.0.1:37510/callback` 启动一次性回调监听
5. 用户在浏览器完成登录
6. 捕获回调中的 `authorization_code`
7. 向 Alibaba OAuth token endpoint 交换 `access_token` + `refresh_token` + `id_token`
8. 从 `id_token` 解码 `user_id` 和 `username`
9. 启动临时 Lingma 实例并通过 `auth/device_login` 同步凭据
10. 从 Lingma 工作目录读取 `cosy_key`、`encrypt_user_info` 等
11. 写入 `auth/credentials.json`
12. 清理临时 Lingma 实例

### 可选参数

```
--client-id        OAuth client_id (默认自动生成 UUID 格式 machine_id)
--listen-addr      本地回调监听地址 (默认 127.0.0.1:37510)
--redirect-url     显式回调 URL (默认 http://<listen-addr>/callback)
--output           输出文件路径 (默认 ./auth/credentials.json)
--lingma-bin       Lingma 二进制路径 (默认自动探测 ~/.lingma/bin/ 下最新版本)
--use-lingma       使用本地 Lingma 完成凭据派生 (默认 true)
--print-only       仅打印 OAuth 链接和 PKCE 参数，不执行完整流程
```

### 使用场景

**场景 A：新机器首次授权** (无需本地 Lingma 缓存)

```bash
go run ./cmd/lingma-auth-bootstrap
```

**场景 B：仅获取 OAuth 链接** (调试/手动操作)

```bash
go run ./cmd/lingma-auth-bootstrap --print-only
```

**场景 C：指定 Lingma 二进制路径**

```bash
go run ./cmd/lingma-auth-bootstrap --lingma-bin /path/to/Lingma
```

## 一次性迁移工具

如果本机已有 Lingma 登录态（`~/.lingma/cache/user` 存在），可用一键迁移：

```bash
cd lingma2api
go run ./cmd/lingma-import-cache --lingma-dir ~/.lingma --output ./auth/credentials.json
```

这个命令读取本机 Lingma 缓存文件并导出项目内认证文件，不改变主服务运行态边界。

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
