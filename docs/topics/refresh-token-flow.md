# Lingma refresh_token 续命流程

> 日期：2026-04-27
> 目标：在 `lingma-auth-bootstrap` 中增加 `--refresh` 子模式，使已有凭据在 access_token 过期后无需重新走浏览器登录即可续命。

## 结论

阿里云 OAuth 网关支持标准 `grant_type=refresh_token` 端点，与 `authorization_code` 共用同一个 token URL（`https://oauth.alibabacloud.com/v1/token`）。`lingma-auth-bootstrap` 现已集成该能力，用法：

```bash
go run ./cmd/lingma-auth-bootstrap \
  --refresh ./auth/credentials.json \
  --client-id <REAL_ID>
```

---

## 1. 技术背景

### 1.1 Token 生命周期

- `access_token`：短期有效（实测约 3600s）。
- `refresh_token`：长期有效，用于换取新的 `access_token`。
- `id_token`：OIDC 身份声明，过期后通常不再提供。

### 1.2 端点与参数

| 参数 | 值 |
|---|---|
| URL | `https://oauth.alibabacloud.com/v1/token` |
| method | POST |
| Content-Type | `application/x-www-form-urlencoded` |
| grant_type | `refresh_token` |
| refresh_token | 从凭据文件 `oauth.refresh_token` 读取 |
| client_id | 必须与 authorize 阶段使用的 client_id 一致 |

**注意**：refresh 请求**不需要** `code_verifier`、`redirect_uri` 等 PKCE 参数。

---

## 2. 实现改动

### 2.1 `internal/auth/token_exchange.go`

新增结构体与函数：

```go
type RefreshTokenConfig struct {
    RefreshToken string
    ClientID     string
    TokenURL     string
    HTTPClient   *http.Client
}

func RefreshTokens(ctx context.Context, cfg RefreshTokenConfig) (ExchangedTokens, error)
```

实现要点：
- 复用既有的 `ExchangedTokens` 结构与 `TokenExchangeError` 错误类型。
- 错误处理与 `ExchangeCodeForTokens` 完全一致：200 解析 JSON、400 优先解析 `{"error","error_description"}`、非标准体回退到 HTTP status + raw body。

### 2.2 `cmd/lingma-auth-bootstrap/main.go`

新增互斥 flag `--refresh <credentials.json>`：

```go
flag.StringVar(&refreshFile, "refresh", "", "refresh existing credentials.json")
```

执行流程：

1. 读取已有 JSON → 提取 `oauth.refresh_token`。
2. 确定 `client_id`：
   - 优先级：`--client-id` > 环境变量 `LINGMA_CLIENT_ID`。
3. 调用 `auth.RefreshTokens(...)` 换取新 token 对。
4. 根据 `--use-lingma` 决定派生方式：
   - `true`（默认）：启动本地 Lingma 二进制，用新 `access_token` 同步 cosy_key。
   - `false`：调用 `auth.DeriveCredentialsRemotely(...)` 远程登录获取 cosy_key。
5. 更新凭据文件中的 OAuth 字段与派生出的 Auth 字段，写回原路径。

### 2.3 `internal/auth/token_exchange_test.go`

新增 5 个测试用例覆盖：

| 测试名 | 场景 |
|---|---|
| `TestRefreshTokens_OK` | 200 + 正确 JSON，验证表单字段 grant_type/refresh_token/client_id |
| `TestRefreshTokens_StructuredError` | 400 + 标准 error/error_description，返回 `*TokenExchangeError` |
| `TestRefreshTokens_FallbackError` | 400 + 非标准体，fallback 错误含 HTTP 状态码和原文 |
| `TestRefreshTokens_MissingRefreshToken` | 空 refresh_token 前置校验 |
| `TestRefreshTokens_MissingClientID` | 空 client_id 前置校验 |

---

## 3. 使用示例

### 3.1 纯远程续命（推荐无本地 Lingma 环境）

```bash
export LINGMA_CLIENT_ID=$(cat lingma2api/configs/client_id.txt)

go run ./cmd/lingma-auth-bootstrap \
  --refresh ./auth/credentials_remote.json \
  --use-lingma=false \
  --session-key "YOUR_SESSION_KEY"
```

### 3.2 本地 Lingma 续命

```bash
go run ./cmd/lingma-auth-bootstrap \
  --refresh ./auth/credentials.json \
  --client-id "YOUR_CLIENT_ID"
```

### 3.3 验证续命成功

```bash
# 检查 models 接口是否正常
curl -s http://127.0.0.1:8080/v1/models | jq '.data | length'
# 期望输出 > 0
```

---

## 4. 已知风险与回退

| 风险 | 说明 | 回退 |
|---|---|---|
| refresh_token 本身过期 | 阿里云可能设置 RT 生命周期 | 只能重新走完整浏览器登录（`--capture-client-id` + 正常 bootstrap） |
| client_id 失效 | 应用被禁用或轮换 | 同左，重新抓取 client_id |
| 远程登录因 session_key 错误失败 | Stage B 尚未完成 | 先用 `--use-lingma=true` 绕过 |
| 后端返回非标准错误体 | 字段名与 RFC 6749 不一致 | fallback error 会打印完整 raw body，便于人工调整 |

---

## 5. 与整体方案的关系

本阶段（Stage C）在以下文档中被引用：

- `docs/superpowers/specs/2026-04-27-client-id-and-session-key-analysis.md` — 末尾追加「方案 D：refresh 续命」章节。
- `docs/topics/client-id-extraction.md` — Stage A 提取 client_id 后，配合本阶段的 `--refresh` 可实现免浏览器续命。

---

## 参考文件

- `lingma2api/internal/auth/token_exchange.go` — `RefreshTokens` 实现
- `lingma2api/internal/auth/token_exchange_test.go` — 单元测试
- `lingma2api/cmd/lingma-auth-bootstrap/main.go` — `--refresh` CLI 入口
- `lingma2api/internal/proxy/types.go` — `StoredCredentialFile` / `StoredOAuthFields` 结构
