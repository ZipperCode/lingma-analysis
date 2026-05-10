# Lingma OAuth client_id 提取过程

> 日期：2026-04-27 ~ 2026-04-28
> 状态：**等待浏览器捕获**（client_id 为服务端注入，需完成阿里云登录后从 302 链截取）
> 目标：获取真实的 OAuth `client_id`，使 `lingma-auth-bootstrap` 在不依赖本地 Lingma 二进制的情况下也能完成 PKCE + OIDC 授权链。

## 结论（当前状态）

`client_id` **不是** 客户端生成的，而是由 **Lingma 服务端在 302 跳转链中注入** 的。经过 2026-04-28 的全面排查确认：

- **程序结构静态分析**：无硬编码 client_id **值**，仅有 Go 结构体字段 `json:"client_id"`（MCP client transport 层）
- **VS Code 扩展**：无 client_id（扩展为瘦客户端，OAuth 全部委托给 native binary）
- **API 探索**：`client_id/register` 路径在所有域名下返回 HTML 首页或 404
- **配置文件**：`portable_config.json` 等无 client_id 缓存
- **历史流量采集**：全部为 Chat API 流量，不含 OAuth 流

**唯一的提取路径**：浏览器完成阿里云登录后，在 DevTools Network 面板截取 `signin.aliyun.com/oauth2/v1/auth?client_id=<REAL_ID>` URL。

---

## 1. 重定向链结构

### 1.1 获取登录 URL

有两种方式获取 Lingma 登录入口 URL：

**方式 A：WebSocket `login/generateUrl`**（推荐）

连接 `ws://127.0.0.1:PORT` → initialize → 调用 `login/generateUrl`：

```json
// Request
{"jsonrpc":"2.0","id":2,"method":"login/generateUrl","params":{}}

// Response (国内区域)
{
  "loginUrl": "https://devops.aliyun.com/lingma/login?state=...&challenge=...&challenge_method=S256&machine_id=...&nonce=...&port=37599",
  "nonce": "...",
  "verifier": "...",
  "challenge": "...",
  "challengeMethod": "S256",
  "success": true
}
```

**方式 B：CLI `--capture-client-id`**

```bash
go run ./cmd/lingma-auth-bootstrap --capture-client-id
```

### 1.2 区域差异

| 区域 | Lingma 登录入口 | OAuth 授权端点 |
|------|----------------|---------------|
| 国内 (cn) | `devops.aliyun.com/lingma/login` | `signin.aliyun.com/oauth2/v1/auth` |
| 国际 (intl) | `lingma.alibabacloud.com/lingma/login` | `signin.alibabacloud.com/oauth2/v1/auth` |

当前环境为国内区域，因此使用 `devops.aliyun.com` 链路。

### 1.3 完整 302 链

```
1. devops.aliyun.com/lingma/login?state=...&challenge=...&machine_id=...&port=...
       ↓ [302]
2. account.aliyun.com/login/login.htm?oauth_callback=<urlencode(lingma_login_url)>
       ↓ [用户完成登录]
3. signin.aliyun.com/oauth2/v1/auth?client_id=<REAL_CLIENT_ID>&response_type=code&...
       ↓ [用户授权]
4. http://localhost:<port>/callback?code=<auth_code>&state=...
```

**client_id 出现在第 3 步**的 URL query string 中。由于是 302 重定向，浏览器会自动跟随，需在 DevTools Network 面板中截取。

### 1.4 关键证据

- `D:\Project\lingma\callback.html:53` 的 `window.login_url` 暴露了跳转链结构
- Lingma 二进制 `.rdata` 中包含三个区域配置：Qoder（废弃）、阿里云国内、阿里云国际
- 二进制字符串 `client_id/register`（RVA `0x249BF62`）有三个代码引用（RVA `0xA8C4E9`、`0xA8FA2F`、`0xA906F1`），推测为 HTTP client 调用的 URL 路径片段，但在所有已知域名下均返回 HTML/404

---

## 2. 浏览器提取法（推荐）

### 2.1 为什么不能用自动化浏览器

阿里云登录页面 (`account.aliyun.com/login/login.htm`) 有**反自动化检测**，Playwright/Selenium 等自动化工具打开的浏览器会被识别并拒绝登录。**必须使用普通浏览器**。

### 2.2 操作步骤

1. **启动 Lingma**（如果未运行）或使用已运行的实例
2. 通过 WebSocket `login/generateUrl` 获取登录 URL（见 1.1 节）
3. 打开**普通浏览器**（Chrome/Edge，非无痕窗口）
4. 按 `F12` → **Network** 面板 → 勾选 ✅ **Preserve log**
5. 在地址栏粘贴登录 URL 并回车
6. 完成阿里云登录
7. 在 Network 面板搜索框中输入 `client_id`（Ctrl+F）
8. 定位 URL 包含 `signin.aliyun.com/oauth2/v1/auth?client_id=` 的请求
9. 复制 `client_id=` 后的值（到 `&` 之前）

### 2.3 直接获取登录 URL（Python）

```python
import websocket, json, time

SOCKET_PORT = 37099  # Lingma 默认 WebSocket 端口
ws = websocket.create_connection(f"ws://127.0.0.1:{SOCKET_PORT}")

# Initialize
init_data = json.dumps({
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {
        "processId": None,
        "clientInfo": {"name": "cid-tool", "version": "1.0"},
        "rootUri": "file:///tmp/cid",
        "capabilities": {},
        "workspaceFolders": [{"uri": "file:///tmp/cid", "name": "cid"}],
    },
})
ws.send(f"Content-Length: {len(init_data)}\r\n\r\n{init_data}")
time.sleep(1); ws.recv()  # 跳过 init 响应

# 获取登录 URL
req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "login/generateUrl", "params": {}})
ws.send(f"Content-Length: {len(req)}\r\n\r\n{req}")
resp = ws.recv()
login_url = json.loads(resp[resp.index("{"):])["result"]["loginUrl"]
print(login_url)
ws.close()
```

### 2.4 保存与复用

```bash
# 将提取到的 client_id 保存到 gitignored 文件
echo "YOUR_CLIENT_ID" > lingma2api/configs/client_id.txt

# 后续 bootstrap 时直接读取
CLIENT_ID=$(cat lingma2api/configs/client_id.txt)
go run ./cmd/lingma-auth-bootstrap \
  --client-id "$CLIENT_ID" \
  --use-lingma=false \
  --output ./auth/credentials_remote.json
```

---

## 3. 备用：Frida 流量采集法（A2）

如果浏览器因风控/境外 IP 等原因无法完成登录，可使用已就绪的 Frida 脚本：

```bash
python tools/frida_extract_client_id.py \
  --target lingma.exe \
  --out tools/oauth_traffic.jsonl
```

该脚本动态拦截 `WinHttpConnect` / `WinHttpOpenRequest` / `WinHttpSendRequest`、`GetAddrInfoW`、`WSASend`，过滤包含 `oauth/client/token/login/auth/register` 的流量，从输出的 JSONL 中搜索 `signin.alibabacloud.com/oauth2/v1/auth` 即可提取 `client_id`。

**注意**：该脚本从未在本项目实际运行过，仅作为浏览器法失败时的回退。

---

## 4. 已排除的路径

| 假设 | 验证结果 | 日期 |
|------|---------|------|
| `client_id == machine_id` | **否**。将 `machine_id` 当作 `client_id` 会收到 `invalid_client / App not exists`。 | 2026-04-27 |
| client_id 硬编码在二进制 `.rdata` | **否**。全量搜索仅有 JSON tag `json:"client_id"`（MCP transport 结构体），无值。 | 2026-04-28 |
| client_id 缓存在配置文件中 | **否**。`portable_config.json`、`config.json`、`env.json` 等均无。 | 2026-04-28 |
| client_id 在 VS Code 扩展中 | **否**。`package.json`、`dist/extension.js`、`dist/env/env.json`、`webview-ui/.../main.js` 均无。 | 2026-04-28 |
| 远端 API `client_id/register` | **否**。`lingma.alibabacloud.com/client_id/register` 等 6 个变体均返回 HTML 首页或 404。 | 2026-04-28 |
| OAuth introspection/userinfo | **否**。`oauth.alibabacloud.com/v1/introspect` 等不识别 Lingma 的 `pt-` 格式 token。 | 2026-04-28 |
| WebSocket 方法返回 client_id | **否**。尝试 10+ 种方法名均返回 "method not found" 或不含 client_id。 | 2026-04-28 |
| Frida 内存扫描 | 技术可行但 98MB 二进制全扫超时；已知工具脚本 `frida_extract_client_id.py` 从未成功运行。 | 2026-04-27 |
| 历史流量采集 `capture/*.jsonl` | **否**。全部为 Chat API 流量，不含 OAuth 流。 | 2026-04-28 |
| 自动化浏览器 (Playwright) | **否**。阿里云登录页面有反自动化检测，拒绝 automated browser。 | 2026-04-28 |
| `~/.lingma/cache/user` 解密搜索 | **否**。解密后字段：`security_oauth_token`, `refresh_token`, `key`, `encrypt_user_info`，无 client_id。 | 2026-04-29 |
| `~/.lingma/cache/client.json` | **否**。仅含 `debug` 和 `extensionConfigPullInterval`。 | 2026-04-29 |
| `~/.lingma/cache/machine_token.json` | **否**。含空 token 和 type 字段。 | 2026-04-29 |
| `~/.lingma/logs/lingma.log` 全量搜索 | **否**。日志含大量 token 刷新记录，但无 client_id 或 OAuth URL。 | 2026-04-29 |
| `~/.lingma/bin/*/config.json` 所有版本 | **否**。仅含版本号。 | 2026-04-29 |
| SQLite `supabase_token` 表 | **否**。表为空。 | 2026-04-29 |
| `auth/pollToken` WebSocket 方法 | **否**。返回 "unknown method"。 | 2026-04-29 |

## 5. `client_id/register` 程序结构分析

在 Lingma v2.11.1 二进制中，字符串 `client_id/register`（RVA `0x249BF62`）被三处代码引用：

| 引用位置 | 第二个 LEA 目标 | 函数模式 |
|---------|----------------|---------|
| `0xA8C4E9` | `0x2318FC0` (类型元数据) | 构造 HTTP 请求路径 |
| `0xA8FA2F` | `0x2318FC0` (同上) | 同上 (重复代码) |
| `0xA906F1` | `0x2318FC0` (同上) | 同上 (重复代码) |

三处模式一致（`edi=9` 参数 + `call 0x140018980`），推测为 Go HTTP client 调用的 URL 路径片段。但在所有已知 Lingma 服务端域名下均无响应，可能为：
- 内网 API 端点（仅 `devops.aliyun.com` 内部使用）
- 已废弃的旧版 API
- 需要特殊认证头才可访问

## 6. 后续使用

提取到 `client_id` 后，配合 `--session-key`（Stage B 已解析）即可走通纯远程 bootstrap：

```bash
go run ./cmd/lingma-auth-bootstrap \
  --client-id <REAL_ID> \
  --session-key d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw== \
  --use-lingma=false \
  --output ./auth/credentials_remote.json
```

如需 refresh（C 阶段已完成）：
```bash
go run ./cmd/lingma-auth-bootstrap \
  --refresh ./auth/credentials_remote.json \
  --client-id <REAL_ID> \
  --session-key d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==
```

## 7. WebSocket 方法发现

通过分析 Lingma 二进制 pclntab 符号表，确认了 `login/generateUrl` 方法（由 `GenerateUrlHandler` @ RVA `0x3DBD6A4` 处理）。其他尝试的方法名：

| 方法名 | 结果 |
|--------|------|
| `login/generateUrl` | 返回 loginUrl、verifier、challenge 等 |
| `auth/device_login` | 返回 success（需正确 token） |
| `client_id/register` | method not found |
| `auth/client_id` | method not found |
| `login/clientId` | method not found |
| `login/getClientId` | method not found |
| `auth/oauthConfig` | method not found |

---
## 参考文件

- `lingma2api/internal/auth/bootstrap.go` — `BuildLingmaLoginEntryURL` / `WrapLingmaLoginURLForBrowser` / `BuildAuthorizeURL`
- `lingma2api/cmd/lingma-auth-bootstrap/main.go` — `--capture-client-id` 入口 / `runCaptureClientID()`
- `lingma2api/internal/auth/token_exchange.go` — `ExchangeCodeForTokens` / `RefreshTokens`（均需要 client_id）
- `callback.html:53` — 服务端跳转链原始证据
- `tools/capture_client_id_browser.py` — Playwright 自动捕获脚本（因反自动化检测不建议使用）
- `tools/frida_extract_client_id.py` — 备用 Frida 流量采集脚本
- `docs/topics/session-key-analysis.md` — Stage B 推导文档（session_key 已解决）
