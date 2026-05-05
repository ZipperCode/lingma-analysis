# Lingma OAuth 半自动获取脚本使用说明

## 概述

基于 IDA Pro 逆向分析 Lingma.exe 程序，实现了**独立生成**登录 URL 的 OAuth 半自动捕获脚本。

**核心突破**：通过分析 `PrepareLoginRequest` 函数和 `callback.html` 中的 URL 嵌套结构，脚本可以**脱离 Lingma 程序独立生成有效的登录 URL**，无需 WebSocket 连接或 Lingma 运行。

## IDA 分析关键发现

| 项目 | 值 | 说明 |
|------|-----|------|
| 本地 HTTP 服务器端口 | 37510 | 可通过 `LINGMA_HTTP_PORT` 环境变量配置 |
| 登录 URL 路径 | `/lingma/login` | 国际版入口（IDA 字符串验证） |
| 认证服务器 | `https://account.alibabacloud.com/login/login.htm` | 阿里云账号登录 |
| URL 嵌套结构 | 三层 | logout.htm → login.htm → lingma/login |
| PKCE 方法 | S256 | SHA256 code_challenge |
| Nonce 格式 | UUID 去掉 "-" | 32 字符十六进制 |
| State 格式 | `1-<nonce>` 或 `2-<nonce>` | 1- 需要登录，2- 已登录 |

## 使用方法

### 1. 完整流程（生成链接 + 监听回调）

```bash
python lingma_oauth_capture.py
```

脚本会：
1. **独立生成**国际版登录链接（无需 Lingma 运行）
2. 启动本地 HTTP 服务器监听 35710 端口
3. 询问是否自动打开浏览器
4. 等待 OAuth 回调并捕获凭据
5. 导出结果到 `oauth_result.json`

### 2. 仅生成登录链接

```bash
python lingma_oauth_capture.py --link-only
```

适合只需要登录链接的场景，生成的链接包含完整的三层嵌套结构。

### 3. 自定义端口

```bash
python lingma_oauth_capture.py --port 35711
```

### 4. 自定义超时时间

```bash
python lingma_oauth_capture.py --timeout 600  # 10 分钟
```

### 5. 选择区域

```bash
python lingma_oauth_capture.py --region cn    # 国内版 (devops.aliyun.com)
python lingma_oauth_capture.py --region intl  # 国际版 (lingma.alibabacloud.com)
```

## 工作流程

```
┌─────────────────────────────────────────────────────────────┐
│                    脚本独立生成 URL                           │
│                                                             │
│  1. 生成 nonce (UUID 去掉 "-")                               │
│  2. 生成 PKCE challenge (SHA256)                             │
│  3. 构造最内层 URL: lingma/login?...                          │
│  4. 三层嵌套编码: logout.htm → login.htm → lingma/login      │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                     用户浏览器                               │
│                                                             │
│  5. 打开登录链接                                             │
│  6. 完成阿里云账号登录                                       │
│  7. 浏览器重定向到回调地址                                   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                 本地 HTTP 服务器 (35710)                     │
│                                                             │
│  8. 接收 OAuth 回调                                          │
│  9. 捕获 code, state, nonce 等参数                          │
│  10. 导出到 oauth_result.json                               │
└─────────────────────────────────────────────────────────────┘
```

## URL 嵌套结构详解

脚本生成的 URL 遵循三层嵌套结构（从 `callback.html` 第 53 行验证）：

```
最外层: https://account.alibabacloud.com/logout/logout.htm?oauth_callback=<middle_encoded>
   ↓ 清除旧会话并跳转到中间层
中间层: https://account.alibabacloud.com/login/login.htm?oauth_callback=<inner_encoded>
   ↓ 显示登录页面
最内层: https://lingma.alibabacloud.com/lingma/login?state=...&challenge=...&nonce=...
   ↓ 包含 PKCE 参数和回调信息
```

**最内层 URL 参数：**
- `state`: `1-<nonce>`（需要登录）或 `2-<nonce>`（已登录）
- `challenge`: PKCE code_challenge (SHA256)
- `challenge_method`: "S256"
- `machine_id`: UUID 格式设备 ID
- `nonce`: 32 字符 UUID（无 "-"）
- `port`: 本地 HTTP 回调端口

## 输出示例

成功捕获后，`oauth_result.json` 包含：

```json
{
  "method": "GET",
  "path": "/auth/callback?code=xxx&state=yyy",
  "query_params": {
    "code": "授权码",
    "state": "状态令牌",
    "nonce": "随机数"
  },
  "headers": {...},
  "timestamp": 1777649031.123
}
```

## 注意事项

1. **端口占用**：确保 35710 端口未被其他程序占用
2. **防火墙**：如有防火墙，请允许本地端口访问
3. **浏览器**：建议使用现代浏览器（Chrome/Edge/Firefox）
4. **超时**：默认 5 分钟超时，可根据需要调整

## 技术细节

### PKCE 支持

脚本内置 PKCE (Proof Key for Code Exchange) 支持：
- `code_verifier`: 32 字节随机数，URL-safe Base64 编码
- `code_challenge`: SHA256(code_verifier)，URL-safe Base64 编码

### OAuth 流程

1. 客户端生成 PKCE 参数
2. 构建授权 URL 并打开浏览器
3. 用户在认证服务器完成登录
4. 认证服务器重定向到回调地址
5. 本地服务器捕获授权码
6. （可选）使用授权码交换 access_token

## 相关文件

- `lingma_oauth_capture.py` - 主脚本（独立生成模式）
- `oauth_result.json` - 捕获结果（运行后生成）
- `tools/oauth_callback_intercept.py` - 旧版拦截器（参考，需要 WebSocket）
- `tools/test_standalone_url.py` - URL 结构验证测试
- `callback.html` - URL 嵌套结构的原始证据（第 53 行）

## 验证结果

运行 `python tools/test_standalone_url.py` 验证生成的 URL 结构：

```
=== URL 结构验证 ===

✓ 最外层 URL 格式正确 (logout.htm)
✓ 中间层 URL 格式正确 (login.htm)
✓ 最内层 URL 格式正确 (lingma/login)
✓ 参数 state: 1-<nonce>...
✓ 参数 challenge: <SHA256>...
✓ 参数 challenge_method: S256...
✓ 参数 machine_id: <UUID>...
✓ 参数 nonce: <32字符>...
✓ 参数 port: 35710...

✓ state 格式正确
✓ nonce 长度正确: 32 字符
✓ challenge_method 正确: S256

=== 与 callback.html 对比 ===
callback.html 参数: ['state', 'challenge', 'challenge_method', 'machine_id', 'nonce', 'port']
生成 URL 参数:      ['state', 'challenge', 'challenge_method', 'machine_id', 'nonce', 'port']
✓ 参数列表与 callback.html 完全一致

=== 所有验证通过！ ===
```
