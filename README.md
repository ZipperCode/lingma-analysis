# lingma-analysis

通义灵码（Lingma）安全研究与逆向工程分析仓库。

已实现完全脱离 Lingma 程序的自主 OAuth 登录 + Chat API 调用。

## 快速开始

```bash
pip install -r requirements.txt

# 1. OAuth 自主登录（打开浏览器认证，获取完整凭据）
python lingma_oauth_complete.py login

# 2. 查看凭据状态
python lingma_oauth_complete.py status

# 3. Chat API 测试（自动从 ~/.lingma/portable_config.json 读取凭据）
python lingma_remote_api.py

# 4. 本地 37010 WebSocket 客户端（需灵码运行中）
python lingma_client.py "你好"
```

## 目录结构

```
lingma-analysis/
  lingma_oauth_complete.py       # v5.0 自主 OAuth 登录（主力）
  lingma_remote_api.py           # Chat API 远端客户端（主力）
  lingma_client.py               # 本地 37010 WebSocket 客户端

  callback.html                  # OAuth 回调页面参考
  frida_oauth_monitor.js         # Frida OAuth 流程监控
  frida_network_monitor.js       # Frida 网络监控
  frida_token_extractor.js       # Frida Token 提取

  tools/
    credential_extractor.py      # 凭据管理（本地缓存解密）

  docs/
    topics/                      # 已验证专项分析（4篇）
      oauth-flow-verified.md         # OAuth 完整流程（最新）
      callback-37510-simulation.md   # IDA 逆向分析
      encode1-complete-analysis.md   # Encode=1 算法
      session-key-analysis.md        # Session Key 分析
    remote-api-direct-connection.md  # Chat API 直连说明
    ida/                             # IDA Pro 反编译数据

  frida_hooks/                   # 10个 Frida JS hook 脚本
  lib/                           # Java 依赖库（cosy-intellij 等）
  archive/                       # 归档
    scripts/                     # 历史脚本
    tools/                       # 旧迭代工具
    capture/                     # 历史抓包数据
    scripts-noise/               # ~215个历史实验脚本
    binary-artifacts/            # 二进制文件
```

## 核心技术发现

- **OAuth V2 回调**：`state="2-{nonce}"` 触发含 Encode=1 编码 token 的 V2 回调
- **Encode=1 编码**：64 字符自定义字母表 + 3 块反转（`floor(E/3)` 分割）+ `$` 填充
- **COSY Bearer 认证**：`MD5(payload_b64 \n cosy_key \n date \n body \n path)`
- **Session Key**：`d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==`（"war, war never changes"）
- **本地缓存解密**：AES-128-CBC，`machine_id[:16]` 作 key 和 IV
- **Chat API**：POST 原始 JSON（无需 Encode=1），SSE 流式响应
