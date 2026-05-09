# lingma-analysis

通义灵码（Lingma）安全研究与逆向工程分析仓库。已破解自定义认证协议、编码方案和 API 机制，产出了可独立使用的客户端。

## 快速开始

```bash
pip install -r requirements.txt

# 方式1：本地 37010 WebSocket 客户端（需灵码运行中）
python lingma_client.py "你好"

# 方式2：远端 HTTPS 直连客户端（无需灵码）
python lingma_remote_api.py --portable-config credentials.json "你好"

# 方式3：OAuth 凭证半自动捕获
python lingma_oauth_capture.py
```

## 目录结构

```
lingma-analysis/
  lingma_client.py              # 本地 37010 WebSocket 客户端
  lingma_remote_api.py          # 远端 HTTPS 直连客户端
  lingma_oauth_capture.py       # OAuth PKCE 凭证捕获
  mitmproxy_capture_refresh.py  # mitmproxy 流量拦截
  frida_oauth_monitor.js        # Frida OAuth 流程监控
  frida_token_extractor.js      # Frida Token 提取
  frida_network_monitor.js      # Frida 网络监控

  tools/                        # 7个已验证工具（认证模拟、刷新、提取等）
  frida_hooks/                  # 10个 Frida JS hook 脚本

  docs/                         # 分析文档
    topics/                     # 已验证的专项分析（4篇）
    doubt/                      # ⚠️ 未验证推测区（11篇 + 矛盾注册表）
    ida/                        # IDA Pro 反编译原始数据
    archive/                    # 历史归档
    tools-archive/              # 工具阶段报告
    plans/                      # 下游 lingma2api 设计
    superpowers/                # 下游设计规格

  archive/                      # 归档
    tools/                      # 旧迭代脚本（已归档）
    scripts-noise/              # ~215个历史实验脚本
    binary-artifacts/           # 二进制文件（exe, JAR, 反编译class）
```

## 文档入口

- 仓库导航：[docs/README.md](./docs/README.md)
- 当前结论总览：[docs/lingma-analysis-overview.md](./docs/lingma-analysis-overview.md)
- 最终状态：[docs/lingma-analysis-final-status.md](./docs/lingma-analysis-final-status.md)
- 使用说明：[USAGE.md](./USAGE.md)
- 工具目录：[tools/README.md](./tools/README.md)
- **未验证推测区**：[docs/doubt/](./docs/doubt/) — 含跨文档矛盾注册表

## 核心技术发现

- **两条可用路径**：本地 WebSocket `ws://127.0.0.1:37010` 和远端 HTTPS `lingma.alibabacloud.com`
- **自定义 Encode=1**：64 字符字母表 + 3 块反转 + `$` 填充（已验证编解码往返一致性）
- **COSY Bearer 认证**：`MD5(payload_b64 \n cosy_key \n date \n body \n normalized_path)`
- **Session Key**：`"war, war never changes"`（base64），1/3 Oracle 验证
- **本地缓存解密**：AES-128-CBC，`machine_id[:16]` 作密钥和 IV
