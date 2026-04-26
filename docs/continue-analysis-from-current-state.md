# 从当前阶段继续分析

更新时间：2026-04-25

## 这份文档解决什么

用于把“已经完成的分析”和“下一步不该再重复的部分”切开。

如果你从当前仓库继续推进，应该直接把下面三层当作已收敛前提，而不是重新回到 plugin/UI 或早期 `getAppSalt` 追踪。

## 已经收敛的三层现状

### 1. 本地 `37010` 直调用已经成立

- `ws://127.0.0.1:37010` 当前在线
- `initialize -> auth/status -> chat/ask` 可用
- 主实现见 `lingma_client.py`

这条线现在的价值是：

- 稳定调用
- 捕获新样本
- 作为泛化能力最强的工程入口

### 2. 远端 GET 离进程调用已经成立

- `GET /algo/api/v2/model/list` 已实测成功
- 主实现见 `lingma_remote_api.py` 与 `tools/offprocess_model_list.ps1`

这部分已经不是主要未知点。

### 3. 远端 POST 只到受约束 PoC

- `POST /algo/api/v2/service/pro/sse/agent_chat_generation` 已可发通
- 控制型短提示可返回非空结果，但自由问答仍可能空掉
- 但当前仍依赖：
  - `~/.lingma/cache` 凭据
  - 已捕获模板 body
  - 模板允许范围内的用户消息替换

因此当前最大的剩余问题不是 bearer、不是 endpoint、也不是 plugin 到本地服务的边界，而是：

- 如何构造通用 `Encode=1` POST body
- 如何解释并生成那段绑定文本的二进制载荷

## 不要再重复投入的方向

- 不要再把 plugin 是否直接发远端请求当主问题
- 不要再把 `37010` 是否可调用当主问题
- 不要再把 `model/list` 是否可离进程访问当主问题
- 不要再默认把 `getAppSalt` 当成唯一主战场

这些方向的证据已经足够，继续堆新脚本只会增加噪声。

## 现在最值得继续的主线

### 主线 1：`agent_chat_generation` body 构造

优先回答这些问题：

- 二进制段和 text/business 的绑定规则是什么
- 是否存在多个模板族，而不是单一模板
- 哪些字段会影响二进制段重算

### 主线 2：`remoting/auth/transport` 的真正边界

当前更值得追的是：

- 哪一步决定二进制段如何拼进 body
- 哪一步决定第四槽位到底喂给 bearer 签名什么内容
- 哪些输入会改变可接受的远端请求形状

### 主线 3：保留 `37010` 作为样本采集入口

`37010` 现在更像：

- 稳定触发器
- 新模板和新业务形状的采样入口

而不是需要继续证明成立与否的对象。

## 当前推荐入口

- 总览：`docs/lingma-analysis-overview.md`
- 本地主线：`docs/lingma-analysis-request-flow-pruned.md`
- 远端直连现状：`docs/remote-api-direct-connection.md`
- 当前客户端：`lingma_client.py` / `lingma_remote_api.py`
- 工具目录说明：`tools/README.md`
