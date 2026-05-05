# Lingma 本地服务、Endpoint 与签名边界

> 编辑说明（2026-04-25）：
> 这份文件现在主要保留长链证据和阶段性补证，不再作为“当前最终状态”的唯一来源。
> 如果你只想知道当前已经成立到什么程度，请先看 `docs/lingma-analysis-overview.md` 和 `docs/remote-api-direct-connection.md`。
> 另外，`2026-04-26` 之后远端 Chat API 已确认可直接发送原始 JSON body；本文件中凡是把 `agent_chat_generation` 视为“仍必须依赖 Encode=1 模板重放”的段落，都应按阶段性结论理解，而不是当前最终结论。

更新时间：2026-04-24

## 适合什么时候看

当你要回答下面这些问题时，看这份文档：

- `plugin` 到底是不是在直接请求模型
- 本地 `37010` 怎么调
- 哪些本地服务方法已经坐实可直接调用
- 远端 endpoint 是什么
- 为什么当前 bearer token 还不能脱离本地程序直连远端

相关文档：

- 总览入口：[lingma-analysis-overview.md](./lingma-analysis-overview.md)
- token 与模型刷新链：[lingma-analysis-token-flow.md](./lingma-analysis-token-flow.md)
- 完整时间线：[lingma-analysis-snapshots.md](./archive/lingma-analysis-snapshots.md)

## 高置信结论

### 1. `plugin` 不直接请求远端模型接口

- `plugin` 与本地服务之间走的是本地 `WebSocket/IPC + JSON-RPC/LSP`。
- 真正的远端 HTTP/SSE 请求由 `~/.lingma/bin/2.11.1/aarch64_darwin/Lingma` 发起。
- 因而“plugin 只是转发层，本地服务才是执行主体”已经是证据结论，不再只是推断。

### 2. 当前可直接复用的是本地服务，不是远端接口

- 本地服务入口已经坐实：
  - `37010`: 主 websocket/LSP
  - `37510`: 本地 HTTP/callback/profile page
  - `38510`: profile websocket
- 其中真正稳定可程序化复用的是：
  - `ws://127.0.0.1:37010`

### 3. 远端 API 面已知，但还差 native 签名链

- 当前已坐实两层远端路径：
  - 直接命中验证过的 SSE：
    - `https://lingma.alibabacloud.com/algo/api/v2/service/pro/sse/llm_completion_stream?FetchKeys=&Encode=1`
  - `chat/ask` 主聊天链真实流量采集到的：
    - `POST /algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1`
- 同一轮流量采集还补齐了：
  - `GET /algo/api/v1/ping`
  - `POST /algo/api/v1/heartbeat?Encode=1`
  - `POST /algo/api/v3/user/status?Encode=1`
  - `POST /algo/api/v3/user/login?Encode=1`
  - `GET /algo/api/v2/config/getDataPolicy?...`
  - `POST /algo/api/v2/service/business/finish?Encode=1`
- 直接拿 bearer 访问远端 SSE，已确认仍返回：
  - `{"code":"101","message":"Signature invalid"}`
- 因而当前阻塞点不是 API 路径未知，而是签名与访问控制未复现。

## 调用链

### `plugin -> 37010 -> ~/.lingma -> remote`

当前最稳的调用链可以写成：

1. `plugin` 组装本地 RPC 参数
2. `LanguageWebSocketService` 通过本地 websocket/LSP 调 `37010`
3. `Lingma` 本地服务组装远端请求
4. 本地服务发起远端 HTTP/SSE
5. 本地服务再把 `chat/answer`、`session/title/update` 等事件回推给 `plugin`

这意味着：

- `plugin` 可绕过
- 但当前还不能绕过 `~/.lingma` 本地服务本身

## `37010` 最小协议模板

### 协议要求

- 连接目标：
  - `ws://127.0.0.1:37010`
- 消息必须使用 LSP framing：
  - `Content-Length: <n>\r\n\r\n<json>`

### 最小顺序

1. 建立 websocket 连接
2. 发送 `initialize`
3. 再发送业务方法

### 已知边界

- 裸 JSON 不行，会触发 `Unknown message header`
- `initialized` 当前不是必需步骤，服务端会把它当未知方法处理

## 已验证可直接调用的方法

### `auth/status`

- 用途：读取当前活跃登录态
- 已确认可返回：
  - `status`
  - `name`
  - `id/accountId`
  - `token`
  - `refreshToken`
  - `userType`
  - `cloudType`

### `config/queryModels`

- 用途：读取当前模型注册表
- 已确认可返回：
  - `assistant/chat/developer/inline` 等场景
  - `dashscope_qwen3_coder_default`
  - `dashscope_qwen3_coder`
  - `dashscope_qwen_plus_20250428_thinking`
  - `dashscope_qwen_max_latest`
- 结构上还能看到：
  - `format = openai`
  - `source = system`
  - `isReasoning = true/false`
- 但 `url/apiKey/model` 当前为空，不能据此直接推出远端开放配置

### `auth/profile/getUrl`

- 用途：获取 fresh profile URL 与 fresh `state`
- 结论：
  - `state`、`PROFILE_WEBSOCKET_PORT` 不是 plugin 手工拼的
  - 这些关键参数由本地服务生成并注入到最终 URL

### `chat/ask`

- 用途：直接触发真实聊天请求
- 已确认现象：
  - 同步响应 `success = true`
  - 后续会异步回推：
    - `chat/process_step_callback`
    - `session/title/update`
    - `chat/answer`
- 已抓到的主远端请求：
  - `POST /algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1`
- 真实头部里至少包含：
  - `Authorization: Bearer COSY.<base64-json>.<hex>`
  - `Cosy-Key`
  - `Cosy-Date`
  - `Cosy-User`
  - `Cosy-Data-Policy`
  - `Cosy-MachineId`
  - `Cosy-MachineOS`
  - `X-Request-ID`
- 对同一批流量采集继续做横向比对后，当前更稳的判断是：
  - `Authorization` 中段 `base64-json` 里的 `info` 在同一批请求里是稳定常量
  - `Cosy-Key` 在同一批请求里也是稳定常量
  - 真正每请求变化的是：
    - `requestId`
    - `Authorization` 末尾 32 位 hex
    - `Cosy-Date`
- 这说明：
  - 后续继续协议研究时，不该再优先怀疑 `info` 是“每请求现算”的主体
  - 更应优先怀疑 `requestId/date + 某个稳定密钥材料` 的组合签名链
- 但跨实例对照又补了一层结论：
  - 换一个新的 `Lingma` 实例和 `workDir` 后，`info` 与 `Cosy-Key` 都会整体变化
  - 因而它们不是“机器全局固定常量”
  - 更合理的定位是：
    - 单实例稳定
    - 跨进程 / 跨工作目录可变化
    - 属于会话级或实例级安全材料
- 进一步的同目录重启实验又补了一层更强的判断：
  - 对同一个 `workDir`，即使重启为新的进程和端口，`Cosy-Key` 与 `Authorization.info` 仍保持不变
  - 这说明它们至少不是“纯进程临时随机值”
  - 当前更合理的定位应升级为：
    - 工作目录级稳定材料
    - 跨工作目录变化
    - 更像落在 `workDir` 持久化状态或由其派生出的安全上下文
- 再进一步的定点删除实验表明：
  - 在同一个 `workDir` 下，仅删除 `cache/id` 后重启
  - `Cosy-Key` 与 `Authorization.info` 仍然完全不变
- 这说明：
  - 当前至少可以排除“它们直接依赖 `cache/id` 明文值”的简单猜法
  - 后续若继续定位来源，应优先看：
    - `cache/user`
    - `cache/quota`
    - 本地 DB
    - 或启动阶段写入的其他工作目录状态
- 随后的第二个定点删除实验又进一步收紧了范围：
  - 在同一个 `workDir` 下，删除：
    - `cache/user`
    - `cache/quota`
    再重启并重新 `device_login + chat/ask`
  - 结果：
    - `Cosy-Key` 整体变化
    - `Authorization.info` 也整体变化
- 这说明：
  - `cache/user/quota` 与 `info/Cosy-Key` 的生成或恢复过程存在强相关
  - 当前至少不能再把这两个文件视为“与聊天签名链无关的纯用户态缓存”
  - 若要继续定位来源，优先级应升级为：
    - `cache/user`
    - `cache/quota`
    - 然后才是本地 DB
- 再继续拆成单文件实验后，当前边界已经更清楚：
  - 只删 `cache/user`：
    - `Cosy-Key` 改变
    - `Authorization.info` 改变
  - 只删 `cache/quota`：
    - `Cosy-Key` 不变
    - `Authorization.info` 不变
- 因而当前更合理的优先级是：
  - `cache/user` 是更关键的实例级安全材料入口
  - `cache/quota` 至少不是恢复 `info/Cosy-Key` 的必要条件
- 最强的恢复实验也已经完成：
  - 在删 `cache/user` 后重新生成出“新一版 `cache/user`”的实例上
  - 直接把稳定实例原来的 `cache/user` 覆盖回去
  - 再起新实例并触发 `device_login + chat/ask`
  - 结果：
    - `Cosy-Key` 恢复到旧基线
    - `Authorization.info` 也恢复到旧基线
- 这说明：
  - `cache/user` 不只是“相关”
  - 它已经接近决定 `info/Cosy-Key` 的关键持久化入口
- 进一步的直接替换实验已经把这点坐实：
  - 解密 `cache/user` 后，手工把明文里的：
    - `key`
    - `encrypt_user_info`
    改成哨兵值
  - 再按同样 `machineKey` 重新加密写回
  - 新实例真实出站头会直接变成：
    - `Cosy-Key = 哨兵 key`
    - `Authorization.info = 哨兵 encrypt_user_info`
- 这意味着当前已经可以直接下结论：
  - `cache/user.key` 就是出站 `Cosy-Key`
  - `cache/user.encrypt_user_info` 就是 `Authorization.info`
- 因而后续真正剩下的签名问题已经收缩成：
  - `Authorization` 末尾 32 位 hex 的生成链
- 进一步拆成单字段实验后，当前边界更细：
  - 只改 `cache/user.key`
    - `Cosy-Key` 改变
    - `Authorization.info` 保持原值
    - 末尾 32 位 hex 仍然改变
  - 只改 `cache/user.encrypt_user_info`
    - `Cosy-Key` 保持原值
    - `Authorization.info` 改变
    - 末尾 32 位 hex 也仍然改变
- 这说明：
  - 末尾 32 位 hex 至少同时感知：
    - `Cosy-Key`
    - `Authorization.info`
  - 因而它不只是 `requestId/date` 的函数
- 当前还可以再补一条排除结论：
  - 已对这些显式字段做过小范围 `md5` 拼接枚举：
    - `Cosy-Key`
    - `Authorization.info`
    - `requestId`
    - `Cosy-Date`
    - `Cosy-User`
    - `method`
  - 组合方式覆盖了：
    - 2 到 4 项排列
    - 常见分隔符 `'' ':' '|' ',' '\\n'`
  - 当前没有命中尾 32 位 hex
- 这说明：
  - 尾签名不是这些显式字段的简单直接拼接 `md5`
  - 更可能还混入了额外上下文、隐藏常量或另一层编码步骤
- 同样也已排除一类更强的低成本模型：
  - 使用这些候选作为 `HMAC` key：
    - `machineKey`
    - `Cosy-Key` 文本
    - `Cosy-Key` base64 解码后二进制
    - `Authorization.info` 前缀二进制
    - `security_oauth_token`
  - 对这些候选消息：
    - `auth_request_id`
    - `auth_request_id + date`
    - `auth_request_id + key_raw`
    - `auth_request_id + info_raw`
    - `auth_request_id + key_raw + info_raw`
  - 分别做 `HMAC-MD5 / HMAC-SHA1 / HMAC-SHA256` 截断比较
  - 当前仍然全部不命中尾 32 位 hex
- 这说明：
  - 尾签名也不是“可见字段 + 简单 HMAC”的直接模型
  - 后续若继续协议研究，应优先怀疑：
    - 额外隐藏输入
    - 结构化签名基串
    - 或 `code.alibaba-inc.com/cosy/encrypt` 里的自定义编码步骤
- 第三个定点删除实验又进一步排除了本地 DB：
  - 在同一个 `workDir` 下，仅删除 `cache/db/local.db*`
  - 保留 `cache/user/quota`
  - 再重启并重新 `device_login + chat/ask`
  - 结果：
    - `Cosy-Key` 仍完全不变
    - `Authorization.info` 也仍完全不变
- 因而当前更合理的收敛是：
  - `cache/user/quota` 的相关性明显强于 `local.db`
  - 本地 DB 至少不是恢复 `info/Cosy-Key` 的必要条件
- 工程含义：
  - 外部客户端若要稳定复用 `37010`，还需要兼容服务端回推/ack 语义
  - `chat/ask` 主链不能再简单等同于旧文档里的 `llm_completion_stream`

### 当前不要视为稳定能力的方法

- `user/plan`
  - 现阶段返回错误，不应并入稳定接口集合

### 2026-04-24 Windows 当前机器实跑补证

这轮直接在当前机器上做了运行时复现，不再只依赖历史文档和日志。

#### 官方 CLI 启动链已跑通

当前二进制：

- `C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe`

已直接确认：

- `lingma version`
  - 返回 `version: 2.11.1`
- `lingma status -o json --workDir C:\Users\Zipper\.lingma`
  - 返回：
    - `logged_in = false`
    - `version = 2.11.1`
- `lingma start --help`
  - 明确暴露：
    - `--socketPort`
    - `--httpPort`
    - `--transportType`
    - `--workDir`
    - `--endpoint`

这说明 Windows 当前产品线存在正式 CLI 启动入口，不需要只能依赖 IDE/plugin 唤起本地服务。

#### 当前机器已直接拉起 `37010/37510/38510`

使用：

- `lingma start --workDir C:\Users\Zipper\.lingma`

当前 `lingma.log` 实时出现：

- `Using http server: 37510`
- `Using profile websocket channel: 38510`
- `Communication servers ready - WebSocket: 37010, HTTP: 37510, IPC: \\.\pipe\lingma-ed76e3`

系统监听端口也同步出现：

- `127.0.0.1:37010`
- `127.0.0.1:37510`
- `127.0.0.1:38510`

因此这条本地服务启动链现在已经是当前机器可重复执行的过程。

#### `37010` 最小调用链已在当前机器复现

当前机器上直接用 websocket + LSP framing 发送：

1. `initialize`
2. `auth/status`
3. `config/queryModels`

实际返回：

- `initialize`
  - 成功返回 `serverInfo.name = lingma`
  - `serverInfo.version = 2.11.1`
- `auth/status`
  - 当前未登录样本返回：
    - `status = 1`
    - `token = ""`
    - `refreshToken = ""`
    - `accountId = ""`
- `config/queryModels`
  - 当前直接返回空结果 `{}`

这进一步把边界说清楚了：

- `37010` 这条本地 API 面当前是活的
- 但当前样本未登录，所以还拿不到可用 token，也拿不到模型表

#### `auth/profile/getUrl` 当前机器也已直接拿到 fresh URL/state

同样通过：

- `initialize -> auth/profile/getUrl`

当前实际拿到：

- `http://127.0.0.1:37510/profile?...&state=3a7fd46062fa440388ca72683c56df5c...`

这说明：

- `fresh state` 的生成当前机器是活的
- `auth/profile/getUrl` 仍然是 profile 链的关键服务端入口

后续只读验证也已经补上：

- 直接 HTTP GET 这个 fresh `/profile?...&state=`：
  - HTTP `200`
  - 返回 HTML
  - 但日志同时记录：
    - `Profile Invalid login parameters`
- 直接连：
  - `ws://127.0.0.1:38510/ws?state=3a7fd46062fa440388ca72683c56df5c`
  - websocket 可以成功 `OPEN`
  - 日志记录：
    - `3a7fd46062 ws build success`

因此当前最稳判断是：

- fresh `state` 当前依然能驱动 `38510` profile websocket 建连
- 但由于当前机器未登录，profile 页面仍然无法进入完整已登录态

#### 上述空 token 结论只对应早期快照，当前机器已恢复登录态

后续继续在当前机器补跑后，结论已经发生变化：

- `Lingma.exe status -o json --workDir C:\Users\Zipper\.lingma` 当前返回：
  - `logged_in = true`
  - `username = zhang640@blny.de`
  - `user_type = personal_standard`
- 直接通过 `37010` 查询：
  - `auth/status.status = 2`
  - `id/accountId = 5930676910898027`
  - `token = pt-5zmkcs3cUpPGP8FGb88WGkSJ`
  - `refreshToken = rt-gHWjpgS9NQ4TOhmtvmN55ELZ`
  - `expireTime = 1782107060847`
- `config/queryModels` 当前也已返回完整模型注册表，不再是空结果。

这说明：

- “当前机器没有真实登录态”只适用于前一轮未登录快照
- 到本轮为止，当前机器已经具备可复用的本地登录态与模型注册表
- 因而“脱离 plugin UI 调用模型”的本地 API 条件已经成立

## profile 与本地页面链

### `37510`

- 承担本地 callback server 与 `/profile` 页面入口
- 直接访问 `/profile` 只能得到模板页，不是最终成品页

### `38510`

- 承担 profile websocket 通道
- 不是开放入口
- `/ws?state=...` 中的 `state` 需要服务端生成的有效值

### 当前结论

- `auth/profile/getUrl` 是 profile 链的关键服务端入口
- `state` 本质上更像服务端持有的一次性状态值
- raw HTTP 直接拉 `/profile` 不能替代整条 profile 链

## Windows 当前安装态补证

### 当前版本与程序入口

- `C:\Users\Zipper\.lingma\bin\config.json` 当前写的是：
  - `cosy.core.version = 2.11.1`
- 对应实际程序目录：
  - `C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\`
- 其中已直接看到：
  - `Lingma.exe`
  - `LingmaLocal.exe`
  - `LingmaWin7.exe`

这说明 Windows 安装态至少明确分成了：

- 主程序壳层
- 本地服务二进制
- Win7 兼容分支

### 固定本地端口在 Windows 当前样本里也持续成立

`C:\Users\Zipper\.lingma\logs\lingma.log` 多次重复出现：

- `Using http server: 37510`
- `Using profile websocket channel: 38510`
- `Communication servers ready - WebSocket: 37010, HTTP: 37510, IPC: \\.\pipe\lingma-...`

而且这些日志跨多个版本升级点都保持一致：

- `37010`
- `37510`
- `38510`

当前更稳的判断是：

- 至少在这条 Windows 产品线里：
  - `37010` 主 websocket
  - `37510` 本地 HTTP / callback
  - `38510` profile websocket
  不是一次性实验端口，而是稳定产品拓扑的一部分
- 变化的主要只是：
  - IPC pipe 后缀
  - 以及版本目录

### `extension` / MCP 子系统在当前 Windows 样本里也已坐实

当前真实安装目录 `C:\Users\Zipper\.lingma` 下，除了前面已经反复使用的：

- `bin`
- `cache`
- `index`
- `logs`

还稳定存在：

- `extension\local\config.json`
- `extension\local\mcp.json`
- `extension\server\config.json`
- 根目录 `lingma_mcp.json`

当前机器直接读到的配置状态是：

- `C:\Users\Zipper\.lingma\extension\local\config.json`
  - `contentHandlerRules = null`
  - `contentHandlerScripts = null`
  - `commands = null`
- `C:\Users\Zipper\.lingma\extension\local\mcp.json`
  - `mcpServers = {}`
  - `userConfigMD5 = 1a6618c9486afd375cdf1135b5b2acc4`
- `C:\Users\Zipper\.lingma\extension\server\config.json`
  - 当前也是空配置
- `C:\Users\Zipper\.lingma\lingma_mcp.json`
  - 当前也是 `mcpServers = {}`

而 `C:\Users\Zipper\.lingma\logs\lingma.log` 当前还能直接看到这组启动与运行日志：

- `Module extension started successfully`
- `Starting MCP Proxy IPC listener quest-mcp-adaptor on \\.\pipe\mcp_adaptor_...`
- `broadcast(call) method: extension/register, 0 clients, 0 success, 0 failed`
- `ExtensionApi executor not inited.`
- 退出时还会看到：
  - `MCP server stopped`
  - `Module extension stopped successfully`
  - `MCP Proxy IPC listener quest-mcp-adaptor ... closed`

这条链的当前稳定含义是：

- `Lingma` 本地程序内部确实有独立的 extension module
- 这个 module 还带着一条 MCP proxy IPC listener
- 它会周期性尝试做 `extension/register` 广播
- 但当前样本没有任何真正连上的 extension executor / MCP client

### plugin 侧当前只看到“入口和辅助动作”，没有看到真正的注册实现

对 `lib/cosy-intellij-2.11.1.jar` 做代码结构还原后，当前和 MCP 直接相关的 plugin 侧证据已经可以进一步收敛：

- `LingmaToolWindowPanel`
  - `openMcpTool()`
    - 直接走：
      - `openProfilePage(null, true)`
  - `openMemoryRecordPage(memoryId)`
    - 走：
      - `openProfilePage(memoryId, false)`
  - `getProfilerUrl(memoryId, openMcpView)`
    - 最终仍然只是：
      - `LanguageWebSocketService.getProfileUrl(GetProfileUrlParams)`
  - `updateProfile(...)`
    - 也是把 profile 展示参数同步给本地服务
- `CefMessageRouterHandler`
  - `MSG_TYPE_OPEN_MCP_CONFIG`
    - 实际落到：
      - `handleOpenFile(...)`
    - 只会读取 `message.filePath` 并在 IDE 本地打开文件
  - `MSG_TYPE_FIX_MCP_ERROR`
    - 实际落到：
      - `handleMcpQuickFix(...)`
    - 行为是：
      - 切到当前聊天面板
      - 强制切到 `AGENT` 模式
      - 把 `message.content` 塞进输入框
  - `MSG_TYPE_EXPERIENCE_MCP_CASE`
    - 实际落到：
      - `handleMcpQuickExperience(...)`
    - 行为是：
      - 新建聊天
      - 切到 `AGENT` 模式
      - 把 `message.content` 塞进输入框并直接发送

这说明当前 plugin 侧 MCP 能力更像是：

- 打开 MCP/profile 页面
- 在 IDE 里打开配置文件
- 给聊天面板预填或直接发送一段与 MCP 相关的 prompt

而不是：

- 在 plugin 里自己启动 MCP server
- 在 plugin 里自己维护 server 注册表
- 在 plugin 里自己连上 `quest-mcp-adaptor`

### `LingmaLocal.exe` 当前已经直接暴露出“配置监听 + merge + refresh”更靠近本地服务

这轮对 `capture/goresym-lingma.json` 的定点检索，又把 MCP 运行态继续往本地服务侧收紧了一层。

当前已直接看到这些符号痕迹：

- `cosy/bootstrap/modules.(*MCPModule).Start`
- `cosy/bootstrap/modules.(*MCPModule).Stop`
- `cosy/extension/mcp.InitMCP`
- `cosy/extension/mcp.startWatchUserConfig`
- `cosy/extension/mcp.MergeUserConfigAndRefreshServers`

同时还能直接看到 MCP 相关配置和 RPC 结构：

- `mcpconfig.MCPOfficialConfig`
  - 持有 `MCPServers`
- `definition.McpSeverEditParams`
  - 直接以 `McpServers map[...]` 作为编辑参数
- 一组返回结构里直接带：
  - `UserConfigFilePath`
  - `UserConfigError`
  - `UserConfigErrorMsg`
  - `mcpServers`
- ACP SDK 侧会话结构里也直接带：
  - `McpServers []api.McpServer`
- `api.McpServer`
  - 已能分出：
    - `Http`
    - `Sse`
    - `Stdio`

这条证据的当前稳定含义是：

- 本地服务不是只知道“有个 MCP 页面”
- 它内部已经有：
  - 用户配置监听
  - 配置合并
  - server refresh
  - server 编辑/列表 RPC
  - 会话级 `mcpServers` 注入结构

因而对“为什么当前 `extension/register` 一直是 0 clients”的更稳判断是：

- 当前更像不是 plugin 忘了发注册
- 而是本机没有任何真正激活的 user MCP server / extension executor 能完成后续握手
- plugin 侧现有动作只够把用户带到：
  - 页面
  - 配置文件
  - 聊天引导
- 真正的 server 生效路径仍然要落回：
  - `~/.lingma\extension\local\mcp.json`
  - `~/.lingma\extension\server\config.json`
  - 以及 `MCPModule + extension/mcp` 的 watcher / refresh 链

因此当前对“plugin 项目 + 本地运行程序”的关系，可以再补一条更精确的判断：

- 不是只有：
  - `plugin -> 37010 -> remote`
- 还存在：
  - `plugin/profile/MCP UI -> ~/.lingma extension module -> quest-mcp-adaptor / extension register`
- 只是这台机器当前用户态配置为空，所以这条 extension/MCP 支链还没有进入“已激活扩展”状态

补充现象：

- 这轮新起的隔离 workdir 副本里，也会自动带出 `extension\local\config.json` 与 `extension\local\mcp.json`
- 说明这不是主目录偶然残留文件，而是产品运行态固定目录结构的一部分

### `LingmaLocal.exe` 直接暴露出的内部实现面

对 `C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\LingmaLocal.exe` 做字符串扫描后，当前能直接看到完整的 Go 包路径痕迹，例如：

- `cosy/core/api/auth/status.go`
- `cosy/core/api/auth/profile.go`
- `cosy/core/api/auth/login.go`
- `cosy/core/api/config/endpoint.go`
- `cosy/core/api/agent/chat/ask.go`
- `cosy/core/transport/handler/websocket/websocket.go`
- `cosy/core/transport/handler/http/http_server.go`
- `cosy/bootstrap/modules/communication_servers.go`
- `cosy/bootstrap/modules/transport.go`

这条证据虽然不是源码级符号跳转，但它足够继续坐实：

- `auth/status`
- `auth/profile/getUrl`
- `chat/ask`
- `endpoint` 路由
- websocket / http transport

这些能力面都属于本地服务二进制自身，不是 IDE plugin 单独实现出来的假入口。

## endpoint 路由

### 已确认

- 本地二进制内置多套官方 remote config 模板：
  - Qoder
  - 阿里云国内
  - 阿里云国际
- endpoint 不是简单常量，而是运行时路由结果
- 当前机器缓存显示：
  - `regionEnv = intl`
  - 自定义 `endpoint` 为空

### 当前国际环境样本

- `big_model_endpoint`：
  - `https://lingma.alibabacloud.com/algo`
- 已看到的真实远端 API 面：
  - `GET /algo/api/v1/ping`
  - `POST /algo/api/v1/heartbeat?Encode=1`
  - `POST /algo/api/v3/user/status?Encode=1`
  - `POST /algo/api/v3/user/login?Encode=1`
  - `GET /algo/api/v2/config/getDataPolicy?...`
- `POST /algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1`
- `POST /algo/api/v2/service/business/finish?Encode=1`
- `POST /algo/api/v2/service/codebase/embedding_k2?Encode=1`
- `llm_completion_stream` 仍然是已验证可命中的接口，但当前更合理的定位是：
  - 它证明 `algo` 域下的模型 SSE 入口存在
  - 但不应再被视为 `chat/ask` 的唯一主链

## `Lingma` 程序内部的 API 调用原理

### 不看 plugin，只看本地程序内部可以收敛成五段

如果只分析 `~/.lingma` 这个本地程序本身，而不看 IDE/plugin 接入，当前更稳的内部模型是：

1. communication server 暴露本地入口
2. 本地 API handler 收到结构化请求
3. remoting 层决定远端路径、是否加 `Encode=1`、是否改写 body
4. auth provider 生成 `Authorization/Cosy-*` 头
5. transport 层发出真实 HTTP/SSE，再把结果回流到本地会话

这五段当前分别已经有对应证据：

- 启动 / 通信层
  - `cosy/bootstrap/modules/communication_servers.go`
  - `cosy/bootstrap/modules/transport.go`
  - `cosy/core/transport/handler/websocket/websocket.go`
  - `cosy/core/transport/handler/http/http_server.go`
- 本地 API handler
  - `cosy/core/api/auth/status.go`
  - `cosy/core/api/auth/profile.go`
  - `cosy/core/api/agent/chat/ask.go`
- remoting
  - `cosy/remoting.trimQueryPath`
  - `cosy/remoting.encodeRequestBody`
  - `cosy/remoting.shouldAddEncodeParam`
  - `cosy/remoting.shouldEncryptBody`
  - `cosy/remoting.addBigModelAuthorizationHeaders`
- auth
  - `cosy/bootstrap/modules/adapter.(*remotingAuthProvider).AuthenticateRequest`
  - `cosy/auth/user.getAuthPayload`
  - `cosy/auth/user.getAuthSignature`

因此当前对“程序内部怎么调用 API”的更精确说法应是：

- 本地程序先把外部输入落成内部 handler 请求
- 再经过 remoting + auth 两层加工
- 最后由 transport 层真正发起远端 HTTP/SSE

### 第 1 段：communication server 只是入口，不做最终远端调用决策

当前已经直接看到：

- `37010`
  - websocket/LSP
- `37510`
  - 本地 HTTP / callback / profile
- `38510`
  - profile websocket

这说明本地程序的第一层只是：

- 接收请求
- 路由到本地 API handler
- 维护会话与连接

它还不是最终决定远端请求长什么样的层。

### 第 2 段：本地 API handler 负责把业务动作转成“内部语义请求”

当前已知的本地 API 面至少包括：

- `auth/status`
- `auth/profile/getUrl`
- `config/queryModels`
- `chat/ask`

这层的职责当前更像是：

- 定义本地程序对外暴露的稳定方法名
- 接收结构化参数
- 维护会话上下文
- 决定接下来走哪条 remoting 业务链

以 `chat/ask` 为例，当前已经可以确定：

- 它不是直接返回模型文本
- 同步返回更多只是“受理成功”
- 后续真正结果通过异步事件继续往回推：
  - `chat/process_step_callback`
  - `session/title/update`
  - `chat/answer`

这说明 `chat/ask` 在本地程序内部更像一个：

- 任务提交入口

而不是：

- 一次同步完成的 HTTP 包装函数

### 第 3 段：remoting 层决定远端请求“该怎么发”

当前对内部 remoting 链已经可以进一步精炼成：

1. 先决定远端 path
2. 再决定 query 是否加 `Encode=1`
3. 再决定 body 是否需要编码/加密
4. 再补授权头

这层当前最关键的函数已经坐实：

- `trimQueryPath`
  - 会把流量采集里的 `/algo/...` 归一成签名使用的 `/api/...`
- `shouldAddEncodeParam`
  - 决定 URL 上要不要补 `Encode=1`
- `shouldEncryptBody`
  - 决定 body 是否走编码/加密链
- `encodeRequestBody`
  - 真正处理 body
- `addBigModelAuthorizationHeaders`
  - 进入鉴权头拼装流程

因此当前更稳的理解是：

- `Lingma` 不是先有一个“完整远端请求”再去补签名
- 而是 remoting 层按规则一步步把请求形态构造成最终样子

### 第 4 段：auth provider 不是只塞 token，而是生成整套鉴权材料

当前已经能直接排除一个误解：

- 本地程序不是简单把某个 token 塞进 `Authorization` 就完事

更接近真实情况的是：

1. `addBigModelAuthorizationHeaders`
   - 进入授权头加工
2. `remotingAuthProvider.AuthenticateRequest`
   - 真正执行请求级鉴权
3. `getAuthPayload`
   - 生成 bearer 中段 payload
4. `getAuthSignature`
   - 生成 bearer 尾部签名

而且当前已知：

- `trimQueryPath` 的结果会进入签名
- `Cosy-Key`
- `Cosy-Date`
- bearer payload
- 以及一个当前仍未完全命名的第四槽位
都会进入 `getAuthSignature` 的 preimage

所以这层本质上是：

- 请求级签名生成器

而不是：

- 单纯的 token 读取器

### 第 5 段：transport 真正把请求发出去，并负责重试和回流

当前真实远端聊天主链已经抓到：

- `POST /algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1`

而且同一条本地 `chat/ask` 已经观察到：

- 可以触发多次远端 `agent_chat_generation` 重试
- 每次重试会刷新：
  - bearer 内嵌 `requestId`
  - bearer 尾 32 位 hex
  - `Cosy-Date`
  - `Encode=1` body
- 但会共用同一个本地 `chat/ask.params.requestId -> X-Request-Id`

这说明 transport 层的职责至少包括：

- 真实 HTTP/SSE 发起
- 重试
- 流式分片处理
- 把结果重新包装成本地异步事件

因此当前如果只站在 `Lingma` 程序内部看，最合理的流水线模型是：

- 本地 handler 接收请求
- remoting 构造远端请求形态
- auth provider 计算鉴权材料
- transport 发出远端请求
- transport / session 层再把结果回流给本地会话

### 一条真实 `chat/ask` 的内部调用时序

把当前已经拿到的静态符号、动态 trace、HTTP 捕获放到同一条时间线上，可以把主聊天链进一步压成：

1. 本地入口收到：
   - `chat/ask`
2. 本地 handler 先受理任务并保留：
   - `chat/ask.params.requestId`
   - `sessionType = chat`
3. remoting 主链进入：
   - `BuildBigModelSvcRequestWithConfig`
   - `doBuildRequestWithConfig`
   - `buildRequest`
4. `buildRequest` 内部先做请求整形：
   - `encodeRequestBody`
   - `shouldEncryptBody`
   - `createHTTPRequest / createCompressedHTTPRequest`
5. remoting 决定远端形态：
   - 目标 path 落到
     - `/algo/api/v2/service/pro/sse/agent_chat_generation`
   - query 决定是否带
     - `Encode=1`
     - `FetchKeys=llm_model_result`
     - `AgentId=agent_common`
6. 签名链先做 path 归一：
   - `trimQueryPath`
   - `/algo/api/... -> /api/...`
7. 头部加工阶段进入：
   - `addBigModelSignatureHeaders`
   - `addBigModelAuthorizationHeaders`
8. `Authorization` 不是 remoting 直接拼，而是继续委托：
   - `remotingAuthProvider.AuthenticateRequest`
   - `auth/user.AuthToken`
   - `getAuthPayload`
   - `getAuthSignature`
9. transport 发出真实远端 `POST` + SSE，请求头至少包含：
   - `Authorization: Bearer COSY...`
   - `Cosy-Date`
   - `Cosy-Key`
   - `Cosy-User`
   - `X-Request-Id`
10. 远端结果不会作为 `chat/ask` 的同步返回直接结束，而是：
    - 先由本地进程异步消费 SSE
    - 再回推：
      - `chat/process_step_callback`
      - `session/title/update`
      - `chat/answer`

这条时序当前还能再补一条非常关键的请求级语义：

- `chat/ask.params.requestId`
  - 会稳定映射到远端：
    - `X-Request-Id`
- bearer payload 内部的 `requestId`
  - 不是这个值
  - 而是 auth 链为每次远端请求单独生成的另一条 UUID
- 因此同一条本地 `chat/ask`
  - 可以对应多次远端重试
  - 并出现：
    - 相同 `X-Request-Id`
    - 不同 bearer 内 `requestId`
    - 不同 `Cosy-Date`
    - 不同 bearer 尾签名
    - 不同 `Encode=1` body

### 当前最稳的工程判断

如果你的目标是“分析 `Lingma` 程序里 API 是怎么调用的”，当前最值得记住的是：

- 关键不在 plugin
- 关键在 `LingmaLocal.exe` 内部的：
  - `core/api/*`
  - `remoting.*`
  - `remotingAuthProvider.AuthenticateRequest`
  - `auth/user.getAuthPayload`
  - `auth/user.getAuthSignature`
  - `transport/handler/*`

也就是说，当前这套程序内部 API 调用原理，更像一条：

- `local method -> internal business handler -> remoting policy -> auth/signature -> HTTP/SSE transport`

而不是：

- `local method -> 直接拼一个远端 URL -> 发请求`

## 远端签名边界

### 直接远端访问的当前结果

- 用 `auth/status.token` 直接请求远端 SSE：
  - HTTP 层可达
  - `Content-Type` 为 `text/event-stream`
  - 首条 SSE 事件返回：
- `{"code":"101","message":"Signature invalid"}`

### 当前已经排除的低成本路径

- 只带 bearer
- 伪造 `Authorization: Bearer COSY.<type>.<token>`
- 叠加 `Cosy-Key`
- 叠加 `Cosy-Date`
- 叠加 `Cosy-User`
- 叠加 `Cosy-MachineId`
- 叠加 `Cosy-MachineToken`
- 叠加 `Cosy-MachineOS`

这些组合当前都没有穿透服务端校验，统一落到：

- `Signature invalid`

### 早期 `signature` 头的当前边界

- 自定义 endpoint 流量采集还能看到一条更早期的 `signature` 头链，主要出现在：
  - `POST /algo/api/v1/heartbeat?Encode=1`
  - `POST /algo/api/v3/user/status?Encode=1`
  - `POST /algo/api/v3/user/login?Encode=1`
- 当前已确认的现象：
  - 同一秒内的 `user/status` 与 `user/login` 请求，`signature` 可以完全相同
  - 例如：
    - `Fri, 24 Apr 2026 07:54:36 GMT`
    - `signature = e8b434d0a2596ca2ff99c60c4756a1ff`
- 这说明：
  - 这条早期 `signature` 头至少不是“强绑定 body 的逐请求签名”
  - 它更可能依赖时间窗、固定上下文或会话级材料
- 但当前仍不能把它直接等同于后续 `Authorization: Bearer COSY...` 末尾 32 位 hex 的生成链

### 当前真正的剩余问题

- `SecurityGuardSDKManager` 输出了哪些 native 安全因子
- `UrlSignInterface / DTSignInterface / UMIDInterface / SecurityFactors` 各自承担什么角色
- `urlSign / tokenSign / GenerateSignatureBaseString` 如何组合成最终签名
- `Bearer COSY...` 中间 `base64-json` 的 `info` 字段如何生成
- `Encode=1` 请求体为什么会变成客户端自定义编码载荷

## 脱离 Lingma 程序直连的当前阻塞补证

### plugin jar 里目前没有可直接复用的远端签名实现

这轮又补看了当前工作区里的：

- `lib/cosy-intellij-2.11.1.jar`

目前直接确认的点是：

- `LanguageWebSocketService`
  - 负责本地 `chat/ask`
  - `auth/status`
  - `config/queryModels`
- `ObjectEncoder`
  - 只是在做：
    - URL encode/decode
    - `ChatContextTag` 的 Java 序列化 + Base64 包装
  - 前缀是：
    - `lingma:`

因此当前更稳的判断是：

- plugin jar 确实持有本地 websocket 客户端和参数对象
- 但这轮没有从 jar 里再挖出可直接复用的：
  - `COSY bearer` 生成逻辑
  - `Cosy-Key` 派生逻辑
  - `Encode=1` 远端 body 编码逻辑
- `ObjectEncoder` 也不是我们要找的远端 `Encode=1` 编码器

### Windows 主程序字符串继续指向“签名链在本地二进制里”

这轮继续对：

- `C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe`
- `C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\LingmaLocal.exe`

做了只读字符串扫描，当前直接能看到：

- `Cosy-Key`
- `Signature invalid`
- `agent_chat_generation`
- `Encode=1`

这进一步说明：

- 远端聊天主链与签名失败分支都已经被编进本地程序
- 当前真正掌握签名与编码链的，更可能是本地服务二进制或它加载的 native 安全组件
- 不能指望只从 plugin jar 里把“脱离 Lingma 程序的远端调用”直接抠出来

### 当前能不能直接实现“脱离 Lingma 程序调用”

到这一步，当前结论可以说得很直接：

- 如果“脱离 Lingma 程序”指的是：
  - 不依赖 `Lingma.exe` / `LingmaLocal.exe`
  - 自己直连远端 `algo` HTTP/SSE
- 当前仍然不能实现成一个真实可用的调用器

阻塞不是：

- token 不够
- endpoint 不知道
- 模型 key 不知道

而是：

- 远端签名链还没有被完整复刻
- `Encode=1` 的真正编码载荷还没有被还原

因此当前最稳判断仍然是：

- “脱离 plugin UI” 已成立
- “脱离 Lingma 进程本体” 还没有成立

## 附加边界

### 原始程序不可附加

- 原始 `~/.lingma/bin/2.11.1/aarch64_darwin/Lingma` 即使由当前账号自行启动，`frida` 与 `lldb` 仍会被系统拒绝附加。
- 当前更合理的解释是：
  - 问题不在“是不是同一用户启动”
  - 而在原始签名与 hardened runtime 附加限制策略

### 分析副本可附加

- 复制二进制并做 ad-hoc 重签名后，分析副本可以被 `frida` 和 `lldb` 成功附加。
- 当前实际使用的分析副本是：
  - [/tmp/lingma-debug/Lingma](/tmp/lingma-debug/Lingma)
- 这份副本已用于：
  - 运行时枚举 `SecurityGuardSDKManager`
  - 主动调用 `UMIDInterface` / `SecurityFactors`
  - 继续验证 Go 侧与 ObjC 侧哪条链真正参与聊天请求

### 当前更稳的实现判断

- ObjC 层的 `SecurityGuard` 接口都是真对象，不是死字符串。
- 但在“启动后再附加”的自然 `device_login + chat/ask` 业务流里，没有直接捕到 `UMIDInterface.getSecurityToken:` 或 `SecurityFactors.getMiniWua::` 的命中。
- 当前更合理的判断是：
  - 这些值可能在更早阶段已生成并缓存
  - 或者当前 macOS 这条产线主要走 Go 侧实现，而不是直接通过 ObjC wrapper 现算

### 关于 `machineToken/machineType` 的当前边界

- 当前所有已抓到的远端请求里：
  - `Cosy-MachineToken = ""`
  - `Cosy-MachineType = ""`
- 但分析副本 `machine-info` 明确能返回：
  - `machineToken`
  - `machineType`
- 这说明：
  - 当前聊天/登录这条请求链并不会把 `machine-info` 暴露出来的值直接透传到这两个 HTTP 头里
- 过去围绕 `Cosy-MachineToken` / `Cosy-MachineType` 的手工伪造思路，当前可以进一步降权

## 当前 Windows 已登录样本的本地聊天链补证

### 顺序化最小调用链

当前已经通过工作区里的：

- `tools/lingma_probe.py`

稳定复现了这条最小本地链：

1. 连接 `ws://127.0.0.1:37010`
2. 发送 `initialize`
3. 发送 `auth/status`
4. 发送 `config/queryModels`
5. 发送 `chat/ask`

其中 `initialize` 当前更推荐带上：

- `rootUri = file:///D:/Project/lingma`
- `workspaceFolders = [{uri,name}]`

因为如果完全不给 workspace，日志里会出现：

- `get mtree failed: workspacePath is empty`

### `initialized` 在这条本地实现里不是必需步骤

补跑发现：

- 向 `37010` 发送 LSP 风格的 `initialized` notification
- 服务端日志会记：
  - `err occur in initialized, isReq: false, err: unknown method: initialized`

因此当前更稳的实现判断是：

- `37010` 虽然整体长得像 LSP transport
- 但方法面并不完整遵循标准 LSP 生命周期
- 真正可用的程序化最小链里，不需要再发 `initialized`

### `config/queryModels` 当前返回的有效模型面

当前已直接读到这些场景：

- `assistant`
- `chat`
- `developer`
- `inline`
- `quest`

其中当前样本稳定出现的 key 包括：

- `auto`
- `dashscope_qwen3_coder`
- `dashscope_qwen_plus_20250428_thinking`
- `dashscope_qwen_max_latest`

同时每个模型项还能直接读到：

- `displayName`
- `format = openai`
- `source = system`
- `isReasoning`
- `isVl`

### `chat/ask` 的当前最小可用参数形状

当前直接跑通的一组最小参数是：

```json
{
  "requestId": "d081516141c9412486dd5d4263ee9c41",
  "chatTask": "FREE_INPUT",
  "chatContext": null,
  "sessionId": "",
  "codeLanguage": "",
  "isReply": false,
  "source": 1,
  "questionText": "Reply with exactly: pong",
  "stream": true,
  "taskDefinitionType": "",
  "extra": null,
  "sessionType": "chat",
  "targetAgent": "",
  "pluginPayloadConfig": null,
  "mode": "normal",
  "shellType": "",
  "customModel": null
}
```

当前同步返回是：

- `success = true`
- `errorCode = ""`
- `errorMessage = ""`

### 当前实际观测到的异步回包方法

同一条 `chat/ask` 请求，后续继续收到：

- `chat/process_step_callback`
  - `step = step_start`
  - `status = done`
- `chat/process_step_callback`
  - `step = step_end`
  - `status = done`
- 多条 `chat/answer`
  - `text = "pon"`
  - `text = ""`
  - `text = "g"`
  - `text = ""`

把这些 `chat/answer.text` 片段拼起来，当前实际得到：

- `pong`

这把“本地 `37010` 是否真的可作为程序化模型入口”进一步坐实成了：

- 不只是能发请求
- 而是已经能稳定收到分片式回答通知

### 当前与远端链的关系

这次本地问答继续把远端主链也补实了。

日志里已经直接出现：

- `POST https://lingma-api.tongyi.aliyun.com/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1`

说明：

- `chat/ask`
  - 本地入口在 `37010`
  - 远端主聊天 SSE 在 `/algo/api/v2/service/pro/sse/agent_chat_generation`

当前这台机器上，这条远端请求偶发返回：

- `EOF`

但这个 `EOF` 不影响我们对调用过程的判断：

- 本地可编程入口已经明确
- 异步回包方法已经明确
- 真正仍未解决的只是“脱离 Lingma 进程以后如何自己复刻远端签名与编码链”

## 隔离 endpoint 流量采集补证

### 当前已经能安全抓到 Lingma 本体的真实出站 HTTP

这轮没有去动当前正在使用的 `C:\Users\Zipper\.lingma` 主实例，而是新起了一份隔离副本：

- 启动本地流量采集服务：
  - `python .\tools\lingma_capture_server.py --port 18080 --log .\capture\lingma-http-capture.jsonl`
- 启动隔离 Lingma：
  - `Lingma.exe start --workDir D:\Project\lingma\capture\workdir-18080 --copyDataDir C:\Users\Zipper\.lingma --socketPort 37011 --httpPort 37511 --endpoint http://127.0.0.1:18080`

同时 `capture/workdir-18080/logs/lingma.log` 已直接记录：

- `Communication servers ready - WebSocket: 37011, HTTP: 37511`

因此当前已经可以在不破坏主安装态的前提下，把 Lingma 本体实际发往远端 endpoint 的请求完整落盘到：

- `capture/lingma-http-capture.jsonl`

### 早期握手阶段仍然是 `Signature` 头，不是 bearer

隔离实例最先打出来的请求已经直接坐实了“前置握手”和“已登录主请求”不是同一套头体系。

当前已抓到：

- `GET /algo/api/v1/ping`
  - `Signature = 460e2aba79cd5e919885ba6f5b1c9289`
- `POST /algo/api/v1/heartbeat?Encode=1`
  - `Signature = 460e2aba79cd5e919885ba6f5b1c9289`
  - `body_len = 984`
- `POST /algo/api/v3/user/status?Encode=1`
  - `Signature = 8c0c5a3e88297aba157fddc9929cc258`
  - `body_len = 240`
- `POST /algo/api/v3/user/login?Encode=1`
  - `Signature = 8c0c5a3e88297aba157fddc9929cc258`
  - `body_len = 128`

这把前面的工程判断进一步收紧成：

- 早期 `Signature` 不是最终聊天接口直接可复用的 bearer
- 远端主聊天链至少分成：
  - 早期握手/状态同步阶段
  - 登录后带 `Authorization: Bearer COSY...` 的主业务阶段

### 登录后已抓到完整 `COSY bearer + Cosy-*` 头集合

在隔离实例里注入一次 `auth/device_login` 后，`capture/lingma-http-capture.jsonl` 已直接出现完整的远端主业务请求头。

当前真实抓到的头字段包括：

- `Authorization: Bearer COSY.<base64-json>.<32hex>`
- `Cosy-Date`
- `Cosy-Key`
- `Cosy-User`
- `Cosy-Data-Policy`
- `Cosy-Machineid`
- `Cosy-Machineos`
- `Cosy-Machinetoken = ""`
- `Cosy-Machinetype = ""`

当前直接解开 `Authorization` 中段 base64 JSON，可以稳定看到：

- `cosyVersion = 2.11.1`
- `ideVersion = ""`
- `info = ...`
- `requestId = ...`
- `version = v1`

并且同一隔离实例内已经能直接对出这些关系：

- `info` 在整轮流量采集中保持不变
  - `infoLen = 664`
  - `infoSha256` 前 16 位稳定为：
    - `4a6f229b26eb37b4`
- `Cosy-Key` 在整轮流量采集中也保持不变
- 每个远端请求都会生成新的 bearer 内嵌 `requestId`
- bearer 尾部 32 位 hex 也会随请求变化

这说明：

- 当前已经不是“不知道远端头长什么样”
- 真正还没解出来的是：
  - bearer 尾 32 位 hex 的生成链
  - 它与 `info / Cosy-Key / Cosy-Date / bearer.requestId / path / body` 的精确组合关系

### `agent_chat_generation` 已抓到真实出站请求与请求体

这轮最关键的新证据，是已经把真实聊天主链直接落盘了。

当前已抓到：

- `POST /algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1`

并且请求头里同时出现：

- `Authorization: Bearer COSY...`
- `Cosy-Date`
- `Cosy-Key`
- `Cosy-User`
- `X-Request-Id = 601e8990a5db44b4ba94aff7192cf64a`

同时 `capture/workdir-18080/logs/lingma.log` 已记录：

- `doAsk params.SessionType: chat, ChatMode: normal`
- `Async chat, request id: 601e8990a5db44b4ba94aff7192cf64a`

这把两条链路之间的关系补实成：

- 本地 `chat/ask.params.requestId`
  - 会直接进入远端头：
    - `X-Request-Id`
- bearer 中段 JSON 里的 `requestId`
  - 不是这个 `X-Request-Id`
  - 而是另一条每请求重建的 UUID

当前已抓到的三次同一聊天链重试还进一步说明：

- `X-Request-Id` 可保持不变：
  - `601e8990a5db44b4ba94aff7192cf64a`
- 但每次重试都会重新生成：
  - bearer 内嵌 `requestId`
  - bearer 尾 32 位 hex
  - `Cosy-Date`
  - `Encode=1` body

### `Encode=1` 的 body 仍是当前直连的硬阻塞

这轮流量采集已经把“远端 body 不是普通 JSON”也直接坐实了。

当前已抓到的聊天请求体特征包括：

- 第一次：
  - `body_len = 11476`
  - `body_sha256 = 93ef473514afeab0d29a055628a5366f7118d8e149656b41d0949ced3a1e0604`
- 第二次：
  - `body_len = 6608`
  - `body_sha256 = da2e8a955cb87bb520cece09f0d068055643b83cba8d5bd5bf1f1d8f5c47058a`
- 之后还有更长一次：
  - `body_len = 34040`
  - `body_sha256 = d128a8bb2e224e4637448fbcc508ba4fb4b272a0fd709efd9abd4d0937f14a3c`

其正文当前直接表现为高密度自定义字母表文本，例如混合：

- 大小写字母
- `@ * & # % ^ _ , . ( ) !`

进一步按整轮已抓到的 POST body 统计，当前还能直接看到：

- 所有 `Encode=1` body 长度都能被 `4` 整除
- 全量字符并集当前只有 `65` 个字符：
  - `!#$%&()*,.@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz`
- 聊天 body 里当前直接搜不到这些明文字段：
  - `pong`
  - `Reply with exactly`
  - `601e8990a5db44b4ba94aff7192cf64a`
  - `5930676910898027`
- `$` 只在少量 body 内部出现，且不是末尾 padding：
  - 例如第二条聊天 body 里只出现 1 次
  - 第三条聊天 body 里连续出现 2 次，但位置在中部，不在结尾

这说明它当前更像：

- 二进制 payload
- 再经过一层自定义 64/65 字符表编码

而不是 JSON、URL-encoded JSON 或常规 base64 文本。

### `COSYENC1` 是当前新出现的本地编码格式线索

这轮继续只读扫 `Lingma.exe` / `LingmaLocal.exe` 时，又补到一个新的高价值常量：

- `COSYENC1`

当前已经直接确认：

- `Lingma.exe` 中存在 `COSYENC1`
  - 至少 5 处命中
- `LingmaLocal.exe` 中当前没有搜到 `COSYENC1`
- 同一个二进制字符串区附近还能直接看到：
  - `chatTask`
  - `end_turn`
  - `modelKey`
  - `cosy_key`

同时代码段附近还能看到对 `COSYENC1` 的直接比较/写入痕迹。

当前更稳的工程推断是：

- `COSYENC1` 很像 Lingma 主二进制内部某种编码容器的 magic 或版本标记
- 它很可能和当前看到的 `Encode=1` body 有关
- 但到这一步为止，还不能直接把它等同成：
  - 远端 body 明文
  - 或单步可逆的现成算法名

### 新补证：`COSYENC1` 更像本地 AES-256 加密文件容器，不是远端 body 直接协议名

继续沿着 `COSYENC1` 做局部反汇编后，这轮已经把它的角色进一步收紧了。

当前直接命中的 `.text` 逻辑包括：

- `0x1408a5b0c`
  - 先按 `input_len + 9` 分配输出
  - 把前 8 字节写成：
    - `COSYENC1`
  - 再把第 9 字节写入一个单字节值
  - 然后继续复制后续 payload
- `0x1408a5179`
  - 先检查前 8 字节是否等于：
    - `COSYENC1`
  - 再读取第 9 字节
  - 再继续做后续校验与解包

但更关键的是，这两个函数引用到的错误串已经直接暴露了它们更像“本地加密文件读写”而不是“远端聊天 body 编码”：

- `encrypted file requires 32-byte key`
- `key must be 32 bytes for AES-256`
- `failed to read nonce: %v`
- `failed to write header: %v`
- `failed to write encrypted data: %v`
- `invalid nonce size: expected %d, got %d`
- `invalid file format or not encrypted`

这把当前判断从“`COSYENC1` 可能是远端 body magic”修正成了：

- `COSYENC1` 更像 Lingma 本地某种：
  - AES-256
  - nonce
  - header
  - 加密文件容器
- 它和 `Encode=1` 仍可能共享底层材料或编码组件
- 但它当前已经不再是“远端聊天 body 直接协议名”的首选解释

### 当前更值得继续逆的主链已经收窄到 `cosy/remoting`

在同一份 `Lingma.exe` 里，这轮还直接补到了 Go build info 与 remoting 模块名面：

- `Go buildinf:`
  - `go1.22.1`
- `path`
  - `cosy`

同时已直接扫到这批与远端大模型请求高度相关的函数名：

- `cosy/remoting.BuildBigModelSvcRequestWithConfig`
- `cosy/remoting.doBuildRequestWithConfig`
- `cosy/remoting.BuildBigModelAuthRequest`
- `cosy/remoting.BuildBigModelSignRequest`
- `cosy/remoting.buildRequest`
- `cosy/remoting.GetMessageEncode`
- `cosy/remoting.encodeRequestBody`
- `cosy/remoting.createHTTPRequest`
- `cosy/remoting.createCompressedHTTPRequest`
- `cosy/remoting.shouldAddEncodeParam`
- `cosy/remoting.shouldEncryptBody`
- `cosy/remoting.addBigModelSignatureHeaders`
- `cosy/remoting.addBigModelAuthorizationHeaders`
- `cosy/remoting.GetBigModelEndpoint`
- `cosy/remoting.GetBigModelHost`
- `cosy/remoting/sse.NewSseAgentChatClient`
- `cosy/remoting.GetAgentChatClient`

并且当前还直接扫到了对应源码路径名：

- `cosy/remoting/big_model.go`
- `cosy/remoting/common.go`
- `cosy/remoting/http_client.go`
- `cosy/remoting/definition.go`
- `cosy/remoting/sse/client.go`
- `cosy/remoting/sse/sse_client.go`

这意味着下一步真正应该继续抠的，不再是：

- `COSYENC1`

而是这条更直接的主链：

1. `BuildBigModelSvcRequestWithConfig`
2. `doBuildRequestWithConfig`
3. `buildRequest`
4. `GetMessageEncode / encodeRequestBody`
5. `shouldEncryptBody / shouldAddEncodeParam`
6. `addBigModelSignatureHeaders`
7. `addBigModelAuthorizationHeaders`

### 新补证：GoReSym 已把主链函数映射到具体代码地址

这轮新增引入了只读分析工具：

- `tools/goresym/GoReSym.exe`

并已对：

- `C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe`

跑出完整 Go 符号与函数表，当前已经把关键主链直接映射到了这些地址：

- `cosy/remoting.BuildBigModelSvcRequestWithConfig`
  - `0x14087fc00 - 0x14087fe20`
- `cosy/remoting.doBuildRequestWithConfig`
  - `0x14087fe20 - 0x140880720`
- `cosy/remoting.buildRequest`
  - `0x140880da0 - 0x140881480`
- `cosy/remoting.encodeRequestBody`
  - `0x140881820 - 0x140881980`
- `cosy/remoting.shouldAddEncodeParam`
  - `0x140882540 - 0x140882680`
- `cosy/remoting.shouldEncryptBody`
  - `0x140882680 - 0x140882760`
- `cosy/remoting.addBigModelSignatureHeaders`
  - `0x140882760 - 0x140882ba0`
- `cosy/remoting.addBigModelAuthorizationHeaders`
  - `0x140882ba0 - 0x140882c80`

同时 `buildRequest` 里的调用顺序已经能直接看清：

1. `encodeRequestBody`
2. `shouldEncryptBody`
3. `createHTTPRequest` 或 `createCompressedHTTPRequest`
4. `addBigModelSignatureHeaders`
5. `addBigModelAuthorizationHeaders`
6. `addBasicHeaders`
7. `logRequest`

这把当前总链条进一步收紧成：

- `Encode=1` 与 body 变换
  - 发生在 `encodeRequestBody / shouldEncryptBody / createCompressedHTTPRequest`
- 头签名与 bearer
  - 发生在 `addBigModelSignatureHeaders / addBigModelAuthorizationHeaders`

### `Encode=1` 不是所有接口都加，当前判定逻辑已经直接抠出来

这轮把两个最关键的开关函数完整抠出来了。

#### `shouldAddEncodeParam`

当前函数体已经坐实：

- 它先检查一个全局配置开关是否为字符串：
  - `"1"`
- 然后排除这些路径：
  - `/api/v1/service/next_edit_predict`
  - `/algo/api/v1/organizations`
- 然后只对这些 HTTP 方法开放：
  - `POST`
  - `PUT`
- 其中 `PUT` 还要再额外满足路径命中：
  - `/api/v2/remoteAgent/qoder`

当前更稳的实现判断是：

- `Encode=1` 不是“全接口默认附加”
- 它受：
  - 全局开关
  - 路径白黑名单
  - HTTP 方法
  共同控制

#### `shouldEncryptBody`

当前函数体已经直接坐实：

- 它先排除：
  - `/ncqs/api/v1/quotas`
  - `/algo/api/v1/organizations`
- 其他情况下会继续回落到：
  - `shouldAddEncodeParam`

因此当前最稳的协议判断是：

- body 是否进入“加密/编码链”
  - 基本跟 `Encode=1` 同步
- 但还存在更严格的排除面
  - 不是所有带路由的请求都会走 body 加工

### `encodeRequestBody / shouldEncryptBody` 不只在 `Encode=1` POST 上命中

这轮继续用动态 trace 对正在运行的已登录态实例补了一次更细的实证：

- tracer：
  - `capture/frida-body-trace-loginseed-20260424-222811.jsonl`
- 对应 HTTP 捕获：
  - `capture/lingma-http-capture-loginseed-20260424-222811.jsonl`

`frida` 在 `2026-04-24 22:29:14 +0800` 实际打到的是：

- `encodeRequestBody.enter`
  - `method = GET`
  - `url = http://127.0.0.1:18084/algo/api/v2/model/list`
  - `normalized_path = /api/v2/model/list`
- `shouldEncryptBody.enter`
  - 同样看到：
    - `GET`
    - `http://127.0.0.1:18084/algo/api/v2/model/list`
    - `/api/v2/model/list`

同一秒对应的 HTTP 捕获也确实是：

- `GET /algo/api/v2/model/list`
- `body_len = 0`

这说明当前必须把结论再收紧一层：

- `shouldAddEncodeParam`
  - 仍然是当前已知最直接的 `Encode=1` 判定闸门
- 但 `encodeRequestBody / shouldEncryptBody`
  - 自身并不是“只要命中就一定在做 `Encode=1` POST body 编码”
  - 它们也处在更通用的请求整理路径上
  - 即便是无 body 的 `GET /api/v2/model/list`，也会进入这两个函数

因此当前更稳的理解应改写为：

- 是否真正发生远端 body 编码
  - 不能只看有没有进 `encodeRequestBody / shouldEncryptBody`
- 还必须同时结合：
  - HTTP 方法
  - 路径
  - `Encode=1` 查询参数
  - 以及最终实际出站 body

也就是说：

- 这两个函数仍然重要
- 但它们现在更像“通用请求整形/条件判断节点”
- 而不是“`Encode=1` body 编码已经发生”的单点铁证

### `addBigModelAuthorizationHeaders` 不直接算 bearer，而是委托给 auth provider

这轮把 `Authorization` 的真实生成层也补实了。

当前已确认：

- `cosy/remoting.addBigModelAuthorizationHeaders`
  - `0x140882ba0 - 0x140882c80`

它自身不直接做 bearer 拼装，而是：

1. 先调用：
   - `cosy/remoting.trimQueryPath`
2. 再调用：
   - `code.alibaba-inc.com/cosy/common/remoting/provider.GetAuthProvider`
3. 再通过 provider 对象继续走认证请求链

当前真实落到的实现 provider 是：

- `cosy/bootstrap/modules/adapter.(*remotingAuthProvider).AuthenticateRequest`
  - `0x141c370a0 - 0x141c37120`

而这个实现继续直接转调：

- `cosy/auth/user.AuthToken`
  - `0x14088f740 - 0x140890140`

这说明：

- `addBigModelAuthorizationHeaders`
  - 只是 remoting 层入口
- 真正的 bearer 与 `Cosy-*` 头拼装
  - 已经进入 `cosy/auth/user` 这条链

### `AuthToken` 已坐实会统一拼 `Authorization` 与多组 `Cosy-*` 头

当前在：

- `cosy/auth/user.AuthToken`

内部，已经直接抓到这些字符串引用：

- `Bearer COSY.%s.%s`
- `Cosy-User`
- `Cosy-Date`
- `Cosy-Key`
- `Authorization`
- `Cosy-Organization-Tags`
- `Cosy-Organization-Id`
- `Cosy-Data-Policy`
- `AGREE`
- `DISAGREE`

同时它还直接调用：

- `cosy/auth/user.GetCachedUserInfo`
- `cosy/auth/user.getAuthPayload`
- `cosy/auth/user.getAuthSignature`

这把当前 bearer 结构进一步补实成：

- 中段 payload
  - 由 `getAuthPayload` 生成
- 尾部 32 位 hex
  - 由 `getAuthSignature` 生成
- 其他 `Cosy-*` 头
  - 也在 `AuthToken` 层统一补齐

### `frida` 动态追踪已把 `trimQueryPath / getAuthPayload / getAuthSignature` 三段串实

这轮新增了运行时追踪辅助脚本：

- `tools/frida_trace_signature.py`

成功样本落在：

- `capture/frida-signature-trace-37017-login.jsonl`
- `capture/lingma-http-capture-frida.jsonl`

这次不再只是“静态符号 + 字符串引用”推断，而是已经把同一条真实请求的三段关键处理链逐一对上。

### `trimQueryPath` 已被运行时证明会把 `/algo` 归一到 `/api`

对真实请求：

- 原始 HTTP 路径：
  - `/algo/api/v2/model/list`

`frida` 动态追踪里直接看到：

- `trimQueryPath.enter`
  - 输入：
    - `/algo/api/v2/model/list`
- `trimQueryPath.leave`
  - 输出：
    - `/api/v2/model/list`

因此当前对 bearer 签名链的更稳判断是：

- 真正进入签名拼接的不是流量采集里看到的原始 `/algo/...`
- 而是归一化后的：
  - `/api/...`

### `getAuthPayload` 已被运行时证明会产出 bearer 中段 payload

同一条动态样本里，已经直接看到：

- `getAuthPayload.enter`
  - 输入：
    - `cache/user.encrypt_user_info`
      对应的长字符串
- `getAuthPayload.leave`
  - 输出：
    - bearer 中段 base64 payload

这把 bearer 结构进一步补实成：

- `cache/user.encrypt_user_info`
  - 不是直接原样进 `Authorization`
- 它会先被：
  - `getAuthPayload`
  - 包装成 bearer 中段 payload

### bearer 尾 32 位 hex 已从“最后一步是 Md5Encode”推进到“已知精确五段 preimage 顺序”

当前已确认：

- `cosy/auth/user.getAuthPayload`
  - 引用了这些字段名：
    - `requestId`
    - `info`
    - `cosyVersion`
    - `ideVersion`
- `cosy/auth/user.getAuthSignature`
  - 最终会调用：
    - `code.alibaba-inc.com/cosy/encrypt.Md5Encode`

更关键的是，这轮已经拿到一条真实请求的完整入参与出参对照：

- 请求：
  - `GET /algo/api/v2/model/list`
- 归一路径：
  - `/api/v2/model/list`
- `Cosy-Date`：
  - `1777038686`
- `Cosy-Key`：
  - 流量采集与 trace 完全一致
- `getAuthSignature.enter`
  - `rax_rbx`
    - bearer 中段 payload
  - `rcx_rdi`
    - `/api/v2/model/list`
  - `rsi_r8`
    - `""`
  - `r9_r10`
    - `1777038686`
  - `stack_08_10`
    - `Cosy-Key`
- `getAuthSignature.leave`
  - `a0c8bb3de47a955df4f786b4000faa0d`

对这组值做独立复算后，已经可以直接命中同一个尾签名：

- `md5(payload + "\n" + Cosy-Key + "\n" + Cosy-Date + "\n" + slot4 + "\n" + normalized_path)`

在当前样本里：

- `slot4 == ""`
- `normalized_path == "/api/v2/model/list"`

PowerShell 独立复算结果也已命中：

- `computed == observed == a0c8bb3de47a955df4f786b4000faa0d`

这意味着当前可以把先前“bearer 尾 32 位 hex 未知”修正为：

- 对至少这类 `/model/list` 请求
- 尾 32 位 hex 已不是黑盒
- 已经拿到可离进程复算的精确五段顺序

### 第四槽位当前仍未命名，但已经排除它直接等于 `Cosy-Data-Policy`

当前这条样本里同时存在：

- HTTP 头：
  - `Cosy-Data-Policy: DISAGREE`
- `getAuthSignature.enter`
  - 第四槽位：
    - `rsi_r8 == ""`

这说明：

- 第四槽位当前不能直接等同于：
  - `Cosy-Data-Policy`

再结合同批流量采集里：

- `Cosy-Organization-Id == ""`
- `Cosy-Organization-Tags == ""`

当前更合理的保守判断是：

- 第四槽位是结构上固定存在的可选字段
- 当前样本里为空
- 它更像组织 / 项目 / 其他可选上下文字段
- 但还没有被当前样本正式命名

### `/algo/api/v2/model/list` 已经被离进程实测打通

在补完上述公式后，已经直接在 `Lingma` 进程外做了两次远端实测：

1. 复用已抓到的 bearer 中段 payload
2. 重新生成当前 `Cosy-Date`
3. 按五段公式重算尾 32 位 hex
4. 直接请求：
   - `https://lingma.alibabacloud.com/algo/api/v2/model/list`

结果：

- 远端返回：
  - `HTTP 200`
- 返回体已直接给出模型列表

进一步又做了一次更关键的验证：

1. 不再复用旧 payload
2. 进程外自行生成新的 `requestId`
3. 用：
   - `info`
   - `Cosy-Key`
   - 新 `requestId`
   - 当前 `Cosy-Date`
   - 空第四槽位
   - 归一路径 `/api/v2/model/list`
   重建整个 `Authorization`
4. 再次直接请求同一远端接口

结果仍然是：

- `HTTP 200`

这意味着当前已经可以把能力边界再前推一层：

- 对无 body 的 `/algo/api/v2/model/list`
  - 已经不是“只能回放旧包”
  - 而是能够在 `Lingma` 进程外
    - 自行生成新 `requestId`
    - 自行生成当前 `Cosy-Date`
    - 自行重算 `Authorization`
    - 直接访问远端

当前这条链真正仍依赖的最小持久化材料已经收缩成：

- `cache/user.encrypt_user_info`
- `cache/user.key`
- `Cosy-User`
- `Cosy-MachineId`

其中：

- `encrypt_user_info`
  - 用于构建 bearer 中段 payload
- `key`
  - 用于 `Cosy-Key`
  - 也进入五段 `md5` 计算
- `Cosy-User`
  - 当前仍作为已知成功头一并携带
- `Cosy-MachineId`
  - 当前仍作为已知成功头一并携带

进一步的泛化验证也已经完成：

- 同一套外部签名逻辑
- 把 endpoint 换成：
  - `/algo/api/v2/config/getDataPolicy?requestId=<uuid>&version=2`
- 归一路径使用：
  - `/api/v2/config/getDataPolicy`
- 结果同样返回：
  - `HTTP 200`

这说明当前已经不应再把它理解成“只对 `/model/list` 碰巧成立”的特例，而应理解为：

- 对同一类无 body 的 GET 接口
- 只要走的是这条 `AuthToken -> trimQueryPath -> getAuthPayload -> getAuthSignature` 认证链
- 当前已经可以在进程外直接构造请求

当前仓库里已经落了一个最小 PoC：

- `tools/offprocess_model_list.ps1`

它当前已实测可直接打通：

- `/algo/api/v2/model/list`
- `/algo/api/v2/config/getDataPolicy?...`

## 当前最稳的落地判断

- 如果目标是“脱离 plugin UI 调用模型”，当前已成立，直接复用本地 `37010` 即可。
- 这条本地链当前已经补齐到了：
  - `auth/status`
  - `config/queryModels`
  - `chat/ask`
  - `chat/process_step_callback`
  - `chat/answer`
- 如果目标是“脱离本地 `Lingma` 程序直连远端 HTTP API”，当前仍未成立。
- 但当前阻塞已经从“完全不知道 bearer 怎么来”收缩成两项：
  - 第四槽位在非空场景下的真实语义来源
  - `Encode=1` 请求体编码
- 也就是说：
  - 对无 body 的 `/algo/api/v2/model/list`
    - 当前已经被离进程实测打通
  - 对同类无 body GET
    - 当前也已经拿到第二条成功样本
  - 对真实聊天主链
    - 还差 body 编码链与第四槽位命名
- 后续若继续做工程落地，更推荐：
  - 封装 `37010` 为自己的稳定 API 层
  - 同时并行推进远端直连 PoC，而不是再把 bearer 尾签名当成主黑盒

## 隔离启动的新约束

这轮还补出一个对后续协议研究很关键的运行约束：

- 直接用：
  - `Lingma.exe start --workDir <new> --copyDataDir C:\Users\Zipper\.lingma ...`
  - 或者把旧 workdir 当作 `--copyDataDir`
- 当前都不能稳定把旧 `cache/user` 带进新实例
- 日志会直接出现：
  - `No cached user info, please login.`

但如果改成：

- 先把已有登录态的旧 workdir 整体克隆一份
- 再直接用这个克隆目录作为：
  - `--workDir`

则本地 `auth/status` 可直接读回：

- `id = 5930676910898027`
- `token = pt-5zmkcs3cUpPGP8FGb88WGkSJ`
- `refreshToken = rt-gHWjpgS9NQ4TOhmtvmN55ELZ`

这说明对于后续所有“隔离实例 + 动态 插桩观察 + 带登录态复现”场景，当前更稳的做法应该是：

- 不要依赖 `--copyDataDir` 迁移用户态
- 直接克隆一个已落地过 `cache/user` 的 workdir 再启动

## 透明代理模式已恢复真实远端行为

这轮还把本地 capture server 从“纯 stub”推进到了“可录制 + 可转发”的透明代理模式：

- `tools/lingma_capture_server.py`
  - 新增：
    - `--upstream-base`
    - `--chat-upstream-base`

当前实测启动方式是：

- 本地 capture：
  - `http://127.0.0.1:18085`
- 上游代理：
  - 普通远端：
    - `https://lingma.alibabacloud.com`
  - 聊天 SSE 远端：
    - `https://lingma-api.tongyi.aliyun.com`
- 本地服务：
  - `ws://127.0.0.1:37024`
  - `http://127.0.0.1:37524`

在这个模式下，本地 `37024` 已重新恢复为真实可用状态：

- `auth/status`
  - `status = 2`
  - `name = zhang640@blny.de`
  - `whitelist = 3`
  - `privacyPolicyAgreed = true`
- `config/queryModels`
  - 再次返回完整模型注册表

这说明当前已经拿到一个比“静态 stub”更适合继续协议研究的环境：

- 远端真实逻辑继续跑
- 本地仍可完整抓到所有出站请求

### `Data-Policy` 同步会在运行时刷新签名材料

这轮透明代理还补出一个之前没坐实的变化点。

在：

- `capture/workdir-proxyseed-20260424-223925/logs/lingma.log`

里，已经直接出现：

- `update data policy sign status successfully, status: AGREE`

随后同一实例抓到的真实出站请求头也发生了同步变化：

- `Cosy-Data-Policy`
  - 从之前常见的：
    - `DISAGREE`
  - 变成：
    - `AGREE`
- `Cosy-Key`
  - 也不再沿用之前那组旧值
  - 而是切换成了新的运行时材料

也就是说，当前必须把一个新的动态性补进签名结论：

- `cache/user.key`
  - 虽然仍是当前已知 `Cosy-Key` 的直接来源
- 但它不是一次抓到就永久稳定
- 至少在真实远端 `data policy` 状态同步后
  - `Cosy-Key`
  - `Authorization.info`
  都可能跟着一起刷新

因此对后续“完全脱离 Lingma 进程直连远端”的工程落地，当前更稳的取材策略应该是：

- 不要长期固化旧的：
  - `info`
  - `Cosy-Key`
- 而要优先从最新一次真实运行态中提取
  - 尤其是在 `Data-Policy` 从 `DISAGREE` 切到 `AGREE` 之后

### 无 `Frida` 时透明代理可稳定复现真实聊天链

这轮继续把“代理模式自身是否稳定”与“`Frida` 挂钩是否导致崩溃”拆开做了单独复现。

本次新实例使用：

- workdir：
  - `capture/workdir-proxynofrida-20260424-224555`
- capture：
  - `http://127.0.0.1:18086`
- 本地服务：
  - `ws://127.0.0.1:37026`
  - `http://127.0.0.1:37526`
- 上游：
  - `https://lingma.alibabacloud.com`
  - `https://lingma-api.tongyi.aliyun.com`

关键点是：

- 全程不挂 `Frida`
- 仅保留：
  - 克隆旧登录态 workdir
  - 透明代理 capture
  - 本地 `lingma_probe.py`

在这个组合下，当前已经再次稳定拿到：

- `auth/status`
  - `status = 2`
  - `privacyPolicyAgreed = true`
- `config/queryModels`
  - 返回完整模型注册表
- `chat/ask`
  - 同步返回 `success = true`
  - 后续收到：
    - `chat/process_step_callback`
    - `chat/answer`

并且这次进程在聊天后仍保持存活：

- `capture/lingma-proxynofrida-20260424-224555.err.log`
  - 为空
- `Lingma.exe`
  - 仍处于 `Responding = True`

这把当前判断再往前推了一步：

- 上一轮 `proxyseed` 实例的 `0xc0000005`
  - 当前更像是 `Frida` 干预窗口或挂钩面导致的不稳定
- 至少不是“透明代理模式本身无法承载真实聊天”

### 纯代理模式下已再次抓到真实 `agent_chat_generation`

在：

- `capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl`

里，这轮已经再次直接抓到真实聊天主链，而且不是一次孤例，而是同一条本地 `chat/ask` 触发出的多次远端重试。

当前抓到的真实出站请求包括：

1. `2026-04-24T22:46:40+08:00`
   - `POST /algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1`
   - `X-Request-Id = b788e2adc80644dabd0b6c75d2f26160`
   - bearer 内嵌 `requestId = f7c083ce-e25e-4738-9182-69c3531f1c89`
   - `body_len = 11548`
   - `body_sha256 = 7fa9644251a80466616d45d45277bbd64e7e265f0072fb1bdc0d9c6d9699bcc6`
2. `2026-04-24T22:46:47+08:00`
   - 同一路径
   - `X-Request-Id` 保持不变
   - bearer 内嵌 `requestId = 867bd8c5-dded-4a5c-89a8-676ea16b7971`
   - `body_len = 6972`
   - `body_sha256 = 938d8b787f49a3680ac09085982b2b5e946b5e0af588aab1e1c7abcbe129c8d2`
3. `2026-04-24T22:46:54+08:00`
   - 同一路径
   - `X-Request-Id` 仍保持不变
   - bearer 内嵌 `requestId = fc4707fc-75b6-48f2-8416-efcdc61d3549`
   - `body_len = 34040`
   - `body_sha256 = 07f63f06a393473659150d69749a6495e876a3538664b2f6fba9cb69ba6638a1`

同一次聊天后，还继续抓到：

- `POST /algo/api/v2/service/business/finish?Encode=1`
  - `2026-04-24T22:46:40+08:00`
  - `body_len = 848`
  - `body_sha256 = 59ad307b7acc5cafec2cf2426e878e895136c16d22e48689d444e72f076251e2`
- `POST /algo/api/v2/service/business/finish?Encode=1`
  - `2026-04-24T22:46:56+08:00`
  - `body_len = 852`
  - `body_sha256 = 365344b45b9165994c75cc8d5c7aaf28f2473c3534db9e2359132f8a6265da3d`

而：

- `capture/workdir-proxynofrida-20260424-224555/logs/lingma.log`

也同步出现：

- `update data policy sign status successfully, status: AGREE`
- `|Chat| doAsk params.SessionType: chat, ChatMode: normal`
- `Async chat, request id: b788e2adc80644dabd0b6c75d2f26160`

这轮把聊天主链的结构关系补得更完整了：

- 本地 `chat/ask.params.requestId`
  - 继续稳定进入远端头：
    - `X-Request-Id`
- 同一次本地 `chat/ask`
  - 可触发多次远端 `agent_chat_generation` 重试
- 每次重试都会重新生成：
  - bearer 内嵌 `requestId`
  - bearer 尾 32 位 hex
  - `Cosy-Date`
  - `Encode=1` body
- 但这几次重试共用同一个：
  - `X-Request-Id`

### 同一次聊天并不只有 SSE 主请求，还会派生出 side-band 收尾请求

这轮把同一个时间窗里的完整网络序列继续展开后，可以把 transport 侧再收紧一层：

1. `2026-04-24T22:46:40+08:00`
   - `POST /algo/api/v2/service/pro/sse/agent_chat_generation?...&Encode=1`
   - `X-Request-Id = b788e2adc80644dabd0b6c75d2f26160`
2. 同秒紧接着出现：
   - `POST /algo/api/v2/service/business/finish?Encode=1`
   - `POST /algo/api/v2/service/codebase/embedding_k2?Encode=1`
3. `2026-04-24T22:46:47+08:00`
   - 第二次 `agent_chat_generation` 重试
   - `X-Request-Id` 仍保持不变
4. `2026-04-24T22:46:51+08:00`
   - `POST /algo/api/v2/service/ask/finish?Encode=1`
5. `2026-04-24T22:46:54+08:00`
   - 第三次 `agent_chat_generation` 重试
   - `X-Request-Id` 仍保持不变
6. `2026-04-24T22:46:56+08:00`
   - 再次出现 `POST /algo/api/v2/service/business/finish?Encode=1`
7. `2026-04-24T22:48:57+08:00`
   - 后续还有 `POST /algo/api/v1/tracking?Encode=1`

这说明当前不能再把 transport 只理解成：

- “发一条 SSE 请求，等返回”

而应该理解成：

- 一次本地 `chat/ask`
  - 会驱动一组相关远端请求
- 其中：
  - `agent_chat_generation`
    - 是主聊天 SSE 链
  - `service/business/finish`
    - 不能再简单理解成“最终收尾”
    - 因为它在第一条 SSE 刚发出时就已经出现过一次
    - 当前更像业务生命周期里的阶段性 `finish` 上报
  - `service/ask/finish`
    - 更接近 ask 级完成上报
  - `service/codebase/embedding_k2`
    - 是并行派生的附属能力调用
  - `api/v1/tracking`
    - 是更靠后的埋点/上报

另一个当前很有价值的边界是：

- 已观察到的 `X-Request-Id`
  - 只稳定出现在 `agent_chat_generation`
- 当前抓到的：
  - `business/finish`
  - `ask/finish`
  - `embedding_k2`
  - `tracking`
  都没有同样的 `X-Request-Id` 头

因此更稳的 transport 判断是：

- `X-Request-Id`
  - 当前更像“主聊天流请求 id”
- 它不是所有 side-band 收尾请求共享的统一链路 id

同一时间窗里，auth 与 transport 的边界也更清楚了：

- `2026-04-24T22:46:40+08:00` 这一秒内的：
  - `agent_chat_generation`
  - `business/finish`
  - `embedding_k2`
  都共用：
  - `Cosy-Date = 1777042000`
  - 同一条 `Cosy-Key`
- 但它们各自 bearer 里的：
  - `requestId`
  - 尾部 32 位签名
  仍然不同

这说明当前更合理的内部解释是：

- `Cosy-Date / Cosy-Key`
  - 更像这一小段时间窗里的签名上下文
- bearer 内 `requestId`
  - 则是每个 HTTP 请求各自重新生成的请求级材料
- 因此“同一秒发出”不等于“复用同一条 bearer”

同时，本地日志和 side-band 请求之间已经能对上一层语义：

- `2026-04-24T22:46:51.768+08:00`
  - 本地日志出现：
    - `finish chat answer requestId: b788e2adc80644dabd0b6c75d2f26160`
    - `[TOKEN_USAGE]`
- 同一秒抓到：
  - `POST /algo/api/v2/service/ask/finish?Encode=1`
  - bearer 内 `requestId = f4da329a-ace3-44dc-85e3-d68f5c658331`

因此当前更稳的边界是：

- `service/ask/finish`
  - 已经可以和本地“本次 answer 已完成”阶段直接对上
- `service/business/finish`
  - 因为既出现在首条 SSE 同秒
  - 也出现在最后一次 SSE 之后
  - 所以它更像业务状态推进节点
  - 还不能草率等同于“聊天真正结束”

因此当前对于“完全脱离 `Lingma` 进程复刻聊天远端调用”的阻塞判断还能再收紧一点：

- 透明代理抓真实聊天
  - 已经不是问题
- 真实重试行为与结束上报
  - 也已经落盘
- 当前仍未解出的核心只剩：
  - `Encode=1` body 变换链
  - 以及第四槽位在非空场景下的确切语义

## 2026-04-24 深夜重抓补证

### `--copyDataDir` 仍不能稳定迁移登录态

在新一轮重抓里，直接执行：

- `Lingma.exe start --workDir D:\Project\lingma\capture\workdir-proxynofrida-20260424-235210 --copyDataDir D:\Project\lingma\capture\workdir-proxynofrida-20260424-224555 --socketPort 37028 --httpPort 37528 --endpoint http://127.0.0.1:18088`

得到的结果仍然是：

- 新 workdir：
  - `capture/workdir-proxynofrida-20260424-235210/cache/user`
    - 缺失
- 日志：
  - `capture/workdir-proxynofrida-20260424-235210/logs/lingma.log`
    - 明确出现：
      - `No cached user info, please login.`
- 流量采集：
  - `capture/lingma-http-capture-proxynofrida-20260424-235210.jsonl`
    - 只剩：
      - `ping`
      - `heartbeat`

这把前面的判断进一步坐实：

- `--copyDataDir`
  - 不能被视为“把旧登录态完整复制到新实例”
- 至少在当前版本和当前目录结构下：
  - 它会生成新 cache
  - 而不是保留旧 `cache/user`

### 先完整克隆 workdir，再直接启动副本，可以恢复真实登录态

随后改成：

1. 先完整复制：
   - `capture/workdir-proxynofrida-20260424-224555`
   - 到：
   - `capture/workdir-clone-20260424-235500`
2. 再直接启动：
   - `Lingma.exe start --workDir D:\Project\lingma\capture\workdir-clone-20260424-235500 --socketPort 37029 --httpPort 37529 --endpoint http://127.0.0.1:18089`

这次恢复为真实可用状态：

- `python tools/lingma_probe.py --uri ws://127.0.0.1:37029`
  - `auth/status.status = 2`
  - `privacyPolicyAgreed = true`
  - `config/queryModels`
    - 返回完整模型注册表
- 日志：
  - `capture/workdir-clone-20260424-235500/logs/lingma.log`
    - 不再出现：
      - `No cached user info, please login.`

因此当前更稳的复现实验准则是：

- 不要继续依赖：
  - `--copyDataDir`
- 要复刻已登录实例时：
  - 先完整克隆一个已带 `cache/user` 的旧 workdir
  - 再把该副本直接作为新的 `--workDir`

### 新一轮聊天样本确认了完整主链和 side-band 序列

在这个 workdir 副本上执行：

- `python tools/lingma_probe.py --uri ws://127.0.0.1:37029 --do-chat --question "Explain your role in one short sentence." --chat-idle-timeout 8 --chat-overall-timeout 25`

本地返回：

- `chat/ask.success = true`
- `chat/answer`
  - 按 chunk 回来：
    - `Hel`
    - `lo`
    - `!`

这轮对应的新流量采集文件是：

- `capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl`

其中与这次 `chat/ask.requestId = b75778fc025b4dbebf5cfde250534dd0` 对上的关键链路是：

1. 预热/配置阶段：
   - `GET /algo/api/v2/config/getDataPolicy?...`
   - `POST /algo/api/v3/user/status?Encode=1`
   - `GET /algo/api/v2/model/list`
2. 主聊天请求：
   - `2026-04-24T23:37:42+08:00`
   - `POST /algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1`
   - `X-Request-Id = b75778fc025b4dbebf5cfde250534dd0`
   - `Cosy-Date = 1777045062`
   - bearer 内嵌：
     - `requestId = 3f1e8ce8-881b-49d1-bf88-bccde593e5a8`
     - 尾签名 `fce11f2d8cef44924b38dd9acee5ef3c`
   - `body_len = 11592`
   - `body_sha256 = ae6b39a187e8c91cec03cd2407862b2e23de79b0a8197bd01788ace88b1cae08`
3. 同秒 side-band：
   - `2026-04-24T23:37:43+08:00`
   - `POST /algo/api/v2/service/business/finish?Encode=1`
     - 无 `X-Request-Id`
     - `Cosy-Date = 1777045063`
     - bearer `requestId = 04b3534e-90e0-45bb-9151-80092fcd270b`
     - 尾签名 `fefb4a839de1175c1b86eb643dabe751`
     - `body_len = 848`
     - `body_sha256 = ef4fce0796ab65409c81152ab749009086b305fda16f27b9e3d17ee115f79c86`
   - `POST /algo/api/v2/service/codebase/embedding_k2?Encode=1`
     - 无 `X-Request-Id`
     - `Cosy-Date = 1777045063`
     - bearer `requestId = 8db10172-289f-49e1-a1ae-0f67008273a0`
     - 尾签名 `2b1c54e14df06cd50f1a644927f507b9`
     - `body_len = 176`
     - `body_sha256 = 5b977c9cd96b9ba7c57e7cb5dfca91554e3a3b9e0bffe30f3e619a5ab8cb4a7a`
4. 第二次 SSE 重试：
   - `2026-04-24T23:37:49+08:00`
   - 同一路径
   - 同一 `X-Request-Id`
   - `Cosy-Date = 1777045069`
   - bearer `requestId = 9d452192-d33a-4ef9-bc31-8240fd3b535e`
   - 尾签名 `3ac7c1548781ffb7b183296d602ba151`
   - `body_len = 7348`
   - `body_sha256 = 19a363ec13c45a23d1840e7a3d0f90ea42089e88ed000b4782a1d8c4a8178a7b`
5. answer 完成阶段：
   - `2026-04-24T23:37:54+08:00`
   - `POST /algo/api/v2/service/ask/finish?Encode=1`
   - 无 `X-Request-Id`
   - `Cosy-Date = 1777045074`
   - bearer `requestId = 776b0bfb-2cc2-4650-8ed4-47859452d207`
   - 尾签名 `865ce4848b0949070111b8082252ba1a`
   - `body_len = 244`
   - `body_sha256 = 9a5cdee5614c65633e8158bc96f76d202845606c87d4ebb7a36dc85244b6e9a1`
6. 第三次 SSE 重试：
   - `2026-04-24T23:38:00+08:00`
   - 同一路径
   - 同一 `X-Request-Id`
   - `Cosy-Date = 1777045080`
   - bearer `requestId = 0fa72d04-c5c3-4e5e-a165-877bab36df9a`
   - 尾签名 `d9fc7dd309cc10f53125f7e71d6796fc`
   - `body_len = 34040`
   - `body_sha256 = 9ed69f4bb86cbda09d48bceb6fd1e84f61c2277e704244451723d1d3e59f32b9`
7. 更晚阶段再次上报：
   - `2026-04-24T23:38:02+08:00`
   - `POST /algo/api/v2/service/business/finish?Encode=1`
   - 无 `X-Request-Id`
   - `Cosy-Date = 1777045082`
   - bearer `requestId = 340d8280-8199-4be2-b71f-ef14580d8073`
   - 尾签名 `2258ca42377240d5d86555ee4918a66e`
   - `body_len = 852`
   - `body_sha256 = 0d6adb266ce4f59beab2a28fb2882101eff90f1f58cfafc785274f0989742386`
8. 更靠后埋点：
   - `2026-04-24T23:40:07+08:00`
   - `POST /algo/api/v1/tracking?Encode=1`
   - `body_len = 18232`
   - `body_sha256 = 932748a9bab7041266faa05b8001697cd6f8b146949c6ba935b9787e9b0c7055`

而本地日志：

- `capture/workdir-clone-20260424-235500/logs/lingma.log`

同步记录了：

- `|Chat| doAsk params.SessionType: chat, ChatMode: normal`
- `Async chat, request id: b75778fc025b4dbebf5cfde250534dd0`
- `[TOKEN_USAGE]: {"cached_tokens":0,"completion_tokens":2,"prompt_tokens":364,"request_id":"b75778fc025b4dbebf5cfde250534dd0","total_tokens":366}`
- `finish chat answer requestId: b75778fc025b4dbebf5cfde250534dd0 cost: 4.0820155s`

### 这轮新样本带来的边界收紧

重新按整份 `jsonl` 解完 bearer 以后，这轮 `23:37` 样本实际上再次完整出现了：

- `service/business/finish`
- `service/codebase/embedding_k2`
- `service/ask/finish`
- 更晚的 `api/v1/tracking`

因此当前更稳的结论是：

- 一次本地 `chat/ask`
  - 会驱动：
    - 预热配置请求
    - `agent_chat_generation`
    - 至少一个 `business/finish`
- 在当前两轮真实聊天样本里：
  - `embedding_k2`
  - `ask/finish`
  - `tracking`
  也都再次出现
- 所以当前更像：
  - 一组围绕主聊天流派生的阶段性 side-band
  - 而不是偶发孤例

这轮还能把“请求级材料”和“时间窗级材料”的边界收紧成下面这样：

- `X-Request-Id`
  - 继续稳定只出现在：
    - `agent_chat_generation`
  - 并且稳定等于本地：
    - `chat/ask.params.requestId`
- bearer 内 `requestId`
  - 是每个 HTTP 请求各自独立生成的请求级材料
- bearer 尾部 32 位 hex
  - 也是每个 HTTP 请求各自独立变化
- `Cosy-Date`
  - 更接近请求发送时刻的时间窗材料
  - 相邻 side-band 可落在同一秒
  - 也可按秒推进
- `Cosy-Key`
  - 这轮在整段聊天窗口内保持同一条值
  - 说明它更像运行态签名上下文
  - 不是每个请求都重新生成

因此当前对于 Lingma 内部 API 调用原理的描述应当收紧为：

- 本地 handler 收到 `chat/ask`
- remoting 层先做配置/状态预热
- 主聊天通过：
  - `service/pro/sse/agent_chat_generation`
  发往远端
- 同一条本地 ask 再驱动：
  - `business/finish`
  - `embedding_k2`
  - `ask/finish`
  - `tracking`
  等阶段性 side-band
- 其中：
  - 主链靠 `X-Request-Id` 绑定回本地 ask
  - side-band 不共享这个头
  - 但共享同一运行态的 `Cosy-Key`

### `tracking` 更像来自独立 `tracker` 模块，而不是主聊天 remoting 发送器

到这一步，`tracking` 已经不适合再和 `agent_chat_generation` / `business/finish` / `ask/finish` / `embedding_k2` 视作同一条 HTTP 发送链路里的“同类 side-band”。

更稳的说法应当是：

- 一次本地 `chat/ask`
  - 会触发主聊天链和若干聊天相关 side-band
- 但更晚出现的 `tracking`
  - 更像后台 `tracker` 模块异步 flush 出去的另一类上报

证据有三层。

第一层，流量采集里的 header 家族已经明显分叉。

在所有已确认的聊天主链与聊天 side-band 请求里：

- `model/list`
- `config/getDataPolicy`
- `service/pro/sse/agent_chat_generation`
- `service/business/finish`
- `service/codebase/embedding_k2`
- `service/ask/finish`

都稳定使用：

- `Authorization: Bearer COSY...`
- `Cosy-Key`
- `Cosy-Date`

而在目前所有已抓到的 `tracking` 样本里：

- `capture/lingma-http-capture-body-20260424-222313.jsonl`
  - `2026-04-24T22:26:16+08:00`
  - `2026-04-24T22:29:16+08:00`
- `capture/lingma-http-capture-loginbody-20260424-222716.jsonl`
  - `2026-04-24T22:30:19+08:00`
- `capture/lingma-http-capture-loginseed-20260424-222811.jsonl`
  - `2026-04-24T22:31:14+08:00`
- `capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl`
  - `2026-04-24T22:48:57+08:00`
- `capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl`
  - `2026-04-24T23:40:07+08:00`

都稳定表现为：

- 有 `Appcode = cosy`
- 有 `Date`
- 有 `Signature`
- 没有 `Authorization`
- 没有 `Cosy-Key`
- 没有 `Cosy-Date`

这说明 `tracking` 并不是“Bearer + Cosy-Key + Cosy-Date” 那个发送器上的一个普通 endpoint，而是落在另一套更老的签名客户端家族里。

第二层，时间关系也更像异步队列 flush，而不是主聊天请求的同步尾巴。

在 `capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl` 这轮里：

- `23:37:42`
  - 第一次 `agent_chat_generation`
- `23:37:54`
  - `ask/finish`
- `23:38:02`
  - 第二次 `business/finish`
- `23:40:07`
  - 才出现 `POST /algo/api/v1/tracking?Encode=1`

也就是 `tracking` 比聊天主链的最后一批已知请求还晚了大约两分钟。这个时间距离更像后台模块按队列或批次做延后上报，而不是主 remoting 调用在一个请求生命周期里顺手发出的同步 follow-up。

第三层，二进制符号和本地日志都直接出现了独立的 `tracker` 模块。

本地日志 `capture/workdir-clone-20260424-235500/logs/lingma.log` 里可见：

- `[tracker] Initialized successfully, storagePath=D:\Project\lingma\capture\workdir-clone-20260424-235500\cache\ai_tracker`
- `|boot| Module tracker started successfully`

而 `capture/goresym-lingma.json` 里同时出现了：

- `cosy/bootstrap/modules.(*TrackerModule).Start`
- `cosy/bootstrap/modules.(*TrackerModule).Stop`
- `cosy/tracker.Initialize`
- `cosy/tracker.getOrCreateQueue`
- `cosy/tracker.RecordInlineChatModification`
- `cosy/tracker.RecordAgentModification`
- `cosy/tracker.VerifyCommit`
- `cosy/tracker.reportAICodeCommit`
- `cosy/core/api/tracker.InitHandlers`
- `cosy/core/api/tracker.RecordQuestApplyHandler`
- `cosy/core/api/tracker.VerifyCommitHandler`

这里最关键的不是某一个函数名本身，而是它们组合起来显示出：

- 本地确实有单独启动的 `TrackerModule`
- `tracker` 自己维护了 queue
- 它关心的是：
  - chat/agent 修改记录
  - commit 校验
  - AI code commit 上报

这与 `tracking` 使用另一套旧签名头家族的事实是相互咬合的。

第四层，历史日志已经把 `tracking` 明确记成了 “report event / report data” 语义，而不是普通聊天请求。

`C:\Users\Zipper\.lingma\logs\lingma.log` 和 `C:\Users\Zipper\.lingma\vscode\sharedClientCache\logs\lingma-2026-01-03T10-29-00.938.log` 里都能看到：

- `post report data failed: Post "https://lingma-api.tongyi.aliyun.com/algo/api/v1/tracking?Encode=1"...`
- `Reported 0/7 events`
- `Reported 6/6 events`
- `Reported 46/46 events`

也就是说，`tracking` 对应的不是“发送一个业务请求”，而是“尝试上报一批事件”。

更关键的是，历史日志里还有直接的事件名：

- `Failed to report event "back-flow-mtree": post report data failed: Post "https://lingma-api.tongyi.aliyun.com/algo/api/v1/tracking?Encode=1"...`
- `Failed to report event "back-flow-edit-seq": post report data failed: Post "https://lingma-api.tongyi.aliyun.com/algo/api/v1/tracking?Encode=1"...`

而在 `2026-04-24` 本地日志里，这种批量语义也仍然存在：

- `post report data failed: Post "https://lingma-api.tongyi.aliyun.com/algo/api/v1/tracking?Encode=1": EOF`
- `Reported 0/7 events`

因此这里可以再收紧一步：

- `tracking`
  - 更像 `tracker` / reporting 子系统定时或批量 flush 的事件上报接口
  - body 很可能承载一批 event，而不是单个聊天请求的同步结果
  - 这也解释了它为什么：
    - 常常晚于聊天主链若干秒到数分钟
    - 使用独立的旧签名头家族
    - 在日志中拥有自己的 “report data / report event / reported x/y events” 术语

因此当前更稳的抽象应当改成“两套出站客户端家族”：

- 家族 A，主聊天 / remoting / 大模型链路
  - 典型头：
    - `Authorization`
    - `Cosy-Key`
    - `Cosy-Date`
  - 典型 endpoint：
    - `model/list`
    - `config/getDataPolicy`
    - `service/pro/sse/agent_chat_generation`
    - `service/business/finish`
    - `service/codebase/embedding_k2`
    - `service/ask/finish`
- 家族 B，旧签名系统 / 状态上报 / tracker 链路
  - 典型头：
    - `Appcode`
    - `Date`
    - `Signature`
  - 典型 endpoint：
    - `ping`
    - `heartbeat`
    - `user/status`
    - `server/version`
    - `tracking`
  - 典型语义：
    - `heartbeat` 是心跳上报
    - `user/status` 是状态探测
    - `tracking` 是事件批量上报

所以现在对“Lingma 程序中 API 是怎么调用的”这件事，应当避免只画成一条线性的聊天请求链。更准确的描述是：

- 本地 `chat/ask` 会进入 remoting 主链
- remoting 主链负责 Bearer / `Cosy-Key` / `Cosy-Date` 这一家族的远端调用
- 与此同时，进程内还存在独立 `tracker` 模块
- `tracker` 模块更可能通过旧签名客户端异步上报 `tracking`
- 所以 `tracking` 与聊天主链有关联，但不应再被视作同一个 HTTP 发送器里的同类请求

### `tracking` 的 body 看起来又和主链共享同一类 `Encode=1` 可打印装甲层

上面的结论描述的是“发送器家族不同”。但如果继续看 `capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl` 里的 `body_utf8`，会发现另一个容易混淆但必须分开的事实：

- `tracking` 的请求头家族明显属于旧签名链路
- 但它的 `Encode=1` body 字符分布，又和聊天主链那批 body 很接近

当前这轮样本里：

- `user/status`
  - 长度 `240`
  - 去重字符数 `53`
  - 只由大小写字母和少量标点组成
  - 没有出现数字
- `heartbeat`
  - 长度 `1024`
  - 去重字符数 `58`
  - 同样没有出现数字
- `business/finish`
  - 长度 `848`
  - 去重字符数 `57`
  - 同样没有出现数字
- `agent_chat_generation`
  - 长度 `11592`
  - 去重字符数 `65`
  - 同样没有出现数字
- `tracking`
  - 长度 `18232`
  - 去重字符数 `64`
  - 同样没有出现数字

也就是说，虽然 `tracking` 不在 Bearer / `Cosy-Key` / `Cosy-Date` 这一家发送器里，但它的 body 仍然高度像同一类“自定义可打印字符装甲”产物，而不是另一种完全不同的编码形态。更稳妥的说法是：

- 发送器 / 认证头家族分了两套
- 但更底层的 `Encode=1` body 装甲层，至少在当前样本里很可能是共享的，或者共享了同一族 codec 组件

这也能和已有 `frida` 现象对上：

- `encodeRequestBody`
- `shouldEncryptBody`

本来就不是“只给聊天 POST 命中”的专用函数；它们在：

- `GET /api/v2/model/list`
- `GET /api/v2/config/getDataPolicy`

这类请求上也会进入。因此它们更像 remoting / URL 归一 / body 处理的公共底层闸门，而不是某个单独业务 sender 的专用实现。

### `tracking` 的 body 内部重复块密度又明显更像“批量事件容器”

虽然 `tracking` 和聊天主链看起来共享同类 `Encode=1` 装甲层，但它的内部结构仍然不像单次聊天主请求，更像把多条记录拼成一个大包后再统一编码。

还是以 `capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl` 里的 `tracking` 样本为准：

- `tracking`
  - `body_len = 18232`
  - `DxK^PSWhBMn*` 出现 `20` 次
  - `JOFYN(Lbu*By` 出现 `27` 次
  - `j@z^VR#kjMz%` 出现 `9` 次
  - `l@VfjMN(l@Tf` 出现 `7` 次
  - `NZKbDZFM` 出现 `4` 次

进一步看 16 字符窗口频次，`tracking` 顶部重复片段已经达到：

- `DoByBMaQV^_(j^#Q`：`14` 次
- `^_(j^#QV@_Il@&fV`：`14` 次
- `#QV@_Il@&fVMN*Go`：`14` 次

而同轮第一个 `agent_chat_generation` 大包虽然也会出现重复窗口，但最高只到：

- `hPDU.%hyGy@Q#SLX`：`4` 次
- `Qu(@Q#OjyDmhyPc#`：`4` 次
- `QG*XycPdQn,vQDhA`：`4` 次

这说明：

- `tracking` 不只是“大一点的同类请求”
- 它内部更像存在重复 record/block 模板
- 这和历史日志里的：
  - `Reported x/y events`
  - `Failed to report event "back-flow-mtree"...`
  - `Failed to report event "back-flow-edit-seq"...`
  是相互咬合的

所以现在对 `tracking` 的最细化描述应该更新为：

- 它不是聊天主链 remoting sender 的普通 side-band
- 它属于 `tracker` / report-event 子系统
- 它很可能复用了 Lingma 统一的 `Encode=1` 可打印装甲层
- 但上层承载的明文结构更像“多事件批量 flush 容器”

### `tracker` 的 flush 行为看起来是固定周期任务，而不是“聊天结束立刻发”

这一步再把时间关系收紧以后，`tracking` 的调度模型也比前面更清楚了。

在 `capture/workdir-clone-20260424-235500/logs/lingma.log` 里，当前这个副本能直接看到：

- `20:44:27`
  - `Reported 27/27 events`
- `20:47:27`
  - `Reported 0/0 events`
- `20:50:27`
  - `Reported 0/0 events`
- `22:48:57`
  - `Reported 15/15 events`
- `22:51:57`
  - `Reported 0/0 events`
- `22:54:57`
  - `Reported 0/0 events`
- `23:40:07`
  - `Reported 15/15 events`

其中连续 flush 间隔基本都落在：

- `179.987s`
- `179.998s`
- `179.225s`
- `180.009s`

这说明 `tracker` 更像是一个固定约 `180s` 的定时批量上报器。一次聊天会往队列里塞事件，但真正的 `tracking` HTTP 发送更像：

1. 聊天或其它行为往 queue 里写入 event
2. 后台定时任务按约 `3` 分钟 cadence 尝试 flush
3. 这次 flush 把当时队列里的所有 event 打成一批，发到 `POST /algo/api/v1/tracking?Encode=1`

因此：

- `tracking` 和聊天行为当然有关
- 但它不是“finish chat 后立即顺手发的同步 follow-up”
- 更像后台 batch reporter 的定时刷盘/刷网动作

### `storagePath=.../cache/ai_tracker` 把本地 queue 的存在坐实了，但成功 flush 后目录会清空

本地日志还给出了 `tracker` 的初始化路径：

- `capture/workdir-clone-20260424-235500/logs/lingma.log:1393`
  - `[tracker] Initialized successfully, storagePath=D:\Project\lingma\capture\workdir-clone-20260424-235500\cache\ai_tracker`
- `C:\Users\Zipper\.lingma\logs\lingma.log:163416`
  - `[tracker] Initialized successfully, storagePath=C:\Users\Zipper\.lingma\cache\ai_tracker`

这说明：

- `tracker` 确实有独立本地存储区
- 它不是单纯把待上报事件塞进业务 `local.db` 里

当前对磁盘侧的进一步检查结果是：

- `capture/workdir-clone-20260424-235500/cache/ai_tracker`
  - 目录存在
  - 当前为空
- `C:\Users\Zipper\.lingma\cache/ai_tracker`
  - 目录存在
  - 当前为空
- 两份 `cache/db/local.db`
  - 都没有直接的 `tracker` / `report` / `queue` 表

这更像：

- `ai_tracker` 是 `tracker` 自己的专用落盘区
- 成功 flush 后会把待上报内容清空
- 而不是长期保留在主业务 SQLite 表里

所以现在对本地实现的理解可以再往前推一步：

- `tracker.Initialize`
  - 会绑定一个独立的 `storagePath`
- `tracker.getOrCreateQueue`
  - 负责管理该本地 queue
- 周期性 flush 时
  - 把 queue 中的 event 打成一个 `tracking` 批量包
- 成功后
  - 本地 queue 可能被清空，因此磁盘上经常只剩空目录

### 当前两次 `15/15 events` 大包已经能和 `tracking` body 的规模稳定对上

这一步虽然还没拿到 pre-encode 明文，但至少能把“日志中的 event 数”和“流量采集中的 body 规模”稳定对账。

两次最关键的样本分别是：

- `capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl`
  - `2026-04-24T22:48:57+08:00`
  - `body_len = 18152`
  - 同时日志：
    - `capture/workdir-clone-20260424-235500/logs/lingma.log:1316`
    - `Reported 15/15 events`
- `capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl`
  - `2026-04-24T23:40:07+08:00`
  - `body_len = 18232`
  - 同时日志：
    - `capture/workdir-clone-20260424-235500/logs/lingma.log:1579`
    - `Reported 15/15 events`

它们都属于：

- 约 `18KB` 的大 tracking 包
- 对应 `15` 条 event 的批量 flush

而更早的 tracking 小样本：

- `len = 1616`
- `len = 1772`
- `len = 1804`
- `len = 3420`

明显更像小批次或低 event 数 flush。虽然目前还不能把某个重复片段精确映射成“一条 event”，但已经可以高置信说：

- `tracking` body 的体积会随 batch 大小显著增长
- `Reported x/y events` 不是日志层虚数
- 它对应的确实是一整个 batched payload，而不是单事件单请求

### `tracker` 的本地入口已经暴露出“文件变更采集”和“提交校验”两类前置 API

这一步虽然还没拿到 `tracking` 的 pre-encode 明文，但符号表已经把 `tracker` 在本地进程里的入口形状进一步暴露出来了。

先看 `cosy/core/api/tracker` 这一组符号：

- `cosy/core/api/tracker.RecordQuestApplyHandler`
- `cosy/core/api/tracker.InitHandlers`
- `cosy/core/api/tracker.VerifyCommitHandler`

而它们旁边的 typed handler 形状分别出现了：

- `WorkspacePath string`
- `SessionId string`
- `TaskId string`
- `FileChanges []cosy/definition.QuestApplyFileChange`

以及：

- `WorkspacePath string`
- `CommitId string`

这里至少能收紧出两件事：

- `RecordQuestApplyHandler` 这一路不是只记一个事件名
  - 它本地就已经接收 `workspacePath + sessionId + taskId + fileChanges`
  - 而 `definition.QuestApplyFileChange` 本身又包含：
    - `FilePath`
    - `OriginalContent`
    - `ModifiedContent`
- `VerifyCommitHandler` 也不是空壳
  - 它本地接收 `workspacePath + commitId`
  - 更像把某次 commit 的 AI 修改统计做本地校验/聚合

同时，在更前面的符号区里还能看到：

- `cosy/tracker.RecordNesModification`
- `cosy/tracker.RecordInlineChatModification`
- `cosy/tracker.RecordAgentModification`

而独立出现的另一组 typed handler 形状正好是：

- `WorkspacePath string`
- `FilePath string`
- `OriginalContent string`
- `ModifiedContent string`

这还不能百分之百逐个函数一一对应，但至少已经足够说明：

- `tracker` 的本地入口层并不是“只采一个 event type”
- 它会在本地先接收文件级 before/after 内容
- 再把这些内容压进后续统计/聚合链路

这和日志里的失败事件名也开始能对上字段来源了。比如符号表里同时存在：

- `back_flow.AgentStartReporter`
  - 带 `sessionId` / `requestId` / `workspacePath` / `mtreeDiff`
- `back_flow.EditSeqReporter`
  - 带 `workspacePath` / `reportReason` / `editSequence`
- `back_flow.NesReporter`
  - 带 `sessionId` / `requestId` / `changes` / `workspacePath`

而日志里恰好反复出现：

- `[back-flow][agent-start]...[requestId] get mtree diff failed`
- `Failed to report event "back-flow-mtree"...`
- `Failed to report event "back-flow-edit-seq"...`

因此现在更稳的说法是：

- `tracking` 的 event 源头并不抽象
- 其中至少一部分来自 `back_flow` / quest apply / commit verify / accepted modification 这些本地 handler 或 reporter
- 这些 handler 在进入 `tracking` 发送器之前，已经掌握文件路径、原文、改后内容、session/task/request 等上下文

### `tracking` 预编码前更像是 `aicodestats` 聚合对象，而不是原样上传全文

顺着 `tracker` 符号继续往下，可以把“本地 rich record”和“最终上报 report”之间的中间层也拼出来。

最关键的是 `aicodestats.RecordParams`：

- `WorkspacePath`
- `FilePath`
- `OriginalContent`
- `AIModifiedContent`
- `Brand`
- `Product`
- `Scenario`
- `SessionID`
- `UserQueryBusinessId`
- `ExtInfo`

也就是说，本地采集阶段确实会拿到：

- 文件原文/改后内容
- 品牌/产品/场景
- 会话 ID
- 用户查询业务 ID

接着，符号表里还能看到行级归因对象：

- `types.LineDetail`
  - `Lines`
  - `Type`
  - `Brand`
  - `Product`
  - `Scenario`
  - `SessionID`
  - `UserQueryBusinessId`
- `types.LineDetailGroupKey`
  - 同样包含 `Type/Brand/Product/Scenario/SessionID/UserQueryBusinessId`

再往上一层，聚合对象已经被拆成两条支路：

- 按 user query 聚合：
  - `aicodestats.UserQueryAIStats`
    - `UserQueryBusinessId`
    - `Files []aicodestats.UserQueryFileStats`
    - `TotalAddedLines`
    - `TotalDeletedLines`
- 按 commit 聚合：
  - `aicodestats.CommitAIStats`
    - `CommitId`
    - `ParentCommitId`
    - `Files []aicodestats.FileAIStats`
    - `TotalAddedLines`
    - `TotalDeletedLines`
    - `TotalAIAddedLines`
    - `TotalAIDeletedLines`
    - `BrandBreakdown`
    - `ProductBreakdown`
    - `ScenarioBreakdown`
    - `RebaseType`
    - `OriginalCommitIds`
    - `IsMergeCommit`
    - `ParentCommitIds`

而真正靠近上报侧的对象名也已经出现了：

- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*UserQueryAIStats).ToAICodeChangeReport`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*CommitAIStats).ToAICodeCommitReport`

对应的 report 结构分别是：

- `aicodestats.AICodeChangeReport`
  - `ChangeID`
  - `Scenario`
  - `Product`
  - `Action`
  - `ModelLevel`
  - `TotalLinesAdded`
  - `TotalLinesDeleted`
  - `CreatedAt`
  - `FileChanges []aicodestats.AICodeChangeFileReport`
- `aicodestats.AICodeCommitReport`
  - `CommitHash`
  - `RepoName`
  - `BranchName`
  - `Product`
  - `TotalLinesAdded`
  - `TotalLinesDeleted`
  - `AILinesAdded`
  - `AILinesDeleted`
  - `ScenarioBreakdown`
  - `ProductBreakdown`
  - `Message`
  - `CommitTs`
  - `CreatedAt`
  - `Files []aicodestats.FileAIStats`
  - `RebaseType`
  - `OriginalCommitIds`
  - `IsMergeCommit`
  - `ParentCommitIds`

这一层非常关键，因为它把 `tracking` 的上层 payload 模型进一步收紧成：

- 本地先保存 rich record
  - 包括原文、改后内容、line details、session/user-query 归因
- 然后按 user query 或 commit 聚合成 `UserQueryAIStats` / `CommitAIStats`
- 最后再转换成更紧凑的 `AICodeChangeReport` / `AICodeCommitReport`
- 再被统一装进 `tracking?Encode=1` 的批量包里

因此目前最稳的判断已经不再是“`tracking` 里可能只是若干事件名 + 参数”，而是：

- `tracking` 的 pre-encode 上层对象很可能已经是压缩过的统计 report
- 原始全文内容更像用于本地比对、归因和统计
- 真正出网的 payload 上层更可能是 change/commit report 的批量集合，而不是整段源码原样上传

这也解释了两个此前现象为什么能同时成立：

- `tracking` body 内部有明显重复块
  - 因为它更像很多同构 report item 的批量容器
- 但 body 体积并没有膨胀到“直接塞进大量全文源码”那种程度
  - 因为 richer 原始内容很可能已在本地被折叠成统计对象和 breakdown

仍然需要保留的一点边界是：

- 现在还没有拿到 `tracking` 最外层 envelope 的明文字段名
- 所以还不能断言最外层 JSON 一定长成什么样
- 但“本地 rich record -> `aicodestats` 聚合 -> change/commit report -> `tracking` 批量上报”这一条链，已经比之前清楚很多了

### `tracking` 更像至少并行承载两类上层对象，而 `buildCommitItemsJSON` 已经把 commit report 那一路钉得更实

在上一节的基础上，再往前推进一层后，可以把 `tracking` 上层对象拆成两种风格不同的来源，但它们是否在最外层共用同一个 envelope，当前还只能做到高概率推断。

第一类是更“普通事件”风格的对象。`goresym` 里已经直接出现了一个完整的 typed handler 入参形状：

- `EventType string`
- `RequestId string`
- `IdeType string`
- `IdeVersion string`
- `PluginPublisher string`
- `PluginName string`
- `EventData map[string]string`

并且同一组符号旁边存在：

- `cosy/core/transport/handler/rpc.RegisterTypedHandler[...]`
  - 其入参正是上述 `eventType/requestId/eventData` 结构

这里需要收紧措辞：

- 这还不能直接证明“这个 handler 出网时一定命中 `tracking`”
- 也不意味着这里要回到“plugin 与 lingma 对接”那个话题
- 但至少说明 Lingma 进程内部除了 `aicodestats` 这一条 rich diff/report 链之外
  - 还存在一条更通用的 `eventType + eventData` 事件对象入口

第二类则是前面已经基本坐实的 AI 代码统计 report 链。这个分支这次又多了三组很关键的静态证据。

先是 report 生成参数对象：

- `aicodestats.AICodeChangeParams`
  - `ChangeID`
  - `Scenario`
  - `Product`
  - `Action`
  - `ModelLevel`
  - `CreatedAt`
- `aicodestats.AICodeCommitParams`
  - `RepoName`
  - `BranchName`
  - `Product`
  - `Message`
  - `CommitTs`
  - `CreatedAt`

同时还出现了两个函数签名类型：

- `func(*aicodestats.AICodeChangeParams) *aicodestats.AICodeChangeReport`
- `func(*aicodestats.AICodeCommitParams) *aicodestats.AICodeCommitReport`

虽然 `goresym` 没把这两个函数类型的具体函数名一起还原出来，但它至少表明：

- `AICodeChangeReport`
  - 并不是只靠 `UserQueryAIStats` 这一个聚合对象隐式长出来
  - 中间还存在一层显式的 report params
- `AICodeCommitReport`
  - 也是类似
  - 其上报前对象至少拆成“统计结果 + 报告元数据参数”两层

更关键的是，这次二进制里已经明确出现：

- `[]aicodestats.AICodeCommitReport`

而且函数区里刚好有：

- `cosy/tracker.reportAICodeCommit`
- `cosy/tracker.buildCommitItemsJSON`
- `cosy/tracker.extractRepoName`

这一组证据放在一起以后，静态上最强的推断已经变成：

- commit 统计这一路
  - 先生成 `AICodeCommitReport`
  - 然后 `tracker.buildCommitItemsJSON`
    - 很可能把 `[]AICodeCommitReport` 或与之极近的对象切片组装成 JSON items
  - 最后再进入 `tracking?Encode=1` 的批量包

反过来说，目前还没有找到同等强度的：

- `[]aicodestats.AICodeChangeReport`
- 或 `buildChangeItemsJSON` 一类对称命名

因此对两条分支的当前把握应该区分开：

- `commit report` 分支
  - 静态证据更强
  - 已经基本收敛到“report 切片 -> items JSON -> tracking 批量发送”
- `change report` 分支
  - 目前只确认到 `ToAICodeChangeReport` 和 `AICodeChangeParams`
  - 但其外层批量容器还没像 commit 分支那样露出明确 builder

这也让 `tracking` 的上层模型需要再修正一次：

- 不是单纯“若干事件名 + 参数”
- 也不应简单压扁成“只有一类 AI 代码统计 report”
- 更像至少并行承载：
  - 一类通用 `eventType/eventData` 事件对象
  - 一类 `aicodestats` 派生出的 change/commit report 对象
- 只是这两类对象最终是否在同一个最外层 JSON envelope 中混装
  - 目前还没有明文字段名能完全坐实

### 多个 `ai_tracker` 目录已被再次核对，当前现场仍支持“flush 后清空队列”

这一步没有拿到新的残留文件，但把“空目录并非偶发”又验证了一遍。

实际定位到的 `ai_tracker` 目录包括：

- `capture/workdir-18080/cache/ai_tracker`
- `capture/workdir-body-20260424-222313/cache/ai_tracker`
- `capture/workdir-clone-20260424-235500/cache/ai_tracker`
- `capture/workdir-frida-20260424-214327/cache/ai_tracker`
- `capture/workdir-frida-20260424-214357/cache/ai_tracker`
- `capture/workdir-loginbody-20260424-222716/cache/ai_tracker`
- `capture/workdir-loginseed-20260424-222811/cache/ai_tracker`
- `capture/workdir-proxynofrida-20260424-224555/cache/ai_tracker`
- `capture/workdir-proxynofrida-20260424-233125/cache/ai_tracker`
- `capture/workdir-proxynofrida-20260424-235210/cache/ai_tracker`
- `capture/workdir-proxyseed-20260424-223925/cache/ai_tracker`
- `C:\Users\Zipper\.lingma\cache\ai_tracker`
- `C:\Users\Zipper\AppData\Local\.lingma\ai_tracker`

而对其中几组关键目录再次递归查看时：

- `capture/workdir-clone-20260424-235500/cache/ai_tracker`
- `capture/workdir-proxynofrida-20260424-224555/cache/ai_tracker`
- `capture/workdir-body-20260424-222313/cache/ai_tracker`
- `C:\Users\Zipper\.lingma\cache\ai_tracker`
- `C:\Users\Zipper\AppData\Local\.lingma\ai_tracker`

当前都没有可见残留文件。

所以这个点现在可以保守但明确地写成：

- `ai_tracker` 的确是 `tracker` 的独立落盘区
- 但从当前现场看
  - 它更像短生命周期队列或中间缓存
  - 成功 flush 后内容会被快速清空
- 因而单靠事后磁盘取证
  - 很难直接还原 `tracking` 最外层 envelope
  - 后续如果要再前进一步，仍然更适合走运行时 插桩观察
    - 抓 `buildCommitItemsJSON`
    - 或抓 `Encode=1` 之前的上层对象

### 真实 `Lingma.exe` 的 JSON tag 字面量又把 `tracking` 上层 schema 往前钉了一步

这一步不再只依赖 `goresym`，而是直接对本机安装的主程序二进制做 tag 提取。

实际命中的程序路径是：

- `C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe`
  - `Length = 102532096`
  - `LastWriteTime = 2026-04-17 21:24:17`

同时把其中抽出的 `json:"..."` tag 落成了一个可复用快照：

- `capture/extracted-json-tags-2.11.1.txt`

这里最关键的不是“某一个字段”，而是字段族本身已经明显分成了两套命名风格。

第一套偏通用事件对象：

- `json:"event"`
- `json:"event_data"`
- `json:"event_time"`
- `json:"event_type"`
- `json:"eventData"`
- `json:"eventType"`
- `json:"request_id"`
- `json:"requestId"`
- `json:"events"`
- `json:"report"`

第二套则明显贴近前面已经拼出来的 `aicodestats` / commit-change report 语义：

- `json:"change_id"`
- `json:"commit_hash"`
- `json:"commit_id"`
- `json:"commit_message"`
- `json:"commit_ts"`
- `json:"repo_name"`
- `json:"branch_name"`
- `json:"product"`
- `json:"product_breakdown"`
- `json:"scenario"`
- `json:"scenario_breakdown"`
- `json:"original_commit_ids"`
- `json:"parent_commit_ids"`
- `json:"ai_lines_added"`
- `json:"ai_lines_deleted"`
- `json:"created_at"`
- `json:"createdAt"`

以及本地采集入口相关字段：

- `json:"workspace_path"`
- `json:"workspacePath"`
- `json:"session_id"`
- `json:"sessionId"`
- `json:"task_id"`
- `json:"taskId"`
- `json:"file_path"`
- `json:"fileChanges"`
- `json:"file_changes"`

这一轮最重要的新增约束有三条：

- 第一，`eventType/eventData/requestId/events/report`
  - 这组字段不仅存在于 `goresym` 的 typed handler 还原里
  - 也真实存在于最终程序二进制的 JSON tag 字面量中
- 第二，`change_id/commit_ts/repo_name/product_breakdown/scenario_breakdown/original_commit_ids/...`
  - 同样真实存在于主程序二进制中
  - 说明前面拼出来的 change/commit report 不是纯推测命名
- 第三，二者并存
  - 进一步支持 `tracking` 上层不是单一 schema
  - 更像至少并行容纳：
    - 一类通用事件对象
    - 一类 change/commit report 对象

需要严格保留的边界仍然是：

- 现在还没有直接抓到“最外层容器字段名”
  - 例如是否真有 `events` 数组、是否还有 `reports` 数组、两类对象是否混装
- 但真实二进制 tag 已经把“至少存在两套上层字段族”这件事从符号推断推进成了程序字面量证据

### 两次大 `tracking` 包的 16 字符窗口重合度很高，但与聊天主请求几乎不重合

在继续往“最外层 envelope”逼近之前，我又补了一层纯样本统计，用来判断 `tracking` 这类 `Encode=1` body 到底是不是“同一种内部模板”，以及它与聊天主链到底有多接近。

样本仍然取自已经抓到的两次大包：

- `capture/lingma-http-capture-proxynofrida-20260424-224555.jsonl`
  - `POST /algo/api/v1/tracking?Encode=1`
  - `body_len = 18152`
- `capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl`
  - `POST /algo/api/v1/tracking?Encode=1`
  - `body_len = 18232`

先看最直观的前后缀：

- 两个 `tracking` body 的公共前缀长度为 `0`
- 公共后缀长度为 `1`

也就是说，这两次大包虽然体积接近、都属于同一个 `tracking` endpoint，但外层装甲后的字符串开头和结尾几乎完全不同。这一点很重要，因为它说明：

- 不能把“看起来前缀不同”直接理解成“内部 schema 不同”
- `Encode=1` 这一层很可能叠加了某种会扰动整体位置分布的按请求变化因子
  - 例如随机盐、nonce、分段偏移、会话相关扰动或同类机制

但如果换成更稳健的内部相似度指标，看结果就完全不一样了。对两次 `tracking` body 分别取所有 16 字符滑动窗口后：

- 第一个样本的唯一 16 字符窗口数：`9407`
- 第二个样本的唯一 16 字符窗口数：`9322`
- 交集：`3943`
- Jaccard 相似度：`0.2667`

而且交集里直接就能看到大量前面反复出现过的 tracker 特征片段，例如：

- `IIVRVkx,BrBEdYu(`
- `NZKbDZFMJgWwmxdL`
- `dLBMn*uHLhD(.iB*`

这个量级已经足够说明：

- 尽管外层装甲让前后缀几乎失去可比性
- 两次 `tracking` 大包内部仍然共享大量稳定子结构
- 所以它们更像“同一种 tracker/report 批量模板在不同请求实例下的两个样本”
  - 而不是两个完全不同的上层协议偶然都走到了 `tracking`

再把它和同一批流量采集中的聊天主请求做对照。以 `capture/lingma-http-capture-proxynofrida-20260424-235500.jsonl` 中首个 `agent_chat_generation` body 为例：

- `tracking` body 长度：`18232`
- `agent_chat_generation` body 长度：`11592`
- `tracking` 唯一 16 字符窗口数：`9322`
- `agent_chat_generation` 唯一 16 字符窗口数：`11275`
- 二者窗口交集：`208`
- Jaccard 相似度仅 `0.0102`

这个对照非常关键，因为它把前面的定性判断又收紧了一步：

- `tracking` 与 `agent_chat_generation`
  - 虽然都走 `Encode=1` 的可打印装甲层
  - 但内部稳定片段族几乎不是一回事
- 因而 `tracking` 不是“聊天主请求的放大版”或“只是在主链 body 外面再包一层”
- 更符合此前已经建立的模型：
  - `tracking` 走独立 `tracker` 模块
  - 上层承载的是 event/report/aicodestats 一类对象
  - 然后再统一经过另一套 `Encode=1` 装甲输出

到这一步，可以把结论更新成更精确的表述：

- `tracking` 的外层编码实例之间
  - 可能存在强烈的按请求扰动
  - 所以前后缀不稳定
- 但 `tracking` 内部仍然存在稳定而可重复的子结构族
  - 且这种稳定性远高于它和聊天主请求之间的相似度
- 这进一步支持：
  - `tracking` 是独立的 tracker/report 批量通道
  - 不是聊天主链 remoting body 的简单变体

### 真实二进制里又出现了一个更紧的 commit 打包局部簇，而 change 分支仍然没有对称命名

这一步我不再只看 `goresym` 的函数表，而是直接在真实安装的：

- `C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe`

里做了 ASCII 精确命中，再检查命中点附近的字符串邻域。结果对 commit 分支非常有价值。

首先，`buildCommitItemsJSON` 在主程序二进制中的精确命中偏移是：

- `63978332`

而它附近一个非常紧的局部簇依次出现：

- `cosy/tracker.reportAICodeCommit`
- `cosy/tracker.reportAICodeCommit.func1`
- `cosy/tracker.buildCommitItemsJSON`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.WrapAICodeCommitReport`
- `cosy/tracker.extractRepoName`

这里最关键的新点不是“又看到了 builder 名字”，而是：

- `WrapAICodeCommitReport`
  - 现在已经在真实二进制里被精确命中
  - 并且它不是散落在远处
  - 而是直接挨在 `buildCommitItemsJSON` 和 `reportAICodeCommit` 一起

这会把 commit 分支的静态链路再往前收紧一步：

- `CommitAIStats`
  - 先通过 `ToAICodeCommitReport`
    - 变成 `AICodeCommitReport`
- 然后至少还存在一个显式的 `WrapAICodeCommitReport`
  - 很可能负责把 report 变成更接近发送器需要的包装对象
- 再进入 `buildCommitItemsJSON`
- 再由 `reportAICodeCommit` 送往 `tracking`

这里仍然要保留边界：

- 还没有直接抓到 `WrapAICodeCommitReport` 的函数体或返回结构
- 所以不能把它写死成“最外层 envelope builder”
- 但它与 `buildCommitItemsJSON/reportAICodeCommit` 的局部共现
  - 已经显著强于此前单靠函数名顺序做推断

第二个关键点是，change 分支目前依然没有出现对称的命名证据。

在 `goresym` 和真实二进制的精确搜索中，目前确认：

- 存在：
  - `reportAICodeCommit`
  - `buildCommitItemsJSON`
  - `WrapAICodeCommitReport`
- 未命中：
  - `reportAICodeChange`
  - `buildChangeItemsJSON`
  - `WrapAICodeChangeReport`

这意味着前面“commit 分支证据强于 change 分支”的判断现在可以写得更明确：

- `commit report` 分支
  - 已经出现：
    - `ToAICodeCommitReport`
    - `AICodeCommitReport`
    - `WrapAICodeCommitReport`
    - `buildCommitItemsJSON`
    - `reportAICodeCommit`
  - 因而静态上已经非常接近一条完整的“report -> wrap -> items JSON -> tracking”打包链
- `change report` 分支
  - 仍然只稳定看到：
    - `ToAICodeChangeReport`
    - `AICodeChangeReport`
  - 但还没有出现同等强度的 wrapper / builder / sender 命名

第三个补充约束也很重要：`items` 和 `events` 这两个字段名虽然在真实二进制里能精确命中，但当前命中点看起来都不属于 tracker commit 簇。

精确命中结果里：

- `json:"items"`
  - 落在一组更泛用的分页/列表类字段附近：
    - `title`
    - `scope`
    - `stage`
    - `items`
    - `total`
    - `order`
    - `level`
- `json:"events"`
  - 落在一组更像 diff/edit 结构的字段附近：
    - `origin`
    - `target`
    - `events`
    - `oldUri`
    - `newUri`
    - `fixEnd`
    - `chunks`

而且对真实二进制做 ASCII 精确匹配时：

- `json:"report"`
  - 当前没有命中完整字面量

因此这一轮需要把措辞再收紧一次：

- `items/events/report`
  - 仍然可以作为 `tracking` 最外层可能字段族的候选
  - 但当前还不能把它们当成 `buildCommitItemsJSON` 这条 commit 打包链的直接局部证据
- 与之相对，
  - `WrapAICodeCommitReport + buildCommitItemsJSON + reportAICodeCommit`
  - 现在已经是更强、且更集中于 commit 上报链的真实二进制局部簇证据

第四个新约束需要收紧表述：至少有一部分 commit 语义字段在真实二进制里同时出现了 `camelCase` 和 `snake_case` 两套 JSON tag，但并不是每个同名字段都能直接归到 `tracking` commit 分支。

精确命中结果包括：

- `json:"parentCommitIds,omitempty"`
  - `33686538`
- `json:"parent_commit_ids,omitempty"`
  - `33703824`
- `json:"originalCommitIds,omitempty"`
  - `33719403`
- `json:"original_commit_ids,omitempty"`
  - `34132140`
- `json:"repoName"`
  - `33245930`
- `json:"repo_name"`
  - `33287640`
- `json:"commitTs"`
  - 当前未命中
- `json:"commit_ts"`
  - `33287667`

但把这些命中点各自放回局部邻域后，强弱要区分开看。

更强、且明显贴近 `ai-code-commit-tracker` / report 链的，是：

- `json:"parentCommitIds,omitempty"`
  - 邻域里直接出现：
    - `code.alibaba-inc.com/cosy/ai-code-commit-tracker`
- `json:"parent_commit_ids,omitempty"`
  - 邻域里仍然贴着：
    - `*map.bucket[string]*aicodestats.UserQueryFileStats`
- `json:"originalCommitIds,omitempty"`
  - 邻域里直接贴着：
    - `*func(string) (*aicodestats.UserQueryAIStats, error)`
- `json:"original_commit_ids,omitempty"`
  - 当前邻域虽更短，但至少保持在前面已经确认过的 commit report 字段区附近

相对较弱、当前不能直接归入 `tracking` commit 上报链的，是：

- `json:"repoName"`
  - 命中点附近是：
    - `RepoType`
    - `*longruntask.TaskRuntime`
    - `*longruntask.PullRequest`
    - `*longruntask.TaskVersion`
    - `*longruntask.BuildStatus`
    - `*longruntask.PortForward`
  - 这一簇目前看起来更像另一套 `longruntask` 结构
  - 不能直接拿它去证明 `tracking` commit 分支里也存在 `repoName -> repo_name` 对应关系
- `json:"commitTs"`
  - 当前还没有命中

因此，这一轮更稳妥的说法应该是：

- 至少对 `ParentCommitIds / OriginalCommitIds` 这一组 commit 语义字段来说
  - 进程内部很可能并行存在：
    - 一套偏内部/中间层的 `camelCase` 对象
    - 一套更贴近最终 report/wire 的 `snake_case` 对象
- 但对 `RepoName / CommitTs` 这类字段
  - 当前还不能因为出现了单个 `repoName` 命中
  - 就把它也直接并入同一条转换链

把这一点和上面的局部函数簇放在一起看，commit 分支现在更像：

- 先在内部对象层保留至少部分 `camelCase` 语义结构
  - 当前证据最强的是 `ParentCommitIds / OriginalCommitIds`
- 再经过 `ToAICodeCommitReport / WrapAICodeCommitReport`
  - 转成更接近发送侧的 report/wire 结构
- 再由 `buildCommitItemsJSON` 统一装配
- 最终进入 `tracking`

当然，这里仍然不能写死每一套字段各自对应哪个确切 struct，但至少对 `parent/original commit ids` 这组字段来说，“内部对象层与最终上报层之间存在显式转换”已经比此前更像真实程序结构，而不是文档化想象。

### `tracking` 的 commit 分支现在更像“三段式静态链”，`WrapAICodeCommitReport` 正好卡在中间桥接点

继续把真实二进制的精确命中点串起来后，commit 分支的静态结构已经不太像“一个包里一路做完”，而更像三段相对分离的区域。

第一段是 `ai-code-commit-tracker` 自己的聚合/验证区。围绕真实二进制偏移 `63969024` 到 `63970454`，已经能看到一整段连续的 package 局部簇：

- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*CommitAIStats).ToAICodeCommitReport`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.newServiceInternal`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.NewHybridBaselineProvider`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.NewRecorder`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.NewVerifier`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*service).RecordAIModification`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*service).getOriginalCommitIds`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*service).mergeWithOriginalRecords`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*service).mergeBreakdown`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*service).mergeFileStats`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*service).CleanupRecords`

这段非常关键，因为它说明：

- `CommitAIStats`
  - 不是一个孤立的数据结构名
  - 它背后确实有一套 service 逻辑在做：
    - `RecordAIModification`
    - `getOriginalCommitIds`
    - `mergeWithOriginalRecords`
    - `mergeBreakdown`
    - `mergeFileStats`
- 所以“内部对象层”现在可以更具体地落在：
  - `ai-code-commit-tracker.(*service)` 这一段聚合/合并逻辑

第二段是更偏类型/签名元数据区，而不是业务发送区。真实二进制里目前至少有两组点属于这一层：

- 偏移 `33142030` 邻域：
  - `ToAICodeCommitReport`
  - `ToAICodeChangeReport`
  - `*aicodestats.Service`
  - `*aicodestats.service`
  - `*aicodestats.Storage`
  - `getOriginalCommitIds`
- 偏移 `33435641` / `33435674` 邻域：
  - `*aicodestats.AICodeCommitParams`
  - `*aicodestats.AICodeCommitReport`
  - `*aicodestats.UserQueryFileStats`
  - `*aicodestats.AICodeChangeParams`
  - `*aicodestats.AICodeChangeReport`
- 偏移 `34533385` 邻域：
  - `func(*aicodestats.AICodeCommitParams) *aicodestats.AICodeCommitReport`
  - `func(*aicodestats.AICodeChangeParams) *aicodestats.AICodeChangeReport`

这一层说明：

- 程序里不仅有最终的 `AICodeCommitReport` 类型名
- 还显式存在：
  - `AICodeCommitParams`
  - `AICodeCommitReport`
  - `AICodeCommitParams -> AICodeCommitReport` 的函数签名
- 所以在聚合层和发送层之间
  - 很可能确实隔着一个“显式 report params / report object”层

第三段才是 `tracker` 的打包/发送区，也就是前面已经拿到的 `63978249` 到 `63978425` 那个局部簇：

- `cosy/tracker.reportAICodeCommit`
- `cosy/tracker.reportAICodeCommit.func1`
- `cosy/tracker.buildCommitItemsJSON`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.WrapAICodeCommitReport`
- `cosy/tracker.extractRepoName`

把这三段放在一起以后，当前最稳的静态模型已经可以升级成：

1. `ai-code-commit-tracker.(*service)`
   - 负责从本地记录里做 commit 维度聚合、回溯和 merge
   - 形成 `CommitAIStats` 一类内部统计对象
2. `(*CommitAIStats).ToAICodeCommitReport`
   - 把内部统计对象转成 `AICodeCommitReport`
   - 这一步旁边还存在 `AICodeCommitParams -> AICodeCommitReport` 的显式函数签名
3. `WrapAICodeCommitReport`
   - 很可能把 report 再包装成更接近发送器需求的对象
4. `buildCommitItemsJSON`
   - 把包装后的 commit item 集合拼成发送前 JSON
5. `reportAICodeCommit`
   - 把这批 item 送到 `tracking`

这里 `WrapAICodeCommitReport` 的位置现在特别重要，因为它刚好把第二段和第三段接上了：

- 它不在纯聚合 service 簇里
- 也不只是孤立出现在类型元数据区
- 而是直接挨着 `buildCommitItemsJSON/reportAICodeCommit`

所以现在对它最稳的定位不是“最终 envelope builder”，而是：

- commit report 从 `aicodestats` report 形态进入 `tracker` sender 形态的桥接器

这一步的收获不是拿到了最终 JSON 明文，而是把“commit 分支确实跨越了聚合层、report 层、sender 层”这件事，已经从单点命名推断推进成了多簇局部共现证据。

### `ai-code-commit-tracker` 包内部至少还能坐实本地 `AICodeCommitParams` 层，但 `63978406` 不能再当独立 report 命中

这一步主要是做两件事：

- 把上一轮里几个容易误读的命中点再校正一次
- 看 `ai-code-commit-tracker` 包内部到底有没有自己持有 `AICodeCommitParams / AICodeCommitReport / CommitAIStats` 这些本地类型名

先说需要纠偏的点。前面有一个 `AICodeCommitReport` 命中偏移：

- `63978406`

这次把它居中展开后可以确认，附近只有：

- `cosy/tracker.buildCommitItemsJSON`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.WrapAICodeCommitReport`
- `cosy/tracker.extractRepoName`

也就是说，`63978406` 本质上只是：

- `WrapAICodeCommitReport`
  - 这个函数名内部的子串命中

因此这里必须明确修正：

- `63978406`
  - 不能再被当成“独立的 `AICodeCommitReport` 类型命中点”
- 它只证明：
  - `WrapAICodeCommitReport` 这个桥接函数名真实存在于 sender 簇里
- 不证明：
  - `AICodeCommitReport` 类型本身也完整落在 `tracker` sender 簇里

反过来，这一轮真正新增的有效证据在 `63976516` 这一带。

围绕 `63976574` 这个 `AICodeCommitParams` 命中点，邻域里能看到：

- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*Verifier).mergeFileAIStats`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*Verifier).supplementDeletedLinesFromModifications`
- `code.alibaba-inc.com/cosy/ai-code-commit-tracker.(*Verifier).filterValidDeletedLines`
- `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.AICodeCommitParams`
- `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.AICodeChangeParams`
- `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.AICodeChangeFileReport`
- `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.VerifyParams`
- `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.Storage`
- `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.Recorder`
- `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.Verifier`

而对这些更严格的精确搜索中，目前确认：

- 命中：
  - `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.AICodeCommitParams`
- 未命中：
  - `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.AICodeCommitReport`
  - `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.CommitAIStats`
  - `type:.eq.code.alibaba-inc.com/cosy/ai-code-commit-tracker.AICodeChangeReport`

这组结果说明两件事。

第一，`ai-code-commit-tracker` 包内部至少明确持有：

- 本地 `AICodeCommitParams`
- 本地 `AICodeChangeParams`
- 本地 `AICodeChangeFileReport`
- 以及 `Verifier / Recorder / Storage / VerifyParams` 这组 verifier 相关类型

也就是说，前面“聚合层和 report 层之间隔着一层显式 params 对象”这件事，现在不只是全局类型表里有名字，而是已经能看到：

- 这一层确实落在 `ai-code-commit-tracker` 包内部的 verifier/type 簇里

第二，当前还不能因为存在本地 `AICodeCommitParams`，就自动推出：

- 本地 `AICodeCommitReport`
  - 也以同样的 `type:.eq...` 形式出现在这一簇

所以对“三段式静态链”还要再补一个更细的修正：

1. `ai-code-commit-tracker.(*service)` / `(*Verifier)`
   - 负责聚合、校验、merge，并且持有本地 `AICodeCommitParams` 这类中间层类型
2. `(*CommitAIStats).ToAICodeCommitReport`
   - 再把内部统计对象推进到 `AICodeCommitReport`
3. `WrapAICodeCommitReport`
   - 把 report 进一步桥接进 sender 所需形态
4. `buildCommitItemsJSON`
   - 统一装成发送前 JSON
5. `reportAICodeCommit`
   - 最终送往 `tracking`

这一版模型比上一轮更稳，因为它去掉了一个可能误导的点：

- 不再把 sender 簇中的 `AICodeCommitReport` 子串误当作独立类型证据

同时又补上了一个更强的点：

- `ai-code-commit-tracker` 包内部确实已经坐实存在 `AICodeCommitParams` 这一层本地类型
