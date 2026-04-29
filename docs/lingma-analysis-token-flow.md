# Lingma Token、登录态与模型刷新链

> 编辑说明（2026-04-27）：
> 这份文件聚焦登录态、用户态落盘和模型刷新链。
> 如果你要看“当前远端直连是否已经成立”，请优先看 `docs/lingma-analysis-final-status.md` 和 `docs/remote-api-direct-connection.md`。

更新时间：2026-04-24

## 适合什么时候看

当你要回答下面这些问题时，看这份文档：

- 登录成功后到底拿到了什么票据
- `securityOauthToken` 和标准 `token` 是什么关系
- `syncUserInfo`、`refreshToken` 怎么分层
- 本地用户态落在哪里
- 模型列表和登录态是怎么接起来的

相关文档：

- 总览入口：[lingma-analysis-overview.md](./lingma-analysis-overview.md)
- 本地服务与签名边界：[lingma-analysis-endpoint-auth.md](./lingma-analysis-endpoint-auth.md)
- 完整时间线：[lingma-analysis-snapshots.md](./archive/lingma-analysis-snapshots.md)

## 高置信结论

### 1. 浏览器回调页面拿到的核心票据是 `securityOauthToken`

从 `callback.html` 已能直接确认：

- `window.user_info.securityOauthToken`
- `window.user_info.refreshToken`
- `window.user_info.expireTime`

而 `window.user_info.authStatus` 内的：

- `token = ""`
- `refreshToken = ""`
- `expireTime = 0`

因此当前最稳结论是：

- 页面层真实拿到的核心票据是：
  - `securityOauthToken`
  - `refreshToken`
  - `expireTime`
- 不是 `authStatus.token`

### 2. 本地服务内部至少存在两层 token 结构

#### OAuth 安全票据层

- `SecurityOauthToken`
- `RefreshToken`
- `TokenExpireTime`

#### 标准 token 层

- `Token`
- `RefreshToken`
- `ExpiresIn`
- `ExpireTime`
- `UserID`
- `Username`

这说明：

- callback 成功后，本地服务内部至少存在一次 token 转换或同步
- `securityOauthToken` 与最终远端请求使用的标准字段不是同一层对象

## 登录回调与用户态同步

### callback 输入不是明文 bearer

本地 callback handler 的输入结构已经能看到：

- `Nonce`
- `Auth`
- `TokenString`

这与浏览器回调 URL 中的：

- `state=<nonce>`
- `auth=<encoded>`
- `token=<encoded>`

一一对应。

当前结论：

- callback URL 中的 `auth/token` 更像内部编码载荷
- 本地服务会把它们转换为后续真正使用的 token 结构

### `syncUserInfo` 更靠近“安全票据入本地用户态”

当前已经能坐实：

- `auth/syncUserInfo`
- `SyncUserInfoHandler`
- `doSyncUserInfoForSave`
- `validateOauthTokens`
- `doSyncUserInfoForUpdate`
- `postSyncUserInfoSuccess`

`syncUserInfo` 的已知入参与返回：

- 入参：
  - `SecurityOauthToken`
  - `RefreshToken`
  - `TokenExpireTime`
- 返回：
  - `Success`
  - `Uid`
  - `Name`
  - `TokenExpireTime`

因此当前更合理的链路是：

1. 页面层拿到 `securityOauthToken + refreshToken + expireTime`
2. 本地服务以这组三元组调用 `auth/syncUserInfo`
3. 本地用户态被保存或更新
4. 后续模型链路建立在这层本地用户态之上

### `refreshToken` handler 更靠近标准 token 续期

本地二进制里还存在另一套 handler：

- `auth/refreshToken`
- `RefreshTokenHandler`

已知结构：

- 入参：
  - `Token`
  - `RefreshToken`
  - `ExpiresIn`
  - `ExpireTime`
  - `UserID`
  - `Username`
- 返回：
  - `Success`
  - `ErrorCode`
  - `ErrorMsg`

当前结论：

- `syncUserInfo` 与 `refreshToken` 不是同一层职责
- 更合理的理解是：
  - `syncUserInfo` 负责登录成功后的安全票据同步
  - `refreshToken` 负责进入标准 token 结构后的续期链路

## 本地用户态落盘

### 已确认现象

成功登录窗口内，历史日志已出现：

1. `Deleted user info file.`
2. `Opening browser to login`
3. `config/changeEndpoint`
4. `model/refresh`
5. `config/refreshModels`
6. `auth/report`

同时：

- `/Users/Zipper/.lingma/cache/user`
  - 修改时间会刷新

### 当前落盘判断

- `/Users/Zipper/.lingma/cache/user`
- `/Users/Zipper/.lingma/cache/quota`

这两个文件都能 base64 解码，但内容是加密二进制块，不是明文 JSON。

因此当前最稳判断是：

- 活跃用户态主要落在本地缓存文件
- 但不是可直接读取的明文 token JSON

### 当前没有看到进入 SQLite `supabase_token`

本机数据库：

- `/Users/Zipper/.lingma/cache/db/local.db`

当前 `supabase_token` 表行数仍为 `0`。

因此当前可以确认：

- 这条主登录链路拿到的 `securityOauthToken/refreshToken` 没有直接写进该表
- `supabase_token` 更可能属于另一条集成链路

### 2026-04-24 Windows 当前样本补证

这轮又直接检查了当前 Windows 安装态的：

- `C:\Users\Zipper\.lingma\cache`
- `C:\Users\Zipper\.lingma\vscode\sharedClientCache\cache`
- `C:\Users\Zipper\.lingma\logs\lingma.log`
- `C:\Users\Zipper\.lingma\cache\db\local.db`

当前看到的结果和前面的 macOS / 调试 workDir 样本并不完全相同：

- 主目录 `C:\Users\Zipper\.lingma\cache` 下当前只有：
  - `db/`
  - `policy`
  - `diagnosis*.bin`
- 没有直接看到：
  - `cache/user`
  - `cache/id`
  - `cache/quota`
- `vscode/sharedClientCache/cache` 下还能看到：
  - `id`
  - `db/local.db`
  - `policy`
  - `config.json`
- 但这里同样没有看到：
  - `user`
  - `quota`

结合日志：

- `Initializing database with path: C:\Users\Zipper\.lingma\cache\db\local.db`
- `No cached user info, please login.`
- `Deleted user info file.`

当前更合理的判断是：

- 这台 Windows 当前样本处在“用户态已清空或当前未缓存活跃 user info”的状态
- 因而不能把“这台机器当前没有 `cache/user` 文件”直接外推成所有平台、所有时刻都没有这类文件
- 更稳的说法应改成：
  - `cache/user/id/quota` 那套持久化链已经在其他调试样本里被坐实
  - 但当前这份 Windows 安装态样本只直接保留了 `local.db`、`policy`、`diagnosis` 和一份旧的 `sharedClientCache/cache/id`

对数据库本身再做只读检查后，当前样本还能补两条边界：

- `C:\Users\Zipper\.lingma\cache\db\local.db`
  - 存在 `supabase_token` 表
  - 但当前行数仍为 `0`
- 同一个 DB 中已经有业务数据：
  - `chat_session = 11`
  - `chat_record = 187`
  - `lingma_memory = 11`
  - `agent_memory = 17`

因此当前更稳的落盘结论应同时包含两层：

- 主登录链路的活跃用户态，没有在当前 Windows 样本里直接落成可见的 `supabase_token` 记录
- `local.db` 主要承载了聊天、memory、agent 侧业务数据；至少在这份样本里，它还不是恢复当前登录 token 的直接入口

## machine-info 与 UMID 对应关系

### 已直接坐实的映射

- 调试副本 `machine-info` 已直接返回：
  - `machineToken`
  - `machineType`
- 其中：
  - `machineToken = P1gAG8XThLpqoN1D9VBAianqTyCn_NlKvtCi1HElzeXUwNrQZds7HUev7PHb6ottSC5-7OX_2_uKmTanGDJZYbGX`
  - `machineType = 0a52ba2b917c062fa0`

### 与 `UMIDInterface.getSecurityToken:` 的对应

- 运行时直接调用 `UMIDInterface.getSecurityToken:` 已看到两类稳定值：
  - 长 token：
    - `P1gAG8XThLpqoN1D9VBAianqTyCn_NlKvtCi1HElzeXUwNrQZds7HUev7PHb6ottSC5-7OX_2_uKmTanGDJZYbGX`
  - 短 token：
    - `ZSN8xcjWeakhsg6VTRxoOVSivrpbIUfU`
- 当前最稳映射是：
  - `getSecurityToken(0/3/4/5)` 返回的长 token 与 `machine-info.machineToken` 完全一致
  - `getSecurityToken(1/2)` 返回的是另一类短 token

### 当前能下的工程判断

- `machineToken` 不是猜测字段，已经能和 native 运行时返回值一一对上。
- 但 `machineType` 当前还没看到通过 `StaticDataStoreInterface.getExtraData:error:` 这类简单 key 查询直接读出。
- 因而更合理的判断是：
  - `machineType` 仍可能来自 Go 侧机器态拼装
  - 不应假设它能直接从 `SecurityGuard` 的简单 KV 接口里读到
- 同时还可以再补一句边界：
  - 即使 `machine-info` 已能返回 `machineToken/machineType`
  - 当前真实流量采集里的远端请求头 `Cosy-MachineToken/Cosy-MachineType` 仍然始终为空
  - 因而不能把 `machine-info` 的输出简单等同于 HTTP 头最终出站值

## user/quota 缓存与实例级安全材料的关系

### 已确认的两组对照

- 同一个 `workDir`，只删 `cache/id`：
  - `Cosy-Key` 不变
  - `Authorization.info` 不变
- 同一个 `workDir`，删 `cache/user` 和 `cache/quota`：
  - `Cosy-Key` 改变
  - `Authorization.info` 也改变

### 当前最稳判断

- `cache/id` 不是决定 `info/Cosy-Key` 的唯一低成本入口。
- `cache/user/quota` 与 `info/Cosy-Key` 的生成或恢复过程存在更强相关。
- 因而当前更合理的工程判断是：
  - 这两个文件不只是“登录展示态缓存”
  - 它们更可能参与了实例级安全上下文的恢复、派生或密钥装载流程
- 进一步的对照也已确认：
  - 删除 `local.db`，但保留 `cache/user/quota`
  - `Cosy-Key` 与 `Authorization.info` 仍保持不变
- 这说明：
  - 当前不应把本地 DB 视为恢复这两类实例级安全材料的必要前提
  - 真正更值得优先追的是 `user/quota` 的解密与恢复链
- 再继续拆成单文件后，当前可以进一步收敛成：
  - 删除 `cache/user` 会让 `Cosy-Key` 与 `Authorization.info` 改变
  - 删除 `cache/quota` 不会让它们改变
- 因而当前最稳判断是：
  - `cache/user` 比 `cache/quota` 更接近实例级安全上下文的恢复源
  - 后续如果只选一条线继续追，应优先追 `cache/user`
- 恢复实验已经把这个判断再往前推了一步：
  - 将稳定实例的旧 `cache/user` 覆盖回 user-reset 实例后
  - `Cosy-Key` 与 `Authorization.info` 一起恢复到旧基线
- 因而当前更稳的结论是：
  - `cache/user` 已经从“高相关”升级为“关键入口”
  - 后续若继续协议研究，应优先围绕它的解密、校验与装载流程

### `cache/user` 的格式侧观察

- 直接对比稳定版与 user-reset 重新生成版 `cache/user`，当前看到：
  - base64 文本总长度相同：`1708`
  - base64 解码后的原始长度相同：`1280`
  - 前 `256` 个原始字节完全一致
  - 差异从偏移 `256` 开始
- 这说明：
  - `cache/user` 不是“全文件完全随机变化”的简单密文
  - 更像“固定头部 + 可变 payload”的容器
- 当前更合理的猜测是：
  - 前 `256` 字节更接近实例级固定材料或容器头
  - 后续变化部分更可能承载影响 `Cosy-Key/info` 的用户态或会话态内容

## `machineKey` 与 `cache/id` 的关系

### 已直接坐实的日志证据

- 故意把 `cache/user` 破坏成非法 base64 后，启动日志会出现：
  - `Unable to decrypt user info. Using machineKey: ...`
- 再进一步做对照：
  - 将 `cache/id` 人工改成：
    - `ZZZ-ZZZ-ZZZ-ZZZ-ZZZZZZZZZZZZ`
  - 保持非法 `cache/user`
  - 启动日志中的 `machineKey` 会同步变成：
    - `ZZZ-ZZZ-ZZZ-ZZZ-`

### 当前最稳判断

- `machineKey` 与 `cache/id` 存在直接对应关系。
- 从当前日志表现看：
  - `machineKey` 至少会吸收 `cache/id` 的前缀内容
  - 当前日志里暴露出来的是一个截断后的前缀，而不是完整 key 材料

### 与前面结论如何同时成立

- 删除 `cache/id` 不会让 `Cosy-Key/info` 改变，并不代表 `cache/id` 无关。
- 当前更合理的解释是：
  - `cache/id` 在删除后会按本机硬件特征重建成同一个值
  - 所以“删掉后重建”为同值，不会改变后续链路
  - 但“人工改成别的值”会立刻影响 `machineKey`

## `cache/user` 的解密结果

### 已直接跑通的解密方式

- 当前已用外部 `openssl` 跑通 `cache/user` 的稳定解密：
  - 算法：`AES-128-CBC`
  - key：`machineKey`
  - iv：`machineKey`
- 在当前样本里，实际可用的 `machineKey` 是：
  - `43303747-3630-49`

### 解密后的核心字段

- `cache/user` 解开后是 JSON，已直接看到这些关键字段：
  - `name`
  - `aid`
  - `uid`
  - `security_oauth_token`
  - `expire_time`
  - `key`
  - `encrypt_user_info`
  - `user_type`

### 与出站请求头的直接映射

- 当前已通过运行时替换实验坐实：
  - 明文里的 `key` 会直接进入出站头 `Cosy-Key`
  - 明文里的 `encrypt_user_info` 会直接进入 `Authorization` 中段 JSON 的 `info`
- 也就是说：
  - `cache/user.key == HTTP Cosy-Key`
  - `cache/user.encrypt_user_info == Authorization.info`

### 为什么这是关键突破

- 之前我们只能说 `cache/user` 与实例级安全材料“高度相关”。
- 现在已经能直接说：
  - 它就是 `Cosy-Key` / `Authorization.info` 的持久化来源
- 因而后续真正剩下的算法问题，已经收缩成：
  - `Authorization` 末尾 32 位 hex 怎么由这些输入再算出来

### `cache/user` 的混合实验

- 已做两组互补混合：
  - 前半段用稳定版、后半段用重生成版
  - 前半段用重生成版、后半段用稳定版
- 两组混合后的实例都会生成第三套新的：
  - `Cosy-Key`
  - `Authorization.info`
- 它们既不回到稳定版，也不等于重生成版。

当前更稳判断：

- `cache/user` 对实例级安全材料的影响不是“只看某一个简单尾部字段”。
- 至少从当前实验看，它更像跨多个区块共同参与派生。
- 因而若继续协议研究，不应假设存在“单个小字段直接等于 `Cosy-Key/info`”这种过度简化模型。

## miniWua 与 SecurityFactors 运行时探测

### `getMiniWua::` 已确认是活接口

- `SecurityFactors.getMiniWua::` 的 Objective-C 类型签名是：
  - `@32@0:8@16@24`
- 也就是说：
  - 它吃两个对象参数
  - 不走 `error*` 风格返回

### 已观察到的返回特征

- 对多组输入，`getMiniWua::` 都会快速返回大段 base64 blob。
- 这说明：
  - `miniWua` 不是静态常量
  - 它更像由输入上下文驱动的安全材料生成接口

### 当前仍未确认的点

- `miniWua` 是否直接进入：
  - `Cosy-Key`
  - `Authorization.info`
  - 还是 `Encode=1` 的 body 编码链
- 但至少当前已经可以确认：
  - `SecurityFactors` 这条链是活的
  - 后续若继续下钻，不该再把它当“纯字符串噪音”

## 模型列表刷新链

### 本地服务存在模型列表接口

当前已通过本地服务直接验证：

- `config/queryModels`

已知返回内容包括：

- `assistant/chat/developer/inline`
- `dashscope_qwen3_coder_default`
- `dashscope_qwen3_coder`
- `dashscope_qwen_plus_20250428_thinking`
- `dashscope_qwen_max_latest`

同时还能看到：

- `format = openai`
- `source = system`
- `isReasoning = true/false`

### 登录成功后会触发模型刷新

历史日志与运行链都支持以下判断：

- 登录成功后会触发：
  - `model/refresh`
  - `config/refreshModels`
- 因而模型列表不是静态写死在 plugin 里，而是依赖本地登录态和配置刷新

### plugin 选择模型时只传 `key`

当前已知现象：

- plugin 侧模型选择只传一个 `key`
- 本地数据库里还能看到历史 `model_key`

工程含义：

- plugin 层并不持有完整上游模型配置
- 真正的模型解析和远端路由仍然在本地服务里完成

## 本地 `37010` 聊天调用最小链

### 当前已登录 Windows 样本

到当前这轮补证为止，Windows 当前机器已经不再是早期“空 token”状态。

- `Lingma.exe status -o json --workDir C:\Users\Zipper\.lingma` 当前返回：
  - `logged_in = true`
  - `username = zhang640@blny.de`
- 本地 `37010` 的 `auth/status` 当前直接返回：
  - `status = 2`
  - `id = 5930676910898027`
  - `token = pt-5zmkcs3cUpPGP8FGb88WGkSJ`
  - `refreshToken = rt-gHWjpgS9NQ4TOhmtvmN55ELZ`
  - `userType = personal_standard`
  - `whitelist = 3`
  - `cloudType = cloud`

这说明：

- `device_login` 注入进去的用户态当前已经稳定落地到正式运行态
- `auth/status` 已经可以作为读取当前活跃本地用户态的标准程序接口

### 当前最小可用调用顺序

当前通过工作区里的：

- `tools/lingma_probe.py`

已经稳定复现下面这条顺序链：

1. `initialize`
2. `auth/status`
3. `config/queryModels`
4. `chat/ask`

其中当前更推荐在 `initialize` 里显式带上：

- `rootUri = file:///D:/Project/lingma`
- `workspaceFolders = [{uri,name}]`

否则日志里会出现：

- `get mtree failed: workspacePath is empty`

### `initialized` 当前不要再发

这轮补跑还确认了一条实现细节：

- 如果额外发送标准 LSP notification：
  - `initialized`
- Lingma 当前服务端会直接记录：
  - `unknown method: initialized`

因此当前更稳的结论是：

- transport 形状虽然像 LSP
- 但程序化使用时应该按 Lingma 自己暴露的方法集来走
- 不要把标准 LSP 生命周期步骤生搬硬套进去

### `chat/ask` 的最小可用参数

当前已直接跑通的一组参数是：

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

当前返回分成两层：

- 同步响应：
  - `success = true`
- 异步通知：
  - `chat/process_step_callback`
  - `chat/answer`

### `chat/answer` 是分片式文本流

这轮实际抓到的 `chat/answer.text` 片段是：

- `pon`
- ``
- `g`
- ``

拼接后得到：

- `pong`

因此当前最稳的协议理解是：

- `chat/ask` 只返回“请求已受理”
- 真正的回答正文要从后续多条 `chat/answer` 里拼接

### 与远端主链的关系

日志已经把这条本地链转发到远端哪一个接口补实了：

- `POST /algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1`

也就是说：

- 本地 `37010` 负责：
  - 本地鉴权态承接
  - 模型注册表
  - 请求接入
  - 回包通知
- 真正远端生成仍然走：
  - `agent_chat_generation`

所以如果目标是：

- “从本地程序外部拿到一条可用的大模型访问路径”

当前最稳答案已经不是：

- 直接自己打远端 HTTP

而是：

- 复用本地 `37010`，按本地协议消费 `chat/answer` 流

## 与远端请求的边界

### 已经确认的部分

- `securityOauthToken` 会进入本地用户态同步
- 标准 `token` 可通过 `auth/status` 从本地服务读出
- `config/queryModels` 可从本地服务读出模型注册表
- `chat/ask` 可直接触发真实聊天链路

### 当前仍未确认的部分

- 标准 `token` 是否直接等于远端请求中的最终 `Authorization`
- `securityOauthToken` 到最终 bearer 的精确映射关系
- token 与机器态、签名态如何组合成远端请求头

## 隔离 endpoint 流量采集后的头字段关系补证

### 当前已经把 bearer 中段 JSON 直接解开

这轮通过隔离 endpoint 流量采集后，已经能直接从真实远端请求头里把：

- `Authorization: Bearer COSY.<base64-json>.<32hex>`

中的中段 JSON 解出来。

当前直接读到的字段是：

- `cosyVersion = 2.11.1`
- `ideVersion = ""`
- `info = ...`
- `requestId = ...`
- `version = v1`

这说明当前远端 bearer 至少不是“单个 token 原样透传”，而是：

- 固定结构前缀 `COSY`
- 中段 JSON
- 尾部 32 位 hex 校验/签名片段

### `info` 与 `Cosy-Key` 在同一实例里稳定，`requestId` 每请求变化

结合 `capture/lingma-http-capture.jsonl` 里这轮抓到的多条请求，当前已经能直接对出：

- `infoLen = 664`
- `infoSha256` 前 16 位稳定为：
  - `4a6f229b26eb37b4`
- 同一隔离实例的所有 bearer 中：
  - `info` 不变
  - `Cosy-Key` 不变
- 但每条远端请求都会重新生成：
  - bearer 中段里的 `requestId`
  - bearer 尾 32 位 hex

这和前面已经坐实的持久化映射能严丝合缝接上：

- `cache/user.key == HTTP Cosy-Key`
- `cache/user.encrypt_user_info == Authorization.info`

也就是说当前最稳的链路已经收紧成：

- `cache/user`
  - 至少能恢复 `Cosy-Key`
  - 至少能恢复 bearer 中段 JSON 的 `info`
- 但还不能仅凭这些材料直接算出：
  - bearer 尾 32 位 hex

### `chat/ask.requestId` 与 `bearer.requestId` 不是同一个字段

这轮隔离流量采集把一个之前容易混淆的点彻底拆开了。

对聊天主链：

- 本地 `chat/ask.params.requestId`
  - 当前直接进入远端头：
    - `X-Request-Id`
- bearer 中段 JSON 里还有另一条：
  - `requestId`

两者当前已直接观察到：

- `X-Request-Id = 601e8990a5db44b4ba94aff7192cf64a`
  - 可在同一聊天链的多次远端重试中保持不变
- bearer 中段 `requestId`
  - 每次重试都会变成新的 UUID

因此当前更稳的协议判断是：

- 本地聊天会话级 request id
  - 对应远端 `X-Request-Id`
- 远端签名/鉴权链内部
  - 还会再生成一个独立的 bearer request id

### token 仍不足以脱离 Lingma 进程直打远端

虽然当前已经能从本地 `auth/status` 读到：

- `token`
- `refreshToken`
- `expireTime`

也已经把 bearer 中段 JSON、`Cosy-Key`、`X-Request-Id` 关系补实了，但这轮流量采集也进一步证明：

- 仅有 `token` 还不等于最终可重放的远端 `Authorization`
- 仅有 `token + Cosy-Key + info` 也还不够

因为当前仍缺：

- bearer 尾 32 位 hex 的生成链
- `Encode=1` 请求体编码链

因此当前最稳结论是：

- token 足以证明登录态可用
- 但 token 本身还不足以直接复现远端 HTTP API 调用

## 当前最稳的阅读结论

- 如果你要研究“登录后本地拿到了什么、如何进入用户态、模型如何刷新”，看这份文档即可。
- 如果你要研究“为什么仍然不能直接打远端 SSE”，应该转去看：
  - [lingma-analysis-endpoint-auth.md](./lingma-analysis-endpoint-auth.md)
