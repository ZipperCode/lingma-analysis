# getAppSalt 分析结果

> 状态说明：这份记录属于更早的一轮定位结果，里面关于 `getAppSalt` 返回结构和后续主线的部分判断，已被后续文档补证或修正。继续分析时，请优先看 `tools/getappsalt_analysis_v2.md` 与 `docs/continue-analysis-from-current-state.md`，不要把这份文件单独当作当前结论。

## 核心发现

**getAppSalt 代码地址: RVA `0x882760`**
- pdata entry: #19180
- 大小: 1087 bytes (0x43F)
- 文件偏移: `0x400 + 0x882760 - 0x1000 = 0x881B60`
- 虚拟地址: `0x140882760`

## 定位依据

### 1. 名字表位置
在 pclntab 名字表中:
- [27] `cosy/remoting.addBigModelSignatureHeaders`
- [28] `cosy/remoting.getAppSalt` ← 目标
- [29] `cosy/remoting.addBigModelAuthorizationHeaders`
- [30] `cosy/remoting.trimQueryPath` (已知代码地址 0x882c80)

### 2. pdata 顺序映射
Go 编译时函数按声明顺序排列:
| 名字表索引 | 函数名 | pdata # | 代码 RVA |
|-----------|--------|---------|----------|
| 27 | addBigModelSignatureHeaders | 19179 | 0x882680 |
| 28 | getAppSalt | 19180 | **0x882760** |
| 29 | addBigModelAuthorizationHeaders | 19181 | 0x882ba0 |
| 30 | trimQueryPath | 19182 | 0x882c80 |

### 3. 调用图验证
```
0x880da0 (pdata#19170) ← 请求构建函数
├──→ 0x882680 (addBigModelSignatureHeaders)
├──→ 0x882760 (getAppSalt)  ← 直接调用!
├──→ 0x882ba0 (addBigModelAuthorizationHeaders)
│    └──→ 0x882c80 (trimQueryPath)
└──→ ...
```

## getAppSalt 函数行为分析

0x882760 的 disassembly 显示:
1. 调用 0xa82c0 - 获取配置/客户端
2. 位操作 (bt rax, 0x3f) - 检查某种标志
3. 调用 0x9ea40 - 字符串操作
4. 调用 0x102e0 - strconv (整数转字符串)
5. 调用 0x11bd20 - slice 构建
6. 多次调用 0x2dd360 - map 操作
7. 调用 0x13260 - 内存分配
8. 调用 0x18980 - map 插入

函数返回一个包含 3 个字符串元素的 Go slice。
根据源码 `[]string{"cosy", "lingma", "system"}`。

## 相关函数地址

| 函数名 | RVA | 大小 | 说明 |
|--------|-----|------|------|
| getAppSalt | 0x882760 | 1087B | 返回 salt slice |
| addBigModelSignatureHeaders | 0x882680 | 203B | 添加签名头 |
| addBigModelAuthorizationHeaders | 0x882ba0 | 207B | 添加授权头 |
| trimQueryPath | 0x882c80 | 442B | 修剪查询路径 |
| getAuthSignature | 0x890140 | - | 获取认证签名 |
| getAuthPayload | 0x890380 | - | 获取认证载荷 |
| 0x88f887 | 0x88f887 | - | 组合 getAuthPayload + getAuthSignature |

## 关键字符串位置

- `Salt` at 0x1f40d26
- `SaltLength` at 0x1f56a0c
- `saltBytes` at 0x1f52a38
- 远程端点: `https://lingma.alibabacloud.com/algo`
- 远程端点: `https://lingma-api.tongyi.aliyun.com/algo`

## Hook 脚本

已创建 `frida_hook_getappsalt.py` - 运行时 hook getAppSalt 并打印返回值。

## 下一步

1. 运行 frida_hook_getappsalt.py 验证 getAppSalt 返回值
2. 从返回值中提取实际的 salt 字符串
3. 结合 getAuthSignature 和 getAuthPayload 的输出还原完整签名算法
