# Heartbeat Body 编码结构分析

## 发现

### Body 结构

Heartbeat body 由 `$$` 分隔为两个独立编码的部分:

```
[encoded_part1]$$[encoded_part2]
```

- Part 1: 326 编码字符 → 244 字节
- Part 2: 656 编码字符 → 492 字节

### Part 1 (设备信息 JSON)

**解码后内容** (244 字节):
```
6-A0BA-64C697DA4599","expr_features":"{}","host_system":"x86_64_windows","ide_type":"plugin","ide_types":"","ide_version":"","os_arch":"windows_amd64","os_version":"Microsoft Windows [Version 10.0.26200.8037]","product_type":"lingma","tag":""}}
```

**缺失前缀**: 约 30 字节
推测为: `{"session_id":"[UUID前缀]`
- UUID 结尾: `...6-A0BA-64C697DA4599`
- 完整格式可能为: `XXXXXXXX-XXXX-XXXX-6A0BA-64C697DA4599`

### Part 2 (遥测事件 JSON)

**解码后内容** (492 字节):
```
plugin","aid":"","uid":"","rid":"","yid":"","oid":"","event_data":{"cosy_version":"2.11.1","device_disk_serial_num":"54ad8f9c","device_hardware_id":"PF39BB4E","device_mac_address":"90:2e:16:f8:72:db","device_machine_serial_num":"58A45399-5D14-4D5{"uuid":"0c6226f8-17ed-4dc1-8946-4de6645c37c2","event_time":1777040596228,"event_type":"cosy_heartbeat","mid":"35346164-3866-492d-a339-30773a32652d","os_arch":"windows_amd64","os_version":"Microsoft Windows [Version 10.0.26200.8037]","ide_type":"
```

**缺失前缀**: 约 66 字节
内容: `plugin","aid":"","uid":"","rid":"","yid":"","oid":"","event_data":`
推测为: `{"request_type":"` (16 字节) + 更多字段

**关键信息**:
- `uuid`: `0c6226f8-17ed-4dc1-8946-4de6645c37c2` (capture 1) / 不同值 (capture 2)
- `event_time`: `1777040596228` (毫秒时间戳, 约 2026-04-24)
- `event_type`: `cosy_heartbeat`
- `mid` (machine_id): `35346164-3866-492d-a339-30773a32652d`
- `cosy_version`: `2.11.1`

### 编码方式

两部分均使用相同的自定义 base64 编码:
- 字母表: `_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!`
- 6 bits/字符
- 大端位打包
- **不使用 AES 加密** — 数据为明文 JSON!
- `$$` 作为分隔符

### 截断问题

两个 Part 都缺少开头部分:
- Part 1: 缺失 ~30 字节 JSON 前缀
- Part 2: 缺失 ~66 字节 JSON 前缀

这可能是 HTTP 捕获工具的 bug, 或者是 Go HTTP 客户端发送时的特殊行为。

## 未解决问题

1. **缺失的 JSON 前缀**: 需要找到完整的 JSON 模板
2. **`$$` 的含义**: 是自定义编码的填充符还是分隔符?
3. **是否使用 AES**: 当前数据看起来是明文, 但 `Encode=1` 暗示有加密
4. **签名计算**: `Signature: 8d915d7d99452c143dc52ce040b9a355` — MD5 还是 HMAC?

## 下一步

1. 在二进制中搜索完整的 JSON 模板字符串
2. 确定 `$$` 的确切作用 (填充 vs 分隔)
3. 尝试构造完整 body 并验证签名
