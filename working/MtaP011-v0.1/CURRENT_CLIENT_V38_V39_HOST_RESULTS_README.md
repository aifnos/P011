# v38/v39 当前阶段结果（仅 HOST，不是设备验收）

以下均为 ROOT 首次执行并保留的独立回执。此文档编写时仅读取结果与原始日志，未重复执行任何已通过方法，也未执行新增 CMD。

## 已保留结果

| 方法 | 首次结果 | unittest 原始耗时 | HOST 包装器耗时 | 私有输入 / 公开 ZIP 成员 |
| --- | --- | --- | --- | --- |
| v38 完整组合第一版 | ERROR，child exit 1，无超时 | 181.359 s | 185.579 s | 102 / 2 |
| v38 原生拒绝窄组件 | PASS，child exit 0，无超时 | 2.133 s | 2.453 s | 103 / 4 |
| v38-r2 完整组合 | PASS，child exit 0，无超时 | 179.524 s | 183.641 s | 102 / 4 |
| v39 纯 ctor / `_neutral` | PASS，child exit 0，无超时 | 0.444 s | 0.610 s | 39 / 4 |

v38 第一版错误是 HOST 身份观察引用了不存在的 `store._executor_actor`。旧失败源码、原始日志与失败 ZIP 均保留，未改成 PASS。v38-r2 仅修正这项 HOST 观察：核对真实 marker owner、Provider 原 Proc 观察保留的 actor，以及 Journal 的 typed association executor；原 argv 摘要与入口身份检查继续执行。native Store/Journal 没有新增伪字段。

## 证据范围

- v38-r2 使用实际固定 35 源算法，执行原 INIT、CONNECT、DORA、IP、peer、接收、确认、字节保存及单次恢复/闭合流程。实际 PC ZIP 解析、CRC 和接收文件内容已验证。
- OS 元数据、描述符、进程、RF/kernel、TCP/TLS、借用管道、部署/Parent 准入和时钟均为明确 HOST 模型；模型闭合不是物理 P011 恢复证明。
- v38-r2 原始数值回执记录 4 次 Transfer FULL、34 个 STATUS ticket；34 次 STATUS 中间接收门的新增 context 数均为 0，发送/后检查完整门保留。预筛调用 13828 次均返回 False，旧完整拒绝 owner/reader/accounting 提前捕获次数均为 0；原预算未增加、退款或续期。这是本轮调用成本证据，不是 v37 超时唯一根因的 profiling 证明。
- v38 窄组件验证真实 native count/payload 拒绝、cancelled 优先、FILES 直接传播、原件/replay/unknown 拒绝与独立 CLEANUP 路径；不代替完整 F 或设备恢复验收。
- v39 只运行真实 readonly owner / Store / ResourceBudget 构造、原 `bind_reader`、中性原件检查和所有权拒绝。PC PID/当前线程是真实构造事实，clock1 是显式输入；文件、网络、child、Store 活动入口、collector 与 Proc 读取全部为 tripwire。未执行 ARM 平台验证或 `collect()`。
- 所有结果中 `device_accessed=false`、`phone_tested=false`；生产接收 gate、P011 send/receive 可用性与物理恢复仍为 False。原 v37 完整方法 TIMEOUT 保持历史状态，不由这些结果改写。

## 固定回执

公开成功包含 `result.json`、`README.txt`、`stdout.raw`、`stderr.raw`；失败包只有前两项，失败 raw 与输入快照保持私有。原始 stdout/stderr、HOST exit、timeout 和结果字段不互相替代。

| 回执目录（位于 `results/`） | `public-result.zip` SHA-256 |
| --- | --- |
| `client-refusal-prescreen-v38-native-20261002-120503-51b32680` | `a18fdd1eebc799770cba60af313eb6cbb7936a17cb84387fa9bbda9339608844` |
| `client-budget-refusal-v38-native-20261002-121114-91300f17` | `7e9c2fd9512da22b58ac8cebd7606aedc9be9ec038096f61904168aff14de56c` |
| `client-refusal-prescreen-v38-r2-native-20261002-121513-21f0ca84` | `a9de358e2793e7398f6d45afcdb8147e3dcf5308b3704f9db2ae3a01316f2129` |
| `client-readonly-neutral-v39-native-20261002-122448-7743866d` | `f04c3fe234d24d95b52a6b31902c1f8ab40c401cd13a60334e8bbc86e70728c4` |

## PC-only 手动入口

- `HOST_MTA_CLIENT_RECEIVE_V38_R2_CHECK.cmd`：固定唯一完整 HOST 模型方法，child 上限仍为 300 秒。
- `HOST_MTA_CLIENT_READONLY_NEUTRAL_V39_CHECK.cmd`：固定唯一纯 ctor/neutral HOST 方法，child 上限为 30 秒。

这两项已经有通过回执；无需为补日志、打包或查看结果重复运行。只有确有新的验证需要时才手工启动 CMD。每次手工运行会创建独立新结果目录，不覆盖旧回执，不执行 ADB/设备/RF、不安装候选、不自动重试或修复。包装器保持 `-I -B` 私有固定快照、唯一方法、严格 stdout/stderr 审核，以及成员原始 bytes/size/CRC 读回。
