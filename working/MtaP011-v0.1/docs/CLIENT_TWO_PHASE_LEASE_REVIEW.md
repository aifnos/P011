# CLIENT two-phase Lease：HOST 组合切片

本轮仅新增 `mta_client_two_phase_lease.py`、其专项测试及本文；未改变 core/B/C/Owner、State、UI、能力开关、原厂文件或旧 pending。无 OS/WSL/ADB/RF/网络/真实子进程执行。测试调用真实组件方法，平台观察、IO、fork、进程退出和恢复生产者均显式 Fake；不属于实际 Linux 或 P011 验收。

## 接口与顺序

- `TwoPhaseClientInitProvider(core.ClientInitProvider)`：保留默认不可用方法；新增可信内部 `request_child_stop(exact_child, deadline)`，默认拒绝。返回 `None` 只是停止动作返回，不是退出证明；无默认信号或网络动作。
- `DirectChildLaunchBridge(exact_B, exact_Owner, exact_two_specs)`：纯构造，并纯构造现成 C Registry。可信后台 specs 的形状不是已认证平台 manifest，不从 HTTP/UI 接收。
- `TwoPhaseClientInitLease(provider, exact_B, identity, clock, bridge=None)`：`start(ttl=20, cancelled=None)`、`restore(timeout=20, inherited=None)` 和被动 `status()`；缺 bridge/provider 在 acquire 前拒绝。
- 各角色严格执行：原 Ticket 注册 → journal `*_intent` → 保留本次 operation → 原 Owner ChildTicket + C Registration → 实际 Owner launch 保存真实 pre-exec Actor → C release 经持久化回调后放门 → C resolve 真实目标 Actor/Handle → 立即强引用 → journal `*_saved`。最终真实 Handle 的 exe/argv 不改成父 Python；Journal v4 schema 不变。
- post-exec Handle 返回后先保存再检查晚取消；未得到 Handle、exec 失败或已 fork pre-exec 不伪装成 `UnlaunchedProof`。最多两个角色、每角色最多 16 次显式 resolve、两次间隔使用现成 Owner 的 0.01 秒 adapter。

## 资源、恢复与失败

- operation 在可能创建资源前存入桥及 Lease；ChildTicket、Registration、返回对象（包括畸形返回）及 Handle 全部强引用。部分 prepare、未知 fork、返回后异常、不在桥库存内的 Owner ticket 都不能凭 Handle 数量忽略。
- 外部 `restore` 必须由原 live F 的 owner Executor 执行；拒绝当前 C/D 自身及 external/orphan executor。本切片不实现 F 死亡恢复。
- 真正未 fork/已知负 fork 可关闭原 Owner 库存，不发明 Actor 或 reap；已 fork 而未放门时只对原 `gate_write` 进行 exact registry/metadata/saved F/单线程校验，调用原 Owner `_close_fd` 一次产生 EOF。其余 executable/error/notify/device-dupe 库存须在原 `wait_reap` 真返回及 `fresh_exit` 真读回后才关闭。B/C 借用 FD 不由桥关闭。
- 首次 gate 已确关但等待超时，后续显式 restore 只对同原 row + attempted/closed/nonunknown + fresh EBADF 重读后继续 wait，绝不重复 close。FD 复用、关闭未知或真实 wait 异常继续 pending；门闸 EOF 不是 reap 证明。
- 已放门子进程需要固定可信停止 producer 或已经自然退出；停止动作只请求一次。未知停止、Owner/C close 未知、provider close 异常或畸形 proof 均 sticky，不因后续布尔改变重试/抹除。
- 完整关闭观测覆盖每个实际 Owner ticket、Owner 原 FD、C 原 FD；实际 waited + fresh absence 与 fresh EBADF 分开。`status()` 无 IO、close、clock 或 callback，汇合 core、B、桥及 provider-close 的已存未知事实，只输出固定状态，不泄露路径/PID/argv/凭据。
- 真正结束仍调用旧 core `_finish_receipt` 与完整 B finish/authenticate/semantic validator：fresh baseline/实际恢复 producer、完整 CloseProof、terminal durable、own-marker clear、独立 closure 和 device-last 原顺序不简化。缺 B `_restore_reader` 时保留 marker/锁/资源，不能产生完成 receipt。
- 超时是阶段准入与等待预算，不硬抢占阻塞 callback/OS 调用；无自动重试，不声称原网络已恢复。当前 status 的 `rf_init_possible`、`production_provider`、`orphan_recovery`、`send_available`、`receive_available` 一律为 False。

## 分批 HOST 证据（不覆盖首判、不重复全批）

| 工具记录 | 唯一所跑范围 | 结果与层级 |
| --- | --- | --- |
| `315dd1` → `42a767` | 首 25 个新方法 | 25 / 11.112s：21 PASS、4 FAIL、0 ERROR、exit 1。3 个 restore 失败来自新 Fake `Origin` 的 `is` 比较；1 个 trace fixture 错把源临时文件名当 journal 目标。原失败保留。 |
| `8439e4` | 仅上批 4 个失败方法 | 4 / 3.512s / OK / exit 0；只修新 fixture/断言，runtime 未为首 FAIL 更改。 |
| `1dc2e1` | 4 新边界 + 3 直接影响旧方法 | 7 / 3.197s / OK / exit 0；负 fork、过期不放门、完整 finish 拒错 producer、Owner close unknown 与被动状态/AST。 |
| `c3ef60` | 2 新边界 + 7 直接影响旧方法 | 9 / 3.156s / OK / exit 0；pregate 仅 gate-before-wait、已知 timeout 重入不重关、B acquire unknown 汇合、相应 restore/状态/AST。 |
| `45158e` | 仅 1 受影响 provider-close 方法 | 1 / 0.874s / OK / exit 0；未知 close 在被动资源状态中保留。 |
| `37b016` | 最后源码的 AST 方法 | 1 / 0.016s / OK / exit 0；runtime/tests Python 3.5 AST、无直接 OS/旧错误顺序回退。 |

现有 **31 个不同测试方法**；并非最后源码单次整 31 PASS。Fake 测试对实际 LinuxIo、ProcReader、os fork/exec/kill/wait、ctypes、socket、Popen 路径设 tripwire。没有本轮 actual Linux/P011/TLS/手机或正式收发证据。

## 固定源码及剩余生产依赖

- 新 runtime SHA-256：`402cf2decd35aa31b47c07828e5ee14b7dd06bb5429740736fd11a54dfd11005`（387 行、22996 B）。
- 新 tests SHA-256：`9bc9b1ea2a347a283fc5a0892bf8a473820a38d67b7ea0a731dc4cc798bb75f5`（449 行、27635 B）。
- 只读核验旧 core：`ec2d927c50bf2946614990bdd9fe1d69ce5538047573d9a4d885a3914b0f85f1`；B：`c6d4c8b7fda8370be83efafe61bfad4a4680ef7a8edba51a89f539c6868594cd`。
- 只读核验 C：`833d46f5717e0b7e9db0c5392a0eb93d812d039b4b946a57d49d5903534a1aa0`；Owner：`0a9a02c79e7e6603f86a7d7618f0b030a3c81d3581423801f22790e923839165`。本轮均未修改。
- 仍缺认证实际 manifest/CLI/binary、完整原网/原 actor baseline producer、fixed single-thread F +实际 C/D 行为、固定停止与 fresh readback、B prior/restore producer、实际 CLIENT 创建/恢复 Provider 装配及实际 Linux/P011 验收。association/DHCP/IP/TLS/手机收发与 State 生产接线未因此完成，发送/接收默认不可用。
