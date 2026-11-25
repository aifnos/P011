# CLIENT journal-lock handoff A

状态：HOST FakeIO 专项已运行；待 ROOT/独立源码审阅与真实 Linux 验证。不是完整 ClientInitStore、Executor、继承 OFD 或 RF 准入。既有 transaction 的隔离 Linux PASS 不覆盖本次 A。

## 最小接线 API

```python
released = coord.release_journal_handoff(current_locks, exact_binding, exact_store_epoch, deadline)
reacquired = coord.reacquire_journal(released, deadline)
current_locks = reacquired.locks
```

两种 receipt 都只认可本协调器私有 registry 保存的 exact 实例。形状相等、复制对象、其它 Store epoch/binding/LockSet 均不是 permit。构造 receipt 不发生 I/O，也不认证 owner。

默认 acquire 的六票据预算与旧 release_journal 不变。旧 release 不发行 handoff；新增仅一次 journal-only 尝试允许第七票据。原 device ticket/FD 不重开、不 dup、不传承登记；“保留实际原 FD”不等于证明跨进程同 OFD。

## 实际路径与中间状态

1. 同一外层 RLock 中保存 handoff context；实际原 marker FD/full bytes/metadata、当前 live F/boot、四目录锚、device/journal 锁 entry+FD 均重新读回。
2. 普通 marker/FILES/Coord guard 暂停后，只关闭原 journal 一次；normal return + 原 FD EBADF 才发行 ReleasedJournal。close 未知不发行 permit，也不因随后 EBADF 恢复。
3. 专用 device-only fresh guard 不使用已关闭 journal 作为 live lock，不伪造 pending absence。marker 仍为原 entry/FD/完整 bytes；当前 F/boot、原 device 与目录再次真实读取。
4. journal entry 必须仍为原 regular0600/root/nlink1/空文件身份。新 open 没有 CREAT/EXCL，缺失或替换立即拒绝；第七 creator ticket 在 open 前保存。
5. 已返回 FD、异常 creator、未知 flock、新 LockSet/receipt 在 postcheck 前保存。malformed 返回已被其它组件持有的活 FD 也不能触发盲 close；已严格关闭的历史 FD 数字可被真实新 open 复用。
6. 只重试 known EAGAIN/EWOULDBLOCK/EINTR 且受同一预算限制。新路径 success 必须 `(0, 0)`；未知结果不重试，已确知新 FD 独立最多 close 一次，原 device 保留。
7. shared RLock 内交换 coordinator 当前 LockSet、marker 当前 LockSet 与私有 journal epoch；最终 fresh marker/F/device/new-journal 读回之后才 active。partial 不 rollback/rebind，旧、新 refs/epoch 均保留且普通 guard 拒绝。

初始 immutable LockSet 与新 issued LockSet 历史只允许 read_closed 的被动 original-FD 观察；历史 set 不授予 validate/read_pending。read_closed 不 open/flock/close。Unknown context 仍让 closure observation incomplete；不能以全数字暂时 EBADF 清除未知。

预算先 strict type/range/finite，再统一 monotonic deadline；最多20秒 supplied horizon，并取本组件 timeout 较短值。同步 OS/回调不能被硬抢占；没有 FIFO、公平锁或后台 watchdog 声明。所有 public 组件操作持同 outer RLock。

## B 的直接接点及未实现条件

- active_return 可使用 exact release；本实例 recover 可使用 exact reacquire 后的新 `.locks`。
- A 不把原 prepared journal 当恢复当前值。B 必须持新 journal 锁后调用实际 FILES.read_current，完整 canonical bytes/metadata/core journal 检查，再保存 stage generation CAS。
- inventory 是六/七个原资源记录；core 两 logical slots 的 CloseProof 仍须由 B 正确映射 device/current journal 与历史 inventory，不能拿 observation tuple 形状签名。
- 仍缺真实完整 Store、manifest/actual baseline producer、Executor/F 继承链、Provider、恢复 readback、terminal durable/marker clear/finish。没有外部 finalizer接管或孤儿恢复。
- pending 保留；本次未调用 unlink、LOCK_UN、mkdir、fork、dup、kill、wait、socket、RF 或设备。关闭资源不等于网络恢复。

## 实际 HOST 批次

工具 `81f81b`：PC Python3.12.0 `python -B -m unittest -v`，26 新 `JournalHandoffTests` +19 个精确受影响旧命名方法，共45，0.680 s，OK/host exit0，wall1.0642496 s。包含两个变更源的 Python3.5 AST；无首次 FAIL/ERROR。

首批后源码自审补一个具体 live-FD alias 门禁与新方法。工具 `8591e5` 只运行：

```text
test_client_journal_handoff.JournalHandoffTests.test_malformed_live_fd_alias_never_closes_original_as_new
test_client_journal_handoff.JournalHandoffTests.test_pure_types_python35_and_no_new_actions
```

2 方法，0.052 s，OK/host exit0，wall0.4150697 s。原45结果原样保留，没有重跑全27新方法或项目套测；不能把两批相加称47个唯一方法。

所有实际组件方法通过 FakeIO/合成 ProcReader/合成 baseline 装配，默认 Linux/libc/proc/socket 路径有 tripwire。没有真实 OS 锁、实际 /proc、WSL、P011 或手机测试。错误、IO/F 阶段未知和晚到资源不被 HOST 标签晋升。
