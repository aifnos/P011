# Durable CLIENT Store B：文件、锁与终末生命周期

状态：实现及 HOST FakeIO 专项已完成，待 ROOT/独立审阅；未运行真实 Linux、P011 或手机。不是默认可用的 RF Provider，不开放收发能力。

## 实际切片

`runtime/mta_client_store.py` 保留原 `ClientPreparationStore`，追加 `DurableClientInitStore(core.ClientInitStore)`；`runtime/mta_client_coordination.py` 只追加独立 `close_device_last()`，默认 `close()` 与 A 交接入口语义不变。Pending 的终末清理由另一个任务独立实现，本切片不修改它。

纯构造签名：

```python
DurableClientInitStore(run_token, identity, timeout=3.0,
    _coordination_io=None, _files_io=None, _pending_io=None,
    _proc_reader=None, _clock=None, _restore_reader=None, _prior_reader=None)
```

直接实现核心 Store 接口：`acquire(identity, deadline, inherited=None)`、`lock_valid(locks)`、`current(locks)`、`pending_clear(locks)`、`prior_clear(locks, baseline, deadline)`、`commit(locks, record)`、`pending_matches(locks, record)`、`active_return(locks, record)`、`finish(locks, record, normal_restored, deadline)`、`authenticate_finish(...)`、`closed_locks(locks, deadline)`。额外 `close()` 仅紧急关闭本实例文件资源，不宣称网络恢复。

## 真实组件装配

- 同一进程内共享最外层 RLock 与私有 epoch；实际调用 Coordination、FILES、Pending，不用 mock 正向准入替代这些方法。
- 初次 acquire：同域设备/日志锁 → 实际 FILES open/read → 必须为空；任何旧 pending 或已有 journal 均拒绝接管，包括同 identity 的旧 prepared。
- 首个 prepared：完整 canonical bytes CAS → EXCL 临时文件/write/fsync/rename/目录 fsync/同 inode 完整读回 → 实际 marker create/fsync → exact `bind_files`。返回的 canonical、marker、binding 在后置检查前保存强引用。
- 各阶段保留身份、完整 baseline（含 task 状态）及原 RF deadline；仅合法逐阶段增量。已存在的接口、票据、Actor 不得移除/替换。普通 commit 不生成 reconciled。
- `active_return` 调 A exact handoff：实际只关原 journal FD，返回 core 的 1 个逻辑槽 CloseProof，原 device FD 保留。
- `acquire(..., inherited=exact_old_locks)` 仅同实例一次 reacquire：第 7 个现存 journal 票据、同原 device、实际新 flock 之后读 current；不允许外部 F、复制 LockSet 或 unknown 后重试。
- I/O deadline 与 RF deadline 分开；超 RF TTL 后仍可在新的有限 I/O 预算内保存 cleanup，不延长 RF 授权。
- 历史 LockSet 只作被动闭合观察；`closed_locks` 是 device/current-journal 两个逻辑槽，不以 6/7 个 inventory 元组冒充核心的 CloseProof。

## finish 与清理边界

一次封印 → fresh restore 读取并认证 → terminal reconciled 完整 CAS/durable 读回 → 再 fresh restore → `marker.clear_terminal(self, exact_binding, exact_terminal_canonical, io_deadline)` → marker、FILES、Coord 独立尝试各原资源一次，原 device FD 最后关闭 → 全 inventory 实际 EBADF 读回 → exact 发行 FinishReceipt。

Pending 调用 `_authorize_terminal_clear` 时第三次 fresh restore；终末 canonical 指针不被这次独立读回替换，额外观察另留强引用。清理验证失败时 marker 保留；unlink 后目录 fsync 未确认则记录物理 absent 与 durability unknown，不伪造 retained。marker durable absent、终末 durable 与 FD resources closed 是三个不同事实。

`normal_restored=True` 本身不准入。默认 `_restore_reader=None`，即使传 True 也不清 marker、不签 complete；仍实际独立关闭可确认的本地 FD。未知 creator、未返回 open、关闭异常及多个 close 错误均保留原引用、sticky pending，不靠随后 EBADF 抹去未知。

私有可信 producer 必须实现：

```python
read_restore(exact_store, exact_locks, exact_request_journal, deadline)
# -> exact newly issued tuple(Snapshot, CloseProof)
authenticate_restore(store, locks, request, exact_returned_tuple, deadline)
# normal None；真实发行 registry 必须由 producer 验证
read_prior(exact_store, exact_locks, baseline, deadline)
# -> issued fresh Snapshot
authenticate_prior(store, locks, baseline, exact_returned_snapshot, deadline)
# normal None
```

拒绝布尔、未关闭的 proof、变更 baseline、复用 tuple/Snapshot/proof、错误认证返回。这个类型/调用契约本身不是 kernel、manifest、真实 Provider 或恢复证据；两个 producer 默认缺失、prior 默认拒绝。

## 精确 HOST 批次（原失败不改写）

环境：开发 PC Python **3.12.0**，`python.exe -B`；测试 tripwire 禁止实际 LinuxIo、ctypes、socket、ProcReader 读 self。组件用真实方法，操作系统由 FakeIO，stock/network/Actor/restore producer 全部合成。

1. 工具 `8cff60`：33 个新 B 方法 + 7 个精准受影响旧方法 = **40**；unittest 2.112s，wall 2.4886352s，exit 1；36 PASS、4 FAIL、0 ERROR。完整阶段轨迹成功，实际 FakeIO 库存 **FILES 97/256、Coord 7**；未扩大预算或删历史。
2. 四个 FAIL 同一 fixture 原因：导入 `changed_baseline()` 默认 task 状态 R，而原 baseline 已是 R，实际并没有变化。仅新测试改成明确 `state='S'`，运行时不变。
3. 工具 `de77db`：只重跑四失败；4 方法，0.715s，wall 1.0911043s，exit 1；3 PASS、1 FAIL、0 ERROR。余下一项是故意 `read_restore` 抛异常、尚未返回观察，测试却要求已返回观察库存非空。
4. 仅测试分层：所有分支保存实际 producer call；该尚未返回异常分支要求 observations 为空，其他已返回分支保留 exact observations。
5. 工具 `d99c14`：只重跑余下 1 方法；0.454s，wall 0.8147165s，exit 0，PASS。先前通过的方法未再跑；不累计为 45 个 unique 方法，也不是整项目测试。

新方法覆盖完整 prepared→watchdog/interface/controller 各 intent/saved→ready→active_return→same-F reacquire→cleanup→terminal clear；还覆盖旧标记拒绝、完整 bytes/inode 变化、deadline、fresh restore 变化、unknown 创建、unlink/fsync/close 分离、device-last、exact FinishReceipt 认证及默认 producer 缺失。Python3.5 AST 在首批新/旧指定方法内通过；顶部后续仅文案限定旧 Preparation 范围，单独 AST 检查，不重跑功能。

首批 7 个旧方法：Preparation 的 import/ctor、Python3.5 AST、prepared 实际 CAS、闭合读回；Coord 的各原资源独立 close、纯 read_closed；A 的成功第 7 票据/原 device/历史 epoch。旧 Preparation 8 个定义保持；不扩展默认 A 行为。

## 直接下一接点与尚缺事实

ROOT 后续可用隔离真实 Linux fixture 一次核实际 libc flock、CAS、journal 新 inode、handoff/reacquire、unlink+目录 fsync、全原 FD EBADF 与 device-last；本批没有这种实际证据，旧 Linux PASS 不升级到 A/B。

生产 C 尚需固定完整 manifest/currentF/sameboot/历史 admission producer、真实完整双栈 baseline producer、Provider Actor/资源关闭与恢复认证、真实 Executor/OFD/FD inventory 拓扑。当前核心 `start` 中 Python preexec Actor 与 target Handle 的既知冲突未修改；测试不调用 `lease.start`，不以 target 伪 Actor 隐藏问题。

本 Store 不接 State/默认启动、不继承登记、不 fork/kill/配网、无恢复旧 GO marker、更不把孤立 F 或 typed receipt 当所有者。`production_provider`、`send_available`、`receive_available` 均 False；完整互传和手机验收仍未完成。
