# CLIENT journal / marker transaction — HOST only

本次只新增 `mta_client_journal_transaction.py` 及专项测试；实际依赖
Coordination、FILES、Pending 的 own-marker binding 补丁。未接 State、lease.start、
Provider 或默认启动入口。以下是文件事务，不是完整 `ClientInitStore`。

## 私有 API 与范围

- 纯构造 `ClientJournalTransaction(run_token, identity, timeout=3.0, 私有HOST适配器)`；
  一个内部 epoch object、一个共享 exact RLock，自首 acquire/open 传入三个组件。
- `open()` 只打开已存在、经过组件核验的 fixed CLIENT 私有目录；真实 device / journal
  flock，拒绝任何旧 global pending 和任何已存在 journal，不采用路径名授予 owner。
- `current(exact_session)` 每次实际读回当前完整 canonical bytes / metadata / logical Journal。
- `prepare_initial(exact_session, baseline, deadline)`：空 current CAS→文件 fsync→rename→
  目录 fsync→完整读回→实际 marker create / fsync / owner readback→一次 bind_files→fresh verify。
- `commit(exact_session, exact_latest_receipt, record)` 只允许 `prepared`；无 ready、owned、
  interface/controller/watchdog role；exact identity、完整 baseline 含 task states 不变；
  deadline 只可不变或缩短。进程内 canonical generation 必须实际递增，不能冒充跨进程序号。
- `close()` 永久封印。独立一次 marker→FILES→Coordination close，原 FD EBADF 读回。
  **marker 保留**；本地 FD complete 不等于网络恢复、pending clear 或 successful finish。

## 异常与所有权

组件必须首先保存实际返回的 canonical、marker observation、binding，再做 postcheck。
本组合也保留上述 exact refs；异常不可 rebase、retry、重新 acquire、unlink 或释放未知引用。
三组件共同持有同一 outer RLock，实际 CAS 原子性依赖真实 journal flock 与所有参与写者遵守它；
不把 compare-before-rename 描述为无锁 conditional CAS，也不制造通用 True admission。

操作预算为同一个真实 monotonic deadline，组件不能通过重设自己的预算延長整个事务。
预算只能在步骤边界拒绝，不能硬抢占阻塞中的 OS 调用或内部 reader。
关闭尝试先于 clock/status/报告分配；clock、close、返回结果未知保持 sticky pending。
close observation 只覆盖本组合的三个实际组件 FD inventory；未知 proc reader 使 marker 创建失败，
不把 reader observation 当 reap / Executor / same-OFD 证明。
`status` 是固定私有缓存事实；`prepared_checkpoint` / `marker_bound` 表示曾核验过，
并非新的磁盘、owner 或 RF 观察。`current` / `commit` 始终另做实际 fresh 核验。

## 验证记录

固定依赖在测试前已实际比对 SHA：

- Coordination `6d1b3af860c02046dc53156ecb74ff69423708c919a62fe20e30b9adea223079`。
- FILES `d95afa25d82c02592d3e4d5a904a397d0f3c366124f793433131bd3d62342ed3`。
- Pending `7197c04cb96e4fce5c252664199668abe013489cbf3b247f521b3293a7d34d2c`。

唯一首次 HOST 组合批次工具 `420fd4`：32 方法、0 FAIL、0 ERROR；unittest 0.586s、
工具 wall 0.9720502s、exit 0、OK。无失败首批、无重跑、无累计旧套测。
其中一方法包含 Python 3.5 AST 与无 RF/finish/import 的边界；不是实际 Python 3.5 执行。
PC 为 Python 3.12.0（工具 `6c9789` 实际版本读回），命令：

```powershell
& 'C:\Users\P011_USER\AppData\Local\Programs\Python\Python312\python.exe' -B -m unittest discover -s tests -p test_client_journal_transaction.py -v
```

测试实际调用三个组件的方法，底层统一 FakeIO、合成 ProcObservation；默认实际 I/O / libc / socket / proc
有 tripwire。正常路径不以 mock True 替代绑定；少数 malformed / postcheck 测试仅做故障注入。
覆盖旧 journal/pending 拒绝、两实际组件 flock 调用、同锁域、prepared 发布后 marker、后续代际 rename、
完整 baseline/tasks、receipt exactness、marker/current 同 bytes 换 inode、时限、三个返回后的 postcheck 保留、
unknown open、fsync 未知、BaseException 独立 close、后续 EBADF 不抹 sticky unknown、关闭仍留 marker。

本次稳定源：runtime `2783f66edbb545aff8adfaa2f80a77fd957c8ba5b365c90907474244b603dcaa`
（405 行 / 22053 B）；tests `4c78dbb8c46b165f63801ccabebbd9b670c9602ba7c3fea89016cc17bac06d4a`
（441 行 / 24581 B）。文档最终 SHA 由交付时单独核验，避免自引用。

未执行真实 Linux tempfile/flock、WSL、P011、ADB、RF、网络、全项目套测、freeze 或旧 pending 操作。
实际 manifest / Executor / 完整 F provider / same-OFD 继承与真实 restore / finish / clear 仍缺；
未完成互传双向目标，生产 send/receive capability 不因本模块而开启。
