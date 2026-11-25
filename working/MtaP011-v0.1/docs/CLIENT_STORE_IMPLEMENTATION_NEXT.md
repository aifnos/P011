# CLIENT Store 下一最小实施边界

2026-10-01。**DRAFT／未 ROOT 审批。** 本文只有 HOST 静态设计，不是实现、测试结果、部署入口或恢复许可。
本轮只读现有源码并新增本文；没有 OS/WSL/ADB/RF、测试、冻结或修改旧文件。原 GO pending 与当前原网络异常仍阻断设备试验。

## 现成组件与不能继承的行为

- `runtime/mta_p2p_client_init.py:549–572` 的 `ClientInitStore` 仍全部 unavailable；`start:706`、`restore:791` 只是调用合同。
- `Journal:463–513` 保存 v4 逻辑身份／基线／ticket／Actor，**没有 run 或 parent Actor**；合法对象不能签恢复归属。
- `runtime/mta_client_journal_codec.py:293–324` 提供完整 canonical bytes；decode 只验证 schema，不签磁盘、manifest、当前 Executor 或持久化。
- `runtime/mta_client_files.py` 已有安全 dirfd、EXCL temp、fsync、compare-before-publish、读回与 exact FD inventory；不是 Store／flock。
  `ClientJournalFiles` 的固定目录是 `/tmp/p011-mta-client-rfinit/client-<32lowerhex>`，目录创建责任仍在将来的可信外层。
  它当前对 `/tmp/p011-mta-p2p-device.pending` 的**任何 entry**都阻断 open/commit，因此不能直接接上会创建自己 pending 的 Store。
- `runtime/mta_client_proc.py` 的 live Actor／同 boot absence 只读组件不能提供 wait/reap、same-OFD、父子关系或 ExitProof。
- 固定 V9 `native/private-p2p-runtime-candidate-20261001-v9mroute/runtime/mta_send_wifi.py`（SHA `cfe24fba81332082d4033e148578ac088e07e7efce0ab037f499a40e887901fb`）：
  `DeviceGuard:366–423`、`JournalLock:333–351` 是同域设计参考，**不调用**旧 start/recover/clear，也不照搬缺少严格闭合或吞 fsync 错误的实现。
- `docs/P2P_CLIENT_INIT_IMPLEMENTATION_REVIEW.md` 后续修正的 F/C/D 合同优先于早期 owner plan 中 watchdog 自恢复的草案。

## 同域 pending：从阻断到自有记录的唯一拟议过渡

固定 device gate 仍是 `/tmp/p011-mta-p2p-device.lock` 与 `/tmp/p011-mta-p2p-device.pending`；没有第二把 gate、新 pending namespace 或随机路径绕过。
首次持实际 device flock 后才读取 pending：存在旧 GO／未知／不完整／不可读／非 regular entry，一律 block；不清、不迁移、不解析成当前 CLIENT owner。
即使旧 GO journal 显示 reconciled，也不是本 Store 对旧 pending 的 unlink 权限；prior 只能读取已审固定候选及其完整证据，未知仍 block。
未来自己的 pending 需要单独审批固定 v4 角色 envelope：同 boot、实际规范 run/dir 身份、精确 manifest/Identity、当前 F Actor 与注册 generation。
这些字段是**待实现的绑定数据**，不是在现 codec 中偷偷增加 owner 字段；当前 Journal／codec 与历史 schema 不迁移。
创建顺序拟为：持锁确认全域 absence → EXCL0600 创建自己的 marker → 完整写入／file+dir fsync／身份与 bytes 读回 → prepared journal 持久化 → 才允许 provider 注册／RF。
两文件之间并非事务：任何半写、marker 已有而 journal 未完成、未知 close 或 directory fsync 都保留 block，绝不由缺记录推“没有动作”。
FILES 接线须另审内部的 typed admission capability，绑定实际 Store、LockSet、run dirfd、marker receipt、Executor 与 generation，且每次操作 fresh 核验。
不得把 `_pending_absent` monkeypatch 为 true、传入 Boolean guard、删掉末次 pending 检查，或让 UI/IPC 供应 capability。
不匹配自己的当前 marker仍是阻断；capability只认本次已验证 exact record，不给接管历史 GO 的权限。

## 归属绑定，不靠目录名或 schema

可信装配须实际验证完整 frozen manifest／全部依赖 pins、固定 runtime/WPA/ctrl、目录链 dev/ino/type/uid/gid/mode、完整文件 bytes与稳定 inode 身份。
规范 run token 只隔离文件；`Identity.candidate_sha` 只记录预期 digest，必须由真实完整 manifest 检查绑定实际运行图。
当前 F 要经 proc 双观察取得完整 Actor，再与真实启动／fork registry、实际可执行文件 pin、当前 boot、锁 issuer/generation 一并绑定。
仅 `/proc/exe` 路径或 argv hash 不是 executable hash；若路径被换、PID/start/task 变化或读取未知，停止准入。
跨进程 handoff 只能携带可信继承通道和实际资源注册证据；另一个进程 decode 同一 journal 不能自行变 owner/external_finalizer。
文件比较包含 canonical task state 与全部 bytes，不只 `Journal.key()`；目录合法发布产生的 mtime/ctime 变化不能当换目录。
当前 FILES 最终发布读回已见稳定 metadata[:7]（身份及 size）与 EXCL temp 绑定；本轮未复测该增量，不把旧静态缺口写成当前事实。

## 两种锁与实际 OFD

进程内一个可信协调者的 RLock 保护线程、epoch、注册、cancel／晚资源 handoff与资源 inventory；不是磁盘互斥，不从 UI 注入锁对象。
真实 device `flock(LOCK_EX|LOCK_NB)` 排除其他进程／旧 GO；真实每-run journal flock 排除跨进程 writer；仅同进程 RLock 不够。
固定 lock 文件需 dirfd/no-follow、root regular0600/nlink1与 fresh parent-entry identity；不能 unlink/recreate 锁文件，否则出现两套互斥域。
缺少 fcntl/resource 不要求移植新依赖：明确 libc `flock(c_int,c_int)->c_int`、`use_errno=True`；flags 2|4，预算内重试仅已知 EAGAIN/EINTR。
不猜 ARM syscall 号，不把 POSIX record lock 或 F_OFD_SETLK 当 flock；真实 P011 ABI/errno/close 仍待验证。
同 OFD 继承仅由实际 fork/dup 注册路径证明；相同 dev/ino、FD 数字、lock 文件内容或 `ExecutorProof(..., True)` 均不证明 same OFD。
F/D 共享的 device OFD 不提供彼此 journal 序列化：journal FD 必须按审查后的路径独立打开／获取，而非继承同一 OFD 当第二把排他锁。
不得在仍有继承引用时执行 `LOCK_UN` 提前解除所有共享 OFD 的锁；实际每个 FD 引用独立登记／关闭，最后引用语义另核。
RLock 的线程所有者也需绑定；active_return 不能从另一线程伪造 release，或以一个 FD 关闭回执覆盖逻辑锁未释放。

## 最小实际拓扑与闭合边界

沿用已审最小拓扑：F 是固定 owner/协调者，私有 WPA C 与被动 watchdog D 都是 F 的直接子进程；不再加 janitor/launcher 链。
F 持 device OFD；D 只请求 TTL/断连清理，不调用 restore、不自 reap；F 用真实 waitpid 收集 C/D 的实际退出码与整个 task absence。
每次 fork/dup/open/pipe/socket 之前登记 ticket；返回后立即保留 exact 原对象/FD及角色，exec release 只在实际 Actor 保存/fsync成功后。
异常／晚返回仍留强引用；没有正向 never-forked registry＋全部资源 closed 事实就不能生成 UnlaunchedProof。
`active_return` 对应 core `CloseProof.expected=1`：仅 original journal FD确关并释放相应 journal 锁，device FD强引用与 pending 留存。
Store 的 original 两 lock slots对应 `closed_locks.expected=2`；它不是整个 inherited OFD/child/FILES/netlink/pipe inventory 的总数。
每个模块需独立实际闭合证明，provider负责完整注册资源；方法 return、fd=-1、线程 join调用、leader Z或零计数都不能覆盖未知创建结果。
close 原引用最多一次；错误／Interrupt／FD复用未知保留原 refs，只读核原票据，绝不重 close 可复用数字或重新 acquire 丢失归属。
F死亡后新进程不能 waitpid 已孤儿化的 C/D；当前 core 所需 waited+exit_code 不能用 proc absence代填，本阶段保留 pending，孤儿路径 NOT_IMPLEMENTED。

## finish 是实施阻碍，不能先伪装完整 Store

core `_finish_receipt:639–659` 要整份真实回执：reconciled Journal、complete、pending_retained 与 original locks_closed 同时一致，才释放强引用。
但 pending unlink 与最后 lock FD close 不是同一原子事务：先清 marker 后 close未知，无法如实保证 pending_retained；先关全部锁又失去受锁 clear 权限。
追加一个未记录 guard FD也不是答案：只是把“最后引用关闭未知”后移；不得以泛 true、弱化 pending 含义或新增 janitor掩盖它。
必须先 ROOT 审核 F/D持锁生命周期、可持久化 terminal/clear receipt 与失败顺序如何满足现合同；若合同需要精确阶段拆分，单独审批而非 Store暗改。
未锁定该窗口前，实际锁/文件层可以实施并验证，但不能作为完整 `ClientInitStore` 接到 RF，也不能返回 `finish(..., complete=True)`。
`finish(None, False)` 同样需要 actual close inventory与 block语义；无 marker且没有任何 RF可能路径不能凭回执shape虚构 marker存在。
当前 `/tmp` 是 same-boot界面，未验证挂载/断电持久化；fsync通过不是跨 boot恢复证明。

## 下一最少可编码模块（均待 ROOT 授权）

1. 新 `runtime/mta_client_coordination.py`：纯 constructor；显式 `acquire(identity, executor, deadline)` → 内部 LockSet；固定两锁与 exact FD票据。
   内部 API 最少 `validate(lockset)`、`read_pending(lockset)`、`release_journal(lockset)`、`read_closed(lockset)`；无任意路径、RF或 clear。
   `register_inherited(lockset, actual_fork_ticket)` 只给可信 provider的实际 fork链，不能接受 caller `same_ofd=True`。
2. 后续新 `runtime/mta_client_store.py` 才桥接 core/codec/FILES：`current` 必须锁后 fresh读，commit使用完整 expected bytes+metadata且持真实 journal锁。
   先实现未写/阻断路径、持久化自有 marker与 prepared journal的故障层；内部 FILES admission接线改动另审，不 monkeypatch现模块。
   active_return／未知引用只读可先落地；完整 finish 与 pending clear 必须等上节方案获审，不能先挂 unavailable 的假Store给 State。
3. 实际 Linux provider沿用 proc/caps/raw读件，但直接 child启动/FD3/execgate/waitpid/CTRL、fullSTA/fullIP完整快照仍是另一个明确实施缺口。
   本文不造 ExecutorProof／caps complete／ExitProof／closed Boolean，也不为新 Store改变 current生产 capability false。

## 先测什么与证据层

- 未来 ROOT审后 HOST 真实 Linux隔离 tempfile／子进程可测：dirfd锚、实际 libc flock竞争、dup/fork共享引用、独立 journal锁、file/dir fsync/CAS读回、
  close/EINTR未知处理、FD inventory、同一 F 的直接 C/D waitpid与线程 handoff；只能用私有 fixture目录，不用实际 fixed gate或旧 pending。
- HOST故障注入另测：marker→journal各断点、同 bytes换 inode、publish后fsync未知、锁换inode、旧marker全阻断、F退出与 child registry未知；不能替代物理崩溃。
- 只能 P011确定：Python3.5实际 libc/proc/dir_fd支持、目标filesystem语义、真实继承FD/exec/nativeCTRL、actualfullSTA+CLIENT caps、精确type8与全原网恢复。
  当前旧 pending/原网异常不是这些试验的授权；先由 ROOT独立处理当前状态，不把 HOST完成变设备准入。
- 手机层另验：实际原厂 GO、关联/DHCP/IP/真实 endpoint/TLS/双向文件及完整恢复；Store／CLIENT-init ready不等于手机互传完成。
- 本轮没有执行上列任何测试；历史 HOST batch／设备 FAIL／pending证据原样保留，本文不能填任何 PASS/complete/capability。

## 主来源与阅读约束

[Linux v4.14 locks.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/fs/locks.c)的 filp/fork共享与最后引用语义只支持 OFD设计，不证明目标已测。
[open.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/fs/open.c)的 close行为不能转换成“出错重关安全”；[sync.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/fs/sync.c)负结果不能当durable。
[CPython3.5.5 os](https://raw.githubusercontent.com/python/cpython/v3.5.5/Doc/library/os.rst) 的 dir_fd／rename能力需要平台核验；rename原子替换不是无锁conditional CAS。
下一批准点仅是最小协调锁实现与自有 marker接线合同；本文 **DRAFT未ROOT审批**，不是新 schema迁移、恢复动作、部署或更改用户网络的许可。
