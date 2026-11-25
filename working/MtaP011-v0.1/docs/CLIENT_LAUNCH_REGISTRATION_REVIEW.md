# CLIENT exec 前后持久登记（HOST 切片）

本模块只解决 DirectChildOwner 的实际 pre-exec Actor 与目标程序 post-exec Actor 不能互相冒充的持久登记链。不是 Provider、RF 准入、恢复器或完整互传；旧 core / codec / B Store 均不修改。

## API / 来源

`DurableLaunchRegistry(exact_store, exact_direct_child_owner, timeout=3.0)` 构造无 I/O。`register(exact_target_ticket, exact_child_ticket)` 必须早于 owner.launch，保存当前原 device FD/Ticket、LockSet、Store epoch、共享 RLock、实际 LaunchSpec 与 child ticket，以及 FILES/coord/marker/binding/run anchor 的原对象与原 FD Ticket；每次 guard 核验这些原引用没有替换。它本身不启动子进程。未来调用方必须将同 owner 的 launch / release / resolve 等操作同域序列化，不能在模块外绕开该 mutex 并发调用 owner。

`release(exact_registration)` 持原 Store RLock，调用**现有 DirectChildOwner.release**。实际 owner 在读取 pre-exec 身份后调用本实例 `_persist(child, actual_preexec)`；回调只有真实 sidecar 文件 fsync、目录 fsync、完整读回成功才返回该次 exact PersistReceipt，owner 才实际写 exec 门。登记阶段失败、耗时过期、文件/关闭未知都不能释放门。PersistReceipt 类型本身不认证磁盘，可信来源是这个实际回调及其强引用链。

`resolve(exact_registration)` 调用 actual owner.resolve，post-exec 必须同 boot/PID/start、完整单 task 身份、目标 exe/argv hash。落盘后再实际 ProcReader.read_actor(expected) 核 live/两 pass/同 boot/全部 sidecar FD 已确闭合，再产生 Handle；R/S 正常变化不当换人。返回 None 仅表示仍等待/未知，绝非退出或 reap。有限至多 16 次显式 resolve，不后台重试。

`close()` 封印本实例，只对自己保存的原 sidecar FD 各尝试一次、核实际 EBADF；不会 close Store / borrowed device OFD / child owner。新 FD 数值须与 Store/coord/FILES/marker 和全部 owner child 原 FD 库存无冲突；疑似借用不能关闭。未知 FD、close 失败保留强引用和 sticky pending。上层资源库存仍必须包含本模块，不可只凭旧 Store CloseProof 签完整闭合。公开 preexec_durable_count / postexec_durable_count 只计成功发行本实例 PersistReceipt / Handle；私有阶段与文件事实可在后续身份失败时仍保留，并不因没有 Handle 倒推文件未曾写入。

## 固定 sidecar / CAS / 阶段

只用 exact Store 已打开 run anchor 内 `launch-watchdog.json` 与 `launch-controller.json`；无路径参数、mkdir、pending 清除或旧 GO 接管。原 Store/marker 同一 RLock、current F、原 device FD、完整当前 intent Journal 与绑定均须 fresh 有效。

私有 schema v1/kind=`direct_child_launch_registration` 的 exact keys：version/kind/stage/identity/run/role/deadline/boot/target_ticket/target/parent/preexec/postexec。Actor 保存实际 pid/start/exe/argv_sha/full tasks；target_ticket 保存 token/role/boot/exe/argv_sha；target 保存 exe/argv_sha/binary_sha。没有明文 argv/env/凭据。完整文件最多 32768B，root regular0600/nlink1，元数据、完整 bytes 与本实例保存的当前文件严格比较，不采用旧同形文件或相同 bytes 新 inode。

阶段为 registered → pre_exec_durable → exec_gate_released → post_exec_durable。单次既有 run 内 EXCL temp → 全量写 / fsync → fresh 完整 bytes+identity CAS → rename → parent fsync → 完整读回；可信外层 shared RLock 序列化，compare+rename 不是跨进程原子条件写。预期 bytes / 原 FD / rename 已返回信息均先强引用再 postcheck；失败不 rebase、重试、覆盖恢复或丢旧引用。temp 最多固定两个角色与本实例序列计数；遗留未知不删除。

成功 sidecar 的完整身份、阶段和文件库存来自实际组件操作；schema / 文件名 / directory token 不授 owner 或 exec/RF 权限。初始化和 release 的预算不能超 child 既有 RF deadline；post-exec 迟到持久登记使用独立有限 I/O 预算，保留原授权 deadline 不延长。

## 尚缺的真实接线

旧 ClientInitLease.start 要求 launch 返回已经符合 target Ticket 的 Handle，并在 release_exec 前保存 *_saved；实际 Python pre-exec Actor 无法合法填该 Handle。这一来源冲突必须未来审 core 两阶段接口：登记真实 pre-exec → durable sidecar callback 放门 →实际 resolve →旧 Journal 保存真实 post-exec Handle。此模块没有更改该接口，也没有把 Python Actor 改 exe/argv 或构造 fake target Actor。

当前没有可信 manifest/历史/recovery producer。原 F 死亡、孤儿或 unknown 子进程不能从 sidecar 反序列化获得 wait/reap / ExitProof；没有 recovery API，原 child/exec 门/sidecar 未知库存仍须上层保留。生产 Provider / RF / phone 可用性全 false。

## 已运行的 HOST 证据（原判保留）

工具为 PC `Python 3.12.0 -B`；只新增定向 FakeIO/FakeKernel 与 Python3.5 AST。实际执行的是现成 Store / FILES / coord / Pending / DirectChildOwner 的真实代码，底层 I/O、进程和 baseline 均是明确 HOST fixture。default OS / native / proc / socket / fork/exec tripwire 禁止调用；不实际 OS / WSL / ADB / RF / 设备，不重复项目全套。

- `e1fd61` 首批 34 方法：0 PASS / 1 FAIL / 33 ERROR，unittest 0.463s、wall 0.9033057s、exit1。33 ERROR 均在新 fixture 的 Store prepared 阶段，尚未调用此模块：旧 ProcessOwner FakeReader self file_count=0 不满足当前 Pending 的完整实际 close 观测门槛。`b8c22a` 仅纯 Fake 定位到 Pending.owner_unknown。只补新 CompositeReader 的明确合成 12/12 文件观察，不改旧生产或旧 fixture；1 FAIL 是 AST 测试将 Actor.start 字段读取当作 start() 调用，只改新测试审 Call。
- `94fa0a` 精确重跑这 34 个受影响方法：34 PASS / 0 FAIL / 0 ERROR，unittest 3.861s、wall 4.2558638s、exit0，含两角色完整 Store stage trace、真实回调源与磁盘 fsync/readback→门写顺序、post-fsync 子进程退出 / reexec / 未知、FD alias / partial IO / sticky close、迟到持久化不延长授权、Python3.5 AST。运行时未为首批失败修改。
- 之后按 ROOT 复审仅窄补原组件/anchor/原 FD Ticket 引用保存与逐次核验；`5079bb` 只 1 新增引用替换拒绝 + 2 正向直接受影响方法：3 PASS / 0 FAIL / 0 ERROR，unittest 0.503s、wall 0.9331937s、exit0。首 34 FAIL/ERROR 与 34 PASS 历史保留，未重整 34。当前文件共 35 个不同测试方法；不是累计 71 个测试或项目套测。

首批 / 首次受影响重跑命令：`python -B -m unittest discover -s tests -p test_client_launch_registration.py -v`。末次只调用 `test_original_components_anchor_and_fd_ticket_not_replaceable`、`test_real_preexec_persist_fsync_readback_before_gate`、`test_postexec_actual_identity_durable_then_handle` 三个精确方法。最终仅另做静态 Python3.5 AST / SHA 冻源检查，不重复功能批。

以上仅 HOST composition / AST 证据；没有 actual fork/exec、真实跨进程继承/崩溃、P011、手机、完整 ClientInitLease.start 或生产 Provider 结论。
