# CLIENT own-terminal clear（HOST 实现审查）

本轮仅 Pending 文件终末清除，不是 RF 恢复器、Provider、普通 marker 清理或生产准入。
默认 Store 无实际 restore reader，不能授权 clear；send/receive 门禁不变。

## 固定入口与真实性

`marker.clear_terminal(exact_store, exact_binding, exact_terminal_canonical, deadline)`。
方法内 local import，要求 exact `DurableClientInitStore`，不接受子类／bool／构造回执。
同一 shared RLock 最外层，coord／marker／FILES 自身锁在内；等待锁不是硬抢占 deadline。
检查 Store 九个 exact 归属字段、`_finish_sealed is True`、`terminal_durable` phase。
`_authorize_terminal_clear(...)` 必须正常返回 `None`；默认无 restore reader 拒绝。
发行者登记只防内部替代，不把 Python private 字段提升为对恶意同进程代码的安全沙箱。
网络与 Provider 实际闭合真实性仍由将来的固定恢复 producer 提供，HOST fixture 不是该证据。

## 独立 Pending 前置与一次操作

当前 binding／store epoch／journal epoch／LockSet 必须一致，A 的 initial 旧锁不授权。
FILES exact issued 当前 generation canonical，经真实方法重新读完整 bytes、metadata、grammar。
终末 stage 必须 reconciled、ready=False、候选 identity 与 boot 相符。
原 marker FD、dev/inode/mode/uid/gid/nlink/size/mtime/ctime、完整 bytes、当前 F／boot 都 fresh。
四个 anchors、原 device/journal lock 和 FILES 对应目录 identities 一致并真实读回。
canonical metadata 或内容变化、原 entry 替换、foreign/GO/旧 marker、unknown closure 一律拒绝。

登记请求与 exact strong references；授权完成后永久封印普通 guard／verify／handoff。
唯一写入口是既有 libc 的严格 `unlinkat(dirfd, fixed_basename, 0)`，errno 清零后返回 strict tuple。
只接受 `(0, 0)`，不回退 os.unlink/path chmod/shell，不 unlink journal／目录／其它 marker。
unlink 登记一次后，目录 fsync、严格 ENOENT、稳定 anchors 与原 FD 完整 bytes 读回。
unlink 后原 FD 仍打开：nlink 必须0，原 dev/inode/mode/owner/size/mtime 不变；ctime 自然变化允许。
clear 不关闭任何 FD，不签资源完整闭合，不设置 `complete`。

## 被动事实与未知

`clear_status()`／clear 正常返回固定五键：marker_state、clear_durability、clear_attempted、reason、resource_pending。
物理 marker_state 为 retained_observed／absent_observed／unknown。
clear_durability 为 not_attempted／verified／unknown，和资源闭合独立。
fsync 失败可真实 absent_observed，但不是 durable／complete；replacement 不冒充 retained own marker。
异常仅固定码；KeyboardInterrupt/SystemExit 保存未知及 strong refs 后重抛。
请求后永久禁止重试／补 marker／rollback／reopen；重复 clear 固定 already_attempted，零 I/O。
unknown 仅有界只读 absence 观察，不再 unlink/fsync/close；无法读取则 unknown。
Store 第三阶段才独立关闭 marker／FILES／coord 所有 original resources，且需实际 EBADF。
clear 后普通 marker verify、文件写入与 journal handoff 均不可重新准入。

## HOST 证据（分批保留）

新专项以真实 coord／FILES／Pending／Durable Store 方法运行 over FakeIO。
恢复 producer 明确 synthetic，使用实际发行 tuple 注册／authenticate，不 monkeypatch 正向许可。
默认 Linux I/O、libc、ProcReader、socket 全部 tripwire；无实际 /tmp／WSL／ADB／RF。
Python 3.5 AST，只新增专项和直接受影响命名测试，不跑完整项目／旧批次。
实际 Linux unlinkat、目录 fsync、P011、Provider、生产 Store 装配尚未验收。

首批工具 `60a522`：新27＋旧直接受影响3，共30方法／0.434s／host exit1／27 ERROR。
原因是最后补强 patch 的重复 if 上下文误将 terminal-only original-ticket 检查插入普通 `_binding_live`。
初始 bind 读取尚不存在的 `_clear_refs` 被拒绝；不是设备／Store／恢复 producer 的异常。
仅移动这些检查到 `_terminal_resource_guard`，原批次失败保留，不重写成通过。
增量工具 `da5d34`：直接受影响26新＋1旧 own-marker 方法，共27／4.462s／OK／host exit0。
首批已通过的新 AST、旧 Pending closed observation、旧 A AST 三方法不重复运行。
因此最终30个命名方法具备分批通过证据，不称“单批30 PASS”，也不是完整项目回归。
三个旧文件只改获准的直接受影响方法：implemented 表示方法存在，不授予当前 marker 清除权；
A／own-marker AST 保留 RF／通用 unlink 禁项并明确唯一 fixed terminal 入口。
