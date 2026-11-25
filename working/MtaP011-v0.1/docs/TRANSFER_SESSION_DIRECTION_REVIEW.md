# TransferSession 内部方向终态

2026-10-01，HOST 专项组件变更，等待 ROOT 全文复审。
只修改 `runtime/mta_transfer_session.py`，新增方向专项与本文；State、worker、
provider、HTTP、UI、设备和平台发送能力均未修改。

## 小契约与兼容范围

`TransferSession(..., direction='receive')` 在原参数末尾增加 exact str 内部
枚举，只有 `receive` / `send`；默认值和所有已有 positional 参数保持兼容。
方向在创建任何 Thread 对象前验证。方向不是来自 HTTP 字段的能力开关，
不提供任何网络、归属、恢复或 mutating admission。

原 `Outcome(payload, local_commit_verified, peer_ack_verified)` API 完全保留。
新增 `SendOutcome(payload, local_bytes_verified, peer_ack_verified)`；send 只接受
该 exact 类型，receive 只接受原 exact 类型，两者的两个 flags 必须是 exact
bool。相同字段的 dict/namedtuple、类型 subclass、数字 truthy flag 均拒绝并
保留原 private invalid result。不能把发送 bytes 包装成接收 local commit。

发送调用方将来必须先核真正 worker 的结果，再构造 SendOutcome；typed 类型
自身不能证明实际字节、手机 ACK、kernel 或持久化文件。此任务没有做该接线，
也没有让现有 SendWorker 返回值自动变成可信结果。

## 状态规则

默认 receive 的 status 字段集合和终态完全不变：真实 local commit + peer ACK
且完全 closed 才 completed；commit 有、ACK 无时仍 saved_unconfirmed。

send status 只额外增加固定 `direction='send'` 与 bool `local_bytes_verified`；
原 `local_commit_verified` 始终 false，不序列化 payload 或私有异常。

| 完全 closed | 已验送出 bytes | 对端 ACK | send 状态 |
| --- | --- | --- | --- |
| false | 任意 | 任意 | 保留原 lifecycle 阶段；不能 completed / sent_unconfirmed |
| true | true | true | completed |
| true | true | false | sent_unconfirmed，不是 saved / received |
| true | false | 任意 | 既有 failed / cancelled 回退，不报告发送完成 |

实际事实可以在 cleanup 尚未完成时保留；这不使资源退出或恢复自动变真。
取消后返回的实际 bytes/ACK 事实仍保存，与原接收已落盘后取消的契约一致。
缺失、畸形、跨方向结果不发布 bytes/ACK 或 local commit。

## 生命周期没有放宽

仅结果接受与 status 方向分支改变。原 transport 登记、exact handoff、未知
owner 隔离、generation、Thread.start 未知、实际 worker/finalizer exit、
close/release/extra/restore 顺序及 strict True/计数/原 raw proof 逻辑均未改变。
status 仍被动，不调用 close、callback、网络或清除 owner。
恢复 False、transport/raw 退出未知、迟到未知 owner、活 worker/finalizer 均保持
原 pending / restore_pending；不能通过选择 send 绕过任何恢复门禁。

## 实际批次与证据

PC CPython 3.12，显式 `-B`。首批工具 `8004c4`，HOST exit 0，wall 0.6078406 秒；
unittest `Ran 26 tests in 0.277s / OK`，0 failure / 0 error。
本批为 20 个新增方向方法 + 以下 6 个精确受影响的旧 Session 方法：

- exact_worker_finalizer_owners_are_registered_before_start_and_retained
- normal_cancellation_uses_same_finalizer_and_preserves_real_outcome
- cancelled_exception_does_not_forge_transfer_success
- public_status_is_passive_fixed_counts_and_contains_no_private_result_or_error
- invalid_outcome_flags_do_not_publish_local_commit_or_ack
- constructor_and_wait_budgets_are_finite_non_bool_and_callbacks_are_internal

执行方式：在 tests 目录运行 `python.exe -B -m unittest
test_transfer_session_direction`，同命令显式列上述六个
`test_transfer_session.SessionTests.test_<method>`，加 `-v`。
完整命名输出留于该原工具记录；这是唯一批次，没有失败批次或重跑旧整套。

新增专项使用真实 HOST Python Thread 的 start/join/is_alive，fake transport、
lease/restore/scoped callbacks；包含 worker 返回后仍活、finalizer 阶段返回后
仍活、恢复拒绝、raw proof 拒绝和 unknown owner 保留。fake callback True 不代表
实际原厂/网络恢复。实际 filesystem/process/socket 操作被禁止；只读项目源码。
本批包括 Python 3.5 AST、无 assert/网络/State/worker import 检查，不代表设备
Python 3.5 实际执行、真实字节/ACK、TLS、RF、P011 或手机验收。

## 后续接线限制

State 将来必须按方向使用完成文案与进度，不可继续对 send completed 显示
“文件已保存”。send 不得更新 received/localCommit，也不能依据 SendOutcome
或 HOST fixture 打开 send_available。真实 provider、关联/DHCP/租约、外部恢复
和手机组合尚缺；本次没有 RF、ADB、OS 网络、全套运行或正式候选冻结。
