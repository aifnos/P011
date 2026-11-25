# CLIENT kernel connection v15 — SOURCE / HOST only

本候选逐字派生自冻结 v13 reader `14dbe98d59e8319812e62d75907196b78fbde348f40003942476ecb9ee9c0f93`。原 v13、原 runtime 和 v14 均未修改。本轮仅拥有 `candidate/client-kernel-connect-v15/runtime/mta_client_kernel_proof.py`、专项测试和本说明；尚无真实 GET、Provider 接线准入、CLIENT 租约、IP/DHCP/端点或 State 验收。

## 同步取消与共享绝对期

构造新增 trusted internal `_checkpoint=None, _deadline=None`，构造不调用 clock/callback、无 I/O。`None` callback 仅保持原 standalone 只读 reader 的兼容；实际 Provider 必须传 exact Connection operation 持有的原 F `_cancel_checkpoint`。不能传 `_Connection._checkpoint`，后者正常返回 `None` 而不是严格布尔值。owner 为 exact Connection operation，epoch 从 F 已验证 request.binding metadata 取得；reader 不猜 operation_epoch。

只有 exact `False` 继续；`True`、非 bool（包括 callable 返回 None）、任何 BaseException 均固定映射 `KernelReadError('cancelled')`，reader 的取消状态 sticky，不公开异常文本。callback 在原 caller 线程的 `_check`、`_budget`、send 前、正常 recv 后、真实 Proc 返回后执行；finally 不调用 callback，取消不旁路原资源 once-close。

外部 deadline 必须 exact int/float、非 bool、正有限且不超过 1e12；先范围检查再 float/isfinite，huge int 不泄漏 OverflowError。read 开始只发行一次 `min(read_start + original_timeout, external_deadline)`；不因阶段或 checkpoint 重置。原 timeout 范围不变，时间恰到截止点即失败。该接口是协作式同步检查，不是强行抢占 callback、OS read 或 recv，也不提供新的线程/kill/timeout 恢复机制。

recvmsg 实际返回后先保留原 RawDatagram；未知 ancillary 仍 `receive_unknown` / pending，不因取消变成闭合。正常数据在解析前检查取消。真实 ProcReader 返回原对象立即保留，然后在原 FD EBADF 核验与原 observation 类型/boot/live/两轮校验后检查取消和绝对截止点；缺失/unknown 原结果不填成事件。

## 原关闭库存发行 seam

新增只读 `closed_receipts` tuple，每项 `(io, fd, exact_original_producer)`；producer 只能为本 reader 的原 original_resources dict row 或原 proc_readers 中 exact ProcReader。票据仅在原 `_close` 的当场 `fstat == EBADF` 成功分支、或原 `_self` 的原 `(fs, fd)` EBADF 成功分支发行；不新增 close、fstat、callback 或设备请求。原 rows、ProcReader 与其 `_fd_refs` 强引用保留。1024 收据上限覆盖原两 ProcReader 各最多 280 FD 加三个 kernel 原资源；超限仍 fail closed。

验证/登记失败（包括 MemoryError）置 sticky `receipt_unknown=True`，最终 resources_closed/read_success 不能通过，即使原 FD 实际已关闭。`status()` 仅新增非秘密的 cancel_requested、receipt_unknown、close_receipt_count；观测 private_fields 和公开观测 schema 不变。

这些是 issuer 历史原件证据，**不是**数值 FD 当前所有权、当前合法复用 generation 或恢复权限。Provider 必须另外核 exact reader 已登记、原 owner/epoch/Origin/boot、原 producer/source-domain 成员关系和实际 current known-live generation；不能在整个 read 后仅重新 fstat 旧 fd 数字，也不能复制 closed 布尔值来签闭合。异常 read 不销毁 reader/value/原库存引用，未关闭/未知资源仍 pending。

原 `_fields` STA_INFO PAD33 窄例外、nl80211 ABI/认证 peer/固定 GET 序列、三轮 interface 与两轮 station、两个真实 Proc 观测、原 byte/time/message budgets、最终截止检查、exact authenticate 门禁均保留。没有 launch、RF、Store、锁、任意命令或 IP authority。

## 唯一新 HOST 回执

`python -m unittest discover -s tests -p test_client_kernel_connect_v15.py -v`

工具 `446344`：`Ran 8 tests in 0.029s`，`OK`，exit 0。首批无 FAIL/ERROR；旧 v13 19 方法及旧 source-check/设备测试未重跑。本批是实际 v15 class / 实际 ProcReader over FakeIo/FakeFs，使用旧测试文件中的 fixture 与 OS/socket tripwire 定义，不继承旧 TestCase 方法，不执行旧方法。

八个新方法覆盖：纯 ctor/严格输入；默认 None 与显式 False/共享 min end/确切发行源；True、非 bool 与 BaseException sticky；send 前取消及 finally 无 poll/无重复 close；recv 后 raw/ancillary 留存；真实 Proc 返回后取消的 value/库存；截止前/恰到/晚回及收据登记失败；原 whole SHA、Python 3.5 AST 和未改协议函数 AST。原公开生产可用性始终 False。

本文件记录的是 SOURCE + Fake HOST 证据；不证明实际同步取消、实际 kernel 结果、实际 FD generation 接线、关联成功、无线恢复或完整互传。三源冻结后由 ROOT/其他 agent 独立全文审查；本作者不自签实际准入，不执行设备操作或打包。
