# State platform budget v13 — 隔离 SOURCE

仅新增 `candidate/state-platform-budget-v13/mta_service.py`、专项测试和本说明。原 runtime/mta_service.py 固定 `361fc0b6fdacd982c42dd596e01f0f219189e7326055514dc2951a65a9383c5d` 保留；不改 F、Provider、production gate、QML、旧日志或其他源。未执行设备，作者不自签实机恢复或互传。

## 有限恢复契约

原 State 的 Send restore_owned 5 秒、fresh read_restored .2 秒，与平台恢复最长 60 秒及完整鲜读不相容。候选新增 exact immutable `SendRestoreBudget(total,restore,readback)`，默认 75/60/15 秒；私有 constructor 注入，total≤120、restore≤60、readback≤30，全部正有限非 bool，分段和≤总期。非法参数在文件/能力探测前拒绝。HTTP/QML 不接收预算或平台身份，默认 send_available=False 完全不改。

每个真实 operation 的首次恢复建立一个私有原预算 owner，绑定同 State/op/session/provider/lease/SendWorker/SendIntent/ScanHandoff/task 与 operation/native epochs。仅一个绝对 deadline，不在新段、晚回、异常、close/recover 重入中刷新。每段实传 `min(段 cap,绝对总期余量)`；每次返回后核单调有限 clock、同绑定、段期和总期。恢复原 receipt 与 fresh 原 return 先留存，再判断。迟到、clock 回退/异常、owner/epoch 变更、receipt bool/旧模块同名类型、未 reconciled、cached 原 receipt 或未知均 false/pending。

恢复必须仍是候选 exact 新 `SendRestoreReceipt`，同 provider/lease/task/epoch，四个状态必须 `is True`。鲜读每次真的调用 read_restored，且返回不能是 restore 的原对象；没有 cached status 替代。这个 typed 协议只检验协调层，仍不证明底层 kernel/Journal/fsync/source 认证；真实 SenderProvider 尚未接线，不能靠 fixture 成功开放能力。

同 op 只执行一次恢复/鲜读原调用，失败或完成原记录持留；显式后续 close 不重复未知 mutation、不重置期限、不拿旧正 receipt 自动成功。取消不是跳过恢复的许可，不延长期限。已有真实 SendWorker.scope release/extra close/原票据顺序和 TransferSession 外部 finalizer闭合保持原样。

## 真实接口限制

九方法 provider 的原 API 第四/第二参数仍为有限 numeric 秒数，未静默换接口或把 init-only F 当正式发送平台。State 按剩余绝对期传相对段，并作返回后检查；trusted provider 自己必须合作执行该有限预算。当前接口不能抢占卡死调用，本候选不创建超时 kill/detached timer，活 finalizer 始终 pending。

TransferSession 的 cleanup 120 秒 deadline 目前是其 finalizer 私有局部值，没有传给 State callback；本候选总期是恢复块单一总期，不假称和外部 cleanup 是同一个 deadline。外部 Session 仍在每段之后独立检查其 deadline/代数/线程退出，因此 State 合法返回也不自动成为 session closed。若正式平台需要共用整个 cleanup deadline，必须另行审查增加显式 deadline 合同，不能猜私有值或放宽 Session gate。

六个原新 HOST 方法另加一个精确段截止边界方法，使用实际 State/ScanSession/SendWorker/TransferSession，只有外部 IO、crypto、sender、网络 platform 与时钟为 Fake；真实线程退出/闭合次序保留。段期和总期到达即失效（`now >= end`），不允许 deadline 点的返回。没有重跑原 State 或 Sender 套件，没有设备/RF/网络/打包/清理。

## 新方法回执

- 工具 `5af44a`：显式指定原 6 个新方法，`Ran 6 tests in 0.167s`、`OK`、host exit 0。
- 工具 `9376cb`：仅 ROOT 建议的新 `test_exact_phase_deadline_restore_and_fresh_returns_stay_pending` 方法，`Ran 1 test in 0.026s`、`OK`、host exit 0。

7 个不同方法分两批通过，不称为完整 7 方法同批或旧 suite 回归；本专项无首 FAIL/ERROR。测试中的 restore 6 秒和 fresh 1 秒是私有 Fake 单调时钟推进，不是实机耗时。精确边界覆盖恢复段和鲜读段恰到 deadline、晚回原收据留存但 pending、总剩余缩短第二段、clock 回退、同 epoch/task/owner/new receipt、并发 finalizer 活线程和无重入恢复。实际 State 默认仍 send 不可用，Fake 的显式准入不能变成平台验收。

## 精确源改动

对原文件只添加 `math`、exact 私有预算定义/校验、单一 `_SendRestoreBudgetOwner` 和 Operation 强引用槽位，扩展 State constructor 的私有注入，再替换 Send 恢复块。专项 Python 3.5 AST 确认原函数只有 `Operation.__init__`、`State.__init__`、`State._restore_send_owner` 三处变化；所有其他原函数（含 `_send_receipt_exact`、九方法 provider admission、HTTP action/public schema、receive、实际 worker/finalizer链）AST 不变。原 runtime whole-SHA 同时核为本说明首行固定值。源码、测试、文档三 whole-SHA 在最终冻结消息给出，不在文档嵌入自身 hash。
