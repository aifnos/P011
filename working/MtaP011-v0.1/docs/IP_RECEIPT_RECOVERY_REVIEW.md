# 确认收据的 IPv4 剩余增量：纯 HOST 检查组件

2026-10-01；仅新增 `runtime/mta_ip_receipt_recovery.py`、`tests/test_ip_receipt_recovery.py` 与本文。
没有 socket/Popen/ADB、系统网络操作、地址/路由删除、journal 修改、候选冻结或真实恢复；旧 V9、IP helper、生产 State/gate 与历史 FAIL 不改。
这个组件提供 **supplied records 的检查事实，不提供恢复授权**，不得接入普通 create/restore 或 State 作为缺路由的自动回退。

## 固定依据与失败事实

- 旧 IPv4 core `mta_ip.py` SHA256 `1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5`；旧 helper `mta_ip_lease.py` 为 `39373dba355557ee73cfac354bdbaa95eaf0ddde4e27313450edf0e74742f12c`。
- 固定 V9 runtime SHA256 `cfe24fba81332082d4033e148578ac088e07e7efce0ab037f499a40e887901fb`；本次只读完整相关生命周期/快照/恢复代码，无源码修改。
- `logs/MtaP011-DeviceP2pV9Bounded-20261001-084811-e064eae6/result.json` 实际记录 GO_IP_READY、IP confirmed，但 cleanup=false、owned netdev/IP/pending 未清。原厂/原 STA/原 IPv6 保持，不是完整恢复 PASS。
- 当次 14-trial stdout 仅 ready+cleanup、stderr 0B；restore 捕获所有异常为 ip_ok=false，没有保存恢复阶段/errno。不能从该日志确定失败属于预算、gate、dump 或严格 delta；停止后路由形状也不能倒推停止入口的形状。
- 旧 helper `without_owned` 要求精确完整地址 **及四条预期路由全部在场**。本组件仅另外检查“已确认收据 + 当前精确子集 + 减去子集后全基线相同”，不降低旧 helper 要求，也不把当前地址形状推断为归属。

## 唯一 API：inspect_receipt_delta(current, original_baseline, record, owned)

输入 `current`/`original_baseline` 必须是 exact `core.IpSnapshot`；三个容器必须 exact tuple、每行 exact AddressRecord/RouteRecord/RuleRecord。cacheinfo、metrics 与 nested metrics 必须不可变且严格形状；无效 shape 只报固定 `invalid_snapshot`，不会格式化输入或异常文本。
通过旧 helper 严格 round-trip decoder 再核所有界限、重复、永久/无限生命周期与默认三条 policy rules。**所有 cacheinfo 四字段保留并比较**，不使用 structural_key，不略过 cstamp/tstamp/flags/label/broadcast 或全表 route 字段。
`record` 仅可 confirmed/delete_intent，receipt_fsynced 必须 exact True；调用固定旧 `_validate_receipt` 和 `_expected_routes`。create_intent/receipt_recorded/restored、未知/不完整/非持久收据不能授予任何事实。

检查顺序：

1. 原 IPv4 基线不得包含该 owned ifindex 的地址或路由；它不是原接口 origin 的硬件证明，后者仍由执行端核实。
2. 若当前完整快照已等于原基线，返回 `baseline_already_equal`，地址 None、路由空 tuple；只是单独只读事实，不发送删除，也不认为已清 journal/接口。
3. 否则 owned ifindex 上必须恰好一个 IPv4 地址，完整 AddressRecord 必须与已确认 receipt 相等；缺地址但有剩余 route、额外地址、时间戳/flags 变化全部拒绝。
4. 所有 oif=owned ifindex 的 route 必须是 `_expected_routes` 四项的 **无重复精确子集（0..4项）**；陌生 table/protocol/scope/type/flags/gateway/priority/prefsrc/metrics/default/额外行全部拒绝。
5. 只减去该精确地址和实际出现的 expected 子集；其余 **全部地址、所有 route table 的完整 route、所有 policy rules** 必须与原完整基线相同。foreign delta、缺失原行、重复或未知字段 fail closed。
6. 返回 `ReceiptDeltaFacts`：私有不可变 receipt_address、remaining_owned_routes、baseline_view 与固定 state/receipt_stage。repr/str 不含地址/接口；输入 receipt/journal/快照没有被写改。

`facts.status()` 只返回新固定字典：evidence=`supplied_ipv4_records_only`、state、receipt_stage、地址是否在场、expected present/missing 数量、full_ipv4_baseline_equal_after_subtraction=true、write_authorized=false、recovery_performed=false。
字典没有 IP/MAC/接口名/请求或凭据；修改返回字典不会改变 facts。该 API 没有接口/地址/路由删除方法，也不构造恢复事务。

## 真正执行端不可省略的门禁（尚未实现/执行）

- 只能 root 另行评审的 **当前固定候选 + 当前 exact journal**：完整 manifest/7 pins/private namespace、same boot、pending 当前 identity、fsync 收据与原 baseline 严格核实；不迁移/删除未知历史、不自动 retry/recover。
- 同一 device guard 和 journal 锁、唯一 mutation actor；锁内 fresh 读取 journal/阶段/receipt，不复用等待锁前的状态。实际 controller/watchdog/trial actors gone，PID存在但不可读/复用不是 gone。
- 实际 phy/WDEV/ifindex/name/source receipt 相同、原 baseline 无此对象、当前 type/flags/sysfs 读回；原厂 hashes/原 STA full status、进程身份、全部接口/原 IPv6与非IP基线相同；owned IPv6只准已审 linklocal/精确 mroute profile。
- 使用来自 authenticated kernel、完整且稳定的当前 all-IPv4 dump；本组件不证明 packet sender、鲜度、两个 dump 一致或源快照原子性。每个发送/ACK边界前重新读回这些门禁与完整 delta，不能用早先 bool 当授权。
- 只构造 fixed receipt 地址的 exact DELADDR；前写 durable delete_intent，真实 ACK与后读回全 IPv4原基线均通过才写 restored。未知 ACK/地址变化/foreign delta 保留 pending，不靠删 netdev 顺带消除不明地址。
- IP 恢复之后才能按旧 exact-owned origin/actual controller-gone/安全 L3/原全基线门禁删除该 netdev；最后独立证明 iface/地址/routes/actors/原基线及 pending 都清。禁止 flush、改原网、停 service、sysctl、重启。

## 预算与锁：源码风险，不是本轮根因判定

旧 helper RECOVERY_SECONDS=5.0。confirmed 普通 restore 成功路径有三次 fresh_gate；各 gate 的 backend.snapshot 含原 wpa_cli、/proc、nl80211 与一次 stable_snapshot。连同 current/fresh/after，总计六次 IPv4 stable_snapshot（36个 dump 请求）。原 wpa_cli 单次可耗剩余预算，/proc/额外 nl80211/GETADDR 并非都受同一 deadline 抢占；5秒预算不足是风险，不是现日志已证原因。
DeviceGuard 继承同 FD 且 acquire 在 fd 存在时直接返回，未发现该路径自身 flock 重入死锁。JournalLock 另 open 串行父/watchdog，sublease save 使用 locked=True，不嵌套取同 journal 锁。
但 watchdog recover 在取得 JournalLock 前读取 state，stop 只对 current=reconciled 分支刷新 self.state；其他清理阶段存在旧 state 覆盖新 ip阶段的静态窗口。此处不是已证本轮因果；独立恢复须锁内再读当前收据，不能并发旧恢复 actor。
未来有界恢复预算由 root 显式评审，不能仅放宽时间就声称修好；保留所有 fresh 完整门禁、阶段固定诊断、实际 FD/child关闭与失败 pending。本文不改普通 restore 或其时限。

## 本次实际专项 HOST 证据

命令：`python -B -m unittest discover -s tests -p test_ip_receipt_recovery.py -v`（仅新增专项）。后述阶段捕获补强前为 **53 tests，0.020s，OK，host exit=0**，工具记录 `268236`；Python 3.5 AST 检查包含在专项中。
覆盖全部16种 expected route子集、confirmed/delete_intent/原基线已相同、缺地址/foreign delta、完整 cacheinfo/flags/原 routes/rules、重复、可变容器/非row/metrics、固定错误/public无标识、不可变 facts、禁止 socket/transport/write调用。
首次记录 `276deb` 为53项中一个 fixture失败：`SPEC.address | 254` 与原 broadcast 实际相同，未形成负例；仅修该合成fixture为 broadcast-1，生产判定未为通过测试而放宽。首次输出保留，不改历史设备 FAIL。
旧 helper 的单项测试仍确认 without_owned 对仅一条 route拒绝；旧 core/helper SHA断言通过。这里只检查合成 records；没有把 actual剩余收据、P011导入/恢复、原网清理或手机验收标为 PASS。

## 审查补强：不重读可变输入的阶段

root/独立 UI 审查发现 return 两分支在完成验证后仍读 `record['stage']`。现入口先捕获 receipt_stage scalar，要求 exact str 且仅 confirmed/delete_intent，再照原样调用旧严格 `_validate_receipt`；之后 facts 两分支只用已捕获值，不重读外部可变字典。
新增 HOST fixture 在 `_full_snapshot` 时由 fixture 自己把外部 stage 改成 secret/future 值，覆盖两合法初始阶段和两返回分支；facts/public 仍只保留入口捕获的固定阶段。另验 bool/list/None/int/str subclass 不作为合法阶段。组件本身仍不写输入。
这不是 API 线程安全、原子快照或持久恢复授权承诺；其它字段/真实 journal 仍由执行端 shared lock、fresh 私有完整记录及每次写前门禁负责。旧 helper/V9/core 全部不动。
单次受影响专项最终 **55 tests，0.023s，OK，host exit=0**，工具记录 `8d62cb`，AST3.5/原 helper/core pins 检查仍在内；不重跑全套/设备。
本轮最终 runtime SHA256 `630d474c90b7c2a7da802376d8f4b4350b1f82291ca734fa3743d2afe1770f12`，tests SHA256 `9cdac70a3ec6941d3fa908d7fce433cc0514ab8e163dff13bed8ebfd2ff755eb`；本文最终 SHA 由交付消息另列，避免自引用。
