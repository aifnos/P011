# CLIENT v23 资源发行上界与有限准入草案（2026-10-02）

PC-only SOURCE 推导，供 ROOT 审定；本任务只新增此文档，未改源/test、未运行方法/候选/checker、未执行 OS/设备/网络。基点为 v22 Store `a829dfd1…c97ab`、v19 Provider `58a55789…e1e71` / Connection `ae293225…f159` / F `9e4f0a4c…016cf2`、v18 core/codec、v21 DORA `0a0e5217…db083d` 及 adapter `79442167…003a0`，其余实际 v11/v8/v12/v6/v16 依赖保持原图。这里的“完整路径”仅到活跃 ACK/candidate-current 与一次失败清理，不含配置 IP、端点、GO、正式 F 的 DORA 恢复库存或设备验收。

## 1. 先固定调用图，再算累计原件

条件：新 operation、原 Journal 起初不存在；同 owner/issuer/锁域；最多一次 INIT/CONNECT/cleanup，不额外 disconnect/readback；所有直接 capsule.proof 与负向/超时 producer 都计尝试。拟议 `F≤26` 是新 broker 要强制的 **完整 association fresh 尝试数**，当前 v21 自身并未实现此上限。8 poll、6 send（含原 DISCOVER/REQUEST）、一次 candidate、一次 validate_live 的宽式为 `3+2*8+5+1+1=26F`；最短正常 DORA 是 10F。原同步 IO 不可强制抢占，时间限制不能替代次数上限。

定义：`Q≤64` 为 CONNECT group-wait 循环尝试（含 timeout）；`G` 为其中返回且登记的 group 消息；`Ec` 为 CONNECT pregroup/observe 三 drain 的事件；`Ed` 为后续 F 的 drain 事件。全 operation `G+Ec+Ed≤64`，control packets≤128；末次失败收到但未登记的事件不授权继续，按一个失败前缀封存。`A=4`（普通 FILES anchors）或 `6`（固定 alias）。`C` 是真实 Provider._connection_context，而不是缓存的 True。

| 分段、已读实际接点 | FILES 累计打开票据 / issued CanonicalRecord | 其他累计发行 |
| --- | --- | --- |
| INIT：v12 TwoPhaseLease.start:292 / _role:247 | `A+95 / 71` | collector6、caps2；已有首次 family/interface/CREATE 等 legacy requests6；绝不能从 synthetic-ready fixture 的 caps0 起算 |
| CONNECT：v19 Connection.run:240 | `2Cc+28 / 2Cc+22`，`Cc=60+2Q+G+2Ec` | collector4、kernel2、caps2、receipt1；每 C 又有 legacy request1 与 Provider executor/controller proc 各1 |
| 后续 `F` 次 read_association_receipt | `44F+4Ed / 44F+4Ed`，`Cd=20F+2Ed` | collector/kernel/caps 各2F，receipt≤F；原双 STATUS、双 kernel/caps、双完整 baseline、末 current 全保留 |
| 正常完整 cleanup：v19 Lease.restore:1710 / v22 Store.finish:939 | 已持 Journal `37 / 26`；需原 handoff 再 `+1 / +1` | collector9：四次 lease baseline、两次 cleanup_origin_ready、**三次**独立 restore producer；legacy requests5，caps/kernel/association receipt0 |

发行细节：每 C 的 Lease._fresh 是 `Store.current` 一次加 `pending_matches` 一次，共2 FILES/2 canonical；full fresh 另 baseline._fresh。常规 _save 为9打开/6 canonical；首次 prepared 为7/4；每 Store.current 只开一次 Journal，更新 actual canonical，不替换原 lease.record/baseline。INIT=prepared7+其余7save×9+两role额外6fresh×2+两bridge.prepare current+四baseline×2+interface fresh×2+active_return1，再加 A。cleanup=initial current+pending2、两save18、四baseline8、terminal publish6、terminal callback current1、两 sealed internal readback2；这两次不发行 canonical。正常持久 generation 共13（INIT8+association2+cleanup3），不是每次 fresh 加版本。

合计（已 held）：`Nfiles=A+280+4Q+2G+4(Ec+Ed)+44F`；需 handoff再+1。`Ncanonical=239+4Q+2G+4(Ec+Ed)+44F`；需 handoff再+1。`NStore.current=97+2Q+G+2(Ec+Ed)+22F`（含 INIT 三次 empty current），≤925。用独立原硬门槛作保守放宽：`Ctotal=Cc+Cd≤836`、FILES≤1943（alias/需handoff）、issued canonical≤1896、collector≤71、kernel≤54、caps≤56、receipt≤27、legacy requests≤847。成功时 packets=`13+2F+G+Ec+Ed`，所以128还能收紧；此处不依赖收紧而误把 quiet 下限当准入。

以上是固定图的条件源码成本/安全包络，不是本轮实测。已知生产合同下的负向返回、超时与取消只走前缀及一次 cleanup；额外外部 readback/proof/restore 重入不属于此包络，须在入口计数并撤权。unknown open/close/returned-boxing 仍保原件与 pending，不保证上述成功收据。HOST `8b7fbe` 的 first open 第2fresh **4/4/2/256**仅是 synthetic-ready fixture 首因；实际完整 INIT/CONNECT 还可能先撞 legacy64、proc512/collector32 或 TTL，未定位设备首因。

## 2. 全物理 FD、字节及闭合图：不能只算 FILES

Provider._proc_calls 的宽式为 `2Ctotal +32*(13+2F)+6*(19+2F)+12 ≤4190`：original_actors最多32，调用最多65次；每 collector **最多6次** _private_pids（两 baseline /proc 枚举，以及两个认证 STATUS 的各前后 LinuxStatusSource 枚举）；独立 INIT/live/stop/absence/executor ≤12。该式只覆盖 Provider 表，不含 Pending/Owner/collector/source 内部 ProcReader。

| 原 namespace / SOURCE 局部门槛 | 可保证的静态包络与明确缺口 |
| --- | --- |
| 每 ProcReader operation | physical issuance≤280；successful actor两pass若 T tasks为 `10+2T` 个文件；payload≤2MiB，拒超额末次 retained raw另容32769B。Pending._binding_live 前后各真实 read_self，Owner._single/resolve/fresh_exit、STATUS source 另计，不能并入4190 |
| 一个 v16 KernelReader | 原 ifindex两票+socket一票，前后两 ProcReader：≤`3+2*280=563` physical；正常 _kernel_closed_facts=5个逻辑fact（3resources+2proc rows）。自己的 close-receipts1024够单reader，不证明全 Provider32768足够 |
| 一个 actual v6/authenticated collector | own tickets≤8320；成功 baseline ProcObs≤72，另两 status source 各actor_calls≤8。失败时 `_actors`末尾才查 actors≤32，可先枚举4096 tracked/round；保守 baseline Proc尝试≤`4+4*4096=16388`，不能用成功72当失败上限。每STATUS还有≤2*512 source文件票、8*280 proc票、1socket及≤253 rights，故含失败的宽 physical式≤`8320+16388*280+2*(2*512+8*280+1+253)`；不是同时开着这么多FD，也不是当前全历史已登记 |
| caps / legacy / control | caps每reader ledger socket1，payload≤1MiB+65537B失败尾包；legacy每request≤64 recv，按真实recv合同 payload≤1MiB+262144B，故整个保守 `64J` packets及`J*(1MiB+262144B)` payload；当前没有全累计bytes cap。ctrl128/events64只限票数，仍需按actual bytes及rights前置 charge |
| FILES/Coord/marker/child/C注册 | FILES历史1943与同时known-open不同：正常本组件仅 A anchors+一个Journal或temp；unknown另封存。Coord普通6+handoff1、alias8+handoff1由 v22 exact helper支持，不能退休prefix；marker自身1原票。两子操作各≤16 FD、C registry≤32，Owner resolve每role≤16；Owner/Pending共享reader重复轮次的全历史FD/readout数 **未完全封口** |

当前 ProcReader._begin 会重置 `_fd_refs/_raw`，collector._observations只留观察值，Provider/bridge 捕获也有“最后一轮”接点：正式组必须在 **每轮返回/异常且下一轮 reset前** 留 exact原 readout、FD tuple/creation ticket、立即 EBADF证据和独立 generation；不能把同reader/同数字FD误当同一次原件。`MAX_FD_RECEIPTS=32768`计 `(io,fd,owner)` unique原件组合，不是 logical facts；完整图未补这些 namespace 前，不能宣布全物理发行上界或闭合完备。当前 _proof 的完全正常形状可达 `1proc组+71collector+56caps+54*5kernel+1ledger+2child=401facts`，超过 CloseProof128；需按原注册类别组/≤128叶片分片，组内仍逐 original FD/type/closed/unknown/EBADF与合法 current-owned reuse核验，不接受 caller allTrue。

每 issued canonical actual data≤131072B，1896份仅 raw就可达约237MiB，尚有解码 Journal/Snapshot、metadata/list/hash/actor/proof/callback历史；caps/legacy/collector/proc还更大。binary全文/parts+join是临时峰值而非仅digest；异常 traceback也可能保帧。故上述局部MAX相乘只是有限payload宽界，**不构成 armv7 heap 可用上界**。需要 HOST测每类真实对象布局/多份副本/异常峰值，并给每producer retained+scratch上限；最终 arm设备余量/耗时另验。4.17s只是单collector，不是双collector F；5s callback上限不证明真实完整fresh能在5s内完成。

## 3. 可执行下一 patch：有限组合 owner，不能只放大 MAX256

计数候选 profile（不是已准入成品）：同issuer history FILES2048、canonical2048、collector80、kernel64、caps64、receipt32、Provider proc8192、legacy request1024及packet65536；保 ctrl128/events64/Q64/F26，child/C/Coord固定原layout不变。这些覆盖上面 **原图** 的宽界并留小量失败槽；active FD另计（可保持256），关闭只退active，不退历史原件额度。超大/proc重复tracked环境须在逐observation预占槽时有限拒绝，不能在原MAX8320全部做完后才当已准入。具体全namespace/bytes表未齐前，此组数不得单独宣告可用。

1. 先在真实 producer入口统一同步 owner broker，严格登记 operation/provider/store/locks/issuer/epochs/profile与每轮generation；完整fresh尝试、控制事件/packet、Provider及Pending/Owner/source内部readout、creation、actual bytes全部计账。无IO/等待间纯内存比较可局部复用，跨IO True、原双STATUS/kernel/caps/baseline/currentCAS不得删。信用不足在 Store事务/创建前拒绝，避免先撞 FILES cap再把 Store sticky unknown；真正unknown仍不可清洗。
2. 同时接 FILES发行历史与 Store exact canonical/observations登记，保2048张原件强引用及所有data/metadata/generation；不换issuer开256窗口、不删已闭票、不用hash替代全bytes/currentCAS。Provider分类组捕获每轮真实原库存，根CloseProof保持128，叶片逐FD；v22普通≤7与alias exact8/9 helper不变。先补完整INIT→CONNECT→10F→cleanup新HOST正向和超额撤权，而非只做 always-deny broker。
3. 网络不得借cleanup reserve。可先留 **FILES40、canonical32、collector10、Provider proc至少192、legacy8** 的正常计数reserve，另必须补 Owner/Pending/source/FD receipts与bytes reserve；192来自四baseline×32 stock+9collector×6 exclude+独立cleanup约6，未覆盖内部reader。按有界producer字节合同 `b_j,b_proc,b_col,b_legacy` 至少预留 `32*b_j+192*b_proc+10*b_col+8*b_legacy+B_owner/pending`，scratch和heap另算。剩余F/事件共享池按剩余原图计算，不把每F都永久扣128未用票；实际已发行/unknown额度不退款，未执行的纯reservation可在原锁域归还。cleanup只一次可信owner绝对≤60s，不续association；unknown/晚actor不得凭reserve强称恢复。
4. count通过之后才定可信有限 per-reader/全累计 bytes与heap profile；正常小payload实际source graph必须能正向走完，超profile环境清楚fail-closed。若要支持26F的真实长路径，旧20s active/首次Journal gate、F/watchdog精确argv与5s proof预算不能局部加长：隔离新Journal/codec/profile版本，一次可信 network deadline贯通实际Loader/F/Lease/Provider/子actor；旧trial与v18/v19 pin保留。候选300s只是先前设计上限，不是耗时承诺，也不授权本轮改TTL。

本轮结论：FILES256阻断有可实现的有限历史/active分账方案；1943/1896是固定调用图的保守计数，不是设备成功或完整heap保证。当前尚缺内部readout全历史注册、累计payload/heap准入、真实proof耗时/正式寿命及DORA恢复库存接线。ROOT应据新正向HOST和各命名空间具体边界审定profile，不将本表的条件成本改写为已恢复/已RF/已接通。
