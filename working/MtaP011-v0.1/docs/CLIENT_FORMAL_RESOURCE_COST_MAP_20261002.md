# CLIENT 正式资源成本与下一 patch 顺序（2026-10-02）

PC-only 设计，供 ROOT 审定；未改源/test，未运行方法、OS/设备或网络。已读 ROOT 草案 `CLIENT_FORMAL_RESOURCE_NEXT_20261002.md`、v19 Provider/F、v18 core/Store及原 manifest 指定的 v11 FILES/Coord、v8 Pending、v12 TwoPhaseLease；依赖 hash 与原 manifest 相符。v21 direct-proof actor 的 ROOT 修订另行审定。

## 1. 精确成本：计发行历史，不是同时打开的 FD 数

以下只算既有 Journal/marker、正常原 owner/CAS、没有预算先阻断的路径。`C` 表示 Provider `_connection_context`；`F` 表示成功 `read_association_receipt` 的完整 fresh。marker/proc 的实际打开不属于 FILES 库存。

| 调用与实际来源 | Store.current / FILES 打开票据增量 | 其他原件与边界 |
| --- | --- | --- |
| Store.current（v18 Store:578） | 1 / 1 | `_read_exact→files.read_current` 发行新 CanonicalRecord；当前 canonical 更新，原 lease.record/baseline 不换 |
| Lease._fresh（v18 core:854） | 1 / 2 | 第二次是 `pending_matches→_read_exact`，所以发行两个 canonical；不是 current 自身打开两次 |
| C（v19 Provider:1013） | 1 / 2 | 原 executor、controller 各新 proc observation；`_origin_exact→legacy interfaces` 再发一个 kernel request；不新增 legacy socket |
| full _Connection._fresh（v19 Connection:205） | 2 / 4 | C 加一次 Lease._baseline 的 _fresh；新增一个 collector，另核全部 stock actors |
| 常规 Lease._save（core:868、Store:678、FILES:451） | 1 / 9 | 先 fresh 2，Store publish 6，最后 pending_matches 1；publish 的 FILES.commit 含两次 CAS、temp、readback 共 4 次打开 |
| 首次 prepared _save：原 Journal 不存在 | 1 / 7 | absent current不打开；publish 3，bind_files 2，绑定后 readback 1，pending_matches 1；另计 FILES anchors普通4/固定alias6及 marker自身FD |
| F：三 drain 均首 recv EAGAIN、两 STATUS 单包成功（Connection:309） | 22 / 44 | C=20：STATUS 6、full fresh 2、kernel 4、caps 4、drain 3、末 fresh 1；另两 baseline._fresh。新增 kernel/caps/collector/receipt=2/2/2/1，read_current 发行 44 canonical |

F 内每个 drain 事件再加2C、2 current、4 FILES 打开；原全 operation events≤64、ctrl packets≤128一起记账。receipt入口/出口鉴别是纯内存，不是第二F。marker.verify不打开FILES Journal，但每次 `_binding_live` 有两次真实 read_self；proc task/stock actors、collector status/rights、kernel内部资源使FD/字节量依数据变化，完整总量 **unknown**，不能拿FILES数代替。

成功F的44张Journal票据均close-once后闭合；kernel/caps/collector及proc的临时资源也应已闭合，但原件、canonical/解码Journal、raw与FD证据仍占历史成本。基础FILES anchors普通4/alias6、Coord6/8及handoff新Journal、marker、legacy socket、ctrl/event、子进程/管道的still-open成本另计，完整总量unknown。

最短活跃 DORA 序：open 3 guard/F（factory 前、后、DISCOVER send）→Offer poll 3（recv 前/后、REQUEST send）→ACK poll 2→candidate 1→validate_live 1，共 **10F**。空 poll 也要 2F；重发再 1F。DORA-only 静默路径因而需 220 current、440 FILES opens/issued canonical、20 kernel、20 caps、20 collector、10 receipt，至少 400 Provider proc calls及200 legacy requests，尚未计 INIT/CONNECT/恢复。

actual INIT来自 v12 TwoPhaseLease.start:292：准备期≤20，首次持久Journal前设置一次active deadline；**caps已有两次**，collector含initial、prior producer、四次baseline共6。CONNECT另有caps2/kernel2/receipt1、四次full baseline。最短DORA前后至少caps24/kernel22/receipt11/collector30；正常清理再新增至少7 collector，总下限≥37。全过程FILES/loader/launch/字节总量仍unknown。HOST `8b7fbe` **4/4/2/256**只属synthetic-ready fixture的open第2fresh首个FILES失败，未发DISCOVER，不是完整INIT/设备定位。4.17秒是单collector；5秒上限不保证双轮F完成，不强制抢占同步IO。

## 2. 有限组合 owner + 独立清理额度，而不是单改常量

建议隔离 **DORA-only formal profile草案**：准备≤20秒；首次持久Journal前一次设置网络绝对期≤300秒；最多8 poll，原DISCOVER/REQUEST合计≤6 send，只准一次candidate和一次validate_live，故最多26F；proof≤10秒且受绝对期限制。超额撤权，不滚动续期。这是有限尝试，不保证成功，不含IP/传输。P011耗时、payload/对象开销和内存unknown；额度表/测量未齐保持SOURCE-only，后续阶段另补成本再准入。

同原issuer设固定组合owner：FILES、Coord/marker、Provider ledger、proc、collector、kernel、caps、child/launch、DORA producer各一个有界原件组。保留打开前票据、returned-before-check原件、close-once/EBADF及合法owned-FD reuse证据。`CloseProof≤128`计组root，每组仍逐原FD复核，不能以count/allTrue代替。legacy requests64、ledger64、proc512、collector32、FD receipts32768、reader/receipt8按同图改造；26F静默下限1144 FILES票据，不能循环256窗口换issuer。

active/historical分层：已证明关闭的FD可离开active调度，原票据/reader/receipt强引用进有界历史组；历史numeric FD不可再close。未知open/close、晚返回、proof/runner/factory未真返回不得退休。CanonicalRecord registry保原FILES issuer/generation；Store current/candidate/terminal/observations、marker._prepared、receipt context、v21 call history引用的原件不能删，不能用hash/字节相等替代注册。ProcReader复用前也须保存本次原库存/闭合证据，不能只留最后一轮。整代历史只能在全部owner/consumer、marker及device锁终末闭合后释放。

同同步owner锁在创建前预扣网络额度，另设不能借用的 **cleanup≤60秒和资源reserve**：journal读写、四次lease baseline、两次cleanup_origin_ready snapshot、terminal restore producer、proc absence、最终marker/device闭合。上界unknown，推导留额后才准网络。已知超额应在内层创建前拒绝，避免先撞FILES cap再令Store sticky unknown；真正unknown不能洗白。撤权不等于抢占IO，close/status必须数direct proof及晚返回actor。

## 3. 下一 patch 的最小顺序与不可省略的门槛

1. **先隔离单次F的冗余/生命周期设计**：区分纯内存原件鉴别与真实producer，列重复actor/marker/CAS；只评估同锁、无IO/等待间重复核验的事务原件复用。跨IO不能缓存True，双STATUS/kernel/caps/原baseline不能合并。新单次成本未定，先保上表条件数，不以改quota跳过这步。
2. **再定有限profile/credit broker**，保持旧trial不动；补INIT、CONNECT、失败及cleanup上界/字节预算。网络/恢复独立预留，unknown不退票，返回原件先登记。26F只是有限调用候选，额度未齐拒正式准入。
3. **同步改 FILES/Store/Coord/Provider注册/闭合消费者**，保issuer/epochs/OFD/currentCAS、逐FD证据，核canonical advance、reuse、未知/晚返回、direct proof。特别检查v11 Coord普通6+handoff1、alias8+handoff1；v18 Store._inventory_closed:803统一≤7，alias8/9原库存被拒，不能丢prefix票据绕过。
4. **新Journal/codec及部署manifest显式版本**，不隐式迁移v5；可信profile identity、同boot/owner一次network deadline贯通Loader图/精确argv、F、TwoPhase/Lease、Provider._now、watchdog、Parent/State。旧20秒gate不能局部变300；可信owner的cleanup期不续association。binding/claimed request、device OFD、handoff、终末marker不松。
5. **纳活跃DORA producer/票据入F factory与恢复库存**，保容量首因，分别取证超额撤权/pending、完整fresh正向、清理预留耗尽；ROOT的v21 actor修订单独验收。然后才接live ACK→持久IP intent/owned delta→可信endpoint；不用run已关闭的candidate，不默认CLIENT=.1，不升级为RF/原网恢复/手机验收。

本图的精确数字均是条件成立时的源码成本；未执行完整路径。草案采用组合历史保留来协调多门槛，不授权删除历史/调高旧限额，也不代替 ROOT 审定。
