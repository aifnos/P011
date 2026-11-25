# 正式 CLIENT profile 的最小前置（v26 后 SOURCE 路线）

这是源码接点地图，不是 v27 已实现、配额/TTL 已变更或设备通过。由独立只读审查与原成本图整理。v26 仍为 20 秒 trial；原有 source、测试和失败回执保留。目标保持完整双向互传。

更新：v27实际仅完成终末恢复期窄修，正式profile仍未实现。下一里程碑合并正式原活动期与CLIENT动态IP创建/readback/撤销，不能仅凭新profile静态/测试包称进入互传。最小必要是下面7个现文件；Owner v26原ticket期/min-only能力保持，不重构所有29域。

## 为什么不能只把 20 改成 300

需要明确区分三种原期限：准备期一次 ≤20 秒；网络 active 原件一次发放，`0 < until-issued_at ≤300`；独立 cleanup 一次 ≤60 秒。每个局部 IO 只取 `min(原阶段 until, now+原局部上限)`，不续期，也不以重读或 CAS 重新发放网络权限。300 秒仅为候选上限，不是保证耗时或准入依据。

| 当前实际来源 | 必须处理的接点 |
| --- | --- |
| v18 mta_p2p_client_init.py 的 Journal（544 起） | 现 v5 只有 deadline，缺 profile/issued_at。隔离新 schema，在 key/replace/same_journal 中保一次发放原件，旧 v5 不隐式迁移。 |
| v18 mta_client_journal_codec.py（字段表31、decode305起） | 严格 envelope/version/kind/marker/profile；解码旧记录不能自动取得正式权限。 |
| v24 mta_client_resource_budget.py（42、87、272附近） | 当前固定 SOURCE_ONLY profile。在实际 Store 首次 IO 前选固定内部 profile，不接受 HTTP/caller dict；保原 mutex/epoch/issuer、历史原件/计数不退款、unknown 与独立 CLEANUP 额度。 |
| v24 mta_client_store.py（435起、453、679） | `_begin_io` 的剩余≤20、`_budget_slice` 的≤60、首次 Journal ≤20 需分开总期与局部 IO slice。后续 deadline 不变门、普通磁盘/producer短期不放宽。 |
| v12 mta_client_two_phase_lease.py（292起） | 保一次准备期≤20；首次持久 Journal 前发放原 active_until。正式入口扩展的是可信 profile 的活动上限，不是每轮 now+300。 |
| v26 mta_client_linux_provider.py（576、637、1105、1977、2033附近） | `_now(deadline)` 仍要求剩余≤20；区分总期限验证/局部切片。specs 固定 watchdog `--ttl 20`；新 absolute-until 必须绑定原 Owner/ChildTicket。restore 的独立≤60和撤网络/CLEANUP保持。 |
| v26 mta_client_executor.py | run/main/精确 argv、deployment 来源图与 profile 一致；bootstrap10不是活动期。watchdog 当前使用自己的 before+ttl，正式通道须消费原 Journal until。F 保 early pure Store、start latch、历史闭合及一次 recovery_until。 |
| v26 ParentExecutor | start 精确 argv 与 profile 同步；finish ≤90先关 stdin 请求恢复，再 wait/reap/absence/EOF，并非活动等待，不能改 finish(300) 冒充长租约。 |

v26 终末 Provider 检查曾把 60 秒总期直接传给最多 20 秒局部接口，已隔离窄修；这也说明这些期限不是可互换的数字。

watchdog实际接点：Provider.assemble在首次Journal前已调用specs并存入bridge.specs；仅改F.watchdog不够。需在原Journal已持久化、watchdog注册前，一次绑定携原active_until的精确LaunchSpec，Owner.register继续传actual.deadline，之后不允许替换或重新发放期限。

## 固定次数与容量

DORA 的 proof 总上限26已有前IO拒绝，`run_sync`仍为while True；需把有限预算与实际producer计数对应，保原默认DISCOVER/REQUEST各最多3次（合计≤6 send）和一次candidate/validate_live。成本图“8 poll”仅为候选成本上限，不是MTA/手机协议事实；每poll涉及fresh proof，直接8×.2秒可能提前拒绝迟到OFFER/ACK，不能未经延迟证据硬写这个数字或扩大26原proof额度。现局部proof/poll/锁上限不因网络总期300而自动延长。

完整资源容量、物理 payload、heap 和 P011 实际时延仍须分别核证。已有 HOST 数量或某个闭合原语不能签整个正式资源 profile；也不能先做只会拒绝的空壳便称容量解决。

## 下一最小实现

1. 隔离新 Journal/codec 与固定内部 profile，实接 Store 的阶段期限切片合同；不改旧 trial 来源。
2. 新方法覆盖非法跨度、foreign issuer、重复发放、CAS/重读不续期、到期前拒绝、active 已过期但独立 cleanup 可用、unknown/额度保留。
3. 将原until接到watchdog/Parent的受认证阶段通道，复用Owner已有min-only绝对期，并对应DORA实际有限预算与当前正向流程；不更换跨进程锁语义。
4. 同里程碑接仍活跃ACK的动态IP intent、owned地址ACK/readback与撤销、原baseline恢复。现GO静态`mta_ip_lease.py`不能直接套CLIENT ACK；复用Netlink底层但使用动态IP adapter。初版不添加系统默认路由/DNS。随后可信单文件端点、GO/State/文件中心与真实笔端/手机验收。

参考 [原资源成本图](CLIENT_FORMAL_RESOURCE_COST_MAP_20261002.md)、[资源包络与遗漏](CLIENT_RESOURCE_UPPER_BOUNDS_V23.md)、[v26阶段记录](../results/client-formal-v26-root-review-20261002/README.md)。本地图未执行方法、CMD、target、设备或网络，不构成正式 profile 实现或发布。
