# CLIENT Store finish：三阶段终结决策

2026-10-01。**DRAFT／待 ROOT 全文审批**；仅源码合同审查，不是实现、测试、恢复授权或部署入口。
本轮只新增本文；未执行测试、文件/锁 I/O 实验、OS/WSL/Docker/ADB/P011/RF，旧源码与历史结果均不改。

## 已确认的冲突与现成范围

`mta_p2p_client_init.py:549–572` 的 ClientInitStore 尚不可用；`:639–659` 要求一次 finish 同时交付完整 reconciled Journal、
`complete == requested_complete`、`pending_retained == not complete` 和 `locks_closed=True`，否则统一设置 pending=True。
`:881–893` 只在整份语义合法后释放原 refs，此保护保留；但统一 pending 布尔无法描述“marker 已删除、最后 FD 关闭未知”。
`ClientPreparationStore`（当前 `mta_client_store.py:283–315`）只有准备/本地独立闭合，不写 pending，也不是完整 Store。
`mta_client_coordination.py:398–451` 只有固定锁/absence观察与原 inventory 闭合；`mta_client_files.py:358–451` 只有安全 journal 发布。
二者现有 pending 检查仍拒绝**任何 entry**，不能通过 monkeypatch 或普通 bool接纳未来自己的 marker。
本次阅读固定 SHA：core `88f16ec4c04d0f17e90ef90b912e3b5a3b1ce1a0a01240329702f4ded796889e`；
preparation `6493ff0af4ab43e3222cf5e73272480b17ce5f7e098c50947a427a5a63696577`；
coordination `4a99ebd453760ff7e1ff8d3ede59f6e01ec75c98c31d6963e2c79c16d844b3c0`；
FILES `21a405410474665fca83ea4216d722a2a27b9ea24812dc71c58dfc2fc826d73b`。

## 选择唯一方案：恢复封印 → own marker 清除 → 原资源关闭

不制造 unlink/close 的原子事务；也不增加 guard、janitor、新 pending namespace 或无限最后引用链。
沿用既定 F/C/D 与同一 `/tmp/p011-mta-p2p-device.lock`、`.pending`；实际继承 OFD、Executor、完整 Store 仍待实现。
内部 RLock/epoch串行化全程，设备/journal实际锁仍持有。finish 开始即封锁普通 start/commit/command/RF，异常后也不解除封印。
仅同一 Finisher获一次内部终末发布/own-clear步骤；不是重新开放普通commit，更不能由caller bool跳过任一验证。
唯一内部有界 Finisher 持有 exact Store、LockSet、FILES、IO、inventory、Journal/marker receipts；不向 HTTP/QML暴露对象或路径。

1. **恢复封印及终末发布。** 只有 core 的既定清理路径已验证完整原 STA/non-IP、全 IPv4地址/所有表routes/rules、IPv6基线，
   owned接口确实不存在；Provider 登记的全部 RF/data/helper/controller/watchdog/线程/pipe/socket等已实际退出及闭合，无未知创建，才可进入。
   F实际wait/reap及整个task absence等合同仍适用；bool、leader Z、回调结束、schema合法均不代替这些事实。
   同锁 fresh核 current完整bytes/身份、当前boot、manifest/pins、actualF/资源归属、own marker完整bytes/inode/nlink与祖先。
   发布 `ready=False` 的终末 Journal（拟沿用 reconciled；审批后的新候选明确其仅表示网络/Provider已恢复，不表示 marker/StoreFD已关）。
   通过 EXCLtemp、file fsync、rename、dir fsync、完整bytes+稳定发布inode读回，保存不可变终末 receipt。
   发布/fsync/readback/临时FD闭合任何未知：不调用 unlink；保留原记录/票据、实际 marker已知或未知观察及 resource_pending。
   封印之后永不恢复 start/commit/RF；该终末记录也不签跨进程 owner、旧 GO恢复或孤儿 waited proof。
2. **仅清自己的当前 marker。** 上述事实全部明确后，再同锁 fresh核 own marker与终末 generation，不由名字/版本/complete布尔推归属。
   在已登记 `/tmp` dirfd下仅 unlink 固定 pending basename一次，dir fsync并严格 ENOENT读回；不递归、不 glob、不删 run/journal/temp。
   unlink调用前记录 attempted；未知返回不重试、不补写marker、不rollback。已读到 absence但 fsync失败必须分别记录 absence与durability unknown。
   旧 GO、陌生/损坏/不可读/非regular/换inode marker永不 unlink；首次 absence不冒充 own marker已创建或已清除。
   stat→unlink没有按inode条件删除的原子CAS：所有受信写者必须共同持同一设备锁；祖先/entry不符即拒绝，恶意root并发不在本可信进程模型内。
3. **原资源关闭。** 不再修改文件或 marker；独立尝试每个已登记 Store原文件/目录锚/journal/device锁引用关闭最多一次，device原FD安排最后。
   不调用 LOCK_UN；不得新开 FD代替原引用、重close未知数字、重新 acquire、重新进入清理或用GC/destructor算关闭。
   整份有效闭合观察必须覆盖 FILES/全部anchors/全部锁inventory，不以原“两lock slots”替代总资源。
   每个 original close正常返回并严格 EBADF读回、无未返回资源或 sticky unknown，才算该资源闭合；BaseException亦独立尝试其它known引用。
   中断/读回/close未知保留 exact强引用和现有终末记录；只读原票据，不能将某数字后来EBADF抹除既有未知。
   该阶段未知只可能涉及已封印 Store文件/锚/锁FD，不能仍有可动作的 RF/Provider actor；否则第二阶段根本不可进入。

## 独立事实与诚实失败语义

| 观测 | marker_state | marker_clear_durability | resource_pending | complete |
| --- | --- | --- | --- | --- |
| 自有marker仍经核验存在，尚未clear | retained_observed | not_attempted | 依真实inventory | False |
| unlink结果或entry读回未知 | unknown | unknown | 依实际inventory闭合证据 | False |
| 严格absence但dir fsync未明确成功 | absent_observed | unknown | 依实际inventory闭合证据 | False |
| clear及dir fsync核验成功，原资源关闭未知 | absent_observed | verified | True | False |
| 终末发布/clear均核验，全部original资源闭合 | absent_observed | verified | False | True |

这些都是相应步骤的观测，绝非对未来目录/网络永久不变的保证；未观测用 unknown，不能填 retained_observed保守地“撒谎”。
marker/durability未知但所有资源确关时，resource_pending可以False，cleanup_unresolved仍True；不能把文件提交未知冒充FD仍存在。
即使 marker absence已明确，资源关闭未知时仍保持 resource_pending=True及logical cleanup_unresolved，禁止下一轮动作；不再名为实际 pending_retained=True。
最后锁关闭未知时，物理锁可能仍阻挡他进程，也可能已释放；不把其中任一情况当已证。当前 Finisher无新 acquire/重close权限。
未来另一个可信 owner仍须真实取得同域设备锁并完成其既定 fresh准入/历史terminal审查；本文不新增自动跨候选admission或清理权限。
若 marker清除后 F死亡，终末 Journal保留的只是清除前恢复事实；读回者仍核同boot/完整归属/actors/基线，不回填未知FD退出码。
`finish(None, False)` 没有记录/没有marker时：如实 absent_observed+not_attempted（或unknown），只关登记资源；不得捏造 retained marker。
此分支不签租约恢复完成/RF成功；取得marker之后的失败则依实际自有marker保留/未知，不伪装成无动作路径。
normal_restored=False时不发布恢复成功终末record、不unlink；保留原record/真实marker状态，仍独立关known Store资源，complete=False。

## 核心/Store最小 diff 建议（待一次授权，本文不实现）

保留原 `finish` 内部入口但将输入 `complete` 语义改为 `normal_restored`（仅 core已验证清理路径供应，非UI或Boolean授权）；
实现内部三阶段，返回一个实例/epoch/current-terminal绑定的不可变 FinishReceipt，不增加进程、额外guard或通用恢复服务。
最小字段建议：`record`、`normal_restored`、`terminal_durable`、`marker_state`、`marker_clear_durability`、`resources_closed`、`resource_pending`、`complete`。
`marker_state`只取上表三值；durability只取 not_attempted/verified/unknown；其余事实严格bool，record仍需完整canonical bytes/身份/generation核验。
validator先核**整个**receipt、终末record或None的允许shape、issuer/epoch及阶段关联，再提交任何 refs释放；invalid receipt/Interrupt仍保留原 exact refs。
`complete`是终末+normal恢复+verified marker clear+完整原资源闭合的合取，不再要求等于输入 normal_restored；合法 partial receipt也要保存真实物理观察。
`resources_closed=True`仅整份语义合法且实际全inventory闭合才允许清相应refs；unknown原锁只能既定只读闭合观察，不换锁或再次finish重close。
将 `_finish_receipt:639–659`、restore `:878–893` 与 no-record `start`失败分支的布尔绑定精确调整；`_pending_admission`不增加历史跨角色接管。
status新增/分列 `normal_restored`、`marker_state`、`resource_pending`、`cleanup_unresolved`；原 `pending_retained`不能继续用 logical pending冒充物理entry。
若保留兼容字段，必须三态 True/False/None对应 retained/absent/unknown并让所有内部消费者显式迁移；优先新候选status使用enum而不假strictbool。
旧 core/codec/schema/历史 GO与旧CLIENT结果不重写；新终末语义须新manifest/明确候选身份，existing receive/send false保持，State不因partial finish开门。
`client_init_ready`封印/终末/未知资源始终False；`cleanup_complete`仍仅严格complete，association/IP/DHCP/data/phone均不升级。
FILES/coordination仅允许另审的 own-marker typed admission接线；PreparationStore本轮继续“不完整Store”，不能适配成忽略pending的代理。

## 官方依据与未验证 ABI

[Linux v4.14 open.c:1061–1098](https://github.com/torvalds/linux/blob/v4.14/fs/open.c#L1061-L1098)：close可报错而文件表项已经释放，故不能盲重关；没有 unlink+close事务。
[locks.c:2367–2428](https://github.com/torvalds/linux/blob/v4.14/fs/locks.c#L2367-L2428)：flock绑定filp且在最后引用清理；原FD闭合不等于继承OFD全集证明。
[sync.c:173–219](https://github.com/torvalds/linux/blob/v4.14/fs/sync.c#L173-L219)：fsync派发到filesystem并可失败，不以调用发生推durable。
来源仅支持设计；固定dirfd/unlinkat、ctypes原型、真实目标filesystem fsync、P011 ABI/同OFD/finalizer退出仍未由本文验证，预算不硬抢占OS调用。
`/tmp`仅same-boot边界，fsync不签跨boot/断电保存；下一步先授权core receipt精确拆分+纯HOST故障模型，再实施真实Store，不先接RF。
本轮没有任何PASS/测试计数；原prepare/FILES/协调锁历史证据不升级成完整Store、实际CLIENT或手机互传。
