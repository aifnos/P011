# GO live-owner v71：第一真实发送来源子片

本候选仅完成 SOURCE 拆分：显式 `GoBootstrap.prepare_live()` 在原单线程、原 owner、原绝对 `until` 下准备 GO，返回同一个 owner，不立刻恢复。默认 `run()` 仍在 `finally` 中调用原单次 `restore()`。它不是发送 provider，也不发行 NetworkReceipt、AssociationReceipt、IP/DHCP、ready 或手机兼容结论。

## 固定来源

- 祖先：`candidate/go-baseline-budget-v58/runtime/mta_go_bootstrap.py`，17396 B，SHA-256 `de98101c6c56661b9557cf2f857645ff5ecefa3d7663e58c4ebe1fd16187035d`。
- 新源：`runtime/mta_go_bootstrap.py`，18394 B，SHA-256 `e15a99747fc6b3fd47a0c714fdec45dd815ad377737183078fbc9809d041a442`。
- 当前实际 GO64 资产图仍是 `host/go_fresh_boundary_v62_source_manifest.json`，3955 B，SHA-256 `b959ae92e6ef048b3724e716e09503a7607f0b07e6eef5f4e14be71bd545e842`。本候选不修改或替换该图、任何 Loader、F、Native、Store、preparer 或设备入口。

## 唯一控制流变化

`prepare_live()` 的原 `_owner()` / `already_started` 拒绝在 `try` 外；重复调用不重新准备，不触发恢复，也不覆盖之前的 failure。首次设置 `started=True` 后，原准备顺序和局部预算逐项保留：baseline 15 → watchdog → config 5 → channel 10 → interface 20 → controller → group 20。原 Store intent/publication、CREATE ACK/ECHO/readback、控制通道、GROUP_ADD、事件和 STATUS 调用未改。

原 `group_confirmed=True` 后，新增检查只消费同一个原 `group_until`：`_cancelled(group_until)` → `_owner()` → `return self`；没有计算新的期限。准备段失败保存原异常到 `self.failure`，设置 `stop_requested=True` 并 bare raise，不在此入口恢复。调用方必须在调用前强引用保存实际 owner，并在同一个原 worker 的 `finally` 中调用原 `restore()`；本文件尚未提供该新的外部调用方。

`run()` 保留外层原 `_owner()` / `already_started` 拒绝，随后调用公共 `prepare_live()`，并无条件进入原 `finally restore()`；重复 start 在该 `try` 前拒绝，所以不会错误触发恢复或重试。公共入口带来一次额外的起始 `_owner()` 认证，未省略任何来源门。原 return 判据不变。`restore()` 及其 unknown/pending/单次 cleanup 规则、其他既有方法和 `status()` 的所有 ready=False 原文保留。

## 期限、后续边界和证据

原 owner/session `until`、局部 `_stage min(original_until, now + seconds)`、一次 cleanup 60 秒均不变。没有把局部 group 20 秒当成长期服务授权，没有滚动续期。后续 typed IP/DHCP 必须单独合入当前图，不能直接退回旧 v43 Bootstrap/Store 替代已审的当前来源；旧 DHCP 的一次局部 20 秒服务期也不等同于 sender 的绝对会话期限。

当前只进行了文本读取、apply_patch 新文件生成、原件/新件 SHA-256 和窄文本差异核对。没有 AST、import、候选执行、HOST 方法、部署、ADB、RF、真实恢复或手机收发证据；SOURCE 交付不自签 PASS。GO64 原 wholeFAIL/pending 历史以及所有冻结源码、图和日志均保持。
