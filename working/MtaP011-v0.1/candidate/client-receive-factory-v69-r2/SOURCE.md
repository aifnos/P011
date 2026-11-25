# Fixed receive factory v69-r2 — SOURCE-only

父候选 `../client-receive-factory-v69/runtime/mta_client_receive_factory.py`（53,392 bytes，SHA `c79324764247b720653caaa4dd6eb4d175e17e47021a0c5dd9414dd8234e6f00`）和其 SOURCE 说明保持原件，未执行。r2 仅修主控全文源码审查发现的三个出版库存接点，不改变权限、固定 35 源、F37、STATUS/Provider/Store/Loader、Received 根、State/Session/handoff 原期限，或部署文档格式。

1. `_Files.read` 已得到合法原 FD 后，先直接留存首次实际 `fstat` 的 metadata 与 close identity，然后再执行 active-cap postcheck。若 open 迟到，原 FD 仍能走原同线程/同任务 close-only 一次关闭与立即 EBADF；不续期，也不会在过期后开始内容读取。首次 metadata 自身失败/不明仍保 unknown，不能猜身份关闭。
2. `FixedReceiveDeploymentFactory.__call__` 在任何新的 attempt/IO 前检查全部旧 attempt 的原被动闭合票据；任一旧 publication 未闭合即拒绝重用。`status.resource_pending`/`publication_fds_closed` 聚合全部原 attempt，不能只显示最后一个而隐藏旧 unknown。
3. 初次 open 抛 OSError 且没有返回 FD，只在实际 `errno` 为 exact int 且 `1..4095` 时留 known absence；无 errno、bool errno 等保持 unknown/pending。被动 `closed()` 还重新核此原 errno 条件。known absence 不是 close/EBADF 证书。

固定 boot root 与资源 ABI 仍为 `/tmp/p011-mta-state-v69`（真实 fixed alias 对应 `/var/volatile/tmp/p011-mta-state-v69`），State 自身模块在 `runtime`，35 源 assets 独立在 `runtime35`。未来固定 State-side 来源 manifest 的 factory row 应绑定本 r2 源；不修改父源或使用旧 c793 作为当前可执行图。

无参纯构造及 `factory(exact_handoff)`、`closed_publication_facts(factory,exact_handoff)` 的 9-tuple ABI不变：

```
(factory, handoff, actual_attempt, bridge, session, worker, pid, original_closed_owners, True)
```

attempt 为实际 `_PublicationAttempt`；原 cached tuple、每个实际 owner 和 FD row 按 `is` 保留。空库存只表示实际还未建立受管理 owner 的早期拒绝，不制造 handoff、Parent、ready、RF 或恢复权限。异常类 `ReceivePublicationError` 是 `ValueError` 子类，固定原因在 `args[0]`；没有虚构 `.code` 接口。

目录 FD 有意跨越 Loader 的本次读取，供之后的原目录/条目 postverify；内容文件 FD 逐个即时一次关闭。返回 Factory 结果前，profile/source、writer（含目录）和原 Loader 的所有受管理 FD 都必须闭合；不声称“在 Loader 前已经全闭合”。所有原 writer/reader/loader/errors 都留在原 attempt，partial 目录不删除。

实时 profile 仍仅 private deployment data，`profile_data_collected` 不等于 `status_authenticated`。没有新 Proc/STATUS 授权、fork/helper、Parent/claim_frame、Store.acquire 或 receive_available 设置。保守 comm/proc ENOENT 拒绝尚无新模型或设备验证，不能称已测过或已容忍所有进程波动。

作者仅 apply_patch、读取和 hash；没有 AST/import/HOST/设备动作。完整 Factory 正向只能未来实际已准入 handoff，纯 HOST 出版组件或纯 boot 构造不等于生产接收成功。
