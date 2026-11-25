# CLIENT 三阶段 finish：纯 HOST 合同实施审查

2026-10-01。设计依据是 ROOT 已选定 `CLIENT_STORE_FINISH_DECISION.md`（805c2275636d22650e66678bfe852890b59b9f31a39e7e39a56fa54776cdfc9b）。
本轮只改 core/test并新增本文，**待 ROOT 全文复审**；不是实际 Store、pending writer、Linux闭合、RF/手机或部署验收。
没有改 codec、PreparationStore、coordination、FILES、Provider实现、State、旧GO/native或任何历史结果；receive/send保持false。

## 原源码不可覆盖 SOURCE 快照

修改前用正常构建归档生成 `artifacts/SOURCE-client-finish-contract-20261001-88f16ec4-71b46c0d.zip`，存在即拒绝，不覆写。
ZIP完整 SHA `af9541d1419de19e5e7f1f80cd3a92f407e67d64c7af2157b6c81832696eef23`；逐entry完整bytes核 SHA：

| 原文件 | 字节 | 原 SHA-256 |
| --- | ---: | --- |
| mta_p2p_client_init.py | 52982 | 88f16ec4c04d0f17e90ef90b912e3b5a3b1ce1a0a01240329702f4ded796889e |
| test_p2p_client_init.py | 46048 | 71b46c0df2a0ebd384a131f80067c27060dd6c7e04afb418b150d27d0da2e0c3 |
| P2P_CLIENT_INIT_IMPLEMENTATION_REVIEW.md | 17800 | 3f3ac6f1c79d9810691a5065df657c162f9d4842b55255c8bce6816417d6b644 |

原88f16e/71b46c对应81方法及既有分批记录；快照不是部署候选/固件备份，旧49/30/21等批次不重判成当前通过。

## 精确回执与发行者边界

新私有不可变 `FinishReceipt` 绑定 exact Store、LockSet、request_record（允许None）及 Identity；其repr无私有内容。
八事实是 `record`、`normal_restored`、`terminal_durable`、`marker_state`、`clear_durability`、`resources_closed`、`resource_pending`、`complete`。
marker仅 retained_observed/absent_observed/unknown；clear仅 not_attempted/verified/unknown；其余事实严格bool，不能以1/0或自由文本替代。
输入 normal_restored是core已验证的恢复路径结果，不是UI准入。True只允许当前cleanup_verified/reconciled且ready=False；None不能签正常恢复。
whole validator先核类型、全部exact归属、正常恢复与本次输入一致，再核允许的完整record、终末/clear/资源/complete关联。
`_same_journal` 在Journal.key之外还比较原stock和controller/watchdog完整task状态，不能把同PID/start但不同task state视作同记录。
terminal_durable=True要求normal_restored=True且完整对应reconciled终末record；False允许原record，或正常路径已读到终末但持久化尚未知的record。
clear=verified只能对应正常恢复、durable终末、absent_observed；其它观测不能伪签clear。全Store资源闭合和resource_pending不能矛盾。
complete严格合取normal恢复+durable终末+verified clear+absence+全部Store原资源闭合；不再强求complete等于输入normal_restored。
resources_closed涵盖未来Finisher全部Store原文件/anchors/锁inventory；normal_restored额外要求全部Provider资源已退出/闭合及完整原网恢复。
因此Provider恢复失败、marker/durability未知或已清marker但lastclose未知，都可能是合法partial而绝不是complete。

`ClientInitStore.authenticate_finish(locks, request_record, exact_receipt, deadline)` 是新增**不可用的纯合同**，默认store_unavailable。
未来固定/pinned producer必须鉴别自身发行的exact receipt、当前epoch/current record/原inventory和实际读回；typed construction并不自动登记。
Fake Store只以当前issued object/identity/locks做合成发行者检查；未登记同shape副本被拒绝。**issued registry只证明发行者，不证明kernel恢复。**
全部字段与producer认证合法后才提交观察/释放对应refs；invalid semantic/未知认证或BaseException仍保留exact locks、Store及原返回对象。
真正的 file/dir fsync、own-marker验证/unlink/absence、全部FD inventory、同OFD/Executor/finalizer与actualwait/readback都没有在本文件实现。
内部Python类型不是恶意Python代码沙箱；真实受信装配/outer manifest/generation仍是后续Store职责，QML/HTTP不可注入producer或receipt。

## 一次终结与诚实状态

finish调用前注册once/sealed，保留原请求与返回对象；从此该lease的start/restore/recover/_save不能重开锁、再次finish/close或触发Provider/RF。
未知时重调只读原closed_locks；两lock slots的完整读回也不会抹除已sealed的整Store未知、不释放其原refs。
已完成时重调只返回finish_sealed与先前固定事实，零Store/Provider动作；不把重新调用当新恢复证据。
旧的未finish active_return原引用只读合同保留；它不是新整Store闭合或已实现继承OFD证据。
Core依赖未来可信owner/RLock跨方法串行化；本轮不添加线程锁/launcher，也不宣称任意并发调用本类安全。
normal_restored=False不要求Fake发布终末/清marker；无record失败可以如实absence+not_attempted+complete=False，旧GO/未知pending不接管不清。
Provider close之后增加fresh完整无排除baseline检查，再允许cleanup_verified与正常finish；close前快照不是close后事实。

公共 `pending_retained` 明确三态：True=retained_observed，False=absent_observed，None=unknown；不得以logical未完成伪装physical marker存在。
新增marker_state/clear_durability/normal_restored/terminal_durable/resource_pending/cleanup_unresolved/finish_sealed；固定值不输出路径、Actor、token、IP或原异常。
resource_pending表示Store原闭合仍未全部核实（不表示某FD必然还存在）；cleanup_unresolved还包括Provider恢复、terminal/marker/durability与失败试验未完成。
合法partial记录真实physical facts：例如clear已核验但lastclose未知时pending_retained=False，resource_pending=True，cleanup_complete=False，原refs仍在。
callback没交付可认证回执时，marker只报unknown；不能沿用callback前曾观察存在的旧状态，或猜测异常前是否已unlink。
整份合法resources_closed可释放对应Store refs，但写入/marker未知仍不complete并永久sealed；不以新acquire解决durability未知。
sealed之后client_init_ready恒False；association/IP/DHCP/data/phone与receive/send仍False。物理marker观察只指相应读回时点，不保证未来不变。
本core内部原self.pending仅保留logical未完成意义，旧status消费者需按显式enum/三态迁移；此轮没有接真实receive/State或改任何旧schema。
未来其它工具的旧core源pin需要另审更新/使用不可覆盖SOURCE；不能静默用本次新core满足已冻结的88f16e检查器。

## 唯一实际 HOST 专项

因Fake Store全局finish合同与所有恢复fixture迁移，ROOT授权执行完整**该专项**，不是项目全套或硬件测试。
命令 `python -B -m unittest discover -s tests -p test_p2p_client_init.py -v`，工具 `9d5eab`：
**102 tests / 0.091s / OK / host exit0，wall0.4073015s，0FAIL/0ERROR**。这是首批，未先跑失败批、未重复已过项或追加增量批。
原81方法适配（1方法精确改名）+21新增；含当前Python3.5 AST/import边界、原角色/基线/caps/CREATE/当前record/旧GO/reap/once-close保护。
新增覆盖typed绑定、伪造同shape副本/认证整数/认证BaseException、task状态不被key遮盖、terminal失败、marker未知、absence但fsync未知、
合法partial与不可矛盾complete/资源事实、无record真实absence、旧GO不改、永久sealed/两锁读回不足、Provider close后原网变化及Provider中断。
全部使用合成Provider/Store/clock/资源；发行/FD/marker观察是Fake事实，不是实际OS、磁盘、进程/OFD、RF或网络成功。
正常SOURCE归档之外没有运行真实文件/锁实验、WSL/libc/网络/ADB/P011/native/Docker、旧pending操作、正式冻结或部署。

## 固定交审源码与下一步

当前core1019行/60748B，SHA `ec2d927c50bf2946614990bdd9fe1d69ce5538047573d9a4d885a3914b0f85f1`。
当前tests987行/60726B，SHA `b07bab5370d4498e8b35914856401d4ea22ce482b5e835c82abac801fc0543b4`；本文最终SHA单独交付。
三文件停写供ROOT完整复审；下一步只是实现真实Store的发行者/封印/typed自有pending接线和三阶段file/FD机制，不开放当前RF。
Provider、ClientInitStore默认仍unavailable；准备文件层/协调锁不是完整Store，原pending与当前设备异常没有由本轮修复。
