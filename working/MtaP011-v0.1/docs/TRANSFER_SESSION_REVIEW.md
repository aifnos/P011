# 独立两阶段 TransferSession：HOST 实现检查点

范围仅为新 `runtime/mta_transfer_session.py`、`tests/test_transfer_session.py` 和本说明。没有修改 State、UI session 入口、能力开关、已冻结 transport/scoped、Wi-Fi/DHCP/helper、host 或 package。没有 ADB、RF、socket/TLS、Docker、P011 或手机测试；本组件不是已接入的正式 send/receive worker。

## 可信内部 API

```python
TransferSession(task, restore, lease_owner,
                scoped_owner=None, scoped_release=None,
                extra_actor_close=required_callback,
                cancelled=None, task_timeout=300, finalize_timeout=30)
session.start()
session.attach_transport(exact_transport)
session.register_handoff(exact_transport, exact_raw)
session.cancel()
session.close(timeout=2)  # verified bool，显式失败重核验入口
session.closed()
session.status()        # 被动固定 enum/bool/count，不做网络动作
```

`task(session)`、owners、callbacks 只能由可信后端注入，不从 QML/HTTP 提供。task 返回严格 `Outcome(payload, local_commit_verified, peer_ack_verified)`；两个事实必须是 bool，payload 只在私有对象里保留，不能通过 status 输出 files、路径、地址、证书或异常原文。

lease/scoped owner、exact worker、首个 exact finalizer 在启动前被持有。动态 transport 创建返回后立刻登记；工厂每次交出 raw 后立刻登记 exact handoff，不能等 run 成功才补录。若 factory 抛异常而没有交出 raw，其 producer/scoped capsule 仍必须持有资源并由 extra actor gate 证明闭合。

## 两阶段顺序

1. worker 只保存实际 Outcome / 固定失败事实，finally 独立请求已登记 transport 的 `close(timeout=0)`；不恢复网络、不清 owner、不把请求关闭或函数返回当作实际退出。
2. 唯一存活的外部 finalizer 在锁外等待 saved exact worker 的 `is_alive() is False`，且 start 操作已 resolved。
3. 每个 transport 必须同时满足 `close(...) is True`、`closed() is True`、exact dict lifecycle 的 closing/close_verified=True 和 cleanup_pending=False；socket_records 是严格整数且不少于此 transport 的 handoffs 数。sockets_pending、actors_pending、threads_pending、wrappers_pending、unknown_wrappers、unknown_resources、processes_pending 全部必须存在且为严格整数 0；bool、float、缺字段或 truthy 值不通过。
4. 每个 exact handoff 的 `closure_snapshot(raw)` 必须包含同样完整的 lifecycle schema，再严格包含 recognized_raw、all_sockets_closed、all_actors_exited、close_verified=True，以及 cleanup_pending=False。fd=-1、同地址、同数字 fd、done Event 或 truthy 非 bool 都不替代这些证据。
5. 调用 `scoped_release(scoped_owner, handoffs, snapshots) is True`，随后 `extra_actor_close(lease_owner) is True`，最后 `restore(lease_owner) is True`。没有 handoff 不等于 producer 已退出；extra callback 始终必需。
6. finalizer 完成上述阶段后仍只处于 awaiting_finalizer_exit；外部被动 status/closed/close 必须实际观察所有历史 finalizer 退出，才可推导整个 Session closed。核心不删除 owner / worker / 历史线程引用。

release callback 应把严格快照交给已有 scoped capsule 的 exact context/raw 证明 API，关闭 capsule 并证明其它 producer actors 已退出，而不是直接从本次列表为空返回“网络已安全”。extra callback 必须证明 lease 下 DHCP、BLE/key/selection 或其它 owned actors 真正闭合；callback 返回本身不证明这些任意资源已结束。

所有 callback 都必须在真实租约共享 guard 中核验真实对象/epoch/journal/IP/route/association 归属，具有同 owner 的安全幂等重核验契约。该纯核心没有替实际平台生成证明，也没有操作原厂网络。

## 取消、期限与重试

- task_timeout 允许有限 0..300 秒、exact int/float、非 bool/subclass；0 表示取消而不是推定线程死亡。finalize_timeout 允许有限 0..120 秒；close 的调用方等待预算为有限 0..30 秒。先核类型/上下限再做 finite 检查，huge int、NaN、Inf 均以固定 SessionError 拒绝，不泄漏 OverflowError。
- cancel 只置本 Session Event；普通完成、取消和 close 共用相同逻辑 finalizer。close 不持 Session 锁 join，不 join 当前 worker/finalizer，也不因 worker 在当前线程中调用 close 而形成双方互等。
- Thread.start 前登记对象和 unresolved start actor；实际 target 等自己的 start 返回并确认非 unknown 后才可执行 task/finalizer 阶段。start 未返回不能以 alive=False 或 ident=None 通过；start 抛任意 BaseException 时，保留 exact 身份和 start_unknown。KeyboardInterrupt 可能发生在线程已实际创建后，通用核心无法证明“确实未创建”，即使历史线程随后退出也不自行解除这个 unknown；不得恢复或宣布 closed，需要外层独立 owned 恢复证据。本核心不提供强制清除入口。
- 每个 Session 最多 8 个 admitted transports、64 个 admitted handoffs、8 次 finalizer attempts，最多一个 live attempt。重复、无匹配 transport、缺 scoped owner、未知接口与超限对象保留私有 quarantine references、取消任务并锁住 pending；同 exact object/同 exact transport/raw pair 去重，不同资源不丢引用。8/64 不是 unknown quarantine 的硬总量上限；可信 producer 仍须在创建资源前限量，不能靠超限后丢弃对象“维持固定计数”。
- finalizer 已明确启动且随后失败/超时不会自动恢复或重试。只有下一次显式 close，在上一 attempt 已 resolved、非 unknown 且实际退出后，才可登记新 exact finalizer attempt；历史 threads 持续保留。start_unknown attempt 不准用另起线程绕过。
- 已严格确认成功的 release/extra/restore 阶段保存结果，下一 attempt 不重复执行可能有副作用的 callback。未确认或异常阶段仅由相同 owner 的幂等 callback 重核验；不得新建网络租约绕过 pending。
- 每次 finalizer snapshot、慢操作返回及后续阶段前后重新核验 registration generation。迟到对象不得被 snapshot 漏掉；release/extra/restore 已确认后出现新登记，视为归属契约破坏，保留对象与 unknown pending，而不是静默重新开放。

预算限制本调用方等待与后续阶段准入，不是对任意 callback、OS close 或第三方阻塞调用的硬抢占。阻塞 finalizer 仍存活时，close 返回 False、owner/pending 保留，不能并行启动另一恢复 actor。超过阶段预算后才返回的 True 仍不是限时确认；后续显式重核验只能依赖已声明的安全幂等契约。

## 公开状态与完成事实

status 仅固定 phase/reason 枚举、bool、计数；不调用 close、release、extra 或 restore，不清 owner，不输出 payload/异常字符串。

只有 local commit 与 peer ACK 都为严格 True，且双阶段全部关闭/恢复、worker/finalizer 真退出，才为 completed。local commit=True、缺 peer ACK，在清理完成后为 saved_unconfirmed；恢复/关闭失败则仍 pending，但不抹掉已保存的 commit/ACK，也不自动重发文件。没有有效 Outcome 时仅报告 cancelled/failed，不伪造传输结果。

closed 表示本 Session 的 owned 关闭链已确认，不等同手机 UI 已显示完成，也不是未来环境永远不变化的承诺。callback 确认结果是本次核验事实；新的任务仍必须执行新的 fresh 平台证明。

## HOST 专项与未完成层

`python -m unittest discover -s tests -p test_transfer_session.py -v`：47/47 HOST PASS，1.770 秒、exit 0。使用实际 PC Python threads/Event/join；transport、scoped、lease、restoration 均显式 fake，无真实 socket/文件传输/网络修改。Python 3.5 AST 检查通过。

覆盖 normal/cancel/close、worker 保存结果后 finally 仍活、finalizer 阶段完成后自身仍活、start unresolved/失败/真创建线程后 KeyboardInterrupt、blocked/late callback、锁外等待与 self-join 防止、完整 lifecycle 全 7 pending 计数/每个 exact raw 严格字段、异常独立清理、没有 handoff 的 extra gate、cached stage 不重执行、显式 attempts 上限、late registration/generation、unknown/duplicate/overflow 保留与 identity 去重、huge int/subclass/NaN/Inf budgets、task timeout 仅取消、外部 Event、commit/ACK 保留及固定脱敏 status。

保留历史边界：早期 39/39 是未补本轮严格 schema/start_unknown 前的 HOST 时点，不是当前源码证据。加入 target 等 start-resolve 后的一轮 39 项曾有 1 个 HOST fixture FAIL：`.015s` task budget 在调度下先过期，测试错误期待 task 必然先进入；现仅将该 fixture 改为 `.15s`，仍验证超时只取消、不杀死 held worker。没有放宽核心期限或把此失败归因于设备。

尚未接入生产 State.receive/send、QML/工具箱退出、真实 scoped/lease/DHCP/BLE callbacks、持久 Session recovery 或平台证明。现有 `State.receive` 的局部 transport/worker finally 提前恢复问题仍在原源码中；不得据本组件 HOST PASS 开放 capability、称正式 worker 完成或升级为 P011/PHONE 证据。

下一步应把此核心挂入实际 State owner，令恢复入口只能走上述外部 finalizer；原 prepare/无传输失败路径也要走同 owner 的关闭合同。退出 pending 时须保留会话占用和恢复记录，真实 raw closure proof、owned producer/lease callbacks、独立原厂读回通过后才释放。先做实际调用链的 HOST 故障测试，再分层验收设备和手机。
