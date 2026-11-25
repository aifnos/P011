# State 与外部 finalizer 接线评审

本文件是 HOST 源码/故障检查记录，不是 P011/手机互传验收。此次仅修改四个 runtime、两个相关旧 fixture/test，新增生命周期测试与本文件；已冻结 Session/transport/scoped/IP/native、host harness、候选与包均未修改。

## 现有能力边界

- `native/mta_network.c` 的 `MTA_CONNMAN_STA_VERIFIED` 仍为 `0`，`State.send_available` 仍为 `False`。
- 当前生产接收没有确认原厂 STA 归属，不能因 HOST fake 接收正常而开放实际切网。
- 接收 worker 仍使用原来的 `ReceiverTransport(host, port, storage, cancelled)`。它不提供独立 P2P CLIENT、实际 DHCP、scoped source/factory/association 证明，也不是新建的默认网络回退。
- 真正开放 P2P 前必须提供 durable receipt、完整 fresh owner/interface/address/route/peer 证明、scoped socket factory 和所有 handoff 注册，再保留现有关闭门槛。此次未接线发送 worker。

## 正常接收的真实代码顺序

1. `State.action(discover_start)` 锁内验证能力/忙碌状态，创建 exact `Operation`、取消 Event、`TransferSession`、worker/唯一初始 finalizer，并保留旧闭合 operation 的历史强引用。
2. 锁外 `session.start()`；worker 调用 `WifiBackend.begin_prepare()` 获得 exact lease，登记至 operation/State 后才 `lease.prepare()`，即 Popen/reader start 前已持有 owner。准备失败也不丢 lease。
3. worker 生成并持有内存 key；创建并登记纯 `PrivateHelper` 后才 start。Popen/reader start 均先记 claimed，返回立即登记；未知启动永久 pending，不据 `is_alive=False` 假定未创建。
4. worker 锁外发送固定 listen IPC。native `listen-ready` 仅置 operation Event/phase；worker 检查同 helper/epoch/取消，锁外发送一次 advert。重复/旧 ready 不重复广播；advert-ready 只确认已发送的本 phase。
5. native p2p 回调仅做有界字段校验并交给已持有 worker；解密、NetworkInfo 重新校验均在 worker。连接须 explicit consent、当前能力/epoch、已登记 prepared exact lease；直接 `lease.connect()`，不调用兼容 `backend.receive()` 自动 prepare/inline restore。
6. transport 返回立即登记至 operation、Session、State，然后运行。worker 保存真正结果/本地提交/peer ACK；finally 只置状态并请求 transport close，不恢复网络、不清 owner。
7. 唯一外部 finalizer 等 saved worker **实际退出**，严格检查 transport.close/closed/full lifecycle、全部 pending int 0、每个 handoff 的 exact raw closure proof；无 handoff 不代表未来 scoped producer 已验证。
8. extra 阶段关闭 exact helper，join 实际 reader，确认 process.poll 已退出及 stdin/stdout 真实 closed；仅其通过才 free key。free 抛异常即 unknown，即使 closed flag 已置 True 也不能恢复。
9. 固定 readonly capability Popen 同样在启动前占位、返回立即保留 exact process/两 pipe。未知 spawn 禁止重复探测；communicate 异常只有实际退出+原 stdout/stderr 身份及 closed 严格通过才能闭合。只在显式 finalizer 关闭 own readonly handle，不持 State 锁，不 kill 网络恢复 actor。
10. restore 阶段才执行 exact lease.restore + actors_closed，且 backend `restorePending is False`/`recoveryLocked is False`。finalizer 自己仍活着时不是完全 closed；外部观察其实际退出才得闭合 Session。

## 失败、取消、watchdog 与显式恢复

- prepare/crypto/IPC/connect/transport 失败保留 exact operation、lease、helper、key、transport、worker；Session 外部 finalizer 处理相同顺序。没有假造手机完成、没有自动启动下一任务。
- 普通 cancel/stop、State.close、兼容 restore_network/stop_radio 都走同 owner Session。native closed/stop/error 只置取消/等待 Event，不能在 reader 中 join、close 或恢复。
- `start_watchdog()` 不创建 detached actor；scan 的有限等待在 exact worker，Session 的 task deadline 只请求取消，不把卡住线程当成已退出。native 独立 TTL 仍是平台机制，不能以此冒充 scoped 租约/原网络恢复证明。
- status 只读，不做 deadline cancel、close、recover 或 owner 清除；pending 禁止 rename/新任务，并保留 UI 占用。
- 用户显式 recover 可在同 Session 发起下一次受限 finalizer attempt；旧 lease 必须 `closed is True`、`actors_closed is True` 且 backend active exact 匹配，才可调用 fixed recover_pending。未知/live reader/process 或不匹配继续锁住。
- 恢复仍保留单 exact recovery actor/Popen、原 pipe、PID/starttime；未知 spawn/communicate 不丢引用、不再并行 spawn、不 SIGKILL mutation helper。native restored、journal/hash/boot/ConnMan 归属及两 pipe 闭合后才解除 pending。
- 旧 failed lease 没有当前 journal/已确认 native recovery 事件时，不能仅因 journal 文件缺失宣称恢复。成功重查也不改写旧 lease.restored=False 的历史事实；失败保留 owner/journal/本地提交与 ACK。

## 两个有限 UI 入口的占用锁

- `mta_ui_session`/`mta_toolbox_session` 使用同固定私有 lock，并保存创建时 directory/file dev/inode/UID/type/mode/nlink、exact session 内容、当前 PID/starttime/exe 身份。不是仅靠文件名或字符串匹配。
- 未知 child Popen/serve thread start 保留 pending；HTTP close 抛异常也继续尝试其它 server/State 清理。已知 exact request/serve threads 锁外 join，不能以 worker map 清空冒充已退出。
- 仅 child/HTTP/State 资源严格闭合且当前独立原厂 hashes/processes 一致后，重新验证所有 lock 文件再移除自己的两个成员和空目录。替换、symlink、hardlink、权限/owner/PID-start 改变或未知成员均不删。
- 现有 minhttp 不保留完整历史 request actor ledger；此处保留关闭时 map、bound-target 和显式 serve thread 的 exact 引用。有限试验非生产 LAN 服务证明。若未来 HTTP/LAN owner 需跨服务永久历史证明，应另行实现并验收，不能拿本轮有限清理断言升级。
- 复制工具箱的既有 LAN 状态 cleanup 未在本范围重写；此次没有打开 LAN/用户服务或证明其所有历史 actor。所有实际 P011 QML/lock/原厂读回复验尚未进行。

## HOST 专项证据与历史判定

| 组 | 本轮最后结果 | 证据层 |
| --- | --- | --- |
| `test_service_session_lifecycle.py` | 37 run / 37 PASS / 0 fail/error | 真实 PC threads；fake helper/process/socket/FS/网络，不 spawn OS process |
| `test_wifi.py` | 26 run / 24 PASS / 2 skip / 0 fail/error | 私有 process fixtures；Windows 跳过两个既有 POSIX 权限项 |
| `ServiceIntegrationTests` | 23 run / 23 PASS / 0 fail/error | 真实 PC worker/finalizer 与合成存储；fake 网络/协议，不运行该文件真实 TLS 类 |
| `test_service.py` | 6 run / 6 PASS / 0 fail/error | 既有 HOST loopback HTTP 接口，不是无线/手机验收 |

受影响四组共 92 run：90 PASS、2 skip、0 fail/error；四个 runtime 的 Python 3.5 AST 检查包含于新增组。没有重复整套、Docker、ADB、RF、真实 TLS 或设备 UI 测试。

历史保留：旧 29 项 HOST 是当时的 Service23+HTTP6，不是最终新源码全部证明。新增故障组首次 26 run 有 1 FAIL：fixture 把 start_watchdog mock 成 MagicMock，测试错误期待 None；改为调用预先捕获的真实函数，未削弱源码/断言。随后 28 PASS、36 PASS、37 PASS 为不同测试/源码时点。Wi-Fi 19/22/26 与其它旧 PASS 亦不改写为本轮设备通过。

## 后续必须独立验收

ROOT 全文代码审查、整合 HOST、候选 FD pins、有限 P011 无 RF UI/lock 与原厂独立读回；之后再另行授权真实 owned P2P/IP/DHCP/scoped/peer/手机端测试。既有 P011 TLS 回环报告是旧 transport 层证据，不证明这次 State/UI 接线已在 P011 运行。
