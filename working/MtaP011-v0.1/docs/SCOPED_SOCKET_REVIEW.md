# 自有接口 TCP 工厂：HOST 实现检查点

日期：2026-10-01。实现仅在新增 `runtime/mta_scoped_sockets.py`；未接入 State、transport、DHCP、helper 或生产能力。发送与独立 CLIENT 接收仍不得据此开放。本轮没有 ADB、RF、Docker、真实 TCP socket、手机或用户数据操作。

## 私有 API 与可信输入

`ScopedDataSockets(context, proof_callback, cancelled, ownership_lock, endpoint=None, ...)` 由实际 backend/coordinator 持有；创建任何 socket 前必须已登记该 capsule，恢复网络前必须等待其 `close()` 返回 True。参数、依赖注入和证明不能来自 QML/HTTP。HOST 注入类型/时钟/socket/select/index 只用于假内核测试，不构成平台证明。

- `OwnedContext` 是不可变 tuple：boot_id、task_epoch、native_epoch、phy、wdev、ifindex、ifname、mode、local_ip、prefix、deadline、receipt_id。公开 context/endpoint 属性无 setter。保护 lo/wlan0；地址必须是实际私有 IPv4 host 地址，不能是 wildcard、网络或广播地址。
- `PeerEndpoint(host, port, proof_id)` 是 CLIENT 必需的不可变对象，由真实已校验 P2pInfo、group/association/DHCP/peer 链建立。目标必须在实际 local_ip/prefix 子网内；不猜网关、不推断 BLE MAC 等于关联 MAC、不选默认网络。
- `ownership_lock` 必须是实际 lease mutation/restore 共用的可重入锁。创建/连接期间不持续持锁；每次 proof 与最终 proof+handoff 在该锁内，内部取消/状态锁独立，因此阻塞 proof 时不会误报资源已退出。
- 同步 `proof_callback(context, purpose, budget)` 返回精确 `ScopeProof`，context 必须为同一对象。它必须是有界、只读的真实 backend 读回，不允许缓存布尔值、HOST fixture 或普通 True 替代。

每次 proof 明确要求 `receipt_stage == confirmed`、`receipt_fsynced is True`、`persistent_readback_verified is True` 以及 owner/address/route_baseline 的 exact True。实际 provider 必须证明本次 journal 的 canonical receipt 身份与 context.receipt_id 相符，必要 fsync 已真正返回成功，并持久读回一致；仅内存 receipt_fsynced 字段不足。owner 读回须核对同 boot/epoch、helper/candidate/进程归属、完整 PHY/WDEV/ifindex/name/type 等实际自有租约身份。address/route 读回须核对真实 local/address/prefix/flags/scope/label/broadcast、精确自有 connected routes 以及原网络完整 baseline 未变，不是仅 IP 或同名接口存在。

现有 GO-only receipt validator 为恢复流程接受 delete_intent/restored；本模块明确拒绝这些状态用于数据网络。CLIENT provider 必须独立核验自身持久租约、真实 group association、实际 DHCP 地址/期限及精确 endpoint/peer；不能把 GO /24 地址分配校验器当作 CLIENT 证明。CLIENT 的 association/DHCP/peer 标志及 endpoint 同一对象全部必需。GO listener 的这些标志必须为 False、endpoint 为 None，明确不授予 peer 准入。

## 工厂合同与有界行为

`listener_factory(host, port)` 对齐 SenderTransport：只允许 GO 实际 local_ip，port 为 0 或明确固定端口；返回真实 AF_INET/TCP raw socket，已 bind、未连接、未 listen、非 TLS、非继承。读回 SO_BINDTODEVICE=Linux UAPI 25、if_nametoindex、local IP/实际端口、SO_TYPE/SO_ACCEPTCONN、REUSEADDR/REUSEPORT 均关闭，SO_LINGER 关闭。不开 REUSE，不尝试其它接口或 wildcard。

初次 listener **不要求手机已关联**，否则公布端口/GO 凭据前形成循环依赖。SenderTransport 仍默认 deny-all；调用方必须在 `start()` 实际 listen 后再次证明真实绑定端口/接口/listening 状态，才可发送凭据。只有当前 group 的真实 station + 有效 DHCP lease + 手机对应 peer IP 的独立证据成立，才能调用现有 authorize_peer；DHCP ACK 不是手机配置完成，BLE DeviceInfo.mac 不是 Wi-Fi 关联身份。

`socket_factory(host, port, timeout)` 对齐 ReceiverTransport：只允许 CLIENT 已证实 endpoint，timeout 在 (0,3] 秒且受实际 lease deadline 约束。只创建一次真实 raw TCP，SO_BINDTODEVICE 精确 write/readback 后 bind 实际 source_ip:0。非阻塞 connect_ex + select 每次最多 0.1 秒；前后都重验 proof/epoch/cancel/deadline。核对实际 source IP/ephemeral port 在连接前后不变，getpeername 为精确目标/端口；无 DNS、getaddrinfo/create_connection 或通用网络回退。

创建/绑定/连接/移交各阶段都 fail closed。每次 proof/共享锁获取预算不超过 0.2 秒；同步可信读操作必须自身可终止，超预算返回拒绝。模块不声称能强行中止任意阻塞 callback/syscall：actor 保留到其真实返回，取消/close 期间不能把它丢弃或宣称完成。最多 3 个 outstanding resources/actors、16 次 factory 尝试，lease 最长 300 秒。失败不向公开状态传播 OS/backend 私有异常文本。

`check()` 是未来 coordinator 持续校验入口，失败撤销本 capsule 继续创建的资格，但不自行关闭已移交的 TLS/transport 资源。工厂不提供后台永久监控；worker 必须持续调用 guard/传输取消检查，使 association/DHCP/GO/IP/epoch 失效即时进入有界退出，而不是仅建立连接时证明一次。

## 精确 handoff 与关闭证明

创建 actor 在调用可能晚到的 socket factory 前登记；创建后立即登记 exact raw object，再检查取消/generation/proof。晚到 socket、失败 close 及并发 close actors 保留归属，不能通过第二次 close 或 fd 复用制造完成。

handoff 后该 exact raw object 始终留在 outstanding 表；`close()` **只关闭 pre-handoff 自有 socket**。TLS 包装的 detach、raw.fileno()==-1、fd 数字复用、请求 close 或限时 join 均不解除 handoff。不得用 raw.close、dup 或不符合现有 transport 的包装器假装关闭 SSL 资源。

`confirm_transport_closed(raw, callback)`：callback(context, raw, budget) 必须返回精确 `TransportClosedProof(context, raw_socket, all_sockets_closed, all_actors_exited)`，context/raw 均为同一对象且两标志 exact True。可信 transport owner 必须实际核对该 raw 对应的 listener/accepted/TLS/download socket 及所有 worker 已退出；模块不内置一个默认通过的 callback。慢、错误、泛化 boolean、不同对象或仍有 actor 的证明全部保留 outstanding。关闭证明可在原租约失效后完成，但不会恢复数据网络资格。

未来仍需单独授权的 transport 修补：Sender.close 的限时 join 后尚无线程退出核验/verified 生命周期；Receiver.run 的首个 close 异常可能跳过其它 socket/临时文件清理，service 尚未保留 transport owner。这些缺口没有在本任务修改，也不能调用本 API 的 HOST 证明替代修补。

退出次序：取消/拒绝新连接 → transport TLS/raw/worker 精确关闭 → 所有 capsule.close verified → DHCP 关闭 → 自有 IP/route 恢复 → 私有 WPA/netdev 清理 → 原网络独立复核。pending/unknown 保留 owner/journal/恢复锁，不先撤 IP 或复用接口。

## HOST 证据与平台边界

命令：`python -m unittest discover -s tests -p test_scoped_sockets.py -v`。当前 **56/56 PASS**，全部使用 FakeSocket/FakeClock/假 proof；其中实际 PC 线程仅覆盖阻塞/晚到/并发 actor，不创建网络 socket。Python 3.5 AST 解析检查包含在该专项内。

覆盖：GO 初次 deny-all 与 listener 动态/固定端口；CLIENT 两次连接同一任务/endpoint/binding；confirmed/fsynced/持久及完整读回缺失、陈旧/同值不同对象、ifindex 复用、错误源/端口/peer；callback 超预算、取消、过期、非阻塞轮询/连接错误、无回退；绑定/类型/监听/REUSE/LINGER 读回失败；创建晚到、失败关闭、并发关闭；TLS detach 不解除移交、exact trusted 关闭证明、所有 actors 未退出时禁止恢复。

**NOT_TESTED**：P011 实际 SO_BINDTODEVICE TCP write/readback、内核路由作用域、实际绑定/连接、真实持久 IP/CLIENT lease provider、association/DHCP 手机链、TLS 工厂集成、worker 及手机端到端文件传输。此前真实 GO-only、Python socket API 内省或回环 TLS/hash/ACK 是独立层证据，不能升级本模块为平台可用或互传完成。本检查点不是正式 release。
