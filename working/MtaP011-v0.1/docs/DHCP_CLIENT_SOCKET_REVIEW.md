# 动态 DHCP CLIENT socket 受限适配审查

范围仅为新 `runtime/mta_dhcp_client.py`、`tests/test_dhcp_client.py` 与本文。复用冻结 DORA core `13c03d181139fd9ead7ff3bf2bcbb4930669f1e795b17360da85834dc345e9fa` 和原 wire codec；不改 server、scoped TCP、WiFi、State、既有冻结候选或能力标志。当前真实 owned CLIENT 关联证明提供者尚未实现，因此不能称生产接收完成。

## 私有调用契约

`DhcpSocketClient(context, proof_callback, cancelled, ownership_lock, clock=None, socket_factory=None, if_nametoindex=None, xid=None)` 是同步 open/poll/candidate/close capsule。本模块不创建线程。依赖仅由可信内部协调器注入，不能直接来自 UI、HTTP 请求或任意 True 回调。

`ClientAssociation` 保存 boot、任务/native epoch、phy/WDEV/ifindex/ifname、实际 CLIENT MAC、deadline、持久关联收据 ID。标识与 MAC 均属私有数据；名字匹配本身不证明资源归属。构造阶段不配置网络，也不创建 socket。

`AssociationProof` 必须绑定同一个 context 对象及当前完整身份；真实 iftype=8、关联、ownership、fsync 收据、持久读回、原网络基线、CLIENT 未配置 IPv4 六项严格 True，并独立读回 if_nametoindex。提供者应在与 lease 相同的真实 RLock 内完成实际 native/sysfs/epoch/收据校验。本模块不能靠结构合法的 namedtuple 代替实际证明。

已有 `ScopeProof` 需要 IP/DHCP/端点已成立，不能被循环用于 pre-IP DORA，所以本层使用独立的关联证明；也不把此证明升级为 IP/端点授权。每次绑定、发包、收包后的处理、候选获取都重新证明，任务取消/过期/epoch 变化使操作失败并关闭。

## 广播 profile 与真实尚未验收项

仅 AF_INET/SOCK_DGRAM/IPPROTO_UDP，绑定 `0.0.0.0:68`；绑定可信 owned CLIENT device，禁继承，设置并读回 SO_BINDTODEVICE、SO_BROADCAST、Linux 数字 IP_PKTINFO=8、SO_TYPE、reuseaddr=0、reuseport=0、timeout。默认实际 factory 只接受 Linux；API 缺失直接失败，不提供 raw socket、默认路由或其他接口回退。

DISCOVER/REQUEST 仅发往 `255.255.255.255:67`，辅助数据明确实际 ifindex、源 ZERO。UDP68 已占用仅失败，不关闭系统 listener、不设置 reuse、不启动另一个事务。不猜 `.1`，不安装 router/DNS，不 ARP/IP/route 写入。

接收限长 1472+1 byte，辅助区按 CMSG_SPACE(12) 限定；必须 source port 67、RFC1918 source、一个完整 IP_PKTINFO、实际 owned ifindex、spec_dst=ZERO、目的广播、flags=0。所有截断/未知/重复辅助数据拒绝，最多 64 个报文。真实无 IP CLIENT 的 spec_dst 是否 ZERO **尚未实测**；这是保守广播限定，不是已验证的 P2P kernel profile，不能为通过 HOST 临时放宽。

source 与 option54 一致只是无 relay profile 的 DHCP 一致性，**不是 DHCP 身份认证，更不是 MTA 应用服务器端点证明**。BOOTP siaddr、option3/router、option54、UDP ACK 均不发布为可用 MTA IP。服务器地址、客户端地址与掩码来自实际 Offer 并在 ACK 固定，租期使用 ACK 值；有效期从首次 REQUEST 起算，重传不延长，deadline 截短。继承 core 的有界固定间隔重发，不宣称完整 RFC 客户端调度/续租/重绑定。

`candidate()` 只返回私有 immutable `ConfigurationCandidate(allocation, False, False)`。先前值是历史快照；活跃期间使用前仍须调用该方法并独立验证寿命/关联/IP/端点。同步 `run(ticket)` 返回后会关闭 socket 并取消 core，其返回值也只是历史候选，**不是继续有效的安装许可**；未来 IP 安装器不得靠该快照绕过新的 owned lease、冲突与实际端点证明。

## 关闭、晚到资源与预算

socket factory 调用前先保留 opening/unknown 状态；返回的 exact socket 立即登记，取消后的晚到返回会关闭，不能发送/发布候选。factory 异常或返回无可核对 close/fileno 的对象保留永久 unknown pending，本层没有“通用 True 清未知”入口。

close 登记关闭意图与 generation，取消 core；逐一关闭 exact socket 并核实整数 fd=-1。factory/open、实际 recv/send、proof、closer 尚未返回或 exact close 失败，均不能报告 socket_close_verified。fd=-1 不是线程/IO 已退出；协调器必须在所有 pending 清除前保留网络租约。

MainThread 可以同步调用 open/poll/candidate；非 MainThread 调用这三个生产入口前必须 `reserve_runner(actual_thread, creator)` 登记 exact producer，外部 Session 才能 start。未登记或其他线程借票在任何 factory、发/收包或关联 proof 前失败并关闭；预约必须在首次 open 前进行，不能到已经进入 IO 才补记。直接 open/poll/candidate 的 method return 与 run return 都不等于 thread exit，ticket 会保留；外部 owner 在同一 RLock/current generation 下提供 `RunnerClosedProof`，必须精确绑定本 client/context/ticket/creator，actual thread 已死且所有 producer 确证停止，才能清本 ticket。wrong object、旧 generation、bool-as-int、泛 True 均拒绝。保留未启动线程时，外部证明者还必须保证以后不再 start，不能只查 is_alive=False。close/status/控制端关闭核验不要求生产 ticket。

proof/锁/IO 预算 0.2 秒，事务 deadline 1..300 秒；数值先验 type/range，再验 finite，huge int 不进入 float 转换。锁获取和 socket timeout 有界，但任意 callback/OS IO 无法被本模块硬抢占；超时/取消后未知 actor 保持 pending，不能假装资源都死了。本层不自动重试 factory、重启服务或清系统资源。

`status()` 与 poll 的公开事件只有固定 stage/reason、有限计数与 strict bool；无地址/MAC/nonce/端口/路径/身份/自由异常文本。send_available、receive_available、interface_configured、endpoint_verified 永远 False。报文、收据上下文和 allocation 只能私有留存。

## 实际证据边界

专项入口：在 MtaP011-v0.1 下执行 `python -m unittest tests.test_dhcp_client -v`。先前 **31 HOST tests PASS**（工具输出 `1ab618`，0.229 秒，0 failure/0 error）保持为历史证据。ROOT 随后审查发现非 MainThread 直接 open/poll/candidate 当时尚未强制预约，方法 finally 的计数为零不能证明线程已退出；本轮窄修这三个入口，并让原 race fixture 在 start 前登记票。

当前最终实跑 **33 HOST tests PASS**（工具输出 `c71ba5`，0.239 秒，0 failure/0 error）。保留原 31 项覆盖，新增未预约非主线程在 factory/IO/proof 前拒绝，以及 direct open/poll/candidate return→hold→close 仍 pending→join 后仍 pending→strict typed proof 才完成。仍含 Python 3.5 AST、冻结 core SHA、动态 DORA、绑定读回/冲突/恶意报文、寿命、预算、取消、晚到 factory/阻塞 IO 与 runner 关闭证明。

首次 26 项失败输出 `ac5a17` 保留，不重写历史：Windows 没有 Linux CMSG_SPACE 导致多数未到 factory，静态词检查误中 Thread.start 的说明文本；随后以 **HOST-only** CMSG_SPACE 尺寸 seam 与 AST 检查修正，并修实际 AddressFamily IntEnum 兼容（仍拒 bool）。26 项修正后 PASS `019b03`，新增五项边界后形成上述 31 项。本轮所有 socket 为 fake；使用真实 HOST Thread/RLock 验证生命周期，但没有实际联网 socket、设备/RF、Docker、正式冻结或全套运行。

此前 `logs/MtaP011-UdpLoopback-20261001-073152-11ad27e3/result.json` 只证明真实 P011 UDP **lo primitive**：DHCP ports/P2P interface/DHCP/phone 均未测试。不能把该结果或当前 HOST 标签提升为实际 CLIENT/DORA/手机兼容结论。

后续仍需真实 owned CLIENT 关联证明、实际 UDP68/广播 pktinfo/source 行为、完整调度策略、IP 冲突/安装/恢复子租约、GO 应用端点来源与 TLS 绑定、worker/UI 接线以及原厂手机验收；本层没有完成这些事实。
