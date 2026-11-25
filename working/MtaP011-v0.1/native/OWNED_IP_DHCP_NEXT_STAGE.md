# 自有 P2P IPv4／DHCP／数据 socket：下一阶段设计

日期：2026-10-01。本文是待评审设计，不是实现、RF 授权或设备 PASS。V2 的 runtime／WPA／只读 probe 保持冻结，`send.available=false`、20 秒 GO-only 边界不变；新阶段必须使用新的候选与证据目录。

## 已有组件与实际缺口

| 组件 | 当前源事实 | 不能据此宣称 |
| --- | --- | --- |
| `mta_send_wifi.py` V2 | 管理自有 netdev／private WPA／watchdog／device lock＋pending journal；`SenderGoContext.local_ip=None` | 已分配 IP、已能发送文件、手机兼容 |
| `mta_dhcp.py` | 纯封包＋单客户端 server／严格 client 状态机；HOST 29 项＋恶意输入测试 | UDP 广播收发、P011 DHCP 成功 |
| `P2pInfo` | 当前只提供 SSID、PSK、MAC、port 与加密／任务字段 | 存在 IP、mask、gateway 字段；可猜固定 GO IP |
| `ReceiverTransport` | 已有内部 `socket_factory`＋`source_ip`，核对实际 TCP peer／source，失败不回退普通网络 | factory 已绑定真实 P2P 设备、已经手机实测 |
| `SenderTransport` | 本次源读回仍是精确 IPv4 host bind；root 正新增内部 `listener_factory(host, port)` 钩子；默认 peer deny-all；`authorize_peer()` 只接受内部调用 | factory 已绑定真实设备；DHCP MAC 等同对端应用身份 |

实际 TCP／TLS HOST 或 pen-loopback 证据与 P2P 接口证据属于不同层。现有传输实现可复用，不能绕过 Wi-Fi 准入直接把 LAN／loopback 成功记为互传完成。

## 所有权与租约 API（建议，尚未实现）

`OwnedIpLease` 是 root-reviewed P2P lease 的子资源，不重新 acquire device flock。它借用同一 open-file-description 锁和同一恢复责任链，不能创建第二个并行 private manager。必须持有、逐步读回：

- same boot、严格 `mta`＋8 个小写 hex 名称、ifindex／WDEV／phy／实际 iftype；不是凭名字或 type 推断所有权。
- private WPA PID／starttime／executable pin、实际关联／GO-ready、有限 deadline、原厂完整接口／进程／频点／IPv4＋IPv6 baseline。
- 本次增加的精确 IPv4 address／prefix／ifindex，以及由此形成的实际 connected／local route；未知地址或路由不删除。
- DHCP transaction／可用期限和 socket 归属只在 private 内存与 0600 journal 必要恢复字段中使用；SSID／PSK 不写 journal。IP／MAC／原始 DHCP 包不进入 UI 或公共日志。

建议内部接口：`configure_go_address()`、`serve_one_peer()`、`obtain_client_address()`、`open_bound_tcp()`、`restore()`。返回值包含 private 的实际 local／peer address 与 deadline；公开 `status()` 只返回 `ip_ready`、`dhcp_ready`、`peer_admitted`、stage、固定错误码、计数，不返回凭据或网络标识。QML／HTTP 不接受 interface、source-IP、任意 route 或任意 shell。

## 地址安装及恢复

1. 修改前 fresh 读取所有 IPv4 地址、具体子网路由、规则，以及既有 IPv6 地址／路由基线。GO 子网从有界 private 候选表选择，与所有已有地址／具体子网路由不重叠；默认 `/0` 只保留和比较，不把它误当所有私网都冲突。若策略规则／更具体 route 造成歧义则拒绝。`192.168.49.0/24` 只是 HOST fixture，不是生产 fallback。
2. 使用 scoped rtnetlink `RTM_NEWADDR`＋ACK／CREATE／EXCL，意图先持久化、读回后才 `ip_ready`。禁止 REPLACE、任意 `ip addr flush`、系统 DHCP 脚本、默认路由／DNS／全局 sysctl 修改。IPv4 address readback 必须包含 exact ifindex、address、prefix；所有权改变立即停止。
3. 内核产生的 connected／local route 纳入子租约核对；不增默认路由。只给 on-link 的实际 peer 连接。子网冲突检测不能仅看 `/proc/net/route` 默认表而忽略 policy rules。
4. 取消／超时／父进程消失：先关闭应用／DHCP socket，再撤本次精确 address，核对本次 connected／local route 消失，最后 private WPA 和 netdev。若 address 撤销结果与 kernel 自动 route 行为不同，不盲目 DEL_ROUTE；保留 pending 并报告恢复缺口。
5. 父 watchdog 必须认识新增 journal 版本和 IP 子资源，不能仍按 V2 “无数据 IP 才允许 station 清理”直接拒绝或越过撤地址。最终独立读回原厂 IPv4／IPv6完整 baseline；失败 pending 不清，下一 run 不得换随机名绕过。

## DHCP server：P011 为 GO

- GO 实际地址先安装并读回，之后才打开 UDP 67；最多一个客户端、一份地址、截止来自实际 GO lease，option 51 不延长 GO TTL。
- DHCP UDP socket 设置 `SO_BINDTODEVICE` 并 `getsockopt` 读回名字，`IP_PKTINFO` 校验收到的 exact ifindex；允许 UDP 通配 bind 仅用于该独占接口广播。不开 `SO_REUSEPORT`，初版也不开 `SO_REUSEADDR`；port 冲突失败，不暂停系统服务。
- `SO_BROADCAST`、`sendmsg` 的 pktinfo egress-ifindex／GO source-IP 要实测。recvmsg 拒绝 MSG_TRUNC／MSG_CTRUNC、缺失或重复 pktinfo、错误端口／ifindex、超限包；设置 pps、总包数、总字节与截止上限。
- DISCOVER 不直接授权应用 peer。预期 station 来自实际 private WPA 关联记录以及已完成的互传 BLE admission；须区分 GO device address 与 station interface MAC。实际 ACK 地址只能进入内部 admission binding，不可从“第一个 TCP 请求”或任意 DHCP chaddr 推断用户身份。
- OFFER／ACK 默认不提供 router／DNS；是否手机 P2P 栈接受这一配置仍需互操作验证。DHCP 不具认证能力，WPA2 PSK 也不替代互传任务确认／后续加密协议。

Linux 对 `SO_BINDTODEVICE` 的接收接口限定与读回支持见 [socket(7)](https://man7.org/linux/man-pages/man7/socket.7.html)；pktinfo 是 datagram 的 recvmsg／sendmsg 控制信息，不是 TCP 验证手段，见 [IP_PKTINFO](https://man7.org/linux/man-pages/man2/IP_PKTINFO.2const.html)。这两项 API 文档不证明 P011 驱动的广播路径已验收。

## DHCP client：P011 加入手机 GO

当前 `ClientExchange(expected_server, expected_mask)` 是严格已知服务器的纯 core；互传 P2pInfo 未携带 server／mask，不能向其灌入猜测 IP。

待新版本实现受限 offer selector：仅在已核对的 private P2P_CLIENT 上收包，校验 xid／chaddr／client-id／packet bounds／来源接口／source port、server-id／yiaddr／mask 为可接受私网同子网，最多收集有界数量与时间，选定一个 offer 后 pin 其 server＋mask，后续 ACK 不允许换服务器／subnet／地址。跨原厂 LAN、多个矛盾候选或缺少必要字段失败，绝不扫描其他接口。这个 pin 是 transaction 一致性，不是身份认证。

server-id 不应自动当互传 HTTPS endpoint：手机 GO address、DHCP server、P2pInfo MAC、BLE 对端 address 可能不是同一对象。需要对照上游手机实现的真正 endpoint 选择与 P2P 组读回；没有证据时 `receive.client.available=false`，不借 router／ARP 猜测扩张目标集合。接入官方协议不得新增对方从未提供的假 IP 字段。

client 初次发送／接收可能需要 `0.0.0.0:68`＋广播和限定 interface；有 IP 前的 kernel routing／本驱动广播接收仍未知。若 UDP socket 方案确实失败，AF_PACKET 原始 IP／UDP 是单独安全评审事项，需要 exact ifindex bind／过滤、校验和、长度和截断限制；不会自动改全局 RPF／转发规则或绕过绑定失败。IP 安装前必须完成 ACK 严格核对，租约期限为 ACK 与项目 deadline 较小者。

DHCP 的广播、transaction 和地址租期规则参考 [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html)；本设计不把协议规范转换成手机或设备已成功的结论。

## TCP／TLS 接入

- receiver 复用当前内部 factory：先 fresh 校验 lease identity，建立 raw AF_INET TCP，设置并读回 `SO_BINDTODEVICE`、绑定实际 local-IP，connect 到已证实 on-link endpoint；核对 `getsockname/getpeername`，返回给已有 TLS 层。任何失败不回退 `create_connection`、wlan0、默认路由。
- sender 采用 root 正补的内部 `listener_factory(host, port)`：返回已 bind、尚未 listen 的 raw AF_INET／SOCK_STREAM socket；transport 校验实际 getsockname host／port、拒绝不合类型，factory 异常无默认 socket 回退。lease factory 负责 actual local-IP＋owned device／origin 的 fresh 核对；transport 才执行 listen。所有 accepted socket 保持设备约束，fresh 检查 endpoint 与 active lease；原 `allowed_peer_ip=None` 继续 deny-all，只有实际 DHCP／admission 证据才能授权一名 peer。
- 双方 TLS、任务、取消、大小／文件限制沿用当前 transport，不声称 DHCP 或首个自签证书完成了手机身份认证。所有应用 deadline 不超过实际 IP／P2P lease。

## 分阶段验收，不扩大 V2 试验

| 新候选阶段 | 必需证据 | 仍不能开放 |
| --- | --- | --- |
| scoped IP-only | 有限 GO＋exact address／route readback、正常及 TTL 清理、原厂双栈 baseline 相等 | DHCP／手机传文件 |
| GO＋DHCP | 手机真实关联、完整 DORA、one-peer address、实际 lease、bound socket，恢复通过 | 互传协议兼容承诺 |
| P2P_CLIENT＋DHCP | 手机 GO JOIN、严格 offer/ACK、实际 endpoint 与 scoped connector、恢复通过 | 双向文件成功 |
| 手机端传输 | BLE admission→私有 P2P→bound TCP/TLS→用户确认→内容 hash→取消／结束恢复 | 未测试品牌、目录／大文件范围 |

HOST 可先测 rtnetlink codec／ACK 错误、地址冲突选择、继承 guard、journal 崩溃窗口、scope socket mock、截断／重复 ancillary、错误 peer／source、TTL、关联退出和原厂 baseline 变化。HOST-only 结果不能放行设备网络；所有新 RF 动作由 root 串行执行并另存 raw stdout／stderr／remote exit 与独立恢复报告。
