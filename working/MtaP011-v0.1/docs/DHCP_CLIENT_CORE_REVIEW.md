# 动态 DHCP DORA 纯核心审查

范围：仅新增 `runtime/mta_dhcp_client_core.py`、`tests/test_dhcp_client_core.py` 和本文。原 `mta_dhcp.py` wire codec / 已有固定-server 客户端 / schemas / 冻结候选均不修改。

## 接口与私有数据

`DynamicClientExchange(mac_bytes, deadline, xid=None, retry_interval=1.0, max_discovers=3, max_requests=3, max_packets=64)` 只处理字节与状态。`start(now)` 返回 DISCOVER；`accept_offer(packet, now)` 锁定首个合法 Offer 并返回 REQUEST；`accept_ack(packet, now)` 返回不可变配置快照；`tick(now)` 至多返回一次到期重发；`cancel()` 只取消本地状态。不创建 socket、不传包、不配置地址/路由/DNS、不启动 WPA/RF，也不自动开启新 xid。

配置 `local_ip/server_ip/subnet_mask/prefix/usable_until/server_lease_seconds`、报文字节、MAC/xid 均为私有数据，不能直接进入公开日志。Offer pin 只含不可变 bytes/int，配置为 immutable namedtuple。先前返回的配置仅是历史快照；每次实际使用必须重新调用 `configuration(now)`。取消、有效 NAK、过期、时钟异常或资源预算超限后，该方法不再返回配置。快照本身不能被当作仍有效的授权。

`status(now)` 只含固定 stage/reason、尝试/收包计数、剩余秒数和布尔字段；`interface_configured/endpoint_verified/default_route_installed/dns_installed` 永远为 false。没有 cached=true 或“手机验证成功”的推导。

## 验证与限额

- 从真实 Offer 的 option 54 / yiaddr / option 1 获取 server/address/mask，不猜 `.1`，不要求 option 3 router。server/address 必须是同一 RFC1918 子网内不同合法主机，掩码连续且 /8..30。
- Offer/ACK/NAK 均要求 Ethernet BOOTREPLY、原 xid/chaddr、ciaddr=0；client-id 61 若出现必须精确等于本事务 Ethernet client-id；其格式异常由既有 wire codec 拒绝。缺少 61 不代表认证。
- ACK 不得换 server/address/mask/事务；option 51 必须非零。ACK 可调整租期，使用 ACK 实际值。可选 T1/T2 必须在租期内且顺序正确，不伪造缺失值。合法 NAK 必须来自所选 server 且 yiaddr=0，拒绝后不重启事务。
- RFC 2131 §4.4.1 的租期从原始 REQUEST 发出时刻起算。本组件以首次返回 REQUEST 的时刻保守代替实际发送时刻；调用者必须及时发出或丢弃事务。ACK 到达/重传都不延长有效期；任务 deadline 截短租期，迟到 ACK 已超期则拒绝。
- now/deadline 必须是有限、非 bool、0..2^53 数值；now 不得倒退。重发间隔 0.1..5 秒；各阶段总尝试 1..8；总收包预算 1..64，计数饱和于预算+1。终态、重复包、跨阶段或晚包都不能重新激活/换 pin。
- 复用旧 codec 的 1472-byte/128-option 上限、重复 TLV/截断/relay/overload 拒绝。所有本组件异常仅固定枚举，不转发原报文/自由错误文本；构造实例不接收任意接口或地址写参数。

## 来源与明确非完整实现

独立编写状态逻辑，未复制第三方实现。协议依据为 [RFC 2131 §4.4.1/4.4.5](https://www.rfc-editor.org/info/rfc2131/) 的 Offer 选择、REQUEST/ACK/NAK、租期和 [RFC 2132 §9.2/9.7/9.11/9.12/9.14](https://www.rfc-editor.org/info/rfc2132/) 的选项格式。核心的固定间隔 tick 是有界调度原语，不是 RFC 2131 §4.1 要求的完整随机指数退避客户端；未来真实适配器上线前仍需审核调度策略。

Android 13 固定 tag 的 [DhcpPacket.java](https://android.googlesource.com/platform/packages/modules/NetworkStack/+/refs/tags/android-13.0.0_r1/src/android/net/dhcp/DhcpPacket.java) 将 option 54 映射为 `DhcpResults.serverAddress`，其 [WifiP2pServiceImpl.java](https://android.googlesource.com/platform/packages/modules/Wifi/+/refs/tags/android-13.0.0_r1/service/java/com/android/server/wifi/p2p/WifiP2pServiceImpl.java) 在 P2P CLIENT 成组路径利用该值；这是 AOSP 来源行为，不是用户手机实证，更不等于 DHCP 身份认证。本核心只返回服务器字段，绝不单独把它升格为已验证互传端点。`siaddr` 是 BOOTP next-server，也不当作 GO 端点。

不支持续租/rebind/RELEASE、缓存租约、INFORM/DECLINE、relay、option-overload/重复 option 拼接；未进行 ARP 地址冲突检测。公网子网/单播续租等不在这个有界 P2P 接收 profile 内。未知 router/DNS 值不安装也不采信为端点。

## HOST 证据与后续门槛

专项入口：`python -m unittest discover -s tests -p test_dhcp_client_core.py -v`（在 MtaP011-v0.1 目录）。使用非秘密合成报文，覆盖动态服务器、Offer/ACK pin、NAK、有限寿命、重传/预算/取消、恶意输入、不可变快照、fixed status、socket 创建禁令和 Python 3.5 AST。最终实跑数量与 SHA 由任务完成回报记录，本文不预填 PASS。

HOST / Python 3.5 AST 不证明 P011 import/真实 UDP/L2、关联、DHCP、地址安装或手机互传成功。本轮没有 ADB、Docker、设备/网络写入、正式冻结或全套测试。后续需独立 owned P2P CLIENT 关联及 socket 入口验证、真实链路/服务器来源绑定、有限客户端 IP 子租约与恢复、冲突检测、GO 端点证明；都不得由本核心配置快照代替。
