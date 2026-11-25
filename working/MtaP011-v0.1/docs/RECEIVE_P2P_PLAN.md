# P011 独立 P2P CLIENT 接收路径设计

日期：2026-10-01。状态：**只读源码研究 / 接口设计，未实现或执行新的接收组网、DHCP、RF 或手机互传**。本次仅新增本文，不改 runtime/native/host，也不放开现有 receive/send gate。

> 后续实施修正（root，2026-10-01）：下文 V2 配置是作者当时读取的历史，不应再照抄 `update_config=0`。同一固定 WPA 的无 RF 配置对照已证实 `CONFIG_NO_CONFIG_WRITE=y` 不解析此项；V4 删除该行后真实 GO-only 通过。后续 CLIENT 候选也应不写此项，不执行 SAVE_CONFIG；CLIENT 的 `ap_scan=1`、关联、DHCP 和接口绑定仍须单独实现/实测。V4 GO 与 IPv4 只读证据不升级为 CLIENT/接收完成。恢复责任链和真实 worker 缺口见 `WORKER_IMPLEMENTATION_NEXT.md`。

## 结论与当前边界

可继续研究的路径是：手机经当前 BLE 会话给出真实且已校验的 P2pInfo，P011 在**新建且自有的 P2P_CLIENT** 上关联手机 GO，申请真实 DHCP 租约，用接口绑定的 socket 接现有 ReceiverTransport，完成确认、实际落盘和 ACK 后独立清理。不能在原 wlan0 上普通 STA join，也不能借用 ConnMan 未证明归属的原网。

ConnMan GetServices 为 0、原 wlan0 的独立 wpa 状态 COMPLETED 这一已记录事实，说明现有 ConnMan 快照不足以证明原网络恢复。当前 native 默认 `MTA_CONNMAN_STA_VERIFIED=0`、receive=false 是正确安全门槛。独立 P2P 是另一个后端，不得靠开启该宏、伪造 gateway、延长旧 GO-only TTL 或 runtime fixture 让页面显示可用。

`P2pInfo` 的现有字段为 ssid/psk/mac/port，加可选 key/id/catShare，**不含服务器 IP 或信道**。MAC 的字段格式通过不证明它就是 GO BSSID、DHCP chaddr 或客户端随机 MAC。本次初始阅读的 `ReceiverTransport.connect()` 直接 `socket.create_connection`，没有接口/源地址绑定，不能原样当作安全的独立 P2P 数据通路。root 已实现平台内部连接工厂注入点（见下方合同），并通过真实 P011 **回环** TLS 合成检查；未来 lease 的 SO_BINDTODEVICE、独立 CLIENT 接口及实际 route proof 仍未实现或通过，不可据回环结果开放 P2P receive。

## 本次读到的固定依据

| 依据 | 固定身份与本次结论 |
| --- | --- |
| 官方 wpa_supplicant 2.12 发布源码 | 本地归档 `native/private-p2p-candidate-20260930/source/wpa_supplicant-2.12.tar.gz` SHA256 `08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6` 已读回；下述函数链来自该归档。 |
| 独立 V2 候选 | 只读 `native/private-p2p-candidate-20261001-v2`；读取时 supplicant SHA256 `e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301`，对应 packaged `project-v2-supplicant.patch` SHA256 `bad24af1dcef004ab28cc0a6ab9c9e025cc18b2545587f709ec1118dd35a18c7`。这只是本次源码/包身份，不是已执行的 CLIENT/DHCP 证据；后续 mutation 必须重新冻结 review。 |
| 固定研究项目 | `GOAL.md` 固定 cattysend `540b49e8e3799b796e9114d1241006d325b3884b`、EasyShare `9f308437a7c0241787215dbad39d02f2927adc01`、HandySend `0a78217c2f5ea5a7049434ef1b6fcc3760b7f59b`、LinShare `a2e122a6db4d82b6c2ac87439801abeecca67ac9`。本次读取 cattysend 固定 README；没有本地四仓源码 checkout，未把未读的手机实现当作已核实 MAC 映射。 |
| 本项目现有实现 | 已读 `mta_protocol.py`、`mta_service.py`、`mta_transport.py`、`mta_send_wifi.py`、V2 build/config/transform；已有安全落盘/TLS 合成测试不证明本设计的真实 P2P 网络。 |

cattysend 固定 README 明示通过 NetworkManager/nmcli 管理网络，并允许基础设施连接暂时挂起；它是协议流程参考，不是本机“保留原 wlan0”的恢复实现。不能照搬其运行依赖或抢占策略。[固定 README](https://raw.githubusercontent.com/Tinnci/cattysend/540b49e8e3799b796e9114d1241006d325b3884b/README.md)

## 这不是 legacy STA join

| 控制流 | 实际语义 | 本方案是否接受 |
| --- | --- | --- |
| SET_NETWORK mode=0 → 普通 SELECT/ENABLE_NETWORK | 一般 infrastructure STA profile；仅 mode=0 不会自动变成 P2P | 不在 wlan0 上执行，也不能称为 P2P_CLIENT 验收 |
| mode=0、disabled=2 的私有内存 profile → P2P_GROUP_ADD persistent=<id> | 2.12 的公开 ctrl 入口进入 P2P client 分支 | 本设计候选，仍需真实驱动/手机验证 |
| 自定义 SET_NETWORK p2p_group=1 | p2p_group 是上游内部字段，不是可依赖的公开配置接口 | 不使用 |

固定源码函数链：

1. `ctrl_iface.c:p2p_ctrl_group_add_persistent` 要求当前私有实例 network 存在且 disabled=2，进入 `wpas_p2p_group_add_persistent`。
2. `p2p_supplicant.c:wpas_p2p_group_add_persistent` 以 mode=WPAS_MODE_INFRA 进入 `wpas_start_p2p_client`；mode=P2P_GO 是另一个分支，不能混淆角色。
3. `wpas_start_p2p_client` 建立 temporary network、复制已供给的 SSID/PSK、设置 p2p_group=1，随后进行关联。
4. `wpa_supplicant.c` 把 `ssid->p2p_group` 传入关联参数 `params.p2p`。因此相同 mode=0，在这条入口下使用 P2P 驱动语义，不是仅给第二个普通 STA 改名字。
5. `wpas_p2p_create_iface` 在私有配置 p2p_no_group_iface=1 时不再生成第二个 group iface；`wpas_p2p_get_group_iface` 复用本私有实例的 primary iface。本实例必须只拥有项目新建的 P2P_CLIENT，绝不能把原 wlan0 加入其 global iface 列表。仍需核实驱动是否能在该模式工作；不支持就拒绝，不能为了绕过创建新未知 iface。

“persistent”在这里选择上游 profile/control 语义，不意味着保存用户配置。V2 编译 `CONFIG_NO_CONFIG_WRITE=y`、私有 cfg `update_config=0`，不执行 SAVE_CONFIG；凭据只在私有内存 profile，退出清除。不复制未明确许可项目的实现。上述驱动、group、关联分层与官方 P2P 文档一致；文档页面标为 2.5，精确控制分支以本地固定 2.12 源码为准。[官方 P2P 架构](https://w1.fi/wpa_supplicant/devel/p2p.html)、[固定发布包](https://w1.fi/releases/wpa_supplicant-2.12.tar.gz)

## 最小新增接口（后端合同为建议；ReceiverTransport 注入点已实现）

| owner / 接口 | 最小合同 |
| --- | --- |
| `ReceiveP2pBackend.capabilities()` | 只读接口/组合/当前 ownership；declared 与 actualVerified 分开。未验证 CLIENT 并发、原网保持、DHCP、transport binding、恢复前，available=false。不能把 station+GO 条件用作 station+CLIENT 条件。 |
| `prepare(cancelled, timeout)` | 开启可发现前捕获原厂进程/PID/starttime、wlan0 full-state 私有指纹、接口 identity、addresses/routes、boot/candidate 与共享设备互斥锁；持久“网络未改”checkpoint。不扫描、关联、创建 iface 或开关原 Wi-Fi。 |
| `receive(validated_info, consent, cancelled, deadline)` | 只接当前 helper/native_epoch/operation_epoch 的已校验并解密 P2pInfo；同意绑定一次任务和 TTL。使用同一早基线；任何变更前 active lease/journal 已由 backend 持有。拒绝 UI 任意 SSID/path/ctrl 字符串。 |
| `ReceiveP2pLease` | privately 持有 owned iface `{boot,phy,wdev,ifindex,name}`、私有 WPA/DHCP PID+starttime+exe/candidate、netlink 地址/路由精确项、实际 local_ip、endpoint_ip、port、deadline、阶段。不能用 gateway 字段的旧习惯偷偷把 router 当应用服务器。 |
| `lease.socket_factory(host, port, timeout)` | 供 ReceiverTransport 内部调用的受限 factory：只能连接已核实 endpoint_ip+P2pInfo.port，并返回真实已连接 raw TCP socket；必须 SO_BINDTODEVICE 到 exact-owned iface，并 bind 实际 local_ip。每次连接前确认 identity/租约/epoch及实际 route proof未变，失败不退回默认路由。 |
| `ReceiverTransport(..., socket_factory=..., source_ip=lease.local_ip)` | root **已实现**的平台内部注入点。factory与真实private source_ip必须一并提供，拒绝None/wildcard或只提供一项；不从QML公开。精确工厂签名为 `socket_factory(host, port, timeout)`，必须返回真实已连接的 raw `AF_INET/SOCK_STREAM` socket，不能返回TLS socket/fixture对象。WSS与download均用同一factory，核实raw socket的getsockname源地址等于source_ip、getpeername等于精确目标host/port，再TLS；错误闭socket、无默认路由fallback，保留本task first-pin。两项读回不能单独证明interface：SO_BINDTODEVICE/iface identity/route proof由future lease负责。默认旧连接兼容原调用，但不证明独立接口、不能据此开放P2P receive gate。 |
| `status()/restore_active()/recover_pending()` | 公共只固定 stage/计数/restorePending/recoveryLocked/reason；恢复失败保留 active owner/journal，禁止新 RF。私有绑定数据/凭据不进 HTTP、argv、日志或 ZIP。 |

不新增任意 shell、netlink command、wpa_cli passthrough 或 UI 指定 ifname。原 GO 租约的 owner/journal/watchdog 可抽取共用接口，但不能直接调用 GO-only activate 后把其类型标签改成 client；旧 adapter 的 close 不等于 restore。重实现由 root/native owner 接线。

已读取 root 的 `logs/MtaP011-DeviceTls-20261001-013007-24b9a9d6/result.json`：候选 `ef0ebab3aad65b9f`、`evidence_level=P011_TLS_LOOPBACK_SYNTHETIC`、PASS；两次真实回环factory调用、source socket fixture读回、实际合成文件hash/bytes、匹配接收ACK与自有资源关闭均通过，`radio_operations=false`、`phone_interop=NOT_TESTED`。这证明上述注入点在目标 Python 3.5/TLS 上的回环兼容层，不是独立接口绑定、P2P/DHCP或手机互通证据。本子任务只读报告和源码，没有执行这轮设备试验。

## 关联阶段：先证明自有 CLIENT，后证明 connected

1. 提前持久准备；只有收到当前真实手机 P2pInfo、加密解析/P-256/长度检查通过且本次网络同意有效，才创建 iface。base64/AES-CTR 解密本身不是认证手机身份；不能使用过期或跨 helper 会话的 payload。
2. 使用现有 nl80211 CREATE|EXCL 类所有权策略建立随机 `mta`+8hex iface，真实 ACK/readback 的 phy/WDEV/ifindex/name 必须不在原基线。V2 explicit gate、candidate SHA 与私有 initial P2P type必须核实；不尝试把 wlan0 切成 CLIENT、AP 或 DOWN。
3. 检查实际组合对 station+P2P_CLIENT 的 count 与信道约束。第一轮应限已验证的同信道；手机字段没有 freq，需在本自有 iface 的有界目标扫描中实读手机 GO 频率。不能填原 wlan0 频率假装手机同信道，也不能把 off-channel/多信道 driver 声明当实际并发 PASS。
4. 私有 cfg 用 ap_scan=1、p2p_no_group_iface=1、update_config=0 和项目私有 ctrl 目录；不使用原厂 ctrl socket、系统 D-Bus supplicant 或原 profile。对 SSID 原字节做十六进制编码；PSK 要么在私有内存按 WPA2 派生为 32-byte key 后十六进制提交，要么严格转义到固定 SET_NETWORK 字段。禁止换行注入、拼接任意 ctrl command、把口令放入 wpa_cli argv。
5. 只用私有 ADD_NETWORK 的真实 id，固定设置 RSN/WPA-PSK/CCMP/mode=0/disabled=2，提交 P2P_GROUP_ADD persistent=<id>。没有已验证 GO BSSID 映射时不把 P2pInfo.mac 强塞 go_bssid；也不自动切去 WPS/PBC 或不加密开放网络。
6. private event/readback须同时证明 P2P-GROUP-STARTED 的 **client** 角色、COMPLETED、真实 SSID/安全套件一致、当前 iface identity 仍属于本租约；只有 ctrl `OK`、接口 type=8 或普通 CONNECTED 不够。若出现新未登记 iface、角色 GO、变 station、未知 controller 或 wlan0 状态变化，停止推进，进入 owned cleanup/待核验，不偷偷重试普通 STA。

## DHCP：真实地址租约，不改变原网路由/DNS

需要新增 scoped DHCPv4 client。推荐独立 native 有界 client，仅在 owned ifindex 上收发；可采用接口绑定的 AF_PACKET，避免原厂 DHCP UDP/68 listener 冲突。该推荐是工程选择，不是宣称已有 native 实现。若复用 udhcpc，必须先证明目标 applet、接口/脚本隔离、进程归属、所有权和超时；绝不能执行系统默认脚本、停止原厂 DHCP、删除已有 pidfile 或用静态地址冒充租约。

最低验证：当前事务 xid、chaddr/client identity、BOOTP/UDP 长度、magic cookie、option 边界与唯一/一致 ServerIdentifier；收到匹配 Offer→Request→ACK，取得真实 yiaddr、mask、租期/续租时刻和 option 3 router。ACK 前不配置地址；配置前做地址冲突探测，冲突走 DECLINE/失败，不抢占。RFC 要求 ACK 后核对参数并检查冲突；重试有界且可取消。[RFC 2131 §§3.1、4.4](https://www.rfc-editor.org/info/rfc2131/)

应用状态：

- 拒绝 relay/无法归属的 DHCP来源、bool/非法地址、组播/广播/0地址、非连续掩码、异网段 router、多个不一致关键 option、租期过短或租约过期。对不支持的合规扩展应报不支持，不把截断数据当成功。DHCP 不是认证机制，source/xid 匹配不标成“手机认证”。
- 只把 ACK 的自有地址加在 exact-owned iface，记录 netlink ACK 与独立读回；不安装 default route，不写 resolv.conf、系统 DNS、ConnMan 属性、iptables/sysctl/全局 namespace。
- 优先不生成 connected-prefix route（目标支持时用地址 NOPREFIXROUTE，并实读验证）；仅为核实的应用 endpoint 配置精确、租约自有的 host route/源地址选择。与原 wlan0 子网/地址重叠无法隔离时拒绝，不改原路由 metric 来抢流量。SO_BINDTODEVICE+源地址绑定仍是 transport 必需门槛。
- ACK租约接近过期必须在本接口内有界续租，或在过期前取消/关闭数据通道；不能为了文件传完继续使用失效地址。状态持续核对 iface/地址 identity，晚 ACK/旧 xid 不更新新租约。

## 服务器地址的实际读回与确认

RFC option 3 是 router 列表，option 54 是 DHCP server 标识，两者不同；都不自动证明是 MTA 应用服务器。服务器候选只能来自本租约实际读到的 router/ServerIdentifier，并绑定当前 GO association 的链路/邻居读回；不猜 192.168.x.1、不把 MAC 编成 IP，也不扫描整段网找开放端口。[RFC 2132 §§3.5、9.7](https://www.rfc-editor.org/info/rfc2132/)

最小策略：若本次 DHCP 的唯一、同子网候选能经当前 CLIENT接口读回并证明在当前 group 链路，才在 **P2pInfo 原始 port** 做一次有界 TLS/WSS MTA 协商；候选缺失、router/server不同且不能确定、无法证明链路归属则 unavailable/具体失败，不枚举更多地址碰运气。邻居地址与 GO BSSID/device address 的关系必须通过真实读回确认，不能假设 P2pInfo.mac 必然相等。

应用协商检查 versionNegotiation、sendRequest/taskId/字段边界；本 task 首次 TLS 证书 TOFU，下载再连需完全相同。TLS CERT_NONE 不代表 CA 验证，证书未与 BLE ECDH 公钥密码绑定；当前方案不能宣称已认证手机账号/身份。新增 endpoint verification只能证明“当前私有组内、当前协议通道一致”，不能把地址或 ACK 当更强身份凭据。

## 正式 worker 及结果顺序

```text
prepare（原网只读基线与 owner 持久化）
  → 已核实 capability 后，本次同意/有界 BLE 可发现
  → 同 helper/epoch 的真实 P2pInfo → 解密/字段校验
  → owned P2P_CLIENT association + client/COMPLETED 独立读回
  → scoped DHCP Offer/Request/ACK → 冲突探测 → 自有地址读回
  → 当前 group 的真实 endpoint 证明 → 接口绑定 TLS/WSS/MTA 协商
  → 真正的文件请求与用户确认（拒绝/超时前不下载）
  → 有界 ZIP 实际下载 → SafeZipReceiver 原子提交/实际 bytes
  → 当前 task type=1 通知及匹配 ACK（丢失保持未确认）
  → 关闭应用 sockets → own DHCP/address/route cleanup
  → 精确 private WPA 退出 → own netdev 删除 → 原厂独立读回
```

network consent 与文件接收确认是不同阶段：第一项在网络关联前，第二项在 sendRequest 后、下载前。不得后台补 consent=true 代替 UI 同意。长耗时关联/DHCP/下载/清理不持有 State.lock 或 native reader callback，取消与 status保持响应；旧 epoch不得更新新 UI，但其 owned finally仍需完成。

结果至少拆为 `associationVerified`、`dhcpLeaseVerified`、`endpointVerified`、`localCommitVerified`、`peerAckVerified`、`ownedResourcesClosed`、`originalBaselineVerified`。只有相关真实证据成立才置 true；协议 ACK 不等于手机 UI 完成，原厂文件/进程不变不等于网络恢复，Ctrl ACCEPTED不等于任何文件事实。已落盘而 ACK/恢复失败，保留落盘事实和 recovery_pending，避免诱导重复传输。

## 恢复与崩溃 journal

- prepare 先写 durable 未改网络 checkpoint；CREATE前记录 intent、ACK/readback后记录完整身份；WPA/DHCP启动前后记录准确 PID/starttime/exe；添加每条地址/route前记录 intent，成功ACK后存其精确 identity及租约时限。都 fsync+atomic replace；0700 namespace、600文件、无symlink/额外硬链接。
- journal不存 SSID/PSK/私钥、裸 GATT包或 WPA debug。为精确回收所需的 owned地址/route可仅存在私有 journal，不能进公共状态/ZIP；其他敏感原状态只存私有指纹。口令过进程私有 stdin/ctrl后内存清零，关闭coredump。
- 正常恢复先停本任务socket/DHCP续租并尽力 RELEASE真实有效租约，再清精确自有地址/route、等待私有WPA退出，删除 exact owned WDEV。该 DHCP release发送成功只是一层，不能替代资源恢复；原 wlan0 不被“恢复”重配。
- iface iftype可因私有WPA变动，但同名不是归属证据。须同 boot+CREATE|EXCL origin+phy/WDEV/ifindex/name+不在原baseline+controller已退出。受限转换{CLIENT/GO/station}回收需明确review，不能全局允许删除任何 station。
- 独立 watchdog须保留owner，父进程EOF/SIGTERM/TTL触发有界回收；崩溃后只有完整同boot/candidate/进程/对象证据才recover。跨boot、iface/PID复用、未知管理器、新地址、原baseline变化均锁定，不按名字kill/delete/flush。恢复超时保留 Popen和journal，不起第二个mutation actor。
- 原厂联网在运行中或恢复读回发生外部改变时，清理自身资源后报告 baseline_changed/需人工核实；不要对wlan0发CONNECT、DOWN、SET_NETWORK或停止管理器来“还原”。未核实的网络状态不能报成功。

## 最小失败矩阵与证据门槛

| 注入 / 实际异常 | 必需行为与证据 |
| --- | --- |
| 旧 helper/epoch、非法加密字段/SSID/PSK/port | 关联前拒绝；无新增iface/进程，凭据不泄漏 |
| 不支持 station+CLIENT、手机GO信道超出已验证组合 | 不动原网；不能把GO组合声明或理论双信道当CLIENT通过 |
| interface创建ACK不明、private init失败、type变STA | 保留完整owner，停止推进，exact-owned独立读回；不重复新建 |
| SSID相同但目标安全/GO身份无法确认、握手失败/超时 | 无DHCP/transport；客户端失败事实与恢复事实分开 |
| DHCP wrong xid/旧ACK/NAK/非法mask/router/租约过期/地址冲突 | 不配置或及时撤自有配置；原网无route/DNS改动；无静态IP回退 |
| DHCP endpoint缺失/多候选、neighbor/group证明不一致 | 不TCP扫网段、不猜网关、不把MAC映射成IP |
| 子网重叠/私有socket绑定失败/iface身份改变 | fail closed；证明连接未走wlan0；不能普通create_connection回退 |
| TLS证书轮换、MTA版本/请求不符、文件确认拒绝/到时 | 停本任务；确认前零文件下载/提交，关闭实际socket |
| ZIP越界/CRC错/断流/空间不足/用户取消 | 只清本次临时文件；不覆盖既有文件；大小/hash/进度来源真实 |
| 已提交而ACK丢失、之后资源恢复失败 | localCommit保留，peer未确认/recovery_pending，不假completed/重新发送 |
| 父/私有WPA/DHCP死亡、watchdog/restore超时、PID/iface复用 | 保留durableowner/锁；不同对象不kill，不隐藏残留 |
| 原厂wlan0、route、进程身份或Wi-Fi指纹变化 | 独立检查FAIL并诊断；不自动接管原网“修复” |

后续最少分四级推进，任何一层不能替代下一层：

1. **HOST_CONTRACT**：实际未来worker接fake驱动/私有ctrl/DHCP packet parser，故障与时序断言；再跑真实HOST TLS接口绑定/admission及恶意ZIP。测试报告必须区分mock、真实socket、实际文件，不新造production假实现。
2. **P011_CLIENT_RUNTIME**：root审核冻结候选和固定20秒级CLIENT试验；真实association event+COMPLETED+iface identity，原厂station持续完整；退出后新独立进程查原厂 hashes/PID/starttime、原wpa full fingerprint、routes/interfaces与journal。仅association不称DHCP/文件PASS。
3. **P011_DHCP_DATA_RUNTIME**：当前owned组真实DHCP/ARP/地址/route读回、socket实际local/source/ifindex、WSS+download两次绑定、实际合成文件bytes/hash+matching ACK，取消/断父进程/TTL无owned残留。原网status/路由保持需运行中与结束后的独立证据。
4. **PHONE_E2E**：指定手机品牌/系统/原厂互传版本，发现、加密写入、真实GO与DHCP、用户确认、单/多文件中文名实际hash、手机完成提示、拒绝/取消/超时、原网恢复。人工UI和真实性未通过不得标目标完成或开放未验证品牌。

当前继续交付的是设计、真实源码证据和UI人工清单；没有已实现CLIENT/DHCP或手机互通结论。接收网络能力保持disabled，直到root/native owner完成上述平台与数据层的独立验证。
