# 自有接口 DHCP server socket 适配审查

2026-10-01 checkpoint，不是互传发布或手机 DHCP 验收。新增 `runtime/mta_dhcp_server.py`，复用原 `mta_dhcp.py` 单客户端纯状态机，未修改纯 core、V5/IP/harness/service/UI/能力。本子任务没有执行 ADB、RF、socket 或网络配置。

## 最小 API 与严格前置条件

```python
DhcpSocketServer(ifname, ifindex, server_ip, client_ip, subnet_mask,
                 deadline, fresh_gate, admit_station, cancelled)
server.open()         # 本进程独占的真实 AF_INET/UDP67，不改变网络
server.serve_once()   # 最多 0.2 秒 socket 轮询；无常驻线程
server.run()          # 同步 worker loop，取消/截止自动 finally 关闭
server.allocation()   # PRIVATE：成功 ACK 发送后的 IP/MAC/实际截止，非手机配置证据
server.status()       # 被动固定字段，无 IP/MAC/interface 名或 callbacks
server.close()        # True 仅表示自有 fd、opening/reader/close actor 都已关闭
```

调用方在 `open` 前必须持有真实 GO lease 和**已持久 confirmed receipt、完整实际地址读回**的 owned IP lease。同名、`ip_stage` 标签、HOST 假租约、只读 dump、V4 GO-only 均不满足条件。禁止将这些私有参数从 QML/HTTP 直接传入或允许用户自选接口/地址。

`fresh_gate()` 必须严格返回 `True`，由调用方同步核实 boot/candidate/phy/WDEV/ifindex/name/type、真实 IP/prefix/地址属性/connected route、操作 epoch、journal、TTL 等确切身份。适配器另用 kernel `if_nametoindex` 核对 ifindex，但这不能替代完整归属链。gate 不能仅读旧缓存或 capability；必须快、有界、只读。Session 的共同锁/恢复时序必须阻止 gate 返回后另一个 owner 删除并复用 netdev。

`admit_station(mac_bytes, client_ip)` 来自当前真实 WPA 关联和当前任务准入，严格 `True` 才处理。调用方不能无条件接受首包、把 BLE DeviceInfo.mac 当 Wi-Fi station MAC、把 chaddr/client-id 当认证；首包前、每包、发送前、已有 binding 查询和后续轮询都复核。关联失效/核查异常关闭 socket，不能解除 SenderTransport deny-all；后续 coordinator 仍需实际 station→DHCP lease→peer IP/手机协议证据链。

截止时间必须取真实 owned lease，剩余 1–300 秒，不自动延长旧 GO-only ≤20秒测试。传输参数仅 trusted 平台代码使用。测试专用 `clock/socket_factory/if_nametoindex` 注入绝不向服务暴露。

## socket / packet / egress 边界

- 创建一次 `AF_INET/SOCK_DGRAM/IPPROTO_UDP`，不设置 REUSEADDR/REUSEPORT，读回二者必须为 0；端口67冲突、权限失败或任何配置失败立即关闭自己的 fd，没有第二次通用网络尝试。
- `SO_BINDTODEVICE` 精确绑定自有接口，读回 name；`SO_BROADCAST`、`IP_PKTINFO` 与类型均读回。fd 设 non-inheritable 并读回；超时 0.2 秒并读回。只允许 DHCP 广播所需 `0.0.0.0:67`，getsockname 必须精确；这不授权任何 wildcard TCP listener。
- 仅 `recvmsg(MAX_PACKET+1, CMSG_SPACE(12), 0)`。包 240–1472 字节；任何截断/未知 flags、source 非68、来源非 0.0.0.0/本次候选地址、缺失/重复/未知 ancillary、错长度/ifindex/local-IP/destination 都丢弃，**不回复、不进入状态机**。无 recvfrom 回退。
- 内核 `in_pktinfo` 为本机字节序 ifindex + 两个 network-order IPv4 字段；入口 local address 必须匹配真实 server IP，目的可为本机/实际 subnet broadcast/limited broadcast。只接受一个完整 IP_PKTINFO cmsg。
- 出口只能 `sendmsg` 到由真实 server/mask 算得的**该子网广播:68**；pktinfo 固定当前 ifindex + server IP；不向 UDP 来源、任意单播、默认路由或原 wlan0 回退。未配置 option3/6，不提供 router/DNS。
- 上限每秒20包、会话512包；所有收到的包计入总限额。畸形/未知来源是 fail-closed 丢弃，避免一包关服务；持续限额、归属/关联失效、发送失败则关闭。核心 DECLINE 关闭并交给 owner 精确恢复，不自行换地址/重试网卡。

## 分配与取消/恢复的事实边界

只有完整 ACK 字节被 `sendmsg` 接受、随后 fresh gate 仍通过才发布 private allocation；usable_until 不超过实际 ACK 整秒 lease 与 owned deadline。纯 core 标记 bound 或 OFFER 发出均不够，短写/发送失败/晚取消不能发布。ACK 进入本机 kernel 只证明服务器发送分配，不证明手机收到、安装 IP、应用身份、TLS 准入或文件完成。

Owner 在线程启动前持有 server，恢复顺序必须是 DHCP/data sockets→owned address/route→private WPA/netdev。`close(False)` 保留精确 fd/actor；并发第二次 close 不会把尚未返回的 close actor 当已完成。factory 晚返回的 socket 归属仍保留并关闭；late recvmsg/send/旧 epoch 不得推进 allocation。除短时同步轮询外不创建线程/进程，无 journal 写入、信号、系统 DHCP 服务或原网络修改。

状态是被动历史/资源快照，`allocation_ack_transmitted` 不是当前网络 ready；需要可用性时调用 private `allocation()` 再复核 gate/关联。OS 异常文字、地址、MAC、payload 不进入固定错误/status。

## 证据与仍未完成的实际验收

- HOST：`python -B -m unittest discover -s working/MtaP011-v0.1/tests -p test_dhcp_server.py -v` **44/44 PASS**；fake Linux socket + 真实纯 DHCP codec/DORA，固定绑定/广播、包/cmsg/速率/单client/关联拒绝、失败、取消/晚socket/并发close与Python3.5语法等专项。原有纯核心 `native/tests/test_dhcp.py` **29/29 PASS**（含20,000畸形包 fuzz），core 没有修改。HOST fake socket 不证明 kernel socket 成功。
- Root 独立只读证据：`logs/MtaP011-UdpApiReadOnly-20261001-043409-b782aaca/result.json` PASS。实际 P011 Python3.5 已内省存在 recvmsg/sendmsg/CMSG_SPACE，SO_BINDTODEVICE25/SO_BROADCAST6/MSG_TRUNC32/CTRUNC8/AF_INET2；没有创建 socket，独立原网 before/after 不变。IP_PKTINFO 属性未暴露，本实现显式 Linux UAPI 数值8；**kernel setsockopt acceptance 尚未测试**。
- NOT_TESTED：实际 owned UDP67 bind/readback、内核 pktinfo ingress/egress、广播仅自有接口、当前真实关联准入、手机 DORA/续租/拒绝/地址冲突、无 router/DNS 的手机兼容、取消/TTL 后网络恢复。需要 root 后续明确范围的独立平台试验，不由本模块偷偷测试。
- 未接 mta_service/真实 worker，不改变 send/receive capabilities；未伪造实际 DHCP lease/phone completion，不把源码、HOST 或 API 内省当完整互传。

依据：[RFC 2131](https://www.rfc-editor.org/info/rfc2131/)、[Linux IP_PKTINFO](https://man7.org/linux/man-pages/man7/ip.7.html)、[Linux SO_BINDTODEVICE](https://man7.org/linux/man-pages/man7/socket.7.html)、[recvmsg 截断与 ancillary](https://man7.org/linux/man-pages/man2/recvmsg.2.html)、[Python socket](https://docs.python.org/3/library/socket.html)、[CPython 3.5 socket 实现](https://github.com/python/cpython/blob/3.5/Modules/socketmodule.c)。数值常量仅针对 Linux UAPI，不提供其它平台网络回退。
