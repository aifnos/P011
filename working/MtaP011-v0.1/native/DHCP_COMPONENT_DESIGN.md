# 自有 P2P DHCP 组件与门控

本阶段只实现 `runtime/mta_dhcp.py` 的封包与状态机。没有接入 frozen GO lease，没有创建 socket、改地址/路由/DNS 或执行无线试验。此组件通过 HOST 测试，不是设备 DHCP 成功证据。

## 当前 API

```python
SingleClientServer(server_ip, client_ip, subnet_mask,
                   deadline=actual_owned_lease_deadline, expected_mac=None)
server.handle(private_packet_bytes, monotonic_now)  # response bytes / None
server.status(monotonic_now)                       # sanitized state only

ClientExchange(mac, expected_server, expected_mask,
               deadline=actual_owned_lease_deadline, xid=None)
client.discover(now)              # private packet bytes
client.accept_offer(packet, now)  # request packet bytes
client.request(now)               # retransmit same transaction
client.accept_ack(packet, now)    # private config; DOES NOT install it
client.status(now)                # sanitized, interface_configured=False
```

包体、MAC、client-id、IP 均只在 private 内存返回值中使用，不发送到 UI / 日志 / public artifact。服务端 ACK 的 option 51 来自实际 owned lease 剩余秒数；客户端 usable_until 为实际项目截止与实际 ACK lease 较小值。剩余不足一秒时不发虚构租约。

协议范围：Ethernet BOOTP / DHCP DORA、单地址单客户端、已绑定客户端续租/重启、release、decline。拒绝 relay、option overload、重复 TLV、畸形长度、无 end、非法 cookie、超过 1472 字节或 128 个 options。Rapid Commit 可作为客户端请求忽略，仍正常 OFFER / REQUEST / ACK，不伪造快速提交支持。client-id 若由服务器回显必须精确匹配；未回显的服务器仍需 xid / chaddr / expected-server 同时匹配。

私有 IPv4 子网必须包含预期 server 与候选 client；网络地址、广播地址、服务器自身、不同子网或错误 mask 不能作为 client。server 只提供 subnet / server-id / remaining-lease / client-id，不提供默认 router / DNS。client 对 remote 的 router / DNS 等选项不安装也不传入配置；最终 `interface_configured` 仍为 false。

## 下一阶段 adapter 设计（尚未实现 / 未授权 RF）

1. 只接 root 已实机验证的 private GO / CLIENT 租约，核对 `name, ifindex, WDEV, phy, iftype`、私有 WPA PID/starttime、TTL、journal 身份。没有实际 IP lease，`send.available` 保持 false。
2. 建立地址前先只读收集系统 IPv4 地址与路由子网，确认自有接口无未知地址、选定子网不与原厂 STA / VPN / 其它路由重叠。固定 `192.168.49.0/24` 仅是 HOST fixture，不能作为未经检查的生产硬编码回退。
3. 使用 scoped rtnetlink NEWADDR / DELADDR，带 ACK / CREATE / EXCL，journal 先记录意图，再记录实际读回的地址 / prefix / ifindex。禁止 REPLACE、全局 flush、修改 wlan0。kernel 自动建立的 connected route 也须 scoped 前后读回，地址回收后确认其消失；不设默认路由 / DNS。接口身份变化时拒绝删除。
4. server UDP 67 / client UDP 68 socket 使用 `SO_BINDTODEVICE` 指定唯一自有接口、`IP_PKTINFO` 校验实际 ingress ifindex。不得用 `SO_REUSEPORT` 分享系统 DHCP；bind 冲突直接失败。UDP 的通配 bind 是 DHCP 广播的传输要求，不能当数据 TCP 的 `0.0.0.0` 开门条件；必须证实 SO_BINDTODEVICE 和 pktinfo 后才 accept 包。
5. 每包限制长度 / pps / 总包数 / 截止时间，拒绝 MSG_TRUNC、CMSG truncation、错误 source port / relay / 非本接口。单 peer 地址来自实际 ACK / station + admission，而不是从 UDP 来源、DHCP MAC 或 TLS GET 任意猜测。
6. DHCP 无认证。WPA2 group 已建立也不能把 DHCP client-id / chaddr 当手机账户或应用身份；后续互传加密协议与实际 bound endpoint 必须核对。server 可将 `expected_mac` 绑定实际 admission 的关联 station，但要区分 GO device address 与 interface station MAC。
7. 数据 socket 与 DHCP socket 先关，再撤自有地址及 connected route，最后停 private WPA / 删除自有 netdev。TTL / 父进程退出恢复使用同一 journal；不启动系统 udhcpc 脚本或 dnsmasq，不杀原厂服务。

## 必须继续保持的未验证项

- root 的 GO / 原厂并发恢复结果；此文不替代 root 的实机记录。
- actual owned IP / connected route readback 与恢复；短时断父进程 / TTL 验证。
- 实际 Android / 手机 GO DHCP 互操作；手机能否接受“不提供 router/DNS”的 P2P 租约。
- UDP interface binding / pktinfo / broadcast 与本驱动真实行为。
- 互传应用手机侧 admission、TCP/TLS / 文件校验及取消后的完整恢复。

协议依据：[RFC 2131](https://www.rfc-editor.org/info/rfc2131/)、[RFC 2132](https://www.rfc-editor.org/info/rfc2132/)。实现为独立 bounded codec / state core，没有复制上游 DHCP 程序代码。
