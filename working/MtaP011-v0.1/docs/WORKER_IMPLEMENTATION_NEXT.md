# 真实互传 worker：代码入口与最小实施顺序

2026-10-01，只读审查快照。本轮仅新增本文，不改源码/能力/UI/host，不访问设备、网络或用户数据。
已读 mta_service.py、mta_wifi.py、mta_sender.py、mta_transport.py、SEND_INTEGRATION_PLAN.md，并核对关联文件选择/GO adapter/IP 草稿入口。
独立 V4 GO-only 与真实回环 TLS 已有分层证据；没有把 GO、只读 IP dump、HOST fixture 升为 IP/DHCP/association/手机 worker 完成。
SEND_INTEGRATION_PLAN 的 21 项 ContractFixture/ListenerFixture 是接线要求，不是可部署 worker；其中首轮 GO 失败叙述为历史，不覆盖后来的 V4 GO-only 记录。

## 当前真实入口与缺口

| 位置（本次行号） | 已有代码 | 接正式 worker 前还缺什么 |
| --- | --- | --- |
| mta_service.State.__init__:88、action:143/186 | FileRegistry、SafeZipReceiver、持久 WifiBackend；send 字段仅 deviceId/fileIds | send_available 固定 false，send 分支直接拒绝；没有 SenderTransport/SendWifiBackend/SendSession owner |
| State.start_receive:189 → native_event:226 → receive:276 | prepare 早基线、真实 BLE P2pInfo 解密、接收线程、确认与进度回调 | 仍是 ConnMan STA 后端，不是独立 P2P CLIENT；没有 operation_epoch/session-bound consent，接收内硬传 consented=True |
| State.native_event:226 | helper 的 native_epoch 过滤、fresh cached=false 的发现表 | client_status/client_write 结果未路由；现有 P2P 解密在 reader 回调/State.lock 内执行，正式 worker 应用有界事件队列分派 |
| mta_files.FileRegistry.open_selection:69 | 不透明 fileIds、无 symlink/stale/变更、实际只读 handles；FileSelection.close:19 | sender worker 真实调用并持有，失败/取消 finally 关闭；不能自行构造 FileSelection 或接受 UI 磁盘路径 |
| mta_sender.SenderTransport:93、start:293 | 真实有界 ZIP/实际文件快照、私有 TLS证书、WSS/HTTP、task/ACK、字节计数 | State 未调用；真实 lease 必须提供 local IP 和 listener_factory(host, port)；不得使用 allow_loopback fixture |
| SenderTransport.authorize_peer:357、wait:592、close:610 | None 拒绝全部；唯一 peer 授权、实际发送后才接受 type1，取消与本地资源清理 | authorize 的 association/DHCP proof 属于调用 worker，不由 transport 自证；close 不是网络恢复，也没有返回“所有线程退出”的验证布尔值 |
| mta_transport.ReceiverTransport:207/connect:228/run:264 | factory+source_ip 成对、raw TCP 源/目标读回、同任务 first-pin、确认后下载、SafeZip 提交、matching ACK | State.receive:282 未传 factory/source，仍按 lease.gateway 默认路由；未来 lease 证明 SO_BINDTODEVICE/接口 identity/route/endpoint 后才能接 |
| mta_wifi.WifiBackend.prepare:311/receive:334 | 早 snapshot、私有 stdin 凭据、持久恢复锁、真实 native ConnMan 调用 | 当前原厂 STA/profile 归属未证，不能开 gate；send_lease/create_p2p_lease/create_ap_lease:366 均抛 unavailable，不是 sender 网络实现 |
| State.restore_network:320/stop_radio:333/close:370 | 旧 WifiBackend active 恢复、BLE 退出/独立 capability 读回、关闭等待 | restore_network 只恢复旧 wifi_backend；给 self.lease 塞新 GO/IP lease 后照用它会漏 owner，需按真实 Session backend 汇总恢复/pending |

## 平台组件不要混层

- runtime/mta_send_wifi.py:873 的 SendWifiBackend.create_group 仍是 ≤20秒 GO adapter；SenderGoContext.local_ip=None、ip_ready/dhcp_ready=false，close 仅 backend close。
- 通过的是独立 V4 冻结候选的 GO-only 路径；不能将它等同于 State 已接入，不能只改 send_available，或静默把实验 TTL 扩成正式会话时长。
- runtime/mta_ip.py 是纯 bytes/snapshot/subnet/ACK core；ACK 不等于地址读回或归属。runtime/mta_ip_lease.py 的 RouteTransport/OwnedIpLease.create/restore 正由 IP owner 接 V5，仍属进行中草稿。
- IP-only 草稿与只读目标 snapshot 不提供 DHCP server/client、IP socket、手机 association 或服务 worker；正式接线前仍需地址安装/精确恢复的独立验证。
- 独立接收 CLIENT backend 尚缺实际 association 与 DHCP 租约；不能用 ConnMan gateway、固定 x.x.x.1、假租约或 ContractFixture 网络上下文代替。

## 必须先定的 Session 合同

1. action 接受后先保留 immutable taskId、operation_epoch、native_epoch、exact helper handle/peer、总 deadline、单独 cancel/decision Event；在线程启动前安装 owner/worker。
2. sender 用生成当前 opaque peer 的同一个 helper，且 fresh/noncached/未过期；不能 new_helper 后重用旧数字。native read/write 结果按当前 peer/期望阶段/epoch 分派，不阻塞 IPC reader。
   已核实固定 IPC 为 `{"cmd":"client_read","peer":N}`、`{"cmd":"client_write","peer":N,"payload_b64":"..."}`；精确字段，无 adapter/ttl，N 为整数1..65535。
   `client_status` 带 peer/payload_b64；`client_read/client_write` 完成/错误只有固定 code，write 完成不带 peer/taskId。必须单 active pending+同 helper/epoch/期望阶段匹配，不能伪造 requestId 或让旧完成推进新任务。
   ReadValue 状态≤512字节，canonical-base64 write非空UTF8对象≤2048；单helper表≤32，read停自己的扫描；WriteValue accepted/cancelled_or_late_reply 都不证明传输。stop与晚Connect的归属须等真实helper清理，不全局Disconnect既有连接。
3. 网络同意绑定本任务/时限并可审计；文件确认另在 sendRequest 后。当前自动 consented=True 不可当作未来新网络后端的授权来源。
4. GO/CLIENT/IP/DHCP/transport/selection/key 均在变更前被 Session/backend 持有；prepare 先 durable 未改网络 checkpoint，mutation 前写 intent，真实 ACK/身份读回后写 receipt。
5. 共享设备锁与同一 GoLease journal/watchdog 域；boot、candidate、phy/WDEV/ifindex/name、PID/starttime、IP 地址/路由 exact identity 保留在私有记录，不进 HTTP/公开包。
6. 取消仅置本 Session Event，再由 worker 有界清自身资源；旧 epoch 不更新 UI，却必须继续 finally。长耗时 prepare/crypto/activate/等待/恢复/helper.close 不持 State.lock。
7. 所有 owner 完成清理前不释放 worker 允许新任务；恢复超时保留 actor/Popen、journal、restorePending/recoveryLocked，不另起 mutation actor、不 SIGKILL/按名删未知对象。

## 最小实施顺序

### A. 先完成真实网络租约，不发布 BLE 凭据

1. 固定 V4/V5 身份与原厂早基线；先验证 GO→IP-only create/readback→精确 restore 和断父进程/TTL 恢复，旧 FAIL 不升级。
2. 再接 owned iface 的真实 DHCP server、租约分配/冲突/续租/取消与 exact-owned 清理；server 选择的本地地址必须真实配置并读回，不猜手机 IP。
3. 证明 station 并发、信道、实际 GO/CLIENT 类型、原 wlan0/原路由/DNS未被改；未知 ACK/对象归属或 baseline_changed 均锁住，不扩大旧20秒测试结论。
4. 实现 lease 的 scoped listener/connect 工厂：Sender factory(host,port) 返回 bound 未 listen/未 connected raw AF_INET TCP；Receiver factory(host,port,timeout) 返回已连接 raw TCP。
5. 工厂实际 SO_BINDTODEVICE 到 exact-owned iface，bind/readback真实源地址，每次连接核实租约/identity/route；禁止 wildcard、默认原网回退或只用 getsockname 充当接口证明。

### B. 接 sender worker（新的 State 入口，不用 fixture）

1. action(send) 先严格校验当前 peer/fileIds/同意，真实 registry.open_selection；同 helper client_read，DeviceInfo/P-256/ECDH/空闲状态通过后才 mutation。
2. persistent lease prepare→真实 GO/IP/DHCP ready；创建 SenderTransport(local_ip,0,selection,...,allowed_peer_ip=None,listener_factory=lease 工厂)，start 获取真实 port。
3. 用真实 GO SSID/PSK/go_address 与该 port 构造 P2pInfo，真实 encrypt_credentials→同 helper client_write；遵守 native status512/P2P2048/IPC8192 限制。
4. 真实 association + 当前 DHCP peer/地址/租约读回，并核实目标 peer 关联；DeviceInfo.mac 不可直接等同随机 P2P client MAC。匹配失败保持 deny-all。
5. 才 authorize_peer(真实IP)，wait 真实 WSS/下载/匹配 task type1；BlueZ WriteValue accepted 只是交接，不是文件完成。
6. finally 关闭实际 transport/handles/key/BLE，再正确 backend restore/独立原厂读回；保留 actualBytes、peerCompletion、resourcesClosed、networkRestored 四种事实。

### C. 改接 receiver worker（独立 CLIENT，不偷开 ConnMan）

1. 开可发现前 prepare 早基线；当前 helper/epoch 的真实加密 P2pInfo＋本次网络同意后，执行 owned CLIENT association/COMPLETED/安全套件身份读回。
2. scoped DHCP client 真实 Offer/Request/ACK→冲突检查→owned address/readback；实际 group 链路与协议验证出 endpoint，不能把 router/ServerIdentifier 自动当 MTA server。
3. 替换 State.receive:280–282 的后端/endpoint，并传 socket_factory=lease工厂、source_ip=lease.local_ip；confirm(request) 成功后才下载/原子提交。
4. 保留本 task TLS first-pin；CERT_NONE/TOFU 与 BLE ECDH 没有密码绑定，不能声称手机身份认证。localCommit 与 peerAck/手机UI/网络恢复分开，不因丢 ACK 擦除已落盘事实。

## 验收与开放能力

- 把既有21项合同改挂到实际 worker（测试仍可 fake外设），证明顺序、晚事件/取消、坏peer/key/fileId、mutation/ACK UNKNOWN、恢复失败与状态可响应；不导入 ContractFixture 当 production。
- 再分层验证 HOST真实TLS/scoped工厂 → P011 GO/IP/DHCP/绑定/恢复 → 当前手机加密握手/association/单多文件实际bytes/hash/拒绝取消/手机提示。
- 两向 actual 平台/数据/恢复门槛通过前维持 receive/send unavailable；GO-only、IP-only、回环与手机事实各自报告，正式目标不能以 disabled 或 mock PASS 收尾。
