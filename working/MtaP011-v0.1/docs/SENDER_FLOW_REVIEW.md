# 发送服务接入 review 与证据边界

本文件给出下一步 service 接线方案，不实现虚假的“发送已可用”，也不把回环链等同于手机互通。审查范围为当前 `mta_service.py`、`mta_sender.py`、`mta_send_wifi.py` 以及原生助手的 `client_read` / `client_status` / `client_write` 契约；不在本轮直接修改这些生产模块。

## 已有证据

2026-09-30 的真实 **P011 TLS/WSS 合成文件回环**已通过：

- Python **3.5.5**、OpenSSL **1.0.2p**，真实两次 **TLSv1.2** 握手，而非 HOST mock。
- `FileRegistry → FileSelection → SenderTransport → ReceiverTransport → SafeZipReceiver`，2 个合成文件实际 **1,050,940 bytes**；ZIP 收、发均为 **1,051,228 bytes**。
- 精确校验 ZIP 的 `选择编号/Registry 相对文件名` 映射、落盘大小及每个 SHA-256；请求文件数 / 总大小、最终文件进度一致。
- 接收侧实际完成 ACK 与发送侧匹配 task 的完成状态均已核验。只发起 GET、GATT 写入或收到 HTTP 200 都不会被算作成功。
- owned listener / worker 线程、socket、selection、下载临时 ZIP、证书私有目录均完成清理。原厂文件 hash、PID / starttime / parent 身份经前后**独立** gate 检查保持一致。
- 无 RF 操作、无 Wi-Fi 切换、无 UI 启动、不读取用户文件。loopback 仅是此测试进程 constructor fixture，生产 `private_ipv4` 策略没有改动。

运行入口：`python -B host/device_tls.py`。结果位于：

`D:/project/P011/logs/MtaP011-DeviceTls-20260930-202543-402a0ee7/result.json`

对应 `.sanitized.zip` 只含 `result.json` / `README.txt`；私有 raw / immutable candidate 不入包，证书 / 私钥不入包。候选 manifest 身份为 **04bd57a551f33181**，只包含七个 TLS 必需 runtime 文件，不包含并行开发中的网络助手。

前两次结果原样保留：真实 TLS / ACK / 计数已经通过，但新 harness 先用未加编号的路径作为 ZIP 预期，触发 `AssertionError`。修正的是测试预期的**精确编号映射**，并未修改生产协议、忽略路径或放宽校验。第三次完整字节 / hash PASS；不能把前两次失败改写为成功。

以上不证明手机发现、手机接收提示、实际无线吞吐、P2P/AP 组网、DHCP、路由恢复或物理界面恢复。既有 HOST TLS / native 私有 D-Bus fixture 与本项 P011 证据分开记录，手机层仍为 **NOT_TESTED**。

## 当前 API 的真实含义

2026-10-01 增量：`SenderTransport` 监听初始 deny-all，`authorize_peer()` 只允许调用方在当前真实关联/DHCP/租约证据成立后绑定一次；同地址可幂等，不允许换地址。内部 `listener_factory(host, port)` 返回已绑定、未监听的 raw IPv4 TCP，读回本地地址/实际端口并拒绝连接态/不安全返回；失败不回退到默认 socket。`ReceiverTransport` 的 socket_factory/source_ip 同样要求实际源/目标端点读回。接口 SO_BINDTODEVICE/epoch/route 的平台证明仍未实现，不能凭回环地址读回代替。

候选 `bd98466e6016e3e8` 的 `logs/MtaP011-DeviceTls-20261001-015853-8b278882/result.json` 已在 P011 完成两连接 TLSv1.2、合成字节/hash/双方 ACK、初始拒绝/一次授权、两个接收连接工厂和一个发送监听工厂的普通传输回归；不操作 RF，不证明手机互通。两个新 HOST 确定性 race 回归验证了 close 后晚返回 raw 被关闭、完成 ACK 期间取消不会发假 completed；未将该 race 分支称作实机验收。所有旧报告保留。

服务接线应先启动 deny-all TLS listener 并取得真实端口，再发送含该端口的加密 P2pInfo；真实目标关联与 DHCP/epoch 验证成立后才 `authorize_peer()`。不要猜目标 IP 或让首到连接授权。最终状态回调在 transport lock 外执行；State 不持自己的锁阻塞调用 sender.cancel/close/wait。详见 SEND_INTEGRATION_PLAN.md。

后续 coordinator 接线仍须让终态与 epoch 保持 sticky：底层多线程进度通知可已在调用途中，外层不能让迟到的 transferring/preparing 覆盖 completed/cancelled/failed。当前 transport 的 result/终态事务已确定性验证；尚未实现双向 worker，因此这一外层门槛不能标已完成。

| 已有接口 | 可以依赖的事实 | 不能据此推出 |
| --- | --- | --- |
| native `scan` / `discovered` | 当前 helper 的匿名 peer 编号；`cached` 区分缓存与新事件 | 旧 helper peer 在新 epoch 有效、手机当前在线 |
| `{"cmd":"client_read","peer":N}` | 只连接当前发现表的 MTA peer，并寻找 9955 主服务 / 9954 状态 / 9953 P2P 特征 | 已获正确密钥、对方空闲、可创建 Wi-Fi 网络 |
| `{"event":"client_status","peer":N,"payload_b64":"..."}` | 状态字节已读取；最大 512 bytes，native 仅检查 UTF-8 / JSON 包络 | 完整 DeviceInfo schema、P-256 SPKI 公钥、状态或真实性已经验证 |
| `{"cmd":"client_write","peer":N,"payload_b64":"..."}` | 向同一个已就绪 peer 的 9953 进行有界 WriteValue；解码 payload 最大 2048 bytes | 对方解密 / 同意 / 连接 / 文件接收成功 |
| `accepted_by_bluez_not_file_transfer_complete` | BlueZ 接受了该写入 | 文件传输完成、对方 UI 已提示成功 |
| `SenderTransport.wait()` | 完整 ZIP 已实际发送，匹配任务的 type=1 状态已实际收到并 ACK | 手机已显示结果、网络资源已恢复 |
| `SendWifiBackend.create_group()` | 实验性独占 GO 租约，实际读回 SSID / PSK / MAC | 本地 IP / DHCP 就绪、可给 SenderTransport 绑定、可生产发送 |

`client_status` 是**事件**，不是可以发送的命令；不能添加不存在的 `client_status` / `client_status_read` 命令。peer 必须是当前 helper / 当前 UI epoch 的整数 1…65535，不接受 bool、地址、D-Bus 路径或文件路径。native 调用者 session 只停止自己的扫描，不停止原厂扫描；既有 BLE 连接不由本进程断开。

native 的连接 / ServicesResolved 阶段有约 10 秒 deadline，成功读取或写入后为约 30 秒空闲租约；`stop` 可能只报告 `pending_cleanup`。service 必须处理晚回调及进程退出，不把写请求或 stop 请求当释放成功，也不捏造协议之外的 heartbeat 来延长租约。Wi-Fi 传输开始后的 BLE 释放可独立处理，但交接前的失联 / 未接受必须作为失败。

## 建议接线顺序

```text
用户选择 opaque fileIds + 当前 epoch 的 peer + 确认临时网络操作
  → Registry safely open_selection；持有 handles，任一步失败也 finally close
  → native client_read → client_status → 完整 DeviceInfo / P-256 / state 校验
  → send_wifi.prepare/lease：先持久记录原厂基线和 owned 资源再进行 RF
  → 真实 GO + IP/DHCP 读回 → 绑定实际私有 IP 的 SenderTransport.start
  → 加密实际 P2pInfo → 同 peer 的 native client_write
  → 真实 WSS/version/sendRequest/确认 → ZIP 实际读取 → 匹配 task 完成 ACK
  → owned server + BLE cleanup → send_wifi.restore → 独立基线 / 资源读回
```

1. **入场与生命周期。** `State` 持久持有一个发送 backend / lease，和已有接收租约互斥；有待恢复标志、helper pending cleanup、外部 P2P、并行 task 时拒绝开始。service 启动、Stop、TTL、取消、关闭以及异常分支都保留 resource owner 到恢复验真；未成功清理不能简单丢弃 `self.lease`。先安全打开选择，生成 taskId；不接受 QML 任意路径，不根据网络提供的文件名取本机文件。
2. **私有状态读取。** helper reader 持续消费 IPC，匹配 helper 身份、epoch 与 peer。严格 base64 / JSON 字段 / 公钥 DER / state 校验，拒绝重复字段、未知类型和忙状态。只有 native JSON 包络成功不够。公钥与网络凭据仅驻留私有内存，不写日志、URL query、公共 result 或 ZIP。
3. **实际网络租约。** 需要一个 durable 的 `send_wifi` prepare / owned GO / IP / DHCP 契约：记录启动前 station / route / radio / 原厂进程身份、自己的 interface wdev / ifindex / 进程 starttime，建立独立恢复 watchdog。监听地址必须来自实际接口 readback，不猜固定 gateway，不使用 0.0.0.0、公网或 loopback 作为生产回退。`allowed_peer_ip` 应在真实 DHCP / station readback 后绑定，不把来源为任意局域网的 GET 当目标手机。
4. **先 listen 后发布。** 给 SenderTransport 安全 FileSelection 和绝对已核验 OpenSSL 路径，在 owned 私有目录生成有界 ZIP / 临时 TLS 证书；绑定实际 IP，得到实际端口。listener 不可用则不发布网络包。加密 P2pInfo 只包含实际 lease 返回的 SSID / PSK / MAC / 端口 / 当前公钥，不生成假的参数。主状态、receiver 公钥和 GATT peer 不能跨 epoch 复用。
5. **发送与确认。** GATT 写接受后仅显示“等待对方连接”，version negotiation / 发送请求 ACK / 实际下载分别推进状态。以 `SenderTransport` 的真实字节数和匹配 task 的完成状态推进结果；HTTP 200、空 ZIP、断流、提前 type=1、错误 taskId 都失败。取消后晚回复不得改当前结果。
6. **结果与恢复分开。** `peer_completion_verified` 与 `networkRestored` / `radioRestored` 是不同事实。对方已完成但网络恢复失败时，应保留真实文件完成，并进入“恢复待核实”，阻止重发与新的 RF 操作；不把真实完成误报为全流程成功，也不提示重复发送。缺 ACK 时只报告已发送 / 对方未确认，不编造远端落盘成功。
7. **幂等 cleanup。** 先停止 owned sockets / ZIP worker，释放 GATT client；等 pending callbacks 或核对 helper exact PID 退出，再恢复 Wi-Fi owned lease。只删除确证属于该 lease 的 interface / private profile / process，保留外部资源。恢复返回 False、身份改变、journal 无法校验均保留 recovery lock；正常 close 不得转成 True。凭据、EC native pointer、证书目录和 FileSelection 也须 finally 清理。

## 当前 send_wifi 缺口不能伪补

当前 `SendWifiBackend` 仅是**实验 GO**阶段：`create_group(cancelled=None, timeout=20)` 上限 20 秒，需要显式 `allow_rf=True`，包含独立 watchdog。返回 `SenderGoContext` 的 `local_ip=None`，`status()` 为 `ip_ready=False` / `dhcp_ready=False`，`capabilities()['send']['available']=False`。当前 `mta_network` 的 ConnMan STA `prepare/receive/recover` 也不等于发送 GO 后端。

因此不能拿这个 context 直接打开 SenderTransport，也不能把 TTL 强行延至 180 秒并声称生产可用。下一阶段必须补实际 IP / DHCP / peer admission、持久恢复和有限失败试验，再接入 service。`send.available=False` 是诚实门控，**不是用户完整双向互传目标的完成条件**。

## 必需回归与接受层级

- **HOST service wiring：** fake native helper 严格检查 `client_read → status → group/listener → client_write` 顺序；异步 epoch / peer /晚回调、明确拒绝、busy、非法公钥、取消、创建失败、listener 失败及关闭异常。fake Wi-Fi 不得标为 P011。
- **HOST 真实 TLS：** byte/hash、错误 task / 提前完成 / 不下载、拒绝、partial ZIP / 取消、证书变更、ack 缺失；同时原子落盘和 source identity。已通过的既有 TLS 测试不为 UI 文案修改反复执行。
- **P011 无 RF：**本文件已补 Python3.5 / OpenSSL1.0.2 真实 TLS 双向链及清理，无需凭软件标签再推断兼容。
- **P011 有限 RF owned lease：** driver 实际 GO / 独立 IP / DHCP / 并发 station、断父进程与 TTL 后恢复；前后原厂 hash / exact process、接口 / 路由 / profile 独立 readback。不因只读 `iftypes` 声明就称“可发送”。
- **PHONE：**真实可发现、主动同意、手机→P011 与 P011→手机均至少一个文件；两侧真实 bytes/hash、手机完成提示和 network 恢复分别验收。没有手机结果就保持 `PHONE_NOT_TESTED`，不能从 native 私有 D-Bus mock 或本机 TLS PASS 升格。

只有以上尚缺的网络 / 手机层完成后才可以开放正式发送入口并宣布完整互传目标完成。
