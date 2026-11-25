# 完整 send worker 最小接入契约

范围：只读 review 当前 `mta_service`、native GATT client、`SendWifiBackend` GO-only 阶段及真实 TLS 发送器。本文提出**后续**接口与 failure matrix；本轮仅新增本文和 `tests/test_send_contract.py`，不改 production/native、不调用设备或 RF。

> 后续证据补充（root，2026-10-01）：下文“首轮 GO 失败”为作者当时的历史快照。独立 V4 候选已在 `MtaP011-DeviceP2pV4-20261001-030738-1772afe3` 通过限时 GO 建组与完整恢复；IPv4 核心的两次 P011 实时只读亦通过。V5 IP-only 正在独立审查/验证，不是正式发送网络后端。现有21项 ContractFixture 不等于真实 worker，接线缺口与实施顺序以 `WORKER_IMPLEMENTATION_NEXT.md` 为准；原记录不重判，正式 send=false 不变。

## 当前事实与证据层级

- 当前 `State.send_available=False`，`action('send')` 在打开选择 / 修改网络前拒绝。native client_read/write 可调用不等于 service 已接入；`native_event()` 尚未路由 client_status 给 sender worker。
- 当前 `SendWifiBackend` 只有 TTL≤20 的 GO 实验。`SenderGoContext.local_ip=None`，ip_ready/dhcp_ready=false；capabilities 即使看到 driver 声明仍 available=false。`close()` 只关闭本地控制 socket，**不是 restore**；不能用它作为网络恢复证据。
- 首轮 GO 试验因 private_wpa_exit 失败；未得到 GO ready，启动失败原因仍待定位。后续 exact-owned STA 删除与独立恢复 actual PASS 是**该失败试验的资源恢复证据**，不是 GO、DHCP 或手机发送 PASS。原 FAIL 保留。
- P011 合成文件 TLS/WSS/实际 ZIP bytes/hash/ACK 回环已有独立 PASS，HOST TLS 测试已有独立证据；真实组网 / DHCP / 手机层仍未通过。新 HOST 合同测试不重复制造这一层结论，也不使 availability=true。

## 两个先解决的接线问题

**peer namespace 不能重建。** 选择的 deviceId 是当前 helper 发现表的匿名 peer，不是稳定地址。发起 send 应使用产生该 peer 的当前 helper；`client_read` 自己停当前调用者的扫描。若为了 send 再调用 `new_helper()`，旧 peer 编号即失效，必须拒绝 / 重新发现，不能把同一个数字交给新进程。同时绑定 native_epoch、helper handle、peer、taskId；只允许 fresh 非缓存记录，busy/过期记录不能启用 send。

**先监听与真实 peer IP 有时序差。** IP/DHCP server 就绪后，TLS 必须先监听取得实际 port，才把加密 P2pInfo 写给手机。手机只有得到凭据后才会 association / 取得 DHCP lease，因此它的实际 IP 不能事先猜。当前 SenderTransport 已改为 `allowed_peer_ip=None` **deny-all admission**，新增平台内部 `authorize_peer(ip)`；由 worker 核实本租约的实际 association + DHCP 地址后开放唯一 peer。未经授权连接在 TLS/worker/WS 分配前拒绝，不占用 admitted-peer 重试额度；重复同一地址是幂等，不能换地址。DeviceInfo.mac 与实际 P2P/client randomized MAC 的对应还需要手机协议验证，不能凭格式相同就假定成立。

## 最小 owner / API 合同

以下带“新增”者是建议，不宣称已有功能。生产由 owner 接线。

| owner / API | 必需合同 |
| --- | --- |
| `State` | 持久 send backend；当前 session 对象；send lease、native helper、TLS sender、FileSelection、EC key 的独立归属；restorePending/recoveryLocked。不得只有局部变量导致 activate 抛异常丢 owner。 |
| `SendSession`（新增） | immutable taskId / operation_epoch / native_epoch / helper handle / peerId；独立取消 Event、总 deadline、阶段、公开只计数的结果。接受 UI action 时持有；worker 真正结束前不能清 worker 指针允许下一 RF 任务。 |
| `SendWifiBackend.prepare(...)`（新增） | 明确临时网络同意；先持久记录原厂 station、routes、boot、PID/starttime、接口与 journal，再可能变更；异常前 active lease 已保留。设备级互斥而不仅单 journal 锁。 |
| `lease.activate(...)`（新增） | 实际 owned GO/AP + 独立 IP 配置 + DHCP server/lease 读回，返回 private context：真实接口 identity、本地 IP、真实凭据、MAC、deadline。ip_ready/dhcp_ready/actual_interface_verified 全部核实才可传输。 |
| `backend.status / restore_active`（新增/适配） | prepare/active/restoring/recovery_required 归属持续可读；restore 必须 exact owned 资源 + 原厂独立读回，false/exception 保留 lease/journal/recovery lock。close 不可替代 restore。 |
| `SenderTransport.start()`（已有） | FileRegistry 安全 handles、有界 ZIP、实际私有绑定 IP、绝对 OpenSSL；返回实际绑定 port。若失败不发布 BLE 网络包。 |
| `SenderTransport.authorize_peer(ip)`（已有） | listener 活跃且任务尚未结束才可调用；None 初始拒绝全部，唯一地址绑定，同地址重入幂等、不同地址拒绝。worker 在调用前验证当前 lease / operation/native epoch / association+DHCP proof；transport 不接受 proof 参数，不从 QML action 或对端自报 IP 授权。 |
| native IPC（已有） | client_read → client_status event → client_write；继续读 IPC，不阻塞 reader 等组网 / wait；清理 owned BLE 连接，pending callbacks 单独等待。 |

当前 GoLease 是单次 journal：reconciled 后 state / 文件仍存在，不能直接重复调用同一个 GoLease.start。持久 backend 应在上一租约彻底 reconciliation 后，为下一 task 分配新的 owned 0700 namespace / lease；保留历史 journal，不删除它绕 gate。跨任务后台 watchdog、UI exit、断父进程、超时都需要 durable recovery；不将 20 秒实验 TTL 静默扩大为正式 180 秒。

`State.action` 当前 send 字段只有 deviceId/fileIds。若新增明确网络同意字段，必须同步更新严格 action whitelist 与 UI 确认；不能靠后台自动填 consent=true 或使用过去点击作为无限期授权。

## worker 时序

```text
同意 + fresh opaque deviceId/fileIds + 当前 helper epoch
  → 安全 FileSelection / session key；client_read（同 helper）
  → client_status 全字段 / P-256 点 + ECDH 检查，peer 空闲
  → persistent lease prepare → 真实 GO/IP/DHCP ready
  → TLS start（deny-all）取得实际 port
  → 实际凭据构造 P2pInfo → encrypt_credentials → client_write
  → 真实 association/DHCP peer readback → SenderTransport.authorize_peer(真实 IP)
  → WSS version/sendRequest ACK → ZIP 实际字节 → matching-task type1 / ACK
  → listener/handles/key/BLE 清理 → owned network restore + 独立原厂读回
```

长耗时 prepare/activate/TLS.wait/helper.close 不应持有 State.lock，避免取消/状态页无法操作。读 IPC 的 thread 只分派经过边界校验的事件，不能在回调里阻塞网络或等待传输。每个晚结果先检查 operation_epoch/native_epoch/helper/peer，旧任务不更新新 UI；但旧任务的 finally 必须继续清理它自己持有的资源，不能因 epoch 失效就跳过 cleanup。

## wire、密码与 TLS 边界

- native 状态最大 **512 bytes**，P2P WriteValue 解码 payload 最大 **2048 bytes**，IPC line 最大 8192。协议层默认 MAX_GATT_BYTES=8192 不能替代更小的 native payload 限制。包在提交 helper 前再校验长度。
- client_status 是事件，不是 command。严格 base64/UTF-8/JSON，DeviceInfo 要求 state/mac/key，允许明确 catShare；重复 / 超限 / 缺 key / busy / unsupported 字段拒绝。状态缓存不能冒充本轮空闲。
- DeviceInfo/P2pInfo 的 base64 语法校验不是 P-256 验证。用 OpenSslCrypto 实际解析 91-byte P-256 named-curve SPKI、EC_KEY_check_key/共享派生检查，再创建 RF lease。public key 不跨 session 复用；native private pointer finally free，不写磁盘、argv、HTTP、日志、public result 或 ZIP。
- P2pInfo 采用真实 ssid/psk/mac + **TLS start 返回的 port**，调用已有 encrypt_credentials；没有真实字段就拒绝，不捏造固定网关、IP、凭据或加密成功。
- MTA 固定 IV 的 AES-CTR 不带 KDF/authentication tag，这是现有 wire 属性，不是“认证加密”；不要声称它验证了对方身份或抗篡改。不能为获得漂亮标签发明手机不支持的新线格式。
- ReceiverTransport 的 self-signed TLS 第一次证书摘要是**本 task 的 first-pin / TOFU**；WS 与 download 再连接必须相同。CERT_NONE 不是 CA 验证；该 TLS 证书和 BLE ECDH 公钥未建立密码绑定，第一次连错 peer 仍会 pin 错对象。sender 没有 client certificate 身份认证，因此 association/DHCP admission 不能省略，不能标为“账号或手机身份已认证”。

## 结果合同：三个事实分开

| 字段/状态 | 什么时候成立 | 不代表 |
| --- | --- | --- |
| localBytesVerified / archiveBytesSent | 真实有界 ZIP 读取/发送计数，实际文件 count/size 与确认匹配 | 对方落盘、手机提示完成 |
| peerCompletionVerified | 完整 ZIP 发送后，收到同 WS、匹配 task 的 type=1，发送 ACK | 手机 UI 已显示完成、网络恢复 |
| networkRestored / radioRestored / ownedResourcesClosed | own lease / helper 清理完成，独立原厂/接口/routes/profile/PID 读回 | 文件传输成功 |

三连事实齐备才显示正式完成。BlueZ `accepted_by_bluez_not_file_transfer_complete` 只推进“等待对方连接”；不能变 completed。缺 ACK 只显示“已发送，对方未确认”。peer 已确认但恢复失败保留实际完成，进入 restore_pending，阻止新 RF / 重发；不擦除完成事实诱导重复发送。

手机 UI 完成提示、用户目标文件 hash、实际互操作属于 PHONE 层另行验收，不从 WS type1 或 mock 推导。未知 mutation / ACK 丢失不写“未执行”，保留 UNKNOWN 并只读读回。

## failure matrix

| 边界 / 故障 | 立即行为 | 持久/结果处理 |
| --- | --- | --- |
| cached/stale peer、helper epoch 已换、bool/非法 peerId | 拒绝；不新建 helper 重映射数字 | 无 RF；需要重新发现 |
| fileId stale / 文件变更 / handles 打开失败 | 拒绝；已打开 handles finally close | 不取任意 UI 路径，不发布网络 |
| DeviceInfo 缺 key/busy/非法 SPKI/无效 EC 点 | 拒绝在 RF 前 | key/native buffers finally 释放；无凭据日志 |
| lease prepare 在变更后失败 / journal 不明 | 取消后续 listen / GATT | backend 保留 active owner；恢复失败锁住 |
| GO-only / IP/DHCP 未就绪、driver 条件不符 | 拒绝传输，不拿 None/IP 猜测回退 | exact owned cleanup/readback；available=false |
| TLS 证书/ZIP/绑定失败 | 不 client_write | close owned sender、selection/key、restore lease |
| GATT pending/read/write 失败、helper EOF | 停交接；晚回复不推进任务 | 等 owned callback/exit；清 radio/network，保留 pending |
| 新 MAC/peer 无法与当前 lease 匹配、DHCP 未授权 | deny-all / reject connection | 不泄漏 ZIP、不可首到抢占 WS |
| version/ACK/taskId 错、提前 type1、不下载 | sender failure/cancel | 不 completed；bounded cleanup |
| partial ZIP / source变更 / 超时 / 主动取消 | owned cancel；清临时文件/连接 | 不全局 kill/flush；finally 不因 old epoch 跳过 |
| ZIP 实际发送但完成通知未到 | peer_unconfirmed | bytes事实保留，remote completion=false |
| peer完成后 cleanup/network/helper close失败 | restore_pending | completion保留；owner/journal不丢，不自动重发 |
| 父进程死亡 / 服务重启 | durable watchdog/reconcile | 新 State 启动先核实 journal；未完成阻止新 RF |
| own interface被转换STA / identity改变 / 原baseline变 | 只读 ownership review | 不按同名删；STA例外另行显式审查，不能全局放宽 |

## HOST 合同测试如何使用

```powershell
python -B -m unittest discover -s tests -p test_send_contract.py -v
```

当前 **21/21 HOST PASS，0 SKIP**，Python3.5 语法 PASS。三个测试调用真实当前 State / GO adapter 的门控，用不执行 I/O 的 helpers；其余使用明确 `ContractFixture` / `ListenerFixture` 的内存要求 harness，检查未来接线的顺序/边界和少量真实 protocol 验证。ListenerFixture 使用与真实 listener 相同的 `start()` / `authorize_peer(ip)` 签名，proof 检查位于 worker fixture，不以第二个 transport 参数绕过调用者责任。它不是已实现 worker，不是真实 TLS/RF/手机结果，不属于 availability 的证据。

将来 root 实现 worker 后，应把 ContractFixture 适配到实际 worker（保留 fake helper/lease）验证同样断言，并增加实际 HOST TLS admission、wrong-peer、late events 与 cleanup 故障；再进行独立 P011 owned GO/IP/DHCP、断父进程/TTL 恢复、双向 PHONE 文件 bytes/hash/提示验证。只有真实平台门槛通过后才讨论开放发送能力；完整目标不能以 send.disabled 或 mocks PASS 收尾。
