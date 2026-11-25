# CLIENT DORA v21 私有 proof/coordinator 限定回执

本件只新增隔离 `candidate/client-dhcp-v21/runtime/mta_client_dora.py` 与新 HOST 方法。配合另一个作者的窄修 `mta_dhcp_client.py`，不改任何冻结 v19/v18/runtime/test；未执行 P011、ADB、RF 或实际 socket/network。这个组件不是完整 CLIENT、IP、可信 endpoint、正式长租约、GO、State 或生产收发通过。

## 原件接口与旗标来源

`PrivateClientDora(lease, receipt)` 只有两个权威输入：actual v19 `LinuxClientInitLease` 和其 exact 当前 issued `AssociationReceipt`。不接受 caller context 字典、普通 P2pInfo、全 True callback 或构造的同名 receipt。最初在同 Store RLock 登记 actual provider/operation/claimed request/binding wire、Store/device OFD locks、marker/binding、store/journal epochs、原 Journal/baseline/controller 及 deadline。登记原件同时挂在 actual provider 和 operation，禁止第二个 coordinator 偷换。

`ClientAssociation` 原件由 actual kernel Origin/boot/本机 MAC、validated binding 的 operation_epoch/native_epoch、原 deadline 及 canonical SHA 构造。BLE MAC、惯常地址、caller epoch 不进入该构造。`task_epoch` 是该原 binding 的 operation_epoch。

| AssociationProof 旗标 | 对应本次实际源码链 |
|---|---|
| association_verified | 每次调用 `lease.read_association_receipt`，先保留新返原件，核 actual private issuer/当前票据及两 STATUS/kernel/caps 原件；kernel reader.authenticate 原 operation/epoch，CLIENT8、本机 MAC、BSSID、frequency 与 confirmed record 对齐 |
| owner_verified | 原 provider/lease/operation/claimed request/binding/locks/device/marker/epochs/controller 注册保持；新 issuer consumed context 中原 owner ExecutorProof 与活 actor、实际 OFD/current/readback 链 |
| receipt_fsynced | v19 原 confirmed 保存-before-issuance 链及其原 CanonicalRecord/私有 issuer 当前性，不从 schema 单独推导 OS 成功 |
| persistent_readback_verified | 本次 v19 完整 Store.current/_fresh/currentCAS、pending marker/OFD 验证后发行的新原 receipt；不是缓存上次 True |
| baseline_verified | 两原 Snapshot.key(owned) 均等于登记原 baseline.key；原 stock/process/baseline readback 未删 |
| ipv4_unconfigured | 两 actual IpSnapshot 均无 owned ifindex 的地址，无 owned oif 的路由；不减去未知 IPv4 delta |

actual Provider 的 owner ExecutorProof.same_ofd_verified 保持原 False；该位仅针对 external_finalizer 继承锁。这里的 owner/OFD 依据原 Store locks/device/current 验证，不将该字段伪改 True。

## Store canonical 的受控 advance

actual v18 Store.current 每次保留新原 CanonicalRecord 并置 `_canonical=actual`。Lease._fresh 只返回新解码 Journal，不重绑 `lease.record`。v21 因而保留 constructor 的原 Journal/baseline 指针，只在本次原 fresh 完整验证成功后更新登记 canonical。

新 canonical 必须是 Store 当前原件、actual issued receipt/context 的原件；bytes/metadata/generation/hash 与原登记值相同，new canonical.journal 与原 Journal same_journal；epochs/marker/device/binding 不变。每个 proof call 保留 old/new canonical、input/new returned receipt 和原 proof，失败也不丢返回原件。HOST 正向方法明确核新 canonical 指针不等于旧对象，而 lease.record/baseline 原指针保持，未用固定返回 samepointer 的伪 Store。

## 有界预算、生命周期与 pending

实际 v21 DhcpSocketClient 显式 proof_seconds=5、lock_seconds=.2；UDP poll 仍 .2，原 context.deadline 不变。coordinator 自身每次锁等待也取 .2 与原剩余期限的最小值。每次 producer 预算取 5/传入实际预算/原绝对期限的最小值；不将旧 20 秒 trial 更新为 300 秒。

v19 `read_association_receipt` 没有 slice 参数，内部严格使用原 operation.deadline。v21 不临时改 operation/journal deadline，也不能强制抢占任意同步 OS IO。真实调用超过 5 秒后才返回时，先留新返原件，再撤权/close 并保持 unknown/pending；阻塞期间原 producer 仍未闭合。v20 的约 4.17 秒是一次完整 collector 观测，不是整个双轮 fresh 的成本；不能据此宣称真实 fresh 在 5 秒内完成。

每次 proof 都消费上一张当前 receipt 并取得新原件，原 FILES256、kernel/caps readers 各8、receipt8、packet/retry/库存未知门槛不变。不给缓存 proof、库存剪除或增大上限的成功捷径。

coordinator 走活跃 `open → poll → candidate`，不调用 `run` 取得历史值。现有 run finally→close→core.cancel 完整保留。ACK 捕获 wrapper 先保存实际 ingress 原 packet/source/ancillary、原 client/generation 与本次 poll token，再转给原 envelope/core；只有 actual core 当前 accepted ACK allocation 原件才能登记 LiveAllocation。没有原 ACK 与原 registration 不能发行。

LiveAllocation 保留 exact issuer/client/socket/generation/context、actual core.configuration(now) 原件、原 ACK、发行时 receipt 与 usable_until。candidate 发行时核当前原件；`validate_live` 对当前登记原件再次执行完整 fresh，再 under owner lock 核当前 core/expiry。外部构造的同类型对象返回 False；close、取消、原 deadline 或 epoch/owner 变动撤掉 live 权限。入口失败也先撤权并 close 原 client；unknown owner/late actor/failed close 保持 pending，下一步不能继续 IO。

没有 IP 安装、route/DNS/ARP 写入、endpoint 验证或 production gate。close 不产生恢复证明；原 frozen F 恢复未纳入 DORA socket/producer inventory，正式工厂/恢复接线仍待。可信 caller 必须保留本 capsule 的 close/pending 结果，不能凭 original F 的旧库存宣称新 DORA 已自动恢复。本同步 main coordinator 不创建 runner、不制造 recovery_deadline；另一个作者的 runner 资源闭合恢复预算不续 association 网络期限。

### ROOT 增量：直接 proof 的在途 actor 与关闭线性化

独立 SOURCE 复审发现旧 `153a4405…` 版本直接调用 `proof` 时，尚未返回的同步 reader 不在 adapter._proofs 或 coordinator._active 里；此时 close 可误报 True。这是 SOURCE 找到的闭合漏洞，不是设备上已观测的恢复故障。

当前增量用独立 RLock 将关闭撤权与直接 proof 的入口登记线性化；closed/revoked 的复核和 proof call/counter 登记在同一把锁内，且在等待原 Store owner 锁和调用 reader 前完成。每张 call 保留原 input/returned/canonical/proof，并单独保存 active。close 在 actor 尚未退出时返回 False，status 保持 resource_pending。调用只在 owner.release 后的最后 finally 才去登记；unknown=False 不代表 actor 已退出。若 owner.release 抛错，先保留 owner_release_unknown 和 sticky unknown/pending，不将去登记视为资源已恢复。独立 actor 锁不跨 reader/owner 等待或 client.close 持有。

`cd4ebd`：仅新增 direct-proof actor 方法及受影响 AST/constructor/graph identity 方法，2/3.375s/exit0。新方法在 actual v19 read_association_receipt over FakeIO 的同步入口内重入 close，无新线程：普通返回分支可正常关闭；读回中关闭分支在 adapter._proofs=0/coordinator._active=None 时仍拒绝闭合，原读回实际返回后保留原件并以 closed 撤权/pending。没有执行旧方法、设备 IO 或真实线程竞争；owner.release 异常分支仅 SOURCE 检查，未注入测试。此前 `75b673` 和第一版源码包保留为旧源历史，不能替代本增量证据。

独立复审另指出 caller proof slice 可能在获得 owner 后已用尽，旧版本仅在 fresh 返回后拒绝超时。ROOT 增量在取得 owner 并核其当前性后、调用 reader 前检查 now>=until，已用尽的 slice 不启动新 IO；已有同步 IO 仍不强制抢占。`97bdb4`：新增 slice-expiry 方法及受影响 AST 方法，2/1.347s/exit0；合成时钟在 owner 当前性检查处推进 .11s，.1s slice 耗尽但原 association deadline 未到，验证 reader 调用0、原 reader/caps/receipt/FILES 库存不增、无发送、撤权/pending、actor 实际退出。没有重跑此前 actor 方法或旧套件。

## 唯一新 HOST 证据及第一次失败

测试使用 actual frozen 24-source v19 graph/Store/current/CAS/KernelReader over FakeIO，并加实际 DHCP wire/core/v21 modules 的 private import graph。已有 init actors、保存的 ready Journal、成功连接事件及 baseline 是合成 fixture 前提，不是实际 init/OS/RF/手机证据。没有执行任何旧 test 方法。实际 socket/subprocess/CDLL/os.open/kill/waitpid/root open 均有 tripwire。

- 首次 `842633/8177b0`：新6方法，11.071s，exit1；5方法 OK，changed_* 方法两个 subtest fixture ERROR。首因是合成 owned AddressRecord 缺少 schema 要求的 cacheinfo/label，继发未 finally 清 owner fixture 导致 local_mac case resource_unknown。原失败保留，未改产品 SOURCE 来掩盖。
- `8b7fbe`：仅修合成 AddressRecord 形状与 subtest finally，并对受影响 changed_* 与新增具体容量断言两方法定向复核，2/7.494s/exit0。正常 fresh 原件、预算返回原件保留、旧 live 原件/foreign/close 方法此前通过，不聚合为一次全套成功。
- 实际容量安全方法在 synthetic-ready fixture 的 `open` 第2次 fresh 首先阻断：outer `DhcpSocketClientError:proof_failed`，原 producer `('files','resource_budget')`，原库存数 `(kernel4, caps4, receipt2, FILES256)`。当时尚未发送 DISCOVER。该方法的 OK 仅表示正确预期了阻断/撤权/pending，不是完整 DORA PASS。
- ROOT 后加当前 exact live 原件 `validate_live(current)==True` 的正向尝试：`973dca` 新/受影响两方法，2/5.204s/exit1。新入口 epoch/deadline 方法 OK；live 重复完整 fresh 触发 actual ClientFileError.resource_budget，正向未通过。该真失败保留，不清库存/省 fresh/增上限求 True。
- `c950b0`：仅将受影响 live 重复验证段明确改为已知容量下的 expected revoke/close/pending 安全断言，1/1.739s/exit0；没有产品 SOURCE 修改，不宣称 repeat validate_live 正向通过。candidate 的内部当前原件判据已正向通过，但 ACK/socket 是明确 synthetic active-ACK 前置，绕过完整 open/poll，不能升格为完整 DORA。
- `75b673`：最终 SOURCE 改动后的 Python3.5 AST/constructor/graph identity 受影响方法单次复核，1/.012s/exit0。没有重跑其余已经通过的方法或任何旧方法。

新入口方法核 epoch 或原 deadline 变化后不增加 proof/IO 调用，actual 原 socket 确闭、旧 live 和 association 权限撤掉；未知 epoch 保持 pending。原期限没有延期。

真实完整 init 源码在 CREATE 前已有两轮 Provider.caps，和 synthetic-ready fixture 的 init caps0 前提不同。实际 init→connect→多次 fresh 的 reader/caps/FILES/其他原预算可能更早失败；不能将 HOST open 第2次 fresh 的 FILES 首因外推为设备上的唯一首次位置。kernel/caps8 理论限制也不是本次首先达到的实测故障。

## 冻结源与后续欠账

| 文件 | SHA-256 |
|---|---|
| mta_client_dora.py | `0a0e521704c89467cee7bdaf8e656d684fb697016261143b6e82370594db083d` |
| test_client_dora_v21.py | `f21fe1628b4b1545cce8340bbe6985cd346a7711158677748ae25904d5d03aab` |
| 配合作者 mta_dhcp_client.py | `794421678866d04a10ca46fa9eb7e17174f24c4d9e705cf59016b457702003a0` |
| actual runtime DHCP wire | `631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176` |
| actual runtime DynamicClientExchange | `13c03d181139fd9ead7ff3bf2bcbb4930669f1e795b17360da85834dc345e9fa` |

下一阶段需独立处理有证据的原 reader/FILES 生命周期及正式 lease，才可能重新核真实完整 DORA 与重复 fresh 正向。此后动态 CLIENT IP 只取仍活跃 ACK 的实际 local_ip/prefix，不能用 GO network+1 /24；持久 IP intent/ACK/readback/owned delta/恢复，以及绑定原 P2pInfo/本次握手的可信 endpoint 仍待。完整 State/GO/文件中心与小米15 Ultra双方实机验收仍待，生产 send/receive 保持 False。
