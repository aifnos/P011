# 实际发送 worker（HOST 接线组件，非手机互传完成）

2026-10-01。仅新增 `mta_send_worker.py`、专项测试和本文；未改 State、UI、旧发送器、native 或平台能力，`State.send_available=False` 保持。

## 接口与实际流程

- `SendWorker(ScanHandoff, FileRegistry, file_ids, provider=None, ...)` 纯构造；缺 provider 在任何选文件/GATT/网络调用前固定拒绝。默认真实 `OpenSslCrypto` / `SenderTransport`；HOST seams 不从 HTTP/QML 提供。
- `run(hooks)` 同步在调用方保存的 worker 上执行，不另起线程/helper。当前扫描 helper、native/operation epoch、peer、发现时刻及 task 固定。readback 必须返回同域 `ScanObservation`，非缓存、当前 active、15 秒内；不能 new helper 后复用数字 peer。
- hooks 的 `claim/adopt/attach_transport/handoff` 必须返回同一 exact `CreationTicket`。所有可能创建资源的调用前登记 ticket，返回先强引用再检查；异常/未知/畸形对象保留，不以 callback=True 假装归属。
- Registry 实际打开不透明 fileIds → key → 同 helper `client_read` → 512B canonical base64/严格 DeviceInfo → 实际 P-256/ECDH → reserve 纯 lease（先归属）→ activate → 真实 scoped listener、deny-all TLS start 返回 port → 加密真实 GO 字段（2048B）→ 同 helper `client_write` → 独立 association+DHCP 收据 → authorize_peer → 真实 sender.wait 的 task 结果。
- native reader 仅 `native_event(event, exact_helper, native_epoch, operation_epoch)` 进入至多8条固定阶段队列；不做 IO/crypto/close/provider。write 完成无 peer，靠同 helper/唯一当前 write 阶段，必须先结束旧 pending；accepted 绝不标文件完成。
- native ReadValue 后的30秒 lease 与总 deadline 同时约束网络准备/ZIP/TLS/凭据发布；慢准备失败，不伪续 native lease、不静默扩大 TTL。

## 平台 provider 尚未存在，不能 Boolean 开门

`reserve(handoff,deadline,cancelled)` 返回变更前登记的纯 lease；`activate(lease,handoff,DeviceInfo,deadline,cancelled)` 必须在自身 lease/journal 中先持有所有子 actor/intent，再返回私有 `NetworkReceipt`。

receipt 必须持有同 lease、真实 `OwnedContext(mode=go)`、`ScopedDataSockets`、`DhcpSocketServer` 和真实 SSID/PSK/GO MAC。`read_network(receipt,.2)` 返回当前同 context 的完整 `ScopeProof`（confirmed/fsynced/persistent readback/owner/address/route），GO proof 的 CLIENT/DHCP/peer 字段严格 false，不冒充 peer authority。DHCP 必须实际 listening，无原网 route/DNS；socket 厂仍由实际 scoped capsule 每次核实归属。reserve/activate 获取共享取消 Event，平台必须在实际作用域/关联丢失时撤销它，且其监测/watchdog真实actors保持lease归属；worker不是新的内核监测实现。真实 sender timeout 被网络 deadline 截短，其 accept/write/wait 取消检查还受已确认 association/DHCP 到期约束。

`wait_association(network,handoff,DeviceInfo,deadline,cancelled)` / `read_association(receipt,.2)` 返回不可变 `AssociationReceipt`：同 network/handoff、DeviceInfo 地址、真实 station MAC、到期与实际 association/mapping 私有收据指纹。平台必须独立证明设备与随机 P2P station 的映射，不能令二者 MAC 自动相等。worker 再读取该 exact DHCP owner 的 `allocation()`，匹配 station、ACK分配IP/有效期/当前同子网。ACK 只证明 server allocation，不证明手机配置、账号认证或文件完成。

这些结构/哈希不自行证明内核；真实平台 provider 的 durable journal、控制进程/组/关联/租约读回和跨品牌映射尚未实现/验收。缺 provider 明确 unavailable，不能把 HOST fixture 送入生产或开放 send gate。

## 生命周期、结果与后续接线

- `run` finally 只请求 exact transport.close(0)，不清 helper/key/selection/lease，不 inline restore；真实调用线程仍需退出。
- 外部 finalizer 先证明保存的 worker 实际退出、transport full lifecycle 所有计数0、每个 exact raw 五字段闭合，才 `release_scoped()`。TLS detach / fileno=-1 不是 proof。
- `close_extra()` 外部调用：独立关闭 DHCP、helper、key、唯一 FileSelection owner 和 provider 已知 actors；一处异常不跳过其他 known cleanup。FileSelection 正式 API 是 `lifecycle_status()`（没有额外 `closure_verified()` 方法），核验精确10字段、完整计数与原 wrappers 仅只读 `closed is True`；selection.closed 不作FD proof，不自行重复 close handles；close_requested 后只重读而不重复关闭。外层仍须独立核原 BlueZ/原厂基线，本组件的 helper process 退出不代替 radio restore。
- FileRegistry open 失败的未知 ticket 仅在该 exact registry 实际只读 resource inventory 无 pending/unknown 时核实；原 mta_files 的 FD窗口/首close异常由独立 owner 修复，本组件不能掩盖其历史失败。
- 已知 parent 的失败调用只在其 actual closure 读回后记录 unknown_closed；工厂未知创建/owner registration未知强引用保持 pending。所有 ticket 历史保留，不自动重试或在 status 做动作。
- network restore **未在 worker 实现**：最后仍需同 Session 外部 finalizer 调用 exact lease/provider restore并核原厂/网络/journal，失败保留 owner/锁。`network_restore_required=True` 不升级为 completed。
- `SendResult` 分离实际 archiveBytesSent/localBytesVerified/peerCompletionVerified；没有 localCommit 字段。发送ZIP准备不是接收端落盘，不能硬转 `Outcome(local_commit_verified=True)`。当前手机 UI 完成仍需人工验证。
- State 尚需接 send action、scan→send 同 Session 交接、native 三事件路由、方向独立结果/进度、cancel及外部 finalizer；本轮没有把生产动作可用或完整互传宣称完成。

## 复审窄修与终态保护

- KeyPair 在 native free 前就置 closed。worker 私有事实持有 exact key 的一次 close 请求、正常 None 返回与 sticky unknown；异常（含 BaseException）、畸形返回或 owner 不符都不能被后来 closed=True 抹除，也不重复调用 close。其它 known 资源仍独立尝试清理，所有 key/ticket 引用保留，公开接口不变。
- `_now` 在同 worker 锁内完成采样、有限值/类型/真回退验证及提交，消除合法并发早采样晚提交的误判；NaN/Inf/bool/超大值/真回退仍拒绝。
- 真实 Sender 可能因完成竞争省略 awaiting_result 通知。只有最终结果的精确字段、count/size/实际 archiveBytesSent 等于进度 bytes 与 archiveSize、peer completion 严格 True 全部通过后，才在同锁原子补齐字节验证/发送字节并提交结果与 protocol_complete。缺通知不是补造 localCommit，非法结果绝不补齐。
- 严格最终结果提交后、run finally 尚未结束时，实际 Sender 的 completed/awaiting_result 仍可能晚到。progress 在同锁入口看到 exact `_result` 已提交就忽略，不能把终态降回等待；屏障用例确认字节/结果身份/阶段全不变，不扩大为资源或网络已恢复。

## 证据边界

测试实际调用此 worker，仅外围 registry/crypto/helper/network/kernel socket/sender 用显式 HOST fakes；实际 `ScopedDataSockets` 通过其私有 fake kernel seam参与，未开 OS socket、未做真实加密/文件打开/设备/RF/手机。
测试文件目前43个方法。以下为单独 HOST 批次，不合并成“最终源码全43项单次通过”；未执行全套或重复旧硬件验收。

| 工具记录 | 范围 | 原结果与层级 |
| --- | --- | --- |
| `246817` | 首次30项 | 1 PASS（AST）、29 ERROR；FakeSelection 使用了已变化的构造接口，错误发生在进入 worker 前，原记录保留。 |
| `1372c8` | 修复上述 fixture 后仅29个受影响方法 | 17 PASS、11 FAIL、1 ERROR；FakeRaw 把 SO_TYPE 返回为 HOST enum 而非内核整数，原失败保留，不是实际网络故障。 |
| `2e8a93` | 修正 FakeRaw 后仅12个受影响方法 | 12 PASS；未重复其余已过方法或 AST。 |
| `767339` | 4新增＋5受影响（含 AST） | 9 PASS；核 exact DHCP 配置/活 actor、选择关闭不重试、只读 proof 预算。 |
| `f5ab67` | 2新增＋7受影响（含 AST） | 9 PASS；正式 FileSelection API 对接、精确完整字段/计数/原 wrapper 只读关闭、相关取消及清理。 |
| `f14cf0` | 6新增＋12受影响（含 AST） | 18 PASS，0.034秒、exit0；key close sticky、确定性并发时钟/真回退、漏中间通知的严格最终结果，以及确受影响清理/取消/结果。 |
| `6b3c9b` | 1新增＋5直接受影响（含 AST） | 6 PASS，0.024秒、exit0；最终结果提交后、run finally 屏障暂停期间异步送两种晚回调，严格终态不降级。 |

旧 `ad63a2bafe00bf9994086a1843d48b09fba01e6c50f2d38e3920fbf78e83554d` runtime 与此前全部批次保留历史层级；f5ab67 原0.027秒、exit0并非三处复审修复后的测试。f14cf0 对应 `13ee1121faa7581f5af17bdb69e2b4d4f99ddf26f8b76b93a1bc0750bfb602aa`，未覆盖之后的晚 callback guard。实际默认 FileRegistry/crypto/TLS/网络 provider/手机组合尚未运行；FakeSelection 不再提供生产不存在的方法。三新文件 SHA 由停写后的独立读回报告，不能据这些 HOST 结果开放平台能力或给后续独立 State 接线记 PASS。
