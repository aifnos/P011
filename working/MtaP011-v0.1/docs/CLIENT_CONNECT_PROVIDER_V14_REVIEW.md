# CLIENT connect v14 — SOURCE / Fake review

本轮为隔离连接接线，不是手机互通、关联、IP、恢复或生产能力验收。没有 ADB、WSL、真实 socket、RF、Stage、INIT 或设备试验；旧文件与历史失败不变。

## 固定来源与唯一增量

- Provider 从 `candidate/client-diagnostic-v12/runtime/mta_client_linux_provider.py` 完整复制，来源 SHA-256 `17e09c40d4c04c048b46e50de1151a97726086c0b43cace8a0c7e5fd3d7eb288`。
- 仅新增 connection import、构造中的两行连接库存，以及 connection-v2 的六个固定私有控制方法和三个 Lease 方法；控制方法增加同步取消检查。
- 六个 Provider 接点：`_connection_context/open/channel_gate/exchange/timeout/receive`；Lease 接点：`connect_p2p/read_connection/disconnect_p2p`。
- connection 从 `candidate/client-connection-v2/runtime/mta_client_connection.py` 复制，来源 SHA-256 `84ce100a1449a92562eec9e76b1b5d0bc28a490960fd381e701d29169e081ba3`；只增加原 callback 库存、固定检查方法与相应检查调用。
- 新专项逆向删除上述 Provider 增量后恢复完整 v12；connection 的逆向替换也完整恢复 v2。v12 的 caps-v7、tmp-alias scoped stable5、恢复 60 秒、认证/CAS、诊断和原 FD generation/once-close 完整保留。没有换回 association Provider 的旧恢复或旧能力逻辑。
- v2 的最后 drain 中 DISCONNECTED 撤销逻辑不变。未知/不合法事件仍失败；协商前信息与期望断开仍遵守原规则。

## 固定内部合同

`lease.connect_p2p(info, _checkpoint=F._cancelled)` 保存 exact callback 至原 `_Connection`，在 Store 同一 RLock 内执行；返回 exact 私有 `ConnectionObservation`。它保存实际 GROUP、两次 STATUS 与 Snapshot，但不是 AssociationProof、kernel proof、DHCP 或 endpoint proof。

`True` 表示取消；strict `False` 表示继续。非 bool、缺 callback、callback 的任何异常均固定 `cancelled`，原操作置 failed 且 Provider.cancelled Event 置位。没有异常自由文本进入公开状态；原 callback 与操作强引用保留。该私有形状不能证明 BLE 解密来源、同 Scan/helper/operation epoch/task；Parent/native/State 调用链仍需单独真实接线。

检查点在入口、实际 handoff 已保存之后、fresh 前后、每次 ctrl send 前及 valid reply 后、有界 receive 前后，以及 timeout/EAGAIN 返回路径。已收到 packet 先存原 operation/provider 库存、解析并登记 SCM_RIGHTS 原件，再检查取消；不因取消丢失原 FD。尚未接收的回复只留在 exact 原 socket，不伪造已消费数据。

取消之后没有自动重试、后续 SET/GROUP/STATUS 或为“恢复”发送 DISCONNECT。`read_connection`/`disconnect_p2p` 同样使用保存的 callback；原结果可以保留，但 failed 表示已撤销、不能复用。F 的同 lease.restore 仍是唯一恢复 owner；Provider 原 `_begin` 与恢复流程没有取消检查增量，不能被 CANCEL 阻断。

事件 socket 在动作前由同 Provider `_ledger.sock` 登记；原 `_ctrl_rights`、received packet、两 socket、observations 和 callback 始终私有。原 close_resources/proof 处理同 ledger，不新增独立资源 owner。零线程、零期限续期；保持原 init trial deadline/TTL≤20，不冒称正式 300 秒租约。

## 实际 HOST 批次（不重复已过项）

1. `190482`：新文件首次 loader **ERROR**，尚未执行测试方法，fixture 未加载已冻结 tmp-alias common。仅改测试的私有 import 绑定；不改 Provider 业务。
2. `9f8280`：14 个新方法，13 PASS / 1 ERROR，`Ran 14 tests in 6.822s`，host exit 1。错误是单一测试方法内造两个完整 Provider，真实单 owner 门禁拒绝第二个 fixture；没有放宽源码门禁。
3. `6f013e`：只原失败受影响方法 1 + 新方法 3，共 4，`Ran 4 tests in 2.555s / OK`，host exit 0。将 readback 与 disconnect 分别独立 fixture；新增 blocking-timeout 取消及完整 connection 逆向检查。首失败保留，原 13 PASS 不重跑。

合计 **17 个不同新方法分批通过**，不是单批 17，也不是旧项目全套。测试调用实际新候选方法、真实 Store/coord/FILES/pending 逻辑 over 明示 FakeIO；原 child/网络/锁/socket 都是合成模型，不是 P011 实际证明。新增两源与最终测试均解析为 Python 3.5 AST；默认 Provider 构造仍 pure/unavailable、send/receive false。

覆盖：正常 False callback 同域 connect/readback/disconnect、TTL 不变、缺/True/非 bool/BaseException、handoff 后取消、完整 fresh 后取消、send 前取消、reply 尚未读取/刚读取、event receive 后取消、poll EAGAIN/blocking timeout、已观察 readback/disconnect 撤销、SCM_RIGHTS 原 ledger 保留、v2 final-drain 撤销、两份完整源码逆向。

## 本轮冻结身份

- Provider SHA-256 `4683e4ddc0e9b41adb44c028fb9dd102a63e3b62180e9f7e011fa1508414218c`，1558 行 / 95392 B。
- connection SHA-256 `6ea9c395669ccb321011ea195095e3868a3f3d7e3ad5a02cb97cab4d1a591eb0`，248 行 / 13787 B。
- 新专项 SHA-256 `e007653af661386fb61c0710e162260f634562fdd7c2c2ee8d40b628b41757c9`，312 行 / 17117 B。

F/Loader 由独立作者接入，23 源图尚未由本轮执行；kernel-v13、DHCP、接口 IP 安装、真实手机及正式发送/接收门禁未接/未验证。Python 私有 immutable bytes 不保证凭据已安全清零。上述 SOURCE/Fake 证据不签实际恢复 PASS。
