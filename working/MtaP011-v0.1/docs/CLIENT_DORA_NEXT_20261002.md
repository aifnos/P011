# CLIENT DORA 下一阶段：实际代码接线范围

这是当前源码欠账与执行顺序，不是新producer、设备准入或收发通过。ROOT全文读 `runtime/mta_dhcp_client.py`、`runtime/mta_ip_lease.py`、DynamicClientExchange核心首尾；独立durable_connect_review核同调用链。v19只提供原issued AssociationReceipt及新fresh readback，v20只补只读日志，不产生DHCPProof。

## 先做同owner的DORA proof/coordinator

范围以隔离的CLIENT proof/coordinator及必要窄修的DhcpSocketClient为主，不改原GO地址选择，不造测试固定IP或全True proof。保持同Store RLock、原F/operation/binding/native epoch、原canonical/marker/OFD以及actual kernel本机MAC/Origin，接口上下文不能从BLE MAC或Caller字典拼装。所有返回原件先保留，再核其exact私有issuer/当前性。

`DhcpSocketClient._guard` 当前用同一个0.2秒做锁等待、完整producer调用与本机index核验；`open`多次guard，发送一次guard，每次`poll`在recv前后各guard，`candidate`再guard。原v19每次readback包含两轮STATUS/kernel/caps/fullbaseline；当前只读完整collector为约4.17秒。不能把0.2直接包装成“真实fresh已验证”，也不能用上一次收据或cached true通过门禁。

先明确有限锁等待、producer读回与socket轮询的分别预算；网络操作取原绝对association总期/剩余阶段期的最小值，取消与超时继续立即撤权，不更新原association deadline。资源闭合证明不授予网络权限：它必须仍能在association已过期后核exact dead runner/原socket，以免TTL正常到期永久卡住恢复。该证明保留原有限锁/producer预算，可信恢复owner可以传入独立明确的绝对recovery deadline（最多60秒剩余期）进一步clamp；不由组件自行造新总期，不拿旧网络deadline拒绝所有恢复。

还须核原FILES256、Provider reader及receipt数量上限能否覆盖真实DORA路径；v19的短trial和一次读回通过不证明正式反复调用容量。正式操作长租约需独立定义和实际准入，不能把旧20秒trial当300秒。4.17秒是单次只读完整collector观测，不是连接层双轮fresh总耗时；5秒proof配置只是有限上限，不证明实际producer一定在5秒内完成。v19同步IO只能在返回前后检测超时，内层仍守原deadline，不能宣称强制抢占。

应从实际issued receipt调用fresh读回后，形成真实同context证明；baseline、owned IPv4未配置、原Executor/controller/Origin/current持久记录各旗标必须来自对应实际producer，不把同名tuple或schema验证升格成OS事实。增加针对预算耗时、原件/epoch变化、取消/期限、资源未知和实际DORA状态转换的HOST方法，保留第一次失败，仅重测受影响项；HOST不能替代P011。

## 使用仍活跃的allocation

实际链应是 `open → poll → candidate → 当前allocation核验/受控交付`。`run`的finally始终`close`，而close调用`core.cancel`；其返回的ConfigurationCandidate是历史值，不可直接装IP。不得只删finally关闭或伪造runner闭合。交付/安装必须在活跃原context和当前usable_until内，提前持久记录下一阶段intent，随后原socket/producer按原owner确实关闭。

保留已实现的ifindex/IP_PKTINFO/UDP source与option54一致校验、绑定设备、broadcast-only、有限packet/retry数量；这些证明本次DHCP一致性，不独自证明MTA应用endpoint。

## 然后接动态CLIENT IP adapter

地址和prefix只取本次仍有效ACK，不用 `OwnedIpLease.create` 的GO `network+1 /24`。现GO `_expected_routes/_new_address`固化/24，需要独立CLIENT的实际请求ACK、地址/内核自动路由读回和exact owned delta。持久IP intent在写之前，actual ACK/readback确认后才作为owned事实；写入或闭合未知保持pending，不凭intent删除未知地址。

在同主Journal加入可恢复的CLIENT IP记录、原基线扣除exact自有delta与删除/恢复链之后，再接可信MTA endpoint和scoped data sockets。DHCP server/router/UDP source、惯常 `.1`、第一次TLS证书自身都不能自动当目标应用身份；端点须绑定原P2pInfo/本次握手和已证明网络context。既有端口来自原P2pInfo，不改为随机UI输入。

GO九方法、State与文件中心正式工厂、双方确认/字节进度/取消/安全落盘、退出原网恢复和小米15 Ultra双向验收仍在完整目标内。上述CLIENT范围未完成时不开放production send/receive gate，不把下一阶段文档称作实现。
