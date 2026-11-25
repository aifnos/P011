# P2P CLIENT RF 初始化：独立 owner 最小实施计划

2026-10-01；本轮仅本地只读源码/固定归档核对与本文，不编译、不运行 native、ADB、RF、地址修改或测试。
这是待 root 评审的工程计划，不是 CLIENT 实机验收；既有控制 codec 三文件、V9、生产 gate 与历史结果不变，receive/send 仍 false。
已读 `P2P_CLIENT_NATIVE_NEXT_REVIEW.md`、`RECEIVE_P2P_PLAN.md`、`WORKER_IMPLEMENTATION_NEXT.md` 与固定 V9 runtime 全文。

## 固定依据与已知边界

- V9 源与已冻结副本均 SHA256 `cfe24fba81332082d4033e148578ac088e07e7efce0ab037f499a40e887901fb`；源为 `native/private-p2p-runtime-candidate-20261001-v9mroute/runtime/mta_send_wifi.py`。
- 固定 WPA 为 `e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301`；原始 2.12 归档为 `08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6`。
- 项目 initial patch 为 `6b958f0a282be0be042ca981fb06ca76a73f8d61c2983d1ea0eac20572cb823b`，V2 patch 为 `bad24af1dcef004ab28cc0a6ab9c9e025cc18b2545587f709ec1118dd35a18c7`；路径均在 `native/private-p2p-candidate-20261001-v2/source/`。
- 固定原包 `driver_nl80211.c:246–250` 接受 CLIENT8 或 GO9；V2 early opt-in 仍要求环境 `MTA_PRIVATE_P2P=1`、精确 mta+8hex 名和实际 P2P 类型。没有为初始 CLIENT8 必须重编的源码缺口；不能据此宣称驱动实测通过。
- V9 `ReadWriteNetlink.create:739` **已创建 type8**；`GoLease.start:1187` 随后 GROUP_ADD、检查 type9、进入 IP 子租约。这条 GO 激活流程不能改标签后当 CLIENT。

## 空配置不是“绝对无 RF”的证明

1. 固定 `scan.c:131–154` 对无 network/cred 的配置返回 enabled_networks=0；`wpa_supplicant.c:6613–6628` 因此不安排该普通初始化扫描，置 WPA_INACTIVE。
2. 同原包 `wpa_supplicant.c:6649` 初值却是 INITIAL_SCAN_REQ；`scan.c:1099–1104` 的“无网络不扫”仅约束 NORMAL_SCAN_REQ。若另一路安排 INITIAL/MANUAL 回调，不能靠空配置保证被拒绝；ap_scan=1 本身不是禁扫描开关。
3. `wpas_p2p_init:5854–6102` 设置扫描/监听 callbacks 与渠道配置，`p2p.c:p2p_init:3166–3231` 初始化内存，没有在这些函数直接调用 find/listen；这不覆盖全部异步事件或厂商固件内部行为。
4. `events.c:7458–7491` 的重新启用事件存在安排扫描的路径；本编译 CONFIG_AP 分支置 NORMAL，而非 AP 分支未在该处重置。固定 V2 patch 还真实执行 owned iface UP、驱动能力/模式/密钥初始化。
5. 因而候选和证据名称必须为 **CLIENT RF-init**：工具不主动 SCAN/P2P_FIND/P2P_LISTEN/建组/关联，不预先承诺内核或固件零扫描/零 RF。扫描事件仅私有有限解析为计数/布尔；无事件也不是硬件无发射证明。实施前 root 再评审该 RF 边界。

## 组合声明：能计算，不代替实测

历史只读 `native/tests/private-wifi-readonly-20260930c/wifi-caps.sanitized.json`（SHA256 `59a45f9ddc5fefdf422120f6157ca25258d070c8816390c0fae868f5ef9a8c28`）实际列出 station/ap/client/go/device。
其完整 limits 为 `{station,ap}:1`、`{p2p_client,p2p_go}:1`、`{p2p_device}:1`，max_interfaces=3、num_channels=2。对“1 STA+1 CLIENT、无第三接口”，逐组和为 1/1/0、总数2，声明算术成立；不用 station_plus_go_same_channel 布尔替代 CLIENT。
`mta_wifi_caps.c:154–171` 的完整 counts/limits/coverage 算法可供新 HOST predicate 参考；`:290–298` 目前没有 CLIENT 派生布尔，初版不必为此重编 native。
实施须 fresh 读取同 phy 的完整组合/现存所有接口、重叠 coverage/unknown constraints fail closed；软件接口、radar/beacon 条件不得忽略。此历史简报不含全部新字段，不能直接当 mutation admission。
未关联 CLIENT 无已证 operating channel；不把原 STA 频率当其信道，也不拿 num_channels=2 宣称双信道通过。初版只核接口数量声明与原 STA 运行中保持。

## 必须真正拆开的 GO 限制

| V9 位置/限制 | 新 CLIENT init-only 合同 |
| --- | --- |
| LEASE_IDENTITY、`_journal_envelope:292`、`recover:1432` 固定 go_ip_only/V9 marker/IP keys | 独立新 kind/marker/current schema；旧 GO 仅固定已清 prior 只读准入，不迁移、不接管、不自动 recover。 |
| `capabilities` 要求 STA+CLIENT+GO 与 GO 派生布尔 | fresh 完整 STA+CLIENT counts/limits predicate；不要求 GO 类型，不继承 GO available。 |
| `create` 记录8，`_owned_match:764`/delete 接受8或9/受限2 | 原始 ACK/readback receipt 保留8；init-ready 只准实际8，意外9/10拒绝推进，不泛化删除。 |
| `spawn_private:1019` 的 ap_scan=2/GO-oriented cfg | 私有最小 ctrl 目录 + ap_scan=1/p2p_no_group_iface=1 与已审 private driver gate；无 networks/creds/SSID/PSK/update_config/SAVE_CONFIG。 |
| `PrivateControl:767` 允许 GROUP_ADD/GROUP_REMOVE、不支持 STATUS | init 白名单仅 PING/STATUS/ATTACH/DETACH/TERMINATE；不调用 codec 的 ADD/SET/GROUP 构造器，拒绝任意 ctrl passthrough。STATUS 严格核 INACTIVE，意外 SCANNING/COMPLETED 不推进；只是 ctrl 报告，不是 association。 |
| `group_add:1075` 与 group_add_intent、GO event/凭据/freq/type9 | 全部移除 init 流；新阶段为 private_init_intent/client_init_ready，不解析 GO 密钥，不返回 SSID/PSK/frequency/mac。 |
| `ip_identity_gate:907`/`_ip_identity_gate_original:982` 依赖 GO9、carrier1 | 不调用这些 gate；CLIENT init 无关联不要求 carrier1，实际 carrier 可读报布尔/未知。IF_UP/sysfs ifindex/完整实际 type8 仍 fresh 检查。 |
| DiagnosticOwnedIpLease、`_ip_sublease`、`_ip_gate`、IP receipt/NEWADDR | init 不拥有/配置 IP、无地址/路由 mutator。保留全 IPv4/IPv6只读基线和 exact-owned 自动 linklocal/mroute 安全检查，不把删 IP 字段变成忽略异常 L3。 |
| `GoLease.stop:1364`/watchdog:1493 调 GO recovery 与 IP restore | 新角色恢复函数；无 IP restore。独立验证 controller gone→exact origin删除→全基线读回→pending clear；watchdog 不调用 GoLease.recover。 |
| SenderGoContext/SendWifiBackend/main、private_go_ip_* ready | 不导出 sender context/凭据或生产能力；独立 private_client_rf_init_* 固定结果，association/ip/dhcp/data/phone 均 false/not_tested。 |

## 新 owner、journal 与退出责任链

- 建议新 schema version4、kind=`p2p_client_rf_init_only`、marker=`p011-client-rf-init-v1-1`；这是提议，尚无新候选/freeze ID，不编造 pin。runtime/依赖/native 完整 pins 与固定 namespace 由 root 冻结后才能试验。
- 不 monkeypatch GO globals、不继承 GO.start/activate。新 runtime 必须自己解析严格 role-specific journal/pending/recover；未知 version/kind/marker、旧 active/pending 或 foreign actor 阻断，不擦除历史。
- 继续同一设备级 flock/pending 域、same boot、原基线不含 owned 对象、CREATE|EXCL 与 ACK+phy/WDEV/ifindex/name 精确读回；ACK UNKNOWN 保留 intent/pending，不按名字删。
- watchdog 继承同 open-file-description 锁 FD；父只关自己的引用，watchdog 持有到独立 reconciled。不得先 close 锁再新 backend 重获而自死锁；未知 pending 防随机新名绕过。
- 父在 durable PID/starttime/exe 记录后才释放 exec pipe gate；FD3 仅固定 numeric stage/errno，ctrl 原包不存日志。ctrl/socket/parser/epoch、私有文件 canonical/owner/mode/nlink/pin 在真实调用前核验。
- TTL≤20、同一单调 budget，退出/取消也有界；每个自身 child/FD 都要独立 finally 尝试。记录真实 wait/reap/退出码、watchdog 实际退出与 FD close；Stop请求、线程join调用或缓存 complete 不是退出证据。
- `/proc/<fixed pid>` 存在却不可读不能当 gone；PID复用/权限未知 fail closed，不信号 foreign actor。ctrl gone、私有 controller gone 后，才允许 exact type8 回收。
- 若退出变 STA2，只能另行审查同 boot+origin四元、controller确证gone、原全基线相等、down或dormant且仅受限 linklocal/route；不能把 `_owned_match` 的8/9集合直接扩到所有STA。意外 GO9 初版不自动接受。
- 保留 V9 自动 IPv6 profile：合法 linklocal/64，当前owned接口最多一条逐字段 canonical ff00::/8、UP、source/sourceprefix/gateway零；重复、default/global/未知flags/异常 IPv4拒绝。不写 IPv6/sysctl或 flush。
- 早/运行中/final 独立原厂 hashes、PID/starttime/exe/argv、完整原 wpa status 指纹/COMPLETED、boot、原 wlan0/type/frequency、接口、所有 IPv4地址/全部table routes/rules、原IPv6地址/routes相等；owned只按 receipt 精确排除，不能仅 main-route digest。
- 新 journal 只存私有归属/指纹/固定阶段，不供凭据；完整恢复后才 clear pending。reconciled shortcut 必须 fresh actor/iface absence 与全基线相等，失败保留恢复锁。旧 cleared GO registry 的完整候选/pins/记录/current absence 只能只读验证。

## 最小可实施范围与仍需实机证明

1. 后续建议独立新增 `runtime/mta_receive_p2p_init.py`、专项 owner/caps/ctrl/fault HOST tests，再机械冻结到新 CLIENT RF-init 目录；复用已审纯 ctrl codec 的配置/STATUS部分，不修改它。独立 harness/tests/plan 再由 root 分配，不写现 State/ReceiveP2pBackend。
2. HOST 需覆盖完整 limits/未知组合、精确8 ready、9/2/复用拒绝、无GROUP/SCAN/地址调用、spawn/ACK UNKNOWN、父死/TTL/recovery intent、live unreadable PID、FD/ctrl关闭失败、旧 GO prior 与新 current identity严格隔离；mock不能当实际 watchdog/退出验收。
3. root 审查新完整 source/schema/pins 与 RF-init边界后，唯一显式 ≤20秒 owned CLIENT8 init/退出。实际字段至少 kernel origin/type/flags、私有 PING/STATUS状态、numeric诊断、实际controller/watchdog退出、自动L3行与独立原网全恢复；不以14零诊断或STATUS mode=station代替类型。
4. 本轮没有 CLIENT init/control/type/并发/恢复实机结论；是否出现扫描只能据当次实际观察分层报告，不宣称绝对零RF。没有当前 source-layer 必须重编理由，若真实缺口出现再做最小 private-only native候选。
5. 真正 association 留下一阶段，必须手机处于真实互传发送/GO、当前 BLE/helper/epoch 的新 P2pInfo 与网络同意；信道/BSSID/安全套件/类型/事件需实际读回，不猜频率/IP。之后另做 DHCP/ARP/IP子租约/绑定端点与文件验收，不能自主伪造手机动作。

主来源为本地固定 [官方 2.12 发布包](https://w1.fi/releases/wpa_supplicant-2.12.tar.gz)、上述项目 patch 与实际 V9 源；本文未新增上游源码复制。未运行 HOST 专项或设备动作，仅文档计划。
