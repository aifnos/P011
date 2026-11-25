# P2P CLIENT 接收：固定 WPA 原生入口复核

2026-10-01；仅本地只读源码/归档/二进制身份复核，未编译、启动 WPA、访问设备、扫描、关联或配置地址。仅新增本文，不改任何现有 gate/source/build/tests/host。
已读 `native/P2P_CLIENT_NEXT_STAGE.md`、`RECEIVE_P2P_PLAN.md`、`WORKER_IMPLEMENTATION_NEXT.md`；其历史配置中 `update_config=0` 不可照抄。GO、IP-only、回环和 CLIENT/手机证据继续分层。

## 结论

当前固定私有 WPA **源码入口同时允许 P2P_CLIENT=8 和 P2P_GO=9，不是 GO-only**。为“准入 type8”没有发现必须重编的缺口；需要的是独立 CLIENT runtime/私有控制通道/角色 journal 与真实关联、并发和恢复验证。不能把 GO 成功、字符串存在或宏开启当 CLIENT 已通过，receive.available 仍保持 false。

## 本次实际固定身份

以下均在 `native/private-p2p-candidate-20261001-v2/` 实际读回；源码行号指原始发布包，项目增量另看固定 patch。

| 相对文件 | 字节数 | SHA-256 |
| --- | ---: | --- |
| mta-wpa-supplicant | 1351192 | e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301 |
| source/wpa_supplicant-2.12.tar.gz | 4247413 | 08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6 |
| source/p2p-private-initial-mode.patch | 1331 | 6b958f0a282be0be042ca981fb06ca76a73f8d61c2983d1ea0eac20572cb823b |
| source/project-v2-supplicant.patch | 6996 | bad24af1dcef004ab28cc0a6ab9c9e025cc18b2545587f709ec1118dd35a18c7 |
| source/p2p-private-v2.config | 459 | 1c46fae858e3c7d61213e1f28f9cf5ada2c55246a1c25eef211ffc342452f3bd |
| source/prepare_wpa_v2.py | 7781 | fa7f0cc2b454180cc0131a96faa84cf866a7bd852db1f5a8297ff061568749a6 |
| source/build_p2p_private_v2.sh | 3037 | 60d2e659971ccaa54ea595615848b41ba0a62a1f840e0826758fac15dc46bb81 |
| relink/wpa-application-objects.tar.gz | 788994 | bdfbff0336e1844f56ca514969d9ffcc66cd026709da86f8501d7fc622180ffb |

不仅读取 `.config`：归档内 `build/wpa_supplicant/{p2p_supplicant,ctrl_iface,config}.o.cmd` 的实际 gcc 命令均有 CONFIG_P2P/CTRL_IFACE/CTRL_IFACE_UNIX/DRIVER_NL80211/NO_CONFIG_WRITE/NO_STDOUT_DEBUG；对应对象也在归档。固定二进制中实际有 ap_scan、p2p_no_group_iface、P2P_GROUP_ADD 和相关事件字符串。本轮未重放链接/复现构建；这些是固定包的编译记录与入口存在证据，不是笔端 CLIENT 控制调用验收。

## 初始类型及退出门禁

- 原包 `src/drivers/driver_nl80211.c:246–250` 的 `is_p2p_net_interface` 明确为 CLIENT 或 GO；不包含 P2P_DEVICE=10。
- 初始 patch 在 `finish_drv_init` 先核 `mta`+8 个小写 hex 名与实际 P2P 类型，再保持 `nl80211_get_ifmode`；不是靠晚到的 driver_param 把 STA 宣称为 CLIENT。
- V2 patch 在 `wpa_driver_nl80211_init2` 以进程环境 `MTA_PRIVATE_P2P=1` 显式 opt-in，并在早期传入 `mta_p2p_initial=1 control_port=0`；仍需上述名字/实际类型检查才设置 mta_private_lease。未 opt-in 的原厂进程无此新分支，不把 wlan0 加入私有实例。
- 原包 `wpa_driver_nl80211_deinit_p2p_cli:10552` 经 V2 patch，对动态或 mta_private_lease 接口跳过其强制 STA 分支。该静态例外不证明所有实际退出路径已保持 type8；每次仍须独立读回、controller gone 与 exact-owned 回收，不扩大未知 STA 删除权限。

## 当前编译真实可用的公开 CLIENT 控制流

1. `config.c:5816/5890` 的 ap_scan/p2p_no_group_iface parser 在本编译条件存在；`config.c:2831` 接受 disabled=0..2。候选可用私有 cfg `ap_scan=1`、`p2p_no_group_iface=1`、私有 ctrl 目录；不写 update_config，不调用 SAVE_CONFIG。
2. 原包 `ctrl_iface.c:7359–7389` 要求真实 network id、disabled=2；`P2P_GROUP_ADD persistent=<id>` 进入 `wpas_p2p_group_add_persistent`。不是裸 P2P_GROUP_ADD（GO），也不是普通 ENABLE/SELECT_NETWORK。
3. `p2p_supplicant.c:8366–8465` 的 mode=WPAS_MODE_INFRA(0) 进入 `wpas_start_p2p_client:8231–8362`；其 temporary profile 复制 SSID/PSK、使用 RSN/WPA-PSK/CCMP、置 p2p_group=1 并选择网络。不要从 UI 暴露任意 SET_NETWORK；固定白名单、SSID 字节 hex、PSK 受限编码经私有 socket 提交，凭据不进 argv/日志。
4. `wpas_p2p_create_iface:6200` 在 p2p_no_group_iface=1 时返回 0；`wpas_p2p_get_group_iface:8110–8168` 复用该私有 primary iface。本实例必须只有预先 CREATE/readback 的 owned CLIENT，不能包含原 wlan0、P2P management 父接口或未登记 group iface。
5. `wpa_supplicant.c:5087` 将 p2p_group 送入 params.p2p；`driver_nl80211.c:4650/8123` 的认证/关联路径据此选择 CLIENT 而非普通 STA。此链支持实现方向，不保证目标驱动/手机兼容。
6. persistent 仅选内存 profile/control 语义；NO_CONFIG_WRITE 排除 `config.c:5844–5846` 的 update_config parser。保持 p2p2=false、不请求 SAE/PASN/6GHz；不要为了绕过失败切 WPS/PBC、开放网或原厂 STA。

## 接口并发与字段不可猜

- `mta_wifi_caps.c:290–298` 当前仅计算 station+GO、station+AP 的 same-channel 布尔，**未计算 station+CLIENT**。必须从完整 iftypes/limits/max_interfaces/num_channels 与现有接口数量核真实 CLIENT 组合；声明支持也不等于并发实测。
- P2pInfo 的真实 ssid/psk/mac/port 不含频率/IP。mac 不是已证 GO BSSID；不强填 go_bssid，不用原 STA 频率冒充手机频率。persistent client 在未知 freq 时可进入扫描；传 freq 也不能自动当“所有扫描已受限”。先设计/复核 own-interface 有界目标扫描及信道门禁，再由 root 试验。
- 创建需同 boot、phy/WDEV/ifindex/name、原基线无该对象、共享设备锁/持久 pending/journal/watchdog；角色必须新 CLIENT identity，不把 GO frozen marker 或已清历史记录接管成 CLIENT。

## 原生事件：先私有解析再记录

- `p2p_supplicant.c:1404–1458` 控制事件实际为 `P2P-GROUP-STARTED <ifname> <GO|client> ssid="..." freq=...`，可能带 psk/passphrase、go_dev_addr、[PERSISTENT]。NO_STDOUT_DEBUG **不移除控制事件中的密钥**；禁止保存原始 ctrl 收包到 raw/公开日志，先有限字节白名单解析并只输出固定枚举/布尔。
- `wpas_p2p_completed:9248–9327` 的 client 事件可额外带 ip_addr/ip_mask/go_ip_addr，但仅在 `wpa_sm_get_p2p_ip_addr` 返回成功时出现；不能假定手机提供、不能伪造 DHCP ACK/已安装地址，更不单独当已认证 MTA endpoint。
- GO device address、关联 BSSID、DHCP server/client MAC、MTA endpoint 是不同身份。频率取实际事件/BSS 与 kernel 读回；STATUS 的 wpa_state=COMPLETED、SSID/BSSID/安全套件仅供私有匹配，不能用普通 mode=station 或 CONNECTED 代替 client 角色证据。
- V2 FD3 只有 `MTA_P2P_DIAG stage=<数字> code=<数字>`，用于初始化/退出诊断，不带关联角色、SSID、频率或服务器 IP。14 阶段全 0 不证明关联、DHCP 或数据传输。

## 最小后续实施（均尚未执行）

1. 新增独立 `runtime/mta_receive_p2p.py` 与纯 HOST 私有 ctrl codec/tests；固定 role-specific candidate marker、控制字段/事件上限、epoch、一次任务 TTL、共享锁/持久 ownership 与 secret-free 公共结果。参考已审 GO 恢复合同，不调用 GO activate 冒充 CLIENT；不改原管理器。
2. root 冻结后先 no-RF parser-only 校验该 fixed binary 的最小 CLIENT cfg（无 update_config）；再独立 ≤20 秒 owned CLIENT init/退出候选，不关联手机、不运行 DHCP/data，完整原厂与双栈基线前后核验。命令接受不算关联。
3. 下一轮须真实手机处于互传发送/GO 状态、当前 BLE 会话提供新 P2pInfo 与网络同意。先 own scan/实际信道/组合门禁，再有界 persistent client 关联；要求 client event+COMPLETED+RSN/CCMP+当前私有凭据匹配+actual type8/full identity，运行中和退出后原 STA 完整保持。不由本子任务自主操作手机或 RF。
4. 关联通过后才接既有纯 DORA core、实际 scoped UDP/冲突探测、客户端地址子租约与真实端点证明，再用 socket_factory 做 exact-owned 绑定 TLS/文件/ACK。已有 lo UDP/TLS 不证明该路径；option54 不自动提升 peerVerified。
5. 当前没有 source-layer 必须重编理由。若实际 CLIENT init/私有 ctrl/驱动失败才以该固定源码作新 native candidate：仅增加所缺 fixed-number 诊断或经证据确认的 private-only 兼容差异；不扩大初始类型白名单、不强制 STA、不全局修改服务。未经新审查/冻结不得替换 e069 二进制。

主来源：本地已固定 [官方 2.12 发布包](https://w1.fi/releases/wpa_supplicant-2.12.tar.gz) 与上列项目 patch；[官方 P2P 架构/控制文档](https://w1.fi/wpa_supplicant/devel/p2p.html) 只作概念参考，精确分支以归档行号为准。未新增源码复制或第三方实现。未完成层为 CLIENT 实机并发/关联/恢复、真实 DHCP/ARP/IP/接口绑定/手机端点及端到端文件验收，不能开放接收能力。
