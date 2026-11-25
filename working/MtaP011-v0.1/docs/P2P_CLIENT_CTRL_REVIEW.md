# P2P CLIENT 私有控制 codec（纯 HOST）

2026-10-01。仅新增 `runtime/mta_p2p_client_ctrl.py`、`tests/test_p2p_client_ctrl.py` 与本文；没有 backend、socket、Popen、ADB、RF、WPA 启动、接口/IP 变更、能力开放或正式冻结。原 source/候选和 receive/send gate 未改。
已读 P2P_CLIENT_NATIVE_NEXT_REVIEW、RECEIVE_P2P_PLAN、WORKER_IMPLEMENTATION_NEXT。历史 `update_config=0` 不可复用。实现为独立受限 codec，不复制上游 C 实现。

## 固定主来源与精确输出

- 本地官方 2.12 archive SHA256 `08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6`，固定私有 WPA `e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301`；详细 patch/编译记录在 P2P_CLIENT_NATIVE_NEXT_REVIEW。
- `ctrl_iface.c:3632` 的 ADD_NETWORK 回复为十进制 id 加 LF；`7359–7389` 的 persistent 入口要求 disabled=2；`p2p_supplicant.c:8231/8366` 的 mode0 路径建立 temporary P2P client profile。codec 不推断该 temporary id 等于原 persistent profile id。
- `ctrl_iface.c:2276` 的 STATUS 以 `ssid=%s\nid=%d\n` 输出 **没有外层引号** 的 `wpa_ssid_txt`；`p2p_supplicant.c:1404–1458` GROUP 同一函数输出放在 `ssid="%s"` 内。两层 framing 分别解析；SSID 内容只接受 `common.c:477–523` 的 canonical printf_encode：引号/反斜杠/n/r/t/e、小写两位 xHH、其他 ASCII printable。拒绝上游解码器可能接受但该输出函数不生成的 octal、短 hex 和多余转义。
- GROUP 的 passphrase 与 SSID 不同：源代码直接 `%s` 打印原 ASCII passphrase，**没有 printf_encode**。codec 允许其正常空格/反斜杠；源输出无法无歧义表示的原始引号或 CR/LF 内容拒绝，绝不泛化成 shell/通用引号解析器。
- `src/rsn_supp/wpa.c:wpa_sm_get_status` 输出 pairwise_cipher/group_cipher/key_mgmt，`wpa_common.c:3098` 的固定 RSN PSK 文本为 WPA2-PSK。STATUS mode=station 本身不能证明 CLIENT；GROUP 可含密钥以及 optional IP 三项，原始收包不得进入日志。
- `ctrl_iface_unix.c:wpa_supplicant_ctrl_iface_send` 的 monitor framing 可为 `<level>` 或 `IFNAME=<name> <level>`；本 codec 限 level0..5 且两个 name 均必须匹配调用者的 exact mta8hex 名。支持无 monitor prefix 的已解帧内容，不证明来源可信。

## 受限 API

| API | 精确合同 |
| --- | --- |
| ClientCredentials(ssid, passphrase=... 或 raw_psk=...) | exact bytes；SSID1..32任意原字节，恰一密钥形态；passphrase8..63 printable ASCII → 固定 PBKDF2-HMAC-SHA1/4096/32B，raw_psk明确32B。只保留SSID/派生PSK，不保留口令。 |
| client_config() | 仅 ap_scan=1、p2p_no_group_iface=1 两行；没有自造 ctrlpath、network 来源、update_config 或 SAVE_CONFIG。仅供后续私有配置解析组合，不执行 RF。 |
| add_network_command()/parse_add_network_reply(bytes) | ADD_NETWORK；exact canonical id LF，0..2147483647，拒bool/前导零/多行/缺终止/CR。实际回复来源由未来 provider 核实，不把 HOST bytes 当真实 id 证据。 |
| network_commands(id, credentials) | tuple8条固定 SET_NETWORK：ssid hex、psk64hex、proto RSN、key_mgmt WPA-PSK、pairwise/group CCMP、mode0、disabled2。无任意 key/value 或 extra 输入。 |
| group_add_command(id) | 仅 P2P_GROUP_ADD persistent=id，不接受 freq/BSSID/mac/IP、普通 ENABLE/SELECT、WPS、forceSTA。扫描/信道门禁留给未来 provider。 |
| status_command()/parse_status(bytes, credentials) | STATUS；≤4096B/≤32行/每行≤256B、LF终止、无裸NUL/CR、重复拒绝；canonical SSID匹配当前原 bytes。COMPLETED须完整身份/安全报告字段；不强制id等persistent id。 |
| parse_group_started(bytes, owned_name, credentials) | ≤1024B单帧、exact mta8hex、client role、ssid/freq/go_dev_addr必需；unknown/重复/裸控制字节/坏引号拒绝。可选psk/passphrase只在内存校验，任何一项不匹配均拒绝，不在结果保留。 |
| parse_ok_reply(bytes) | 仅 OK LF→true、FAIL LF→false，表示控制回复，不是关联/配置/恢复。 |

STATUS 白名单：bssid/freq/ssid/id/mode/wifi_generation/max_nss_rx/max_nss_tx/channel_width/pairwise_cipher/group_cipher/key_mgmt/pmf/mgmt_group_cipher/wpa_state/ip_address/p2p_device_address/address/uuid/ieee80211ac/bss_max_idle_period/ssid_verified/bigtk_set。每项各自验证有限形状；RSN PSK只接受WPA2-PSK+CCMP，mode只接受station。其他合法上游用途如 id_str、WPS口令、EAP/verbose/future字段明确 `unsupported_status_field`，不静默忽略。
GROUP 白名单仅 ssid/freq/psk/passphrase/go_dev_addr/[PERSISTENT]/ip_addr/ip_mask/go_ip_addr；IP出现必须完整合法三项、连续mask且同子网不同usable地址。不猜服务器，不使用这些字段安装地址，不伪造DHCP租约或认证；合法但不在本窄IP profile内的包也拒绝。频率仅记录控制报告的正整数，不拿其证明真实信道或并发。

## 隐私与证据边界

- Credentials、命令、私有报告为 immutable slots/tuple/bytes；repr/str固定 `<P2pClientPrivate redacted>`，嵌套容器也不显示SSID/PSK/MAC/IP/ifname。不会声称 immutable bytes 已安全清零；Python内存仍需后续进程/coredump/生命周期控制。
- 命令仅显式 `private_bytes()` 交未来可信私有 ctrl；报告显式 `private_fields()` 返回新副本供内部匹配。这两项会有秘密，调用者不得日志、argv、QML/HTTP、journal/ZIP序列化；返回副本的改变不改变内部pin。
- `public_summary()` 只固定命令/credential enum或控制事实 enum/bool：report_kind、evidence=control_fields_only、ctrl_state、ctrl_completed、ctrl_client_role、ctrl_ssid_matches、ctrl_wpa2_ccmp、ctrl_key_reported、ctrl_key_matches、optional_ip_reported。无frequency、SSID、PSK、MAC、IP/姓名或自由text；不是 associationVerified/endpointVerified。
- CtrlCodecError.args/str/repr只固定 code；失败不附原event、未知key/value或异常自由text。GROUP不保留原event或其密钥字段。未知字段明示unsupported，不降低门禁。
- exact-owned name只做字节相等与语法检查，**不是 boot/phy/WDEV/ifindex/type8 ownership 证明**。控制socket来源/epoch/TTL/原网/组合/真实信道/security handshake与恢复属于未来 provider，未由本codec模拟。
- 本机目标Python3.5是否有可用 pbkdf2_hmac 尚未实测；缺失/不可用固定 unsupported_kdf，不添加Popen/native fallback。HOST AST3.5通过只证明语法，不是P011导入/性能或native配置接受。

## 本轮验证与停写

只运行 `python -B tests/test_p2p_client_ctrl.py` 的合成 HOST 单项：首次36项通过；随后新增精确长度/binary SSID、坏频率/零GO地址不认证、mutable输入拒绝和public固定字段专项，最终 **40项通过 / 0.036秒 / HOST exit0**，完整工具输出 `0e03dd`。没有跑全套或设备测试，也没有新实际网络证据。
覆盖凭据/KDF、id边界/固定命令、两类SSID framing/转义、raw口令、私有repr/嵌套repr/错误不泄漏、STATUS truncated/unknown/duplicate/security、GROUP role/name/priority/injection/密钥/IP三项、不可变pin及Py3.5 AST/限定imports；未接状态机、恢复journal、backend/worker或任何真实控制收包。
后续 root 审查后可先做固定二进制 no-RF cfg parser 与目标 codec 导入/KDF 检查，再单独冻结 CLIENT owner。不得仅因本 HOST PASS 开放 receive/send 或宣称关联/手机完成。来源：[官方固定发布包](https://w1.fi/releases/wpa_supplicant-2.12.tar.gz)。
