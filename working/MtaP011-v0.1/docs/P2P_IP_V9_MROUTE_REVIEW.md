# V9：owned 接口单条精确内核多播路由例外

状态：独立功能候选，仅 HOST；不是 diagnostic-only，不是生产接线或 P011 IP PASS。
仅新增 V9 runtime、专项 tests 与本文。旧 V8／旧入口／冻结包／生产 runtime／历史 FAIL 不改。
没有本轮 ADB、RF、Docker、套测、正式 freeze、DHCP、应用数据 socket 或手机证据。

## 证据分层

ROOT 实际 `logs/MtaP011-DeviceP2pV8RouteDiag-20261001-075353-9ad31b4d`：FAIL，
ip_create / interface_l3 / route_prefix。当前被拒绝行 prefix=8、class=multicast，source/source_prefix/gateway zero，
flags 仅 UP、invalid[]；14 native stage 均0，完整原厂/STA/全部 IPv4 地址与表/rules/IPv6/boot/进程/接口恢复 PASS。
内部失败 cleanup PASS、pending clear，但没有 IP 安装收据；不把恢复成功重标为 IP PASS。
这一实际失败是旧下限10与观察到的 /8 不兼容，不是当前载波、蓝牙或硬件损坏证据。
V8 class 摘要仍不足以证明目的就是精确 ff00::，V9 运行时必须逐列证明其 canonical profile。

主来源 Linux v4.14 [addrconf.c 2213–2245](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/ipv6/addrconf.c)
在正常非 loopback、非 L3-master 接口建 ff00::/8、RTF_UP 多播路由，使用 local table。
[/proc IPv6 route 格式 ip6_fib.c 1995–2013](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/ipv6/ip6_fib.c)
输出目的/源及前缀、gateway、metric/refcount/usecount/flags、IFNAME；数值使用有界十六进制格式。
我们只独立实现上述固定字段校验，没有照搬第三方代码。metric 不作为归属常量，不强制256；
refcount/usecount 可变，不把某次计数值写死。

## 原始复制与差异边界

先验证实际冻结 V8 manifest `7e98dbf4a03abcfaf2cbd38e5f4d95d51e2de2969166b2a3dc5557d606d03c29`，
runtime `83770b7e9264dbcb8887d323e9b49771e3db46e8144a7325fccbaa8be8ba7e89`，再机械复制到新目录；
复制后的 SHA 再确认相同，之后仅 apply_patch 窄改新文件。
V9 路径 `native/private-p2p-runtime-candidate-20261001-v9mroute/runtime/mta_send_wifi.py`；
新 marker `p011-go-ip-only-v9mroute-1`，version3/kind/其余 identity/core/helper/native 不变。
当前 journal/recovery 仍严格新 identity；不接管旧 journal，旧 prior 是否可只读准入留新入口单独审核。

只有两个原函数修改：`_owned_routes_safe`（restore／STA清理）和 `_creation_owned_routes_safe`。
新增一个纯 parts helper `_kernel_multicast_route`，无内核重读或额外控制操作。
其余原函数逐字节保持，包括 link-local 地址、原 link-local 路由分支、ownership、stock、
接口四元/process/全基线/carrier/期限/收据/watchdog/恢复/主 CLI 与 send=false。
不改 sysctl、IPv6 开关、原 wlan0/ConnMan/WPA，不做所有多播、所有 /8 或任意 flags 例外。

## 唯一新增允许 profile

只有调用方已经匹配本次 owned name 的10列行才检查 helper；不匹配 IFNAME 的行不计数，也不授权。
helper 要求 plain list、全部 plain str，目的 exact lowercase `ff`＋30个0、prefix `08`，
source/gateway 各32个0、source-prefix `00`、flags `00000001`。
metric/refcount/usecount 各为8位 lowercase canonical hex，仅形状验证，没有固定数值要求。
每次本接口读取最多允许一条：第二条即创建与恢复均拒绝，不能把 duplicate 自动折叠。
目的不同、任一非canonical/zero差异、额外 flag、default/global/gateway/local128 不适用此例外。
原 link-local 分支保持原判定；本候选没有悄悄增加其 flags 或 metric 规则。

创建确切例外行的 prefix_is_128=false 是实际08读回事实；原首次拒绝 reason/stage/details 保留。
accepted 仍没有 rejected route_details；后续拒绝不会被先前允许行掩盖，也不访问后续行。
恢复和 station cleanup 同用 helper与本次计数；不能只允许 creation 而阻断 rollback。
旧 allow_ipv4=False 的 /proc/net/route 拒绝仍在例外之前；新例外不能跳过地址或原接口归属门禁。

## HOST 验收与仍未验证

专项：`python -m unittest discover -s native/tests -p test_send_wifi_v9mroute.py -v`。
2026-10-01 实际28/28 PASS、0.323秒、exit0，完整工具输出7a3a2b；未运行全套。
完整 frozen V8→V9 diff为c4f0af，git diff exit1仅表示存在窄差异，不是测试失败。
测试只有 StringIO/FakeBackend/FakeLock/MemoryJournal。
覆盖正例、256 prefix、所有额外 flags、canonical字段、变动计数、duplicate／多接口、
create/restore/STA cleanup、原 IPv4拒绝、旧 link-local 同结果、carrier/origin/address short circuit，
同收据/单次 NEWADDR/精确 rollback HOST 契约、first-failure、旧 identity拒绝、AST3.5无新增 IO。
HOST 模拟地址创建/恢复不是 P011 内核成功、真实 watchdog、GO-IP、DHCP 或手机互传证据。
尚无新 harness、正式 V9 ID 或实机 trial；不能直接执行生产 START，也不打开能力 gate。
ROOT 全文审查源码/测试/主来源后，另行审核新入口、实际冻结/固定历史 pins，再决定唯一有界试验。
