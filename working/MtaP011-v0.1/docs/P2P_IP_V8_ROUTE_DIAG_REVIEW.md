# V8：同次拒绝路由行的有界摘要

状态：独立诊断候选，仅 HOST。没有 V8 正式冻结、ADB、RF、Docker、全套或手机证据。
三个新文件为 V8 runtime、native/tests/test_send_wifi_v8routediag.py 与本文。
V7 runtime/入口/冻结包、shared helper/core/native、历史 FAIL 不修改，生产发送仍关闭。

## 已确认与未确认

ROOT 的 V7 actual `072210-d0ad939a`、candidate `3cbd5bf8e5c718b9` 是 FAIL：
`route_prefix` 拒绝；一条 IPv6 地址检查通过，已检查第二条 owned 路由；prefix_is_128 为 false。
因此这次不是 `/128` 假设。原厂/STA/完整 IPv4/IPv6/boot/进程/接口独立恢复全部通过，
nested cleanup complete、pending clear，但没有成功 IP 收据；安全恢复不升级为 IP PASS。
这份报告没有精确 prefix 或目的 class，不能宣称已确认 multicast。

Linux v4.14 的 [addrconf.c:2214–2246](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/ipv6/addrconf.c)
在非 loopback、非 L3-master 接口上添加默认 `ff00::/8`、RTF_UP 路由，通常使用 local 表。
这给出可检验假说：旧 `10<=prefix<=64` 可拒绝该 `/8`，不是允许所有多播路由的依据。
[route.c:2604–2633](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/ipv6/route.c)
另有本地地址 `/128` 路由，但 V7 本次数据已排除该前缀作为当前拒绝点。
标志值来自 [route.h:46–56](https://raw.githubusercontent.com/torvalds/linux/v4.14/include/uapi/linux/route.h)
与 [ipv6_route.h:18–36](https://raw.githubusercontent.com/torvalds/linux/v4.14/include/uapi/linux/ipv6_route.h)，
不是从高层 RTNH_F_LINKDOWN 等另一套标志猜映射。

## 最小变更

- runtime：`native/private-p2p-runtime-candidate-20261001-v8routediag/runtime/mta_send_wifi.py`。
- 新标记：`p011-go-ip-only-v8routediag-1`；journal version3/kind/其余 identity 项保持，旧 journal 不迁移接管。
- V7 初始完整字节复制经 SHA 相等检查，再修改诊断 marker/docstring、三个原函数并新增三个纯摘要函数。
- 三个原函数是 `ip_creation_l3_diagnostic`、`_l3_copy`、`_creation_owned_routes_safe`。
- `_only_link_local`、`_owned_routes_safe`、创建 predicate 的顺序/判定、恢复/收据/watchdog/lease/main 的原函数字节不变。
- 保持一个地址 dump、一个 `/proc/net/ipv6_route` read、相同 short-circuit；不遍历后续拒绝行。

原 predicate 已判当前行拒绝后，`_route_rejected` 仅从那次已分词 parts 生成摘要，返回仍为 false。
诊断的 source/gateway/flags 可能原 predicate 尚未检查：这里明确是“拒绝后同次文本观察”，
不是宣称原门禁已经访问或通过这些字段。它不产生第二次内核观察，也不授权地址或路由。
accepted/未检查路由时摘要为空；原本被忽略的 malformed flags 不新增 accepted 路由门禁。

## 精确新公开 schema

`ip_creation_l3` 为 V7 四键加必有 `route_details`；构造/拷贝拒绝旧四键或未知键。
未观察拒绝行时 `route_details={}`，不能补 false 事实。
非空时仅三个键：`values` dict、`observations` dict、`invalid_fields` list。

`values` 可含：

- `prefix`：exact int，非 bool，0..128；canonical 两位 hex 不合法或超过128时缺失，记录 prefix invalid，绝不 clamp。
- `destination_class`：固定 `linklocal` / `multicast` / `zero` / `other`；目的需 canonical 32位 hex且128bit内。

`observations` 仅已从当前文本成功解析的 strict bool：

- source_zero、source_prefix_zero、gateway_zero。
- flags_up/gateway/host/reject/default/addrconf/nonexthop/expires/cache/local。
- flags_other_bits_set：只表示存在未在上述十位展示的位，不表示未知路由被允许或属于项目。

source/gateway 要32位 hex，source_prefix 两位0..128，flags 八位32bit hex；unknown 字段缺失。
`invalid_fields` 为排序去重固定枚举：shape/destination/prefix/source/source_prefix/gateway/flags。
shape invalid 只记录 shape；无 class/prefix/flags 虚假历史事实。
invalid 字段与对应值/布尔事实互斥；schema拒绝自由文本、原地址、额外键、非bool、bool-as-int。

诊断只在进程内/公开固定摘要，不进 journal/pending；第一拒绝在 cleanup 前保留，晚到 accepted 不覆盖。
未知诊断结构保持 fail closed，不增加“失败后仍允许”路径。
当前新源码没有 V8 实机 harness，须由 ROOT 单独审 schema/固定旧 prior 来源后决定下一有限诊断。

## HOST 验收边界

命令：`python -m unittest discover -s native/tests -p test_send_wifi_v8routediag.py -v`。
2026-10-01 最终专项 30/30 PASS、0 error/0 fail、0.279 秒、exit0，工具块 `7baca7`。
完整 V7→V8 unified diff 为工具块 `e63492`；git diff exit1 表示存在上述窄差异，不是测试失败。
专项仅 FakeKernel/FakeBackend/FakeLock、MemoryJournal/FakeSysfs；没有实际 netlink、进程 fork/watchdog、设备或 RF。
PC 只读固定原源与 helper/native SHA，AST 验证 Python3.5 和无 assert 关键动作。
覆盖256前缀旧判定等价、/8与/128仍拒绝、四种 class、known/other bits、非法字段缺失，
完整 creation/restore 读取顺序一致、first-failure 保留、无 NEWADDR、诊断不入journal、未知结构不授权。
模拟 accepted→真实收据逻辑→恢复只证明 HOST 契约，不能报告 P011 IP PASS。

下一步仍是取得实机拒绝行的 prefix/class/摘要事实。若未来要允许准确的自动多播/local 路由，
须独立功能候选同时审 creation 与 restore：两者共享旧 L3 限制，不能只解锁 creation，
不能因 multicast class、flags_up 或 “典型正常”就归属全部 GO 路由。
