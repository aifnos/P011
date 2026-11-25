# V7 同次 L3 观察诊断：独立试验入口

状态：新入口专项 HOST 24/24 PASS；尚无真实 V7 冻结身份、ADB、RF 或 IP 配置证据。
只读/模拟验收不是手机互传验收，生产发送能力继续关闭。

## 本轮只解决什么

061551 的 V6 权限入口实际进入 RF，原生初始化通过，但 IPv4 创建被 `interface_l3` 拒绝；
carrier 等六个已观察布尔值均为真，独立原厂、STA、完整 IPv4/IPv6 恢复通过。
它没有区分 IPv6 地址门禁与路由门禁，不能据此宣称 `/128` 就是实际原因。
V7 已审运行源仅增加 creation 的同次观察诊断，不改变原检查、顺序、读取次数或恢复逻辑。

- 固定运行源：`native/private-p2p-runtime-candidate-20261001-v7l3diag/runtime/mta_send_wifi.py`。
- SHA-256：`fbf39cfed65400f656ede96be6b12925411c19f65ac1443838e781a1baff4e93`。
- 标记：`p011-go-ip-only-v7l3diag-1`；journal/pending 仍严格 version 3、kind `go_ip_only`。
- 新入口：`host/device_p2p_v7l3diag.py`；旧 V5/V6 运行源、入口、冻结包与历史 FAIL 全部保留。

## 复用与隔离

只复用已审 V6 的纯解析器、白名单验证器、READ_HELPERS、完整基线、prior/journal 字符串。
新程序显式传自己的 pins、IDENTITY3 与历史 registry，不修改旧 module globals，也不调用旧 runner。
HOST 先验证四个旧程序固定 SHA，再由旧权限链验证固定 V5/V6 全部 payload；未知版本不自动接受。
历史 registry 只含 V5 `0f2a45489fd3e03b` 与 V6 `916a02d44aeeaf0d`：

- V5 完整 manifest：`0f2a45489fd3e03b0b56b9bb083cf2d978f005d8260e9148339616d7856591b8`。
- V6 完整 manifest：`916a02d44aeeaf0dcb24a3eaa57b7762fad5f503e3dabac83bed34df10780daf`。
- 两者逐项固定七 payload、原标记、原基线与 process.exe；只读 prior admission 不是迁移恢复。

V7 包严格为五 runtime、两个固定 V2 native 与 654 字节 SOURCE.sha256，共八文件。
WPA `e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301`、
caps `9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6` 不重建、不替换。
core/helper/JSON/safety 与已审固定内容一致，不从“最新目录” glob 选择。

## 唯一执行顺序

1. HOST 固定源码/冻结包校验；明确选择 P011，不使用 ADB 默认目标。
2. 当次只读核对旧固定十六文件 pins/mode/owner/nlink/identity；取得第一完整原厂/双栈基线。
3. 新候选 fresh-only；已有路径即拒绝，所有父/子目录 canonical、无符号链接、root 所有、0700。
4. 仅 push 新八文件；新权限程序不导入候选，先持有八个 O_NOFOLLOW FD，逐一 full SHA/size/type/owner/nlink/metadata 校验。
5. 所有八 FD 都通过后才 fchmod 新 runtime/manifest0400、native0500；全内容与路径/FD 身份再次读取，独立程序再验证完整集合。
6. 此后才允许导入已验证新源，严格检查 prior/pending，建立新的空 0700 owned session。
7. RF 前最后核对新八文件、旧十六文件、prior；最后实际完整基线须与本次第一份逐字段相同。
8. 唯一 `--trial --ttl 20` 调用；没有重试、recover、重启、全局清理或任意设备命令参数。
9. finally 用旧已验证只读程序独立核对完整原厂/STA/IPv4/IPv6；只有新包已验证且 session 已创建才读取新 owned journal。

partial open、fchmod、close、push、最后门禁或超时失败保留真实阶段/计数；不声称“完全未改文件”。
未验证的新运行源不用于 finally 检查；候选目录/私有 raw 不自动删除。
试验不是全程只读：如果原 creation 门禁意外通过，真实 NEWADDR 可以发生，仍受原收据/TTL/watchdog 恢复约束。
不配置 DHCP、不创建应用 AF_INET/TLS socket，不启动 BLE/UI，不访问用户文件。

## 公开诊断与 PASS

每个顶层事件必有 `ip_creation_l3`，严格只有 reason/stage/counts/observations 四键。
reason/stage 固定枚举；counts 仅三个已访字段，int 非 bool，0..4095；饱和为明确下界。
observations 仅固定 strict bool；未访问字段必须缺失，`route_prefix_is_128` 不能用整数或默认 false 补事实。
先验证新语义，再从派生副本删除新键交给旧解析器；原 stdout/stderr/退出记录原样私有保留。
ready 必须 L3 accepted；真实 L3 拒绝必须与旧 creation gate 的 interface_l3 对应。
两事件的同次 L3 观察必须完全相同；异常自由文本、未知键、重复 JSON 键、额外行均拒绝。

主 ready/cleanup PASS 不能覆盖独立恢复失败。最后 PASS 同时要求原完整门禁、权限/metadata、
第一/最后基线一致、L3 accepted、完整 IPv4/IPv6、原厂/STA/进程/接口/boot、pending 与严格 journal 收据恢复。
L3 失败但安全恢复依然是 FAIL；`ip_stage=none` 不倒推出“首次 gate 前从未写过地址”。
公开只含符号化结果，不含地址、SSID、MAC、PID、私有路径、凭据、自由异常字符串；入口不打 ZIP。

## HOST 证据与操作边界

实际执行命令：`python -m unittest tests.test_device_p2p_v7l3diag -v`。
2026-10-01：24 tests、13.393 秒、exit 0；输出工具块 `02b5ad` + `3d8bf3`，没有重跑全套。
FD 是 FakeOS，ADB/无线/内核是 fixture；真实 PC 文件用于验证已审 source/payload/manifest pins。
测试的 TemporaryDirectory 候选只是自动清理的 HOST fixture，不是工作区正式冻结、更非设备运行结果。
覆盖七 payload 固定与 old globals 不变、全部 FD 写前检查、partial/close/fchmod 错误、
prestage/最终门禁拒绝 RF、原 raw 不变、prefix True/False/未访语义、未知未来版本拒绝、
超时无重试，以及主阶段成功但任一完整恢复门禁失败时最终 FAIL。

ROOT 完整审阅三文件后才可 HOST 正式冻结：
`python host/device_p2p_v7l3diag.py --freeze-only`。
再核对实际生成身份/完整八文件包后，ROOT 可决定唯一有限试验：
`python host/device_p2p_v7l3diag.py --execute-reviewed --frozen <实际固定目录> --expected-candidate <实际16hex>`。
当前不提供编造的 V7 候选 ID，不运行这些步骤，START 与默认能力均不改变。

若未来真实读回证明正常 kernel local `/128` 被拒绝，功能候选必须精确对照 owned 地址与 route 语义，
并同时审 creation/restore；旧恢复同样调用原 L3 门禁，不能只放宽 creation 或泛化 prefix<=128。
本版不做该功能修复，只取得可归因事实。
