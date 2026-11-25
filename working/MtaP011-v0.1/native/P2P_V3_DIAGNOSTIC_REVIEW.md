# private P2P V3：只改诊断的候选审查

日期：2026-10-01。V3 是独立 runtime 候选，不是生产版本，不证明 GO 建组或互传成功。作者没有执行 ADB／RF／IP 动作。主 runtime、V2 runtime／native binaries、V1／V2 的冻结与历史日志均保留。

## V2 实机证据能说明什么

根线程 `logs/MtaP011-DeviceP2pV2-20261001-015014-3b76e733/result.json`：GO-ready 未出现、失败为 OSError 类别，native 初始化诊断为空；独立检查原厂进程／原 wlan0／IPv4＋IPv6 baseline 全保持、owned interface／private actors 不存在、journal reconciled、device pending 已清。它是 **GO 建组 FAIL＋本轮恢复 PASS**，不能写成 GO 成功。

根线程后续只读 journal 摘要为 owned 未保存、process 未保存、ctrl／config 未创建、watchdog result 存在。原 runtime 的 baseline／capability 查询和初始 journal 写入在 watchdog 之前，因此本轮窗口已缩小为：watchdog 启动→创建阶段 lock／epoch readback→backend.create 内 GET_INTERFACE／NEW_INTERFACE。没有 errno，仍不能断言是驱动拒绝、fork 失败，或判定 V2 native 初始模式补丁对错。

## 候选路径及不变的边界

独立文件：`native/private-p2p-runtime-candidate-20261001-v3/runtime/mta_send_wifi.py`。

- SHA-256：`eacc3a3a602f2ce047106920adaaa6c45a647e1de13a9ba4e90b5858303aff12`。
- 主 runtime／V2 runtime 仍为 `e7222f0ed14589789faf0fc7d6857269a664264ade9ccf0b46d2c991e9b8b3c6`。
- native WPA 继续复用 V2：`e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301`；只读 caps：`9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6`。
- TTL 1–20 秒、journal version=2、device guard／pending、watchdog 继承 FD、创建／退出／WDEV 精确清理、原厂 baseline／恢复读回全部保持；没有新增 RF command、重试、地址／路由／DNS／DHCP 操作。
- `send.available=false`、`local_ip=None`，不把 V3 诊断或 HOST 测试转成发送可用。

## 唯一变量：失败归因

1. `GoLease.last_phase` 在关键调用前设置，只在进程内，不加入 ownership journal。包括输入、设备锁、baseline、capability、已有接口、pending／journal、watchdog、创建 lock／epoch／interface／journal、spawn／process journal、GO group／identity／deadline 和退出等固定枚举。
2. `_request` 对 kernel NLMSG_ERROR 和 socket OSError 保留数字 errno 与固定 `netlink_command` 标签。只收 `family_resolve/get_interface/new_interface/del_interface/not_recorded`；不解析或导出 extack 文本、属性、SSID、MAC、路径、PSK。
3. 失败事件增加 `failure_phase`／`failure_errno`／`netlink_command`。errno 仅是整数 1..4095，未知为 0，不从 strerror／args／文本猜数值。reason 只保留 `lease_error/os_error/unexpected_error` 类别。
4. `GoLease.failure_info` 在 cleanup **之前**捕获，避免第二个 cleanup OSError 覆盖第一错误。main 仍执行原 cleanup，不把未知 origin 当可删除。
5. backend constructor 失败另输出同样的固定失败事件，避免原 try 外的自由 Python traceback；constructor 只创建私有只读查询 netlink socket、检查路径／pins、降低自身 core/dumpability 限制，不创建 netdev／private WPA／GO group、不改变网络，报告 `no_radio_mutation=true`。

失败 schema 的既有字段继续是 event／reason／cleanup／complete／diagnostics；V3 额外三字段必须被新独立 harness 精确验证。不得用修改 V2 parser 或 monkeypatch V2 全局常量混用新候选。

## 可用于判断的组合，不是预判结论

| failure_phase | netlink_command | errno | 可归因范围 |
| --- | --- | --- | --- |
| watchdog_start | not_recorded | 实际值或 0 | watchdog/fork 初始化，不是 NEW_INTERFACE 结果 |
| create_lock／create_epoch_gate | not_recorded | 实际值或 0 | 创建前 journal／锁／epoch 阶段 |
| interface_create | get_interface | 实际值或 0 | create 的只读既有接口查询 |
| interface_create | new_interface | 实际值或 0 | socket／kernel NEW_INTERFACE，数字 errno 可继续源码定位 |
| interface_journal | not_recorded | 实际值或 0 | create 已返回，持久化自身接口记录失败 |
| private_spawn | not_recorded | 实际值或 0 | 之后的私有进程启动，仍需 native stage 对照 |

errno=0 只表示未知，不等同成功。GO-ready、原厂完整 baseline、owned actors／interfaces 消失和 pending 清理必须继续分别验收。所有新的设备动作由 root 完整审查新冻结后串行执行；没有自动重试授权。IP-only 与 DHCP 继续暂停。

边界：本候选不扩大为通用异常框架；finally 内 backend.close 异常仍可能留在私有 raw 中，新公开 harness 对无效／缺失事件 fail-closed，不把自由 raw 发布。V3 当前目的只定位 V2 已出现的前段 OSError，不因此改造 ownership 或自动修复未知错误。
