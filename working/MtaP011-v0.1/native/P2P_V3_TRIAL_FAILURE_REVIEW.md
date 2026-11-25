# P2P V3：接口创建失败与冷启动对照的只读归因审查

日期：2026-10-01。本文是失败分析，不是发布、组网通过或无线功能恢复证明。没有修改冻结候选、原厂、驱动、WCN/NV 或系统；本分析执行者没有调用 ADB、RF、重启或 SDK 安装。IP/DHCP 阶段保持暂停，普通发送能力保持关闭。

## 1. 已观测的设备事实

两次 V3 试验使用同一冻结身份 `eaf5b85a187eb73f`，runtime SHA-256 为 `eacc3a3a602f2ce047106920adaaa6c45a647e1de13a9ba4e90b5858303aff12`，原生 WPA/caps 沿用 V2 pins。每次 TTL 20 秒，没有 DHCP/IP、BLE、手机互通或 UI。

| 证据 | 原判 | 固定诊断 | 可证明范围 |
| --- | --- | --- | --- |
| `logs/MtaP011-DeviceP2pV3-20261001-022112-fc590b0e/result.json` | FAIL | `interface_create / new_interface / errno=5 / os_error` | 内核拒绝本轮 `NEW_INTERFACE`；尚未到私有 WPA 启动，未 GO ready |
| root 正常重启后的独立只读 `logs/MtaP011-BootReadOnly-20261001-023304-9c8871df` | PASS | 新 boot、原厂 hash/进程、Wi-Fi、无 owned 残留 | 启动基线核验；不是 P2P 组网通过 |
| `logs/MtaP011-DeviceP2pV3-20261001-023349-fe630cf7/result.json` | FAIL | `private_spawn / not_recorded / errno=0 / lease_error` | 同候选本轮已越过接口创建，之后私有初始化没有满足 ready 门槛；未 GO ready |

`errno=0` 是无可导出的内核 errno，不是成功。两轮公开结果的 `diagnostic_events=[]`；暖轮未启动 WPA，冷轮空诊断不能单独证明 exec 失败、固件失败或驱动初始化失败。

两轮独立收尾均核实原厂身份、Wi-Fi 状态指纹、进程、完整接口身份、IPv4 路由、IPv6 地址/路由保持，owned 接口/进程/试验 actor 不存在，pending 清空，journal `reconciled`。公开 result 的独立 `cleanup_event/cleanup_complete` 仍为 false（未收到独立成功事件），不得改写；恢复通过来自独立 readback 与 journal 门槛，而非该事件字段。

### 已经归属到内核的暖状态错误链

root 只读内核采集 `logs/MtaP011-P2pKernelReadOnly-20261001-022543-b740f1df` 的安全摘要，在两次对应失败附近都出现：

```text
init_fw: initial iftype 8, mode 0
sprdwl_sipc_get_msg_buf: command msgbuf unavailable
sprdwl_init_fw: failed
netdev registration: -5
add interface: failed
```

具体自有接口名已脱敏，原始内核 stdout/stderr/exit 分开仅留本地 private-raw。原 wlan0 在接口试验之前及之后均有周期性 scan `-12`。这说明当前暖状态的原厂扫描也受影响，但不能倒推错误最初起因、不能将其归因本次工具修改，也不能把 `-12` 等同 Linux 全局内存不足。

## 2. 精确上游接口层，与相近参考驱动层

### Linux 4.14.174 上游：EIO 不是“没有声明接口能力”的直接分支

已读取 stable `v4.14.174` 的 [nl80211.c](https://github.com/gregkh/linux/blob/v4.14.174/net/wireless/nl80211.c#L2936) 与 [rdev-ops.h](https://github.com/gregkh/linux/blob/v4.14.174/net/wireless/rdev-ops.h)。前者直接检查 `add_virtual_intf` 回调及接口模式声明，失败用 EOPNOTSUPP；随后调用驱动，若返回错误指针则透传其 errno。包装函数不翻译回调返回值。该函数没有直接 EIO 分支。

因此“驱动回调或其下层把失败包装为 EIO”与本机内核摘要一致；它不是仅凭 errno 的确定归因。P011 vendor cfg80211/驱动精确源码尚未找到，不能保证它与上游逐字一致。

只读下载内容 SHA-256（UTF-8 字节，未修改或发布源码）：

- `nl80211.c`：`b8d31ed4f03c7a07125b06d8a8717f16ebd3d7c0e02dc7e97842cb4ccb326a49`
- `rdev-ops.h`：`99d357f61bd034da185c757933ecc28b865b13e00a089760c0d91a6e7b0a1cdf`

### 官方 OEM GPL 驱动参考：SC2332 SIPC 的命令池机制

找到 Xiaomi 官方 [MiCode/SPRD_kernel_module](https://github.com/MiCode/SPRD_kernel_module) 的 `arctic-w-oss`，固定 commit `d7b2f01c32263bae74ee3628145243850fe771e5`。文件明确标注 Unisoc Copyright、GPL-2.0-only。它是 kernel5.15 的 SC2332 SIPC 家族参考，**不是 P011 4.14.174 精确驱动，不能套用其常数/修复为本机结论**。未复制或修改这些源码。

1. [sc2332/sipc.c](https://github.com/MiCode/SPRD_kernel_module/blob/d7b2f01c32263bae74ee3628145243850fe771e5/kernel5.15/wcn/wlan/wlan_combo/sc2332/sipc.c#L768) 初始化一个预分配命令列表，参考版本容量 4；数据列表分开。TX 队列执行时发送/超时/退出路径都会 dequeue。传输层还另有 sblock 资源；不能把两种池混为一谈，也不能凭日志断言是哪条回收路径卡住。
2. [sc2332/txrx.c](https://github.com/MiCode/SPRD_kernel_module/blob/d7b2f01c32263bae74ee3628145243850fe771e5/kernel5.15/wcn/wlan/wlan_combo/sc2332/txrx.c#L164) 为所有命令选择同一列表；分配失败记录命令项不可用并返回 NULL。HIF exit 的快速拒绝是另外一条路径。
3. [common/msg.c](https://github.com/MiCode/SPRD_kernel_module/blob/d7b2f01c32263bae74ee3628145243850fe771e5/kernel5.15/wcn/wlan/wlan_combo/common/msg.c#L96) 的运行时分配是取 freelist，不执行新 kzalloc。空 freelist 或退出引用门槛可返回 NULL；free 把项归还列表并降低引用。因此命令项不可用不是自动等价于全局 RAM/kzalloc 失败。真正初始化 kzalloc 失败是另一条路径。
4. [sc2332/cmdevt.c](https://github.com/MiCode/SPRD_kernel_module/blob/d7b2f01c32263bae74ee3628145243850fe771e5/kernel5.15/wcn/wlan/wlan_combo/sc2332/cmdevt.c#L328) 先取命令项，再分配 skb；两类失败分支不同。scan/open_fw 对 NULL 都使用 ENOMEM，不能仅按 `-12` 区分。还存在 HIF 未开或复位 gate，不应漏掉。
5. [common/cfg80211.c](https://github.com/MiCode/SPRD_kernel_module/blob/d7b2f01c32263bae74ee3628145243850fe771e5/kernel5.15/wcn/wlan/wlan_combo/common/cfg80211.c#L1627) 的 init_fw 先记录初始 mode，然后映射接口 type。mode 0 的前置记录本身不代表类型非法；open_fw 任何失败统一返回 EIO，无法仅按上层 `-5` 分辨下层池、skb、状态或命令应答失败。

参考内容 SHA-256（同上读取方法）：

| 文件 | SHA-256 |
| --- | --- |
| `sc2332/sipc.c` | `b8c5d03932936e1b8ae9e6f736e824410af81a4d441d220a073296a57977f975` |
| `sc2332/txrx.c` | `9ca59f170a91f901723336b922450cac90a1bb54ef06a02604689a275d8734d1` |
| `common/msg.c` | `6cecffb6876aaaec67106670ad8287807db2406974eac0a13415fb61301e1674` |
| `sc2332/cmdevt.c` | `a44cb69290fc4ed06c1f422c18000188afa6b936546b0435ca348759e6fba646` |
| `common/cfg80211.c` | `03bc008ddeadd15521ddbbae190c14e87d8ed35ee87ea011d876655594304c59` |

### 当前证据支持的推断与仍缺证据

- 支持：暖状态接口创建已进入 SIPC 驱动打开上下文链，失败点是命令项申请；同候选冷启动越过该点，故不能据暖轮 EIO 宣称“本机永远无法创建此类型自有 P2P_CLIENT 接口”。这仍不是 P2P GO 组网证明。
- 推断：共享命令列表的占用/回收或驱动状态可能影响原厂 scan 和新接口；具体是持续忙、引用退出、队列不调度、transport/firmware 等待还是泄漏，尚没有本机池计数、精确驱动源码或调度证据。
- 未证明：池容量恰好 4、本机属于相同 SC2332 实现、WCN reset 原因、全球内存压力、工具引发泄漏、P2P GO 可建组、常规网络功能已完全恢复。
- 未采用：论坛其他设备的 rmmod/reset/关闭原厂 STA 等解决方法；能力声明不是真实建组验证，错误码也不是硬件损坏证据。

## 3. 冷启动 private_spawn：补证前范围与已确认配置根因

### 3.1 02:46 补证前的历史只读记录

以下保留当时未知范围，不用后续证据倒改历史 FAIL，也不是最新未决根因结论。

V3 `LinuxBackend.spawn_private` 约 584..638 行仍是冻结源码：创建私有目录/配置；开两对 pipe；fork；子进程读一字节 gate；父持久化 PID/starttime；随后子进程设置 stdin/out/err 到 devnull、诊断 writer 到 FD3，exec 固定 WPA。原始 debug/凭据不会写入结果。

该大阶段的 LeaseError 分支包括：子进程身份未取得、私有 WPA 消失、control socket owner/type 不合格、PING/ATTACH 未 ready、必要数值诊断缺失、ready 超时。`save_process` 自身有独立 phase，因而不能把 `private_spawn` 直接解释为 fork 失败。OSError 会导出其 errno；当前是 LeaseError/0，不是已确认的 exec errno。

子进程的 `except BaseException` 只 `_exit(126)`；未 exec 时没有原生 FD3 诊断。父进程也未记录 waitpid 退出码/子阶段，且所有 LeaseError 子码在公开事件折叠为 lease_error。原生第一条诊断位于 driver init2，不在 main/加载器/配置解析入口；因此成功 exec 后在到 driver-init 前失败，同样可以没有事件。FD3 接线是否实际可写也尚无独立设备证据。

root 后续只读 `logs/MtaP011-SpawnReadOnly-20261001-024645-8ad3725d/result.json` 记录 owned/process/config/ctrl 创建均 true，私有 control socket 不存在，process 已退出，pending 清空/无 actors/原厂保持。父已经保存子身份；但原 runtime 未记录退出状态。这进一步缩小到身份持久化之后的 gate/release/exec/加载器或原生早期初始化/FD3 诊断链，仍不能确定具体一环。

补证前提出的候选方向是固定 child/spawn 子阶段＋有界 errno/exit status，不恢复 raw stderr、不输出自由错误字符串。下节已独立确认一个配置解析冲突，因此不再把新增 child 诊断当作修复该已证冲突的前置条件；其它潜在路径的可观测性缺口仍存在，不能因此宣称它们也已排除。

### 3.2 02:56 官方解析器无 RF 对照：配置冲突已经确认

root 结果 `logs/MtaP011-WpaConfigNoRf-20261001-025636-5a66dea7/result.json` 为 `P011_WPA_CONFIG_PARSE_ONLY / PASS`。使用完全相同的 V2 原生 WPA SHA-256 `e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301`，合成私有配置唯一差异是删除 `update_config=0`：

| 固定输入/证据 | 实际结果 | 边界 |
| --- | --- | --- |
| 原配置含 `update_config=0` | exit 255 | 官方配置解析拒绝 |
| 唯一删除该行 | exit 0 | 官方配置解析通过，不代表 driver init / GO 通过 |
| 固定二进制版本命令 | exit 0，首行符合版本 | 可执行/加载基本链通过；原先过严全文等值断言失败保留，不解释为加载器失败 |
| 无接口参数、无控制/DBus入口、无项目 opt-in 环境 | `radio_operations=false`、`network_configuration=false` | 未触发驱动/RF/组网，不读取用户文件 |
| 独立前后原厂/关联 Wi-Fi/完整接口/网络 actors/IPv4 和 IPv6 路由/同 boot 基线 | 全相同 | 本轮只读环境保持，不是无线功能完整恢复证明 |

确定的源码链来自冻结的官方 wpa_supplicant 2.12 源码与私有 build config。仅本地只读 `source/wpa_supplicant-2.12.tar.gz`（SHA-256 `08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6`），未提取修改、重新编译或运行原生候选：

1. `source/p2p-private-v2.config` 第 12 行为 `CONFIG_NO_CONFIG_WRITE=y`，但冻结 V3 runtime 第 590 行写入 `update_config=0`。
2. 官方 `wpa_supplicant/config.c` 约 5844..5846 的解析字段 `update_config` 仅在未定义 `CONFIG_NO_CONFIG_WRITE` 时编译；禁用配置写入时，它不是可解析的配置字段。`0` 也不会绕过字段缺失。
3. 官方 `config_file.c` 累计未知全局字段解析错误，未设置忽略配置错误时最终返回 NULL；`wpa_supplicant_init_iface` 约 7901..7907 在配置读取失败处提前返回，尚未到 driver init2。

因此这是项目私有配置与编译选项之间的**确定兼容性错误**；源码控制流与同原生二进制/单行差异的笔端无 RF 对照共同确认其足以阻断启动。它解释冷轮 control socket 未出现、`private_spawn` 失败且原生 FD3 事件为空，不需要强行猜测 fork/加载器或无线硬件损坏。本轮没有在原失败进程上取得退出状态，因此仍不伪造该历史退出码；也不把暖轮命令池 EIO 改归配置解析错误。

root/protocol agent 正在制作 V4 单变量配置修正（删除该无效行，仍不支持配置写回）。V1/V2/V3 冻结、binary pins 与原 FAIL 日志保留；本文未修改任何候选源码。**V4 此时尚未完成 GO 实机测试**，不能提前开放发送能力、IP/DHCP 或宣称初始化其它路径均已通过。

## 4. Remaining gates：结构清理与无线功能恢复分开

现有 stop/watchdog 的完整文件/进程/接口/route baseline、same-boot、epoch、origin 与 pending 证明，只覆盖项目所有权与可见网络配置。它没有读取命令池 freelist/ref/busylist，也没有证明原厂扫描新请求完成、SIPC TX 回收、固件上下文余量。因此 `journal_reconciled` 可以支持“owned 资源全清”，不能升级为“驱动命令池恢复”或“无线全部恢复”。

后续只读门槛：

1. 原厂自主 scan 事件的前后有限时间窗结果与错误增量（不自行触发扫描），原厂关联/网络状态保持。
2. 驱动族/构建 config、可得只读版本/符号与 init gate，对照精确 P011 源码；若只能参考源码，继续明确差异与容量未知。
3. 若已有只读诊断节点，限定读取数值池/队列/错误计数；不写 debugfs/sysfs，不加载模块、不 flush/reset、不新增内核探针。
4. 对已确认的配置冲突，先完成 V4 单变量 diff/身份与 HOST 复核，再由 root 串行安排有限 GO-only；新增 child 诊断不是修复该冲突的必需前置。在 GO-ready 与独立恢复证据出现之前，IP/DHCP/正式发送均不接线、不开放。其它路径若再次失败，再按实际新阶段补证，不把配置 parse-only 当成全部初始化通过。

冷启动对照已经由 root 按既有用户重启调试授权执行。本文不授权或自动触发额外重启、RF、原厂服务停止或重复试验。旧 FAIL、私密 raw、V1/V2/V3 冻结保持原样。
