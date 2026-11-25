# 互传终末私有通道与清理期限检查

## 2026-10-04 增量证据

下文为此前 HOST94 检查的历史记录，本节更新后续事实，不改原始日志或旧结论的时间归属。

- HOST95 首次成功运行新增唯一方法和八个实际 Linux stdin/stdout/stderr 管道场景：正常、stderr 16 KiB、截断 EOF、解析拒绝、写入 unknown/zero、原期限到期、wait 结果未知。固定 Entry 响应由 HOST child 模拟，未执行实际 ARM Entry/Body/Loader；它证明 Parent 的管道算法，不证明设备终末采样。首次失败发生在测试数据构造阶段（新启动 WSL uptime 导致负数），仅修测试时间数据后成功，失败原件保留。
- 成功结果：[HOST95 ZIP](results/go-terminal-parent-v95-host-20261003-164331-58aec90b/public-result.zip)，2715 B，SHA256 d02de6ba9021acb3246be9e843c6b73f773af9dcbbaac36fae51c36df68f6fd8。十一份输入快照与四成员 ZIP 已逐字节核对。入口：[HOST95 PC-only 检查](HOST_MTA_GO_TERMINAL_PARENT_V95_CHECK.cmd)。
- Stage97 的 41 源观察图只更新 Body/Loader/Packet/Entry 四项；原预检 Parent97 保留 ReadonlyDataParent API，与新独立 ReadonlyTerminalParent95 分开。State96 已完成 sameworker 强引用消费源码，但尚未实际运行该 worker/恢复路径。
- HOST98 首次新增专项通过：唯一方法、两个新域、28 角色。实际 Boot98 load/authenticate 和 Owner98 原角色校验执行；全定义包括 State96，但 State/Server/Owner 构造、Parent collect、业务进程、无线均零调用。FS/FD/PID/clock 为显式模型；五个新目标源 Python 3.5 AST 通过。没有生产资产封印或收发准入。
- 成功结果：[HOST98 ZIP](results/go-send-terminal-boot-v98-host-20261003-171132-5ec356b5/public-result.zip)，4369 B，SHA256 fff91214bfbc0a5b337aa06df1e74fdd725280ab1ac61daf855bbb5e5cb8a249。三十八份输入快照与四成员 ZIP 已独立逐字节核对。入口：[HOST98 PC-only 检查](HOST_MTA_GO_SEND_TERMINAL_BOOT_V98_CHECK.cmd)。未重放 HOST94/95。

### 当前接收诊断边界

用户明确允许实机接收诊断后，ROOT 先完成两次当前只读状态观察及独立接收前检查。原厂文件/pid/starttime/exe 与网络进程稳定，wlan0、phy0 存在，当前 wpa_state=COMPLETED；BlueZ Powered=True、Discovering=False。没有扫描、配对、Connect、网络修改、候选部署、重启或 pending 删除。

独立接收前结果：[只读诊断 ZIP](results/receive-prerequisite-readonly-20261004-010145-06bf97e5/public-result.zip)，SHA256 0e4733704a0bae490afe9f9f150c596d4d661415791302a2669b0075d680e657。check_complete=True、sources_preserved=True，但 observed_blockers_clear=False。旧 pending 是当前 boot 的 340 字节记录，与历史摘要相同，不能当作跨 boot 残留直接清除。旧只读烟测因 reviewed source pin 过时在 HOST 端停止，没有触设备；新增诊断没有修改旧门或历史结果。

State96 的 receive_available 固定为 False；discover_start 在创建 Operation/helper 之前拒绝。Factory69-r3 对现存 pending 返回 publication_pending_exists。因此目前还不能运行完整手机接收，也没有把这些只读事实升级为恢复通过。

准备独立 BlueZ 组件诊断：核对固定原生 helper（65832 B / SHA256 179fd01f737acd30c7e903d6925217d9e0467400187614189d06a4cffdc44363）的实际目标路径与能力，随后只在明确当前无占用且退出可核验时单次注册自有 GATT、短 TTL 广播。listen 的原生 GATT lease 为 600 秒，短广告 TTL 不代表 GATT 注销；需要原始进程执行 stop/EOF、实际退出和独立后检。该组件不构造 State，不切 Wi-Fi/P2P，不配对/连接对端、不提交文件；保留 pending，receive_available、生产准入、完整网络恢复和手机验收仍为 False。

以上设备事实仅为此次观察，物理界面和小米 15 Ultra 接收尚未测试。后续不启动归档 START。

### 独立 BlueZ 能力诊断已实机通过

修正版独立能力诊断在 P011 运行约 1.55 秒，host/remote exit 0。实际两次原生 capabilities 与独立 before/after 一致：Powered、LE、BR/EDR、connectable 和 31/31 字节包能力均可用，MGMT/BlueZ 广播占用为 0，BlueZ owner 与 Discovering 不变；六个原始子进程及留存 FD 都已闭合。原厂、网络进程、接口、基础路由、boot、pending 字节保持一致。仅为组件基线观察，未执行 RF，未验证 Discoverable/Connected peers 或生产接收准入。

结果：[独立能力诊断 ZIP](results/receive-ble-component-20261004-013843-c66f953c/public-result.zip)，1166 B，SHA256 b4d755f53bb8d2f0bfe01d88ebc056b7a4f5f23d07cc5dd5ec4552cc3e18549f。ROOT 已独立核对两个公开成员、private 原来源/目标来源 hash、原始 RESULT、host/remote exit；公开包不含私有 PIPE、地址、设备名或源快照。一键入口：[只读能力检查](TEST_MTA_RECEIVE_BLE_CAPABILITIES.cmd)。

此前新增诊断首轮在 HOST 60 秒超时：内联 codec 存在 10760 字节单行，raw 只有源码回显，未收到 remote OK/exit。改为每段 1024 字符隐式拼接、所有目标行不超过 2048 后成功，实际 codec 原字节与 pin 不变。这支持 PTY 长行传输限制的诊断，不是蓝牙能力失败。首次超时原件与失败包仍保留在 results/receive-ble-component-20261004-013335-1d4456cc，后续实际进程检查未见遗留诊断 Python/helper。本轮还修正了诊断器对正常 user-owned /mnt/data 的错误假设：绑定现场节点例外，未改变设备权限，toolbox/helper 的 root/pin 门不放宽。

### 独立 GATT / TTL 5 广播组件已实机通过

ROOT 06ce43 首次成功运行修正版 --listen-advertise，整轮约 7.1 秒，host/remote exit 0。原 helper ready → 一次 listen({}) / GATT ready → 原 PID 与锁 inode 对应的 FLOCK → 一次 31/31 字节 DIAG 广播 TTL 5 → 广告到期或撤销 → STOP + 原 stdin 物理关闭/EOF → GATT 注销、stdout/stderr 双 EOF、原 helper exit 0。七个原始子进程和保留 FD 都闭合，无强制终止、命令/流 unknown。这里没有独立的广告运行中 instance=1 采样，不把能力字段 active_instances=0 误写为运行中的计数；它是前后基线值。

前后实际 capabilities、BlueZ owner、Discovering、Discoverable 和 Connected 集合一致，连接数均为 0；原厂 hashes/pid/starttime/exe、网络进程、interfaces、基础 routes、boot 与 pending 字节保持一致。hci 锁是唯一计划内变化：此前不存在，原 helper 创建 root:root/0600 空文件，在 listen 期间核对原 PID/inode 锁归属，结束后同 inode 空文件留存、锁已释放。没有删锁来伪造“未变化”。

结果：[BLE 组件公开 ZIP](results/receive-ble-component-20261004-020624-4ac444f2/public-result.zip)，1662 B，SHA256 efe68bca3b3414ea733f67ae61343fea2e01bc6445065793fbb4c6845dd82f45。两个成员为 result.json（2693 B）与 README.txt（990 B）。ROOT 24a154 独立读回核对保存的 HOST/目标来源、七依赖、原始 RESULT、host/remote exit 0、stderr 0、ZIP 内容/CRC；没有重复执行 RF。源码：[device_receive_ble_diagnostic_20261004.py](host/device_receive_ble_diagnostic_20261004.py)，43345 B，SHA256 95d9f49985e194edb86047a710f489777424207a17838fd7d9705be3096f8a10。目标 SOURCE 50731 B / SHA256 437ed3c149d41d6cdad036f5c8f011c092317773f68cb830335263bdf455c89b，最大行 1030 字节，PC Python 3.5 AST 已通过。一键入口：[单次 BLE 组件测试](TEST_MTA_RECEIVE_BLE_COMPONENT.cmd)，不是文件收件服务。

ROOT e2f79e 额外独立只读后检：helper 进程数 0，原厂及网络进程各一份、三个原厂文件 hash 匹配、Wi-Fi COMPLETED，旧 pending 340 字节/原 SHA 不变，hci 空锁没有持有者。原始私有日志位于 results/receive-ble-post-readonly-20261004-0208/private-raw，不加入公开 ZIP。

首轮 RF 候选在任何 helper 创建或 RF 命令之前退出：目标 SOURCE line 231 的 import fcntl 报 ImportError，host exit 0 / remote exit 1，约 1.4 秒；HOST 无有效 RESULT，按原逻辑保留 rf_executed=null / rf_execution_unknown=True。原件 results/receive-ble-component-20261004-020234-ba0b7ef8 和失败 ZIP 未重写。仓库既有 runtime 已说明目标没有 fcntl 模块；窄修复用 ctypes/libc F_GETFL=3 / F_SETFL=4，只改三个保留原 PIPE 的 NONBLOCK 设置及原 flags/FD 身份读回，不安装包、不改 C/binary/生产门。ROOT 224911 独立新建 local pipe 先验证目标 ABI 与物理关闭；两位 reviewer 仅 SOURCE 复核该增量。

结论只签本轮 BLE 组件，不签完整接收或完整无线恢复。{}、DIAG 广告不是 DeviceInfo；P2P payload 数 0，未测试小米 15 Ultra 发现/握手、ECDH、Wi-Fi/P2P/TLS、用户接收确认或文件落盘。State96 仍固定 receive_available=False，Factory 仍因当前 boot 的 pending 拒绝；还需要真实接收准入/旧任务归属核验以及已有接收链的实机逐层验收。本轮完成单次组件试验和独立收尾后停止，没有重启、配对/Connect、文件提交或 pending 清除。

## HOST94 历史检查

本次完成终末请求、完整响应包、固定 Loader 和学习笔入口的新源码，并取得新增纯数据通道专项的主机通过结果。它解决了旧任务到期后无法合法安排关闭检查的源码限制，以及完整 Journal 与网络快照无法共用旧包容量的问题。

当前仍未部署到 P011，也未运行新的入口管道、终末采样或 State 恢复消费。互传目标保持 active，生产发送和接收仍关闭；尚不属于只剩手机人工验收。

## 本次改动

Body 的终末构造器增加原清理期限 DATA。原 task_until 仍与 F launch 期限一致，service_until 与 parent GO cleanup 不重新发行；观察者只消耗原清理窗口的剩余时间。收到取消或任务超时并不授权延长发送。

源码核对发现，F 的 Bootstrap restore 先固定 start+60，State 稍后另固定 min(now+60,task+60)，这两个原 cleanup 值通常不相等。因此请求和 Body 都限制 observer cleanup 不超过 parent GO、service 和 F 三个原 cleanup 的最小值，不要求它们相等。未来 Parent 剩余窗口不足应返回 unavailable/pending，不能回退到更晚期限。

Packet 保留旧 87 版本完整 13223 字节前缀，追加独立终末模式。请求最多 16384 字节；响应使用固定 magic 和三个长度字段，header 最多 65536 字节，Snapshot、Journal 各最多 131072 字节，整包最多 393216 字节。Finish 原文、Snapshot 原文、Journal 原文均保留，并校验规范编码、长度、摘要、任务与 actor/absence 关联；不截断数据。解析有效或 reader.finish 只证明所提供的数据完整，不证明真实 EOF、采样、reap 或恢复。

Entry 的新显式模式为 --collect --terminal 加原六组绑定参数。空参数和旧 13 项参数委托原预检方法；旧输出上限不扩大。新入口对固定 FD0 保留原票据，检查私有 FIFO、访问方式、nonblocking readback，并要求实际读到 EOF。FD0 留到 Loader、Packet 和 Body 的文件操作结束后才一次关闭，避免后续 os.open 复用编号 0 而被原安全门拒绝；原来源 FD 大于 2 的要求不放宽。随后一次写 FD1，短写或未知结果保留并拒绝续写，清理错误不覆盖原主异常。

上述 Body/Loader/Entry 只有源码和新目标语法证据，没有实际采样或管道运行证据。所有恢复与准入字段保持 False。

## 固定源码身份

| 文件 | 字节数 | SHA256 |
| --- | ---: | --- |
| candidate/go-send-terminal-channel-v94/runtime/mta_go_readonly_preflight.py | 64944 | 0326d422bec605d279403a61c38b14bfd2f91ab0ae3959e5f647dd46ac067e40 |
| candidate/go-send-terminal-channel-v94/runtime/mta_go_readonly_loader.py | 36535 | 075ae9e1cf7736c87929032d14e36d11bc35b48616376a8c0404c7402489b346 |
| candidate/go-send-terminal-channel-v94/runtime/mta_observer_packet.py | 48253 | 004ff5616924a4529ce3a3f710ac83a8d2dedbd55ae2edb790998a68f68fe40f |
| candidate/go-send-terminal-channel-v94/runtime/mta_go_readonly_entry.py | 43263 | af87658a8a7bdf24f0c363a94a6e71c9cfb150f648e5af007e4e17f5d0fc0868 |
| tests/test_go_terminal_packet_v94.py | 23437 | ec48f5027176a7c720f4dfcb57d149e8e57b82312366e1616fa36411ded3add3 |
| host/go_terminal_packet_v94_source_manifest.json | 2086 | 8ad5eee67fb651764da4940c9f32a26f63966ff292dd2aa05a54e349f98d0107 |
| host/go_terminal_packet_v94_check.py | 9404 | f4cf76418a2b8e23092bbac81ea0636e54a84865adeb45ea47e4d2f56674da17 |
| HOST_MTA_GO_TERMINAL_PACKET_V94_CHECK.cmd | 283 | afc41adb3bf1d3c22414016830757243d5f2074ab652517238b45cff5e928eef |

旧 Body93、Loader93、Entry87-r2 和 Packet87 未修改。Body85 的前 24992 字节保留；Loader 原 38 源合同仅更新 Body pin；Entry 原方法正文保留，但新版本的 pin 不是安装证据，也不等于新版预检运行通过。

## 新增主机结果

ROOT 首次执行为 f1ace5，host exit 0、child exit 0、无超时，checker 记录约 0.297 秒。唯一新增方法为 GoTerminalPacket94Test.test_cleanup_request_and_complete_terminal_packet，两个新增域共 26 个独立场景：3 有效、23 拒绝。旧测试方法没有调用。

实际执行的是固定 JSON、IP、Core28、Snapshot DATA85、Packet94 定义中的纯通道算法；Finish、Journal、stock Snapshot、absence、fork/reap 和 metadata 输入均为合成 DATA。各场景设置 Native 构造、系统 IO、时钟和旧预检 API tripwire，不能把这些输入升格为实际设备观察。

四个新 runtime 的 Python 3.5 AST 检查通过。Body、Loader、Entry 没有动态执行；未运行完整 GO/RO 图、真实 Parent/pipe/reap、State、helper、ARM Python、P011 或手机。四个未变纯依赖没有重做兼容 AST，旧通过测试没有重放。

检查器保存九个来源加 plan/checker/CMD，共十二份实际 private-inputs 快照，核对当前文件与快照逐字节一致。公开包不含源码快照，只含以下四件原始结果文件：

| 成员 | 字节数 | SHA256 | CRC32 |
| --- | ---: | --- | --- |
| result.json | 4249 | df0d812ba2e3c69b31ff3a917f933b9e5d3c77ccc00acb6c5276965c19a80f9b | 002f8d1c |
| README.txt | 548 | 07bba771e486c1529d14140beaa0e6b92bdb6d4ae63492cb8e93799f25e3b1b4 | ed737120 |
| stdout.raw | 115 | ca68e4766cc7223083799db949b297e97b4632761780f3c01d6e6a2957ebe414 | 7cde2c68 |
| stderr.raw | 100 | da8cfac799ecbb1782f4bf7d5e3de61eef83bcae0fc6c538ed51f770aa6be057 | c6a2b549 |

结果包：[public-result.zip](results/go-terminal-packet-v94-host-20261003-152016-79ff7b46/public-result.zip)，2588 字节，SHA256 06fc6f62d84eefad9c37b1d31c164e86567bb4b71faab4ccaa7678ab103c440b。ROOT c7e625 与独立实际原件核对 6fdbdb 均确认十二份快照、result/raw、ZIP 成员/CRC/原字节一致，未再运行测试。独立审核同时确认固定 host Python 现盘身份一致；记录的纯通道通过不能升级成 Entry/Body/Loader IO、Parent、设备或恢复通过。

一键入口：[HOST_MTA_GO_TERMINAL_PACKET_V94_CHECK.cmd](HOST_MTA_GO_TERMINAL_PACKET_V94_CHECK.cmd)。这是 PC-only 新专项，不操作 ADB 或无线，不代表生产部署或物理恢复通过。

## 剩余接线

终末 Parent95 的第三条 stdin 管道已完成源码候选：[mta_go_readonly_parent.py](candidate/go-send-terminal-parent-v95/runtime/mta_go_readonly_parent.py)，64795 字节，SHA256 dbe62e66b3a42a0d0d9d9c0c60e950a253064e37d0a100b223f1f6cd84c76cd4。它不属于上面的 HOST94 十二份输入，尚未 AST、导入或运行测试。

新 Parent 使用九参数 DATA 合同。第九个 F 原 cleanup 值由未来 State 从原 Bridge FinishReport 取得，不从 regex 或普通 JSON 导入提取；实际加载固定 Packet 后，必须完整解码请求并核对同值，才允许 Popen。FinishReport.data 内层是可变原 dict，未来 caller 还须前后调用原 getter，重新核对原 raw、report、reap 和双 EOF 强身份，不能把该 dict 直接当不可变恢复授权。

Parent 源码已写入 Popen 前三份票据、返回后先留全部原 raw、逐个检查访问/非继承/nonblocking；同一 bounded select 写请求并排空两输出。请求完全写入且原 stdin 已知一次关闭后，才允许双 EOF 与原 wait 一次；失败先关闭已知 stdin，不补写或重试 unknown，再使用原剩余预算收尾。下一阶段先验证这条新增通道的实际算法与异常收尾，再做 State 接线，不能据源码推断管道运行通过。

旧 Parent92 保持 50693 字节和 SHA256 417af52e6424320d1421f74110526e70edbdd0210e8f42e789ec1ed1e3b84cfa。ROOT 已读新增差异并补读首次 diff 截断部分；原 anchors、FD adoption/current/close、file current/read、EOF、closed facts 与父 close 正文按文本相同。首个 close 文本探针因另有 IO.close 同名而计数退出，随后只核父 close 正文，未重跑此前八项；这是源码探针选择问题，不是 Parent 执行失败，也不构成 AST 或运行结论。

随后在原 GO worker、Bridge 原关闭/reap/双 EOF 完成后接入该 Parent，核对原 launch、Journal、双 Snapshot 与新 recorded-actor absence，外部 finalizer 仅被动消费原 worker 留存结果。不能通过 packet 有效、key 相等、exit0 或报告 bool 直接清除 pending。

最终普通/私有资产图与部署封印、真实接收准入、正式服务及文件中心接线、P011 恢复和双向手机互传仍待。手机型号已确认小米 15 Ultra，HyperOS 与原厂互传版本尚未确认；不会据品牌推断兼容通过。

本阶段未 ADB、未重启、未扫描/配对、未改网络或无线文件，也未删除旧 pending。设备旧 pending 与完整恢复未证的记录保留，未重测不更新。正常重启的许可问题仍未得到回复。
