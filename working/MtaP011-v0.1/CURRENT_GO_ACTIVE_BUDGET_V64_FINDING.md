# GO 原一次准备预算 v64

## 最新：首次实机整体 FAIL，channel 局部超时与恢复采样拒绝分开定位

ROOT `496fd7` 唯一实机 → `c90e47`：结果 `results/go-active-budget-v64-20261002-213823-170ca3c0`，HOST0 / remote1 / 102.140秒 / 无超时。首完整双轮通过、reserve及watchdog启动已经走过；PRIMARY在 observe_channel 的原局部10秒内，经 baseline_current → 新单轮快照 → stock STATUS 的文件读取达到 deadline。active75没有解决局部10秒，不签性能提升。没有 interface CREATE、GROUP_ADD、IP/DHCP或手机数据传输。

RESTORE另在 finish_restore → restore_current 双轮快照 → actors → Proc拒绝 native_actor_unknown。首原诊断明确 kind=unknown / reason=pid_identity_changed / stage=pid_stat / passes=1；它不是PRIMARY原因，亦不是PID复用、进程消失、boot改变或无线损坏的证明。原源码该标签是stable_key(pid/start/comm/flags/ppid)、线程数或root目录元数据的复合OR，现私有F未导出失败pass各原stat，不能定其中哪项。journal原件为generation4 / restore_intent，interface_intent、owned、controller、group_add、group_observed均None；watchdog live只是历史记录，不代表现在仍活。

退出后只读入口因实际pending_exists而拒绝，full round=0；after_read_closed、baseline_restore_verified、journal_reconciled_verified均False、resource_pending=True。ROOT `9df444`纯PC原件审计通过52源、4416516 B载荷、六副本及raw；before实际已闭合421 collector /20 Proc generation /17 datagram，writer31+Python2、父FD6/子Proc3已知原件均闭合，但不提升未导出的完整Native恢复。两成员失败ZIP2044 B，SHA `825b43b0c1e496f3ccc78dc87cbec31c9892af4b98a34eac0fa8f65bed0a6b75`。

ROOT `fe3633`当前窄只读检查确认六个原厂PID/start/exe仍在、wlan0 UP与原default route、该watchdog PID已缺席。不是完整Snapshot.key恢复证明，不回填失败原因。未重试64或删除pending；已向用户询问是否允许保存日志后正常重启并仅处理本轮临时记录，回答尚待。SOURCE继续私有分段/原stat差异诊断，生产和手机仍False，目标active。

64独立原件审计随后封口，与ROOT一致，仍保持整体FAIL。ROOT `6e8c36`只读stat/SHA、`1dc752`固定shell读当前pending：340 B，五个身份字段与本轮原journal一致、issued相同、until与父原go_until相同。未删除或继续恢复。PC重新编码journal子集仅338 B，不能替代设备原文件字节或凭哈希差异判异物；两次exec-out只读尝试 `327ce1`/`08ddbb`原报error:closed、不支持该通道，随后固定shell读成功。以上都是观察，不再签旧deadline或清理权限。

## 最新：63-r2 否定补测通过，v64 首次实机运行中

63-r2只补两个受影响模型域，ROOT唯一执行 `2aeefe` HOST0 / 无超时 / 0.906秒；ROOT `f5d9f5` 与独立28副本/raw/四成员ZIP审计均通过。原63整体FAIL保持，不重放十域、不合称整批PASS；不是设备或完整恢复证明。详情见 [新快照证据](CURRENT_GO_FRESH_BOUNDARY_V62_FINDING.md)。

ROOT `c29ca0` 重新核对ADB SHA与枚举，物理P011 transport1、模拟器transport2；`496fd7` 以冻结driver SHA和显式transport1唯一启动v64候选。当前未有终态，不宣称GO/IP/DHCP/手机可用，不重试旧轮。

## SOURCE 与纯分配边界通过，尚未实机运行

Native62 的中间消费新快照、17 固定图、F60 / Store56 / Bootstrap58 / readonly51 均保留原 hash。HOST63 继续验 Native62 的受影响业务，不重跑旧模型或为父预算变化重跑同一专项。

本候选相对 v62 仅调整父侧原一次 GO 准备分配：GO_ACTIVE_SECONDS 45→75；首次发行所需 remaining 135→165（75+60+30）。原 `min(now+GO_ACTIVE_SECONDS, outer_until-CLEANUP_SECONDS-POST_READ_SECONDS)` 不变，不能在中途续期。外层 180、原一次恢复 60、后读回 30、HOST 210，以及 baseline15 / reserve10 / 局部5/10/20 均不变。

理由是量级评估，不是已测收益：v62 正常路径 active 13 轮完整快照，按 GO60 仅有两次实际完整快照约 4.3–5.1 秒外推，约需 55.9–66.3 秒，还未计发布、控制与等待。因此未运行可能可预见准备45不足的 v62；SOURCE、HOST63和后续唯一实机必须分开记录。75也不是整链成功保证，前置准备超过15秒仍由 remaining 门拒绝；若局部10秒失败，不能称扩大 active 已解决它。

当前 GO60 仍整轮 FAIL。其 journal readback 的 unknown 父票据在 stat 前登记，实际 fd/meta/raw均None、close未调用，原错误类型仅保存 FileNotFoundError；无 errno 原件。Store.reserve 失败早于首次发布，不能把该父观察缺席说成已返回未知FD、无线损坏或出版未知。已知父库存/原厂基线可分别确认，但不能提升未导出的完整 Native 恢复。

生产收发和 ready 关闭；GO / IP-DHCP / State / 文件中心 / 小米 15 Ultra 原厂双向验收尚未完成。目标 active，仍有安全自主开发工作，尚非仅剩人工。

## 来源与纯分配证据

Stage：51283 B / `8c00ea5c765053c133f56f52edb92013ff6d9d4b6514c47db5a63a3c8c9dec75`；HOST：35264 B / `e09f9d9e3404ae20f20d5060618188b8770ca8a1d6e15efa2d414b9f9123fb80`。ROOT 完整两份窄 diff 已读。`778726` 的 AST 归一化已比对整个 Stage 保持仅预算/doc/marker 改变；随后纯 prefix fixture 只截4语句，漏了 semicolon 后独立的 phase 赋值，出现 AttributeError，原失败保留，未运行生产完整函数或设备。

ROOT `0eb248` 将受影响纯 fixture 截为实际前5语句后，6个分配边界通过：remaining165/165.001/180 发行同一75；164.999/90/0在分配前拒绝，原 outer不变、只取一次 now。仅执行抽出的实际分配前缀及明确 ClockModel，不运行 Stage.run、Proc、fork、Native 或 RF，不证明真实准备耗时。

同一 `0eb248` 的首次完整64 PC SOURCE / 52实际来源 Python3.5 AST / 全载荷逐字base64往返通过；零token payload4416516 B，SHA `6b118df036379e2c8e60a447278da26eae16e05c7fd218693b87512fda1e8076`。无 target 导入、ADB 或文件写入。独立64 SOURCE复审已封口无具体阻断；HOST63 首次整体 FAIL、10域有限已完成、两个夹具问题由63-r2只补受影响域，详见 [新快照证据](CURRENT_GO_FRESH_BOUNDARY_V62_FINDING.md)。不合称原63整批通过。v62和v64实际入口均未运行。新64 PC一键未点击，不为补日志重跑。
