# GO 私有后续快照与原stat差异诊断 v65

## 2026-10-03 最新：HOST66 唯一首次方法限定PASS，ROOT原件审计通过，独立复审已PASS封口

ROOT `136546` 实际首次执行新方法1／旧方法0，host0／0.375秒／无超时，HOST66限定PASS；结果 `results/go-private-diagnostic-v66-host-model-20261002-222536-4f4de80a`。[四成员脱敏ZIP](results/go-private-diagnostic-v66-host-model-20261002-222536-4f4de80a/public-result.zip) 5210 B，SHA `bf3ff01235a9e5809e5a69679f9bd7df451d93963e513328adef2edc92ea690d`。ROOT `3a84fe` 实际原件审计PASS：23份snapshot／两个graph、raw严格marker与stderr Ran1 OK，公开ZIP CRC和逐bytes一致；独立实际原件复审已PASS封口，与ROOT原件核验一致。

原stdout128 B／SHA `2cdeb187966f091d1756db3fa61d3aa887dc9c79307fcbd7d7fed84c5aa3d70b`；原stderr100 B／SHA `e8361bc01311df8a0baf2d772958a0777953ac11516cbff713dbbb3f88eeb255`。范围为12timing／33stat（其中10纯parser vector）／9domain／4FD2／160observer callbacks，actual私有17定义＋普通Proc1；不运行实际Loader、auth、Bootstrap业务、进程FD生命周期、设备RF或恢复，不签性能。formatter／observer／私有界限的该模型证据不能扩大为实际Loader入口或65-r2完整流程通过，也不能把stat bits推成目录metadata分支或已修故障。

65-r2五件SOURCE与ROOT PC来源验证维持下方范围，但仍没有65-r2设备结果；原65五件SOURCE域阻断、未执行保持。actual64 wholeFAIL／pending／完整Native恢复未证不改；本轮正常重启和临时记录处理许可尚待，不自动删除pending／重试RF。生产／手机false，目标active且非仅人工。本次独立实际原件复审已PASS封口，仅有限更新，不重放旧方法。[64原失败](CURRENT_GO_ACTIVE_BUDGET_V64_FINDING.md)。下文原时点“HOST66在制”等逐字保留为历史。

## 2026-10-03 最新：65-r2 五件已封口，仅 SOURCE／PC；HOST66 与设备尚待

ROOT `a73baf` 完整五件窄diff主审及独立 SOURCE 复审均已封口，`510a67` 核 whole Native／F 业务 AST 逆诊断后分别等62／60；`429fc1` 核 actual52源 Python3.5 AST、52份base64与3个blob全文逐字往返 PASS。零token载荷4424579 B，SHA `7d3d0300087ac03c6f455af964c00109be172a807870522ae22a545d0a97e1af`。这些检查没有执行目标业务或设备，不等于受影响算法、性能收益、修复、完整恢复或手机互传通过。

| 冻结文件 | bytes | SHA-256 |
| --- | ---: | --- |
| `candidate/go-private-diagnostic-v65-r2/runtime/mta_go_native.py` | 99963 | `4809473ea8cc59ad4b1af66a3bbbf385b8767cd338feb6fe319d44f895d2b4ef` |
| `candidate/go-private-diagnostic-v65-r2/runtime/mta_go_executor.py` | 30661 | `2d2061e98260e39363d3845436d7a0c820fbddca96273177d3a0eb2a73a02eb4` |
| `host/go_private_diagnostic_v65_r2_source_manifest.json` | 3968 | `99a2329c18efeb26baf9bab3a6249e14168440a2ee87430720317be0caadba36` |
| `candidate/go-private-diagnostic-v65-r2/runtime/mta_go_bootstrap_device.py` | 51679 | `2d25af28cb7a640c18aba88488bf77e0549e37cad9de9dcb380847da6d205718` |
| `host/go_private_diagnostic_v65_r2_p011.py` | 36133 | `84735564daa943a2d2d5c441f810ffafe5ecc25c3d20765b1bf1402f7048ff79` |

r2 将纯parser原件tuple移到实际 Loader 私有 Native 模块：`(_proc_v56, _proc_v56.parse_stat)`；F 删除普通顶层 Proc import，只核 exact actual Native tuple 与实际 deployment Proc／函数连续性后纯解析原bytes。没有改Loader或Bootstrap业务入口，不把函数指针连续性扩大成整个Proc globals冻结或任意模块抗篡改保证。清单相对62只有Native／F两个delta，schema／其余15源／顺序保持；Stage／HOST仅身份接线，同宽 `P011_V65_*` 的14／16／17切片保持。

Native私有计时上限2→32，每轮原五observer样本，最多160次observer调用；F只输出首二／末二去重，PROC60→PROC65→SNAP，head2048／aggregate16KiB／原单FD2不变。原PROC60正文不变；PROC65仅在原unknown／pid_identity_changed／pid_stat拒支，按已完成passes+1限定失败pass，比较原同root及有序leader的三stat bytes，输出pid／start／comm／flags／ppid／threads六位差异，无PID／path／argv／raw内容。缺／多／foreign／非有效pass均unavailable；rootmeta／任务数分支证据不足不推因，不新增read／clock／重试／授权。额外observer成本明确，不声明业务时耗等效或提速。

旧65五件仍冻结，仅SOURCE域阻断且从未执行；旧 `6d28ca` 窄diff读取不是原65 SOURCE／算法PASS。新HOST66受影响专项仍在制作，65-r2实际设备／HOST66结果均尚无。原75／180／60／30／210及全部局部stage／库存／取消／恢复判断不变，当前候选仅补私有原因与后续计时可见性。

actual64 wholeFAIL／pending仍在：PRIMARY原channel10 deadline；RESTORE原Proc pid_identity_changed，journal generation4／restore_intent、RF intent=false，完整Native恢复和after完整基线未证。当前六原厂actor／wlan0 UP只读事实不是恢复；本轮正常重启／临时记录处理用户许可尚待，不清pending、不执行新RF。目标active、尚非仅人工；真实GO／typed IP-DHCP／State／文件中心／小米15 Ultra原厂双向与生产准入仍未完成。[64实际原判](CURRENT_GO_ACTIVE_BUDGET_V64_FINDING.md)。下文旧“当前／制作中”等保持为各原时点历史，源与失败原件不改。

## 当前：原65仅SOURCE被阻断，隔离r2制作中，尚未设备运行

64实际PRIMARY是channel原10秒内stock STATUS文件读取deadline；RESTORE另在ProcReader采样一致性拒绝。现SNAP55仅首两条，无法测后续快照；PROC60仅标签，不能区分首/末/leader stat的字段变化。参见 [64实际证据](CURRENT_GO_ACTIVE_BUDGET_V64_FINDING.md)。

新诊断的限定范围：最多32条私有snapshot timing，每条最多五次原observer clock调用（上限160，比旧十次增加）；原业务last/scope/cap、资源读取、完整初始与恢复双轮均不改。纯formatter只选首二/末二去重、先PROC60/PROC65再SNAP；private head2048、总16KiB和原单次FD2写保持。新增PROC65只在原ProcObservation为unknown/pid_identity_changed/pid_stat时，用失败pass（已完成passes+1）中的两个同root stat及一个有序leader stat原RawRecord bytes，原纯parse_stat后输出pid/start/comm/flags/ppid/threads六bit差异；不输出PID/path/raw内容，rootmeta保持unavailable。缺、多、foreign或不匹配原件均unavailable，不推因、不授予权限。

旧65 Native/F窄diff由ROOT `6d28ca`读完：Native99760 B / SHA `5cb3a804cf64fd9d66e5b20f8992221f6efdd966f95d750613012da4f2320a03`；F30680 B / SHA `d2a93aa1bb82e43ed17a93d4cc38f28fe11640e41a117206c9e920f4d6cf5f86`。当时五件SOURCE冻结，未执行。

测试作者、制作作者及独审随后共同确认实际Loader域阻断：Loader33保留正在运行的F模块，却给Proc创建私有ModuleType。旧65在F普通顶层import Proc并捕获parse_stat，与实际deployment Proc不同域，纯formatter模块is比较必失败。顺序加载17定义的PC fixture可能掩盖该问题；不把窄diff读完当SOURCE通过，也没有旧65 HOST或设备PASS。

ROOT已要求保留原五件，制作新65-r2：使用Native现有actual private `_proc_v56`捕获parser原件tuple，F从exact actual Native模块取得并核对deployment Proc及parse pointer；删除F普通顶层Proc import。只改诊断来源，不改Loader/Bootstrap/业务许可。r2最终pins、52来源和HOST66首次新受影响专项尚待；旧模型/设备轮不重放。当前pending尚在，用户本轮正常重启/临时记录处理许可尚待；生产/RF建组/恢复/手机均不签通过，目标active。
