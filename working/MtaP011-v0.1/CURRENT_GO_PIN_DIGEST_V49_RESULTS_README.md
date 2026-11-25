# GO49 同次读取摘要复用：主机专项通过，实机止于前置进程消失

完整互传目标仍 active；小米 15 Ultra 已登记。生产收发未开放，尚未达到只剩手机人工验收。本页保留分层证据，不改判此前 GO47 的实机 FAIL。

## 唯一新 HOST 专项

ROOT `3e0d87` 首次运行 `GoPinDigestV49Tests.test_same_read_digest_two_pin_rounds_and_file_refusals_without_radio`，HOST exit0、无超时、约 0.813 秒。固定 17 图 Loader／Entry／Bootstrap 构造器与 Native 的实际算法运行在明确 Linux/FD/Proc/时钟模型中，不调用 Bootstrap.run／reserve／RF，不重复旧测试方法。

七个新模型实例覆盖：两轮 pin、默认二元返回、同次 retain 摘要原件、内容不符、FD 元数据改变、pathname inode 替换、原 FD 关闭后 EIO。两轮各六次独立读取和六次真正 stdlib SHA，共 12 读／12 SHA，保留原 fresh Proc；没有跨读取缓存。关闭结果不确定的实例保持 Native closed=false／原异常，再次关闭只拒绝、无第二次系统关闭，不清除 pending。

ROOT 离线核 26 份实际私有输入与冻结原件、原 stdout／stderr、四成员 ZIP 字节和 CRC；独立只读审计也通过。原 marker 为 `cases=7 pin_rounds=2 pin_reads=12 pin_sha256=12 refusals=4 uncertain_close_attempts=1 rf_calls=0`。原 stderr 为 Ran 1／OK，测试内部计时 0.643 秒；不得当成笔端耗时。

[脱敏 HOST ZIP](results/go-pin-digest-v49-host-model-20261002-171051-0635eb2e/public-result.zip)，5672 B，SHA-256 `ff2b242621eb07389020cfd9679103cd75d6ce453f3a79e77246ab5673af8cf6`。只签此组件主机模型，不签 P011 十秒可达、完整 GO／恢复、IP／DHCP／手机。

测试 SOURCE `437842f5…`／20363 B、checker `f782655c…`／19723 B；主审／独审后首次运行，没有重试旧流程。

## 正式候选来源与实机状态

Native `0b9fa061…`／88792 B、17map `4b1f0322…`／3951 B：仅同次读取摘要去重，不减六独立读／身份／metadata／anchors／deadline／finally close，不增时限或额度。

准备器 `30c40241…`／50869 B，HOST `dec0be23…`／34733 B。相对 GO47 的完整窄差异仅 Native/map 绑定、标签与新结果名；Readonly47 `212c…`／baseline `593f…`／leaf `8155…`、F45、gen12、原 10／45／60／180／210 秒保持，不接 typed50/gen20。

ROOT 完整窄 diff 与独审通过；`1c49ca` 核 52 源 hash／字节与两个 Python blob 的 Python3.5 AST；默认 PC 检查 `4dacff` PASS、无 ADB。`9a3351` 核 52 源／三 blob 载荷原字节往返与 Python3.5 AST，4386871 B、零 token SHA `77f1b54d98e8d75979ace518ba2190b0572027b8165db7d3b1c13f2cf6d2583c`，没有目标 runtime import。

唯一实际 GO49 `results/go-pin-digest-v49-20261002-171545-1e5a5537`：HOST ADB0／remote1、19.250 秒、无超时，整体 FAIL；写入候选之前的原 before-read 失败，stage0／writer未构造／未fork／RF false，没有实际运行 Native49 或验证十秒性能。此次不是旧 GO47 deadline 的重复结果。

保留的原 collector 异常为初次 `/proc/PID/comm` open 的 FileNotFoundError／exact errno2；原请求路径及 open 异常对应，原票据未得 FD、known-absence／closed=true／unknown=false。实际链 `_actors → _read_file → _open → os.open`，说明本轮枚举到的进程目录在读取前已消失。不能把此原因回填给旧 GO46 的未保留错误。

ROOT `0e9e10` 终核实际52源／三blob载荷／六私有副本／raw／exit／公私投影、318个collector票据和19个Proc generation均已观察闭合；原 after未完成，整轮resource_pending=true保留，不用独立后测代签完整恢复。两成员 [实际失败ZIP](results/go-pin-digest-v49-20261002-171545-1e5a5537/public-result.zip) 1893 B、SHA `3a7fcc52f0ab3927a34501e0247e2948578856c5621872f3dd8675e156bdf959`，原路径／PID／异常只留private-raw。

因为原 after缺席，随后唯一独立 readonly47 当前检查 `results/client-readonly-diagnostic-v47-20261002-172046-45cebe38`：0／0、无超时、12.188秒、完整两轮 PASS。ROOT `6bf47d` 核实际35源／载荷／raw／420 collector及20 Proc闭合，原厂 Actor.key与全部网络 Snapshot 等于GO47 after及GO49已完成首轮，pending前后缺席；当前同session平台前后全等。跨session只核OS／Python／euid，第四项采集PID自然不同，不混作同一进程。

[当前只读脱敏 ZIP](results/client-readonly-diagnostic-v47-20261002-172046-45cebe38/public-result.zip) 四成员3911 B、SHA `c956aac31dfe100e7709895219835242d51f6282c0abb2be030e7be56a0763d9`，原厂／网络当前基线稳定不等于本轮完整原生恢复或生产准入。未重试GO49、删旧run、重启或修复无线。

一键 [PC 来源检查](HOST_MTA_GO_PIN_DIGEST_V49_SOURCE_CHECK.cmd) 仅运行默认源码检查，不启动设备试验，也不重跑已完成 HOST 专项。

## typed IP／DHCP 同步源码

v50 在 typed48 上机械移植同文 `_file`／`_pins`，新 Native `f88a36e2…`／115183 B、20map `2bad5abd…`／4525 B。map 只换 Native 一项，其余 19 项／顺序／schema 不变；typed IP／DHCP／频率／闭合／预算／期限不改。ROOT `cfe4e0` 完整窄 diff、实际 20 源身份／Python3.5 AST与独审通过；没有 import／HOST／设备／F／preparer，不把 GO17 模型结果推广到 gen20 图。

真实 GO／typed IP-DHCP／发现协商／State 与文件中心／双向收发仍待，手机系统／原厂互传版本未验。此前 [GO47 首因与实际结果](CURRENT_GO_READONLY_DIAGNOSTIC_V47_FINDING.md) 保持，不以源码计数代替实测性能。

## 后续窄修 SOURCE（未签HOST／实机兼容）

readonly51 四件 baseline `e950877b…`／31338 B、35map `8e7882ae…`／8096 B、leaf `c2052c39…`／13934 B、HOST `318f2ea6…`／25957 B，主审／交叉独审已读完整窄差异；仅初次comm打开exact ENOENT、原请求／caught异常／恰一个已知未得FD票据一致，才在原_now后继续。不吞已开FD后的stat/read/close、Proc/image失踪、EIO/EACCES，不清票据或pending，原三必需进程计数／image／双轮／额度／期限保持。

Native52 `1d51fbd6…`／90929 B、17map `1a4046f9…`／3952 B也交叉SOURCE通过，仅补私有原open事实及同窄跳过；原四必需计数／pins／双轮／原时限保留。ROOT `e30e3d` 默认51PC与35+17实际源hash／Python3.5 AST、leaf通过；`ac5640` readonly51原载荷往返／AST通过（1665775 B、零token SHA `2663021ce6c87fb0c679a56a649785ae5753076a8e7a63f14cc4340145299fb3`）。新的成对HOST负例仍在SOURCE复审，GO52尚未建组，不能提前宣称兼容分支或互传可用。

## readonly51 唯一实机只读通过（新增跳过分支未触发）

`results/client-readonly-proc-vanish-v51-20261002-173725-85bc2ba2`，ROOT `950137 → 965953`：HOST／remote 0／0、无超时、12.156 秒，完整两轮PASS，不写候选或触发RF。`e2e0be` PC-only 原件审计核35源／leaf／实际定长载荷／raw／退出／公私投影、418collector票据／20Proc generation关闭、17datagram及四成员ZIP CRC／字节；完整原厂Actor.key和全部网络等于此前独立47当前基线，pending前后缺席，同session平台稳定。不同session采集PID不混作同一Actor。

本轮原comm失败票据计数为0，没有实机触发新ENOENT跳过，所以只证明修改后的正常完整读取路径通过；不能以它代替正在复审的明确负例HOST。审计工具 `host/audit_readonly_result.py` 仅读PC原件、不import目标模块／执行载荷／ADB／写文件，SHA `e79c78c90287091c07aa89752b26aba6760b58b868bebe0f941d4bb5ea112c9b`。

[readonly51脱敏ZIP](results/client-readonly-proc-vanish-v51-20261002-173725-85bc2ba2/public-result.zip)：四成员3915 B、SHA `127335a534e22fe7da2e90bef20cf4eed2e815af1dc6690f8f3fd4021bcfe7a8`。一键 [readonly51 PC来源检查](HOST_MTA_READONLY_PROC_VANISH_V51_SOURCE_CHECK.cmd) 只检查固定源，不自动执行设备或重跑已通过的模型。

随后只读独审指出首版 PC 审计器仅认证五个载荷赋值、没有逐字节认证整个原 TARGET_BODY，且 ENOENT 票据计数门不够具体。首版文件与历史回执保持；新增 `host/audit_readonly_result_v2.py`（12040 B，SHA `6518c2e279f519eacbc01b82d49a9b72a6520c76804a065b605df1cbea82fd7c`），只以纯 AST 从固定 driver bytes 取唯一原 TARGET_BODY、重建整个 canonical payload 比较，并核 numeric comm／fd kind／exact flags。没有执行目标代码、ADB 或写入。

ROOT `1bc913` 仅重新审计原有51结果：整个1665775 B载荷、35源／418collector／20Proc／17datagram／0comm缺失票据／原厂与全部网络对照／原四成员ZIP均通过；不是重跑设备或模型，也不增加兼容分支实机证据。

## 新增成对 HOST53 专项通过

ROOT `a1884e` 唯一首跑 `ProcCommVanishV53Tests.test_paired_original_comm_open_absence_and_non_absence_refusals`：exit0／无超时、2.562秒，十组成对场景／20隔离类型域，首次comm已知未打开缺席允许跳过2次，其他18项拒绝或保留pending。关闭不确定的2项只尝试一次，没有重试系统close或清除unknown；迟到ENOENT仍由原期限拒绝。实际CLIENT35的Store／ResourceBudget／ProcReader及GO17的Loader／Entry／Bootstrap构造与原Actor／文件／Proc算法运行于明确OS／FD／时钟模型；不运行原collect、Bootstrap.run／reserve／RF，不把模型时间作为设备性能。

独审已完整读 test `3a5fa023…`／20500 B和checker `4281d5c7…`／20290 B。ROOT `e0b0b9` PC-only终核实际57私有输入副本／52源槽45独特文件／raw严格marker `paired_cases=10 graph_cases=20 known_open_skips=2 refusals=18 uncertain_close_attempts=2 rf_calls=0`／Ran1 OK与四成员ZIP字节CRC。没有重跑53或旧方法。

[HOST53脱敏ZIP](results/proc-comm-vanish-v53-host-model-20261002-175742-8c7ed543/public-result.zip)：8085 B，SHA `b6ac5f85dfea281144e7ef0207dae592444caeb0b1b97ad24c98535216b70c03`。该结论不签P011真实FD／性能／GO／恢复／IP／DHCP／手机。

GO52准备器 `ebe29295…`／50884 B与HOST `50dcbc3e…`／34754 B独审封口；ROOT默认PC `7910c7`、`1509ef`固定52源／2Python blob的Python3.5 AST及3blob载荷往返通过，4391392 B、零token SHA `d55b3871155745fe139821dc498c4c13405b8d64150a9c830b07ac511eca7748`。唯一新实机`bb6873`已启动，尚待终末；不得以这些预检提前签建组或互传可用。

## GO52 唯一实机终末：原十秒基线超时，整体 FAIL

`bb6873 → fd8b71`、`results/go-proc-vanish-v52-20261002-175939-8db436d9`：HOST0／remote1、42.250秒、无超时。before完整只读成功后准备了20个新的候选文件、实际子入口通过，子进程原wait返回exit1、独立absence已核。原707 B stderr 的 PRIMARY 为 `observe_baseline → _stable_snapshot → _snapshot_once → _pins → _proc → _check` 原stage10 deadline，RESTORE仍为 `reservation_or_publication_pending`。本轮未观察RF意图、journal为None，不能把rf_trial_requested=true当建组动作发生或把摘要优化称作十秒可达。

ROOT `1f145f` PC-only终核整个实际4391392 B载荷／52源／六私有来源副本／raw与公私投影、before／after各完整两轮、840collector票据／40Proc generation、31writer／2Python票据／6父FD／3子Proc generation已观察闭合；前后完整原厂Actor.key和全部网络Snapshot.key一致，pending前后缺席。同session平台保持，原Actor.key忽略瞬时live任务状态但保完整PID／start；第一次PC审计直接比较raw snapshot、以及两次旧字段/返回形状假设失败，仅修正审计假设，没有重跑设备或改原件。独立read-only复核也通过，原absence.reap_complete=false保留，不代签原wait。

完整Native库存未导出，journal缺席，原整轮resource_pending=true／remote_closure_verified=false／go_bootstrap_verified=false保留；已观察资源和独立基线一致不等于完整原生恢复PASS。新comm缺席票据本轮仍为0。下一仅加最多两轮、五采样的私有阶段耗时，保原期限／门／失败／恢复，不盲加时限或再次原样尝试。

[GO52实际失败脱敏ZIP](results/go-proc-vanish-v52-20261002-175939-8db436d9/public-result.zip)：两成员1903 B，SHA `c07b08c3cbac28d8adca8c89bd0cd9613b513bd2c14c2a45de72ab71528110f5`；私有trace/标识不公开。一键 [GO52 PC来源检查](HOST_MTA_GO_PROC_VANISH_V52_SOURCE_CHECK.cmd) 只检查源码，不执行ADB或重新运行设备。

typed54两件 Native `b056c570…`／117388 B、20map `a3b29e1e…`／4526 B已主审完整窄diff／独审；ROOT `3fb3ba` 实际20源hash／Python3.5 AST通过。仅机械移入Native52三个open receipt字段与初次comm ENOENT门，map只Native index18，余19源／schema／顺序／typed IP-DHCP／gen20／restore／额度／期限保持；没有入口／import／HOST／设备，不将GO17结果外推为typed20可用。
