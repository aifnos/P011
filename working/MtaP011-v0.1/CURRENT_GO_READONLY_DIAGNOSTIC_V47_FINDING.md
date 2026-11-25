# GO47 实机：基线阶段截止，原厂／网络前后保持

目标仍 active，互传尚不可用；小米15 Ultra 已登记，不需要此时操作手机。本页是实际终末证据，不是新发布或完整恢复签署。

## 本轮实际结果

唯一任务 `results/go-readonly-diagnostic-v47-20261002-163813-7aecfc3f`（目录时间UTC，上海为2026-10-03）：HOST ADB exit0、remote exit1、无超时、42.281秒，整体 FAIL。v46 的 before-read `io_error` 未复现，不能回填旧 errno／路径。

本轮前后独立只读都完整2轮 PASS，原厂 live Actor.key、全部网络 Snapshot 及平台前后一致；pending 前后缺席。新 EXCL run 写入并封存20文件、真实子入口身份通过，子进程实际exit1、wait／absence及输出pipe EOF通过。旧根4个条目及metadata不变，新添一个run；不删除旧记录或候选。

F45 私有原 stderr 为707B：PRIMARY `GoSourceError: deadline`，链为 `GoBootstrap.run → observe_baseline → _stable_snapshot → _snapshot_once → _pins → _proc → _check → _now`；RESTORE 为 `reservation_or_publication_pending`。journal缺席，未观察RF意图。`rf_trial_requested=true`只表示启动了正式子入口，不是已经建组。

ROOT `4525b9` 离线核实际52源／3blob／定长payload、6个私有输入副本、公私投影、raw／exit及ZIP。已观察840个只读collector库存、40个只读Proc generation、31个writer原件、6个父端FD及3个子进程Proc generation均闭合。journal阴性读取／完整Native库存没有成功回执，`resource_pending=true`与整轮FAIL保留；不能用独立当前基线一致代签完整原生恢复。

[脱敏失败 ZIP](results/go-readonly-diagnostic-v47-20261002-163813-7aecfc3f/public-result.zip)，两成员1915B，SHA-256 `0dbc2a3ca20b71232bbd701c2b6a393ed04abd898fbb6bdcdf933c4d0e2b454a`。原标识符、路径、完整源码／进程／网络、错误详情仅在private-raw，不公开分享。

## 截止点的因果边界

原 Bootstrap 第一阶段一次发放 `min(原会话截止点, now + 10秒)`；两轮完整 `_snapshot_once` 共用同一scope。实际trace在 `_proc` 返回且原观测append之后的截止复核失败，尚未进入该观测的Native有效性验证。持久预留、配置验证和RF创建位于基线成功返回之后，故本轮失败早于这些动作。

trace没有轮次、实际stage end／now或分段耗时，不能把HOST42.281秒当10秒阶段耗时，不能断言存储、ProcReader或哪个actor最慢。当前失败轮尚未到接口／STATUS／新增BSS读取，但不能排除上一轮已经读取。

源码中确认一项可独立消除的重复工作：每个round四个原厂pathname及Z03／control_engine两个 `/proc/PID/exe` 共6次独立完整读取；`_file` 为私有retain计算一次SHA-256.digest，`_pins`又对同一返回raw计算SHA-256.hexdigest。即每round6读／12次完整SHA，两round12读／24次SHA。这是确定SOURCE调用数，不是已测耗时或截止首因。

隔离v49只复用**同一次读取、完成原metadata／anchors／截止／close后的摘要**，仍保留全部独立pathname／进程image读及Proc复核，不跨read／session缓存、不增时限／额度、不略过身份门。Native与17map已经SOURCE冻结：Native `0b9fa061…`／88792B、map `4b1f0322…`／3951B；map只改Native一行，其余16源／顺序／schema保持。

ROOT完整窄diff `fff597`、独立SOURCE复审、17图hash／order／Python3.5AST `c4bd50` PASS，无候选import／HOST／ADB，尚未部署。默认False仍二元返回；私有exact-bool选项仅允许原64MiB pin读取返回同一原digest，`_pins`用digest.hex()比对；读取／metadata／截止／close失败仍拒绝成功返回。每round读取6次仍不变，SHA从12次减为6次只是SOURCE计数，实际性能未验。

下一唯一新HOST组件方法正在SOURCE制作：实际17模块的Loader／Entry／Bootstrap／Native配明确OS模型，仅检查pin组件两round仍12独立读取／12实际SHA、默认返回／私有retain、错pin／metadata变化／close失败原拒绝及0RF。SHA计数若用HOST透明proxy仍调用真实stdlib，不能当设备耗时证据；不重复旧频率／AP／拒绝场景或旧整套测试。其后再决定实际试验；若仍超时，补私有轮次／组件计时，不能盲目加大10／45秒。

## 同步的IP／DHCP SOURCE进度

v48 将已经复审的频道兼容接点机械移植到typed v43 Native；其余IP／ACK／DHCP／闭合／时限／额度保持。新Native `a7014541…`／114162B、新20map `bcb01e95…`／4524B；map只换Native一行，其余19行、顺序及schema原样。ROOT完整窄diff `6d9c61`、独审及20图hash／Python3.5AST `27033b`通过，没有候选import、HOST或设备执行。

generation20／F／preparer仍未接线；增加GET_SCAN仍消耗原Native额度，不能据SOURCE宣称wall／余量通过。实际GO／IP／DHCP、State／文件中心、发现／协商／真实双向收发及小米15 Ultra验收仍待，不是仅剩人工操作。

## 来源与可复用证据

GO47 preparer `f54e4499…`／50877B，HOST `039adf21…`／34827B；只替换前后readonly为诊断35图 `212caa6f…`／leaf `81559642…`，GO17 `09039294…`、Native `78e08414…`、F45 `377bc1bf…`保持。ROOT完整窄diff `bcfa65`和独审、默认PC `25a974`、52源／3blob Python3.5AST及载荷原字节往返 `40125b` PASS。原180／45／60／30／210秒和generation12不变，私有原异常不进PUBLIC／ZIP。

[v46前置、HOST有限证据及v47独立只读](CURRENT_GO_FREQUENCY_V46_RESULTS_README.md)保留原判；已经完成的模型断言不因新诊断重复运行或累加为新整套PASS。
