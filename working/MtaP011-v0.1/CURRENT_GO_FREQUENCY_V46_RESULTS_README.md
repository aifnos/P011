# GO v46 频道兼容：只读前置通过，正式试验在建组前失败

当前目标仍 active，生产收发未开放。验收手机为小米 15 Ultra；当前不需要手机操作。本页记录 v46 新证据，不改判 v42/v44/v45 或本轮 HOST 首次失败。

后续正式GO47已终末FAIL于首基线10秒scope，前后独立完整基线一致；最新实际结果／去重优化范围见[GO47首因与当前进度](CURRENT_GO_READONLY_DIAGNOSTIC_V47_FINDING.md)。本页下方各历史时点不改判。

## 只读实机前置

唯一实际只读任务 `results/client-readonly-scan-v46-20261002-160021-d256528b`（时间目录为 UTC，上海时间已为 2026-10-03）：HOST/remote 均 0，无超时，11.953 秒。原 STATUS1 与 STATUS2 包围两次 GET_SCAN 缓存读取；两轮完整 Snapshot 稳定，两轮均为当前 ASSOCIATED BSS，频率 2412 MHz、beacon interval 100。读取的是既有缓存，没有 TRIGGER_SCAN、建组、配对、stage 或原厂修改。

ROOT `1d27ad` 离线独立核对实际请求 cmd32/ifindex、关联 BSS 字段、实际 STATUS、35 源实际载荷原字节、两次 pending 缺席、平台身份及原库存闭合：21 个 datagram，420 个 collector 资源关闭，20 个 Proc generation 全部关闭，未知资源为零。该结论仅为本次只读生命周期，不等于历史无线恢复、正式 GO 或手机互通。

[脱敏只读结果 ZIP](results/client-readonly-scan-v46-20261002-160021-d256528b/public-result.zip)：四成员，3760 B，SHA-256 `61c484ea20171c794947419e496905ce55a7cdfad5da0b83321f63d54a9e1237`；原标识符、原始 netlink/STATUS/进程资料只在 private-raw。

源码冻结：baseline `f06e83b8…`/34793 B、leaf `5d33d832…`/15419 B、35map `fa331741…`/8082 B、HOST `d9e65917…`/25664 B。ROOT/独立完整窄差异复审、PC 默认 `f0de3f`、Python 3.5 AST/载荷原字节 roundtrip `0830ed` 通过；原 10/30/45 秒和全部资源额度保留。

## 因果 HOST 首次失败及有限已完成证据

唯一新方法首次执行 `results/go-frequency-v46-host-model-20261002-160557-b9335060`：HOST 子进程 exit1，无超时，7.921 秒；原方法整体 FAIL，原始输入/输出保留。失败首因是四个 baseline 拒绝场景把实际不可变空元组 `()` 写成空列表 `[]` 的测试断言，不是已观察算法失败。

原 stderr 四条失败都在该断言，另有最终 completed 清单不满七项的汇总失败。completed.append 位于每个场景全部断言之后，原 completed 为正向 missing38、AP 缺 freq、AP 错 freq 三项。ROOT 与独立复审据此确认这三项模型断言已走完：正向至 generation12/reconciled 并模型闭合，两个 AP 拒绝至 generation11/reconciled；正向内的六个不可变事件解析反例亦已走完。它们不是整体方法 PASS，更不是实机证据。

四个 baseline 场景只验证到原第 216 行之前。其后 restore_failure、零 Child tickets、scan 命中以及末态 native.closed_facts/io.live 尚有证据空缺；隔离 r2 只重做这四个受影响场景并纠正空元组，不重跑已完成三项，也不改生产源码/期限/额度。

隔离 r2 首次唯一新方法已在 `results/go-frequency-v46-r2-baseline-refusals-20261002-161205-316cbc5f` PASS：HOST exit0、无超时、0.625秒。四项完整达到末态断言：CREATE=0、GROUP_ADD=0、已知原库存关闭场景=4、实际模型 GET_SCAN 请求总数=3。原方法仍 FAIL；本结果不宣称七场景整体重测或实机建组。

ROOT `c323b3` 独立核 26 个私有输入/快照/当前字节、严格 stdout 数值 marker/Ran1 OK、四成员 ZIP 字节与 CRC。[r2 脱敏结果 ZIP](results/go-frequency-v46-r2-baseline-refusals-20261002-161205-316cbc5f/public-result.zip)：5591B，SHA-256 `07d4fff45be291c886426a30dca1ea910b797ebe47d6b30710c18338b93859c4`。test `f914bcd2…`/13226B、checker `d25651dd…`/19366B；旧 helper/model/17图、原期限/额度不变。

ROOT `df1efc` 核 26 个实际私有输入/复制/当前字节、原 stdout/stderr SHA 和两成员失败 ZIP 字节/CRC。

[原 HOST 失败 ZIP](results/go-frequency-v46-host-model-20261002-160557-b9335060/public-result.zip)：5036 B，SHA-256 `3bf95e8bec4317803e3d435435bc3db0ecf04a71181b1faace18cedb3587f414`。原失败保持，失败 raw 不进入公开 ZIP。

## 正式候选来源与下一步

Native `78e08414…`/87772 B、17map `09039294…`/3950 B、保留 F45 `377bc1bf…`/16874 B；新 preparer `0940e3d7…`/50706 B、HOST `b75640e0…`/30531 B。ROOT 与独立窄差异复审，PC 默认 `e446f2`、52 源/3 blob Python3.5 AST 和实际生成载荷 roundtrip `648329` 通过。正式候选前后仍使用原 35 源只读图，原 180/45/60/30/210 秒、generation12 和恢复逻辑不变。

只读实机前置、原三项有限已完成证据和 r2 四受影响完整拒绝满足本次窄修的入场检查，但不代表实机 GO 已通过。

唯一实际正式调用 `results/go-frequency-v46-20261002-161257-6114830f` 已终末 FAIL：HOST ADB0／remote1、无超时、15.547秒。首因在原 35 源 before-read 的 `BaselineCollector.collect`，为 `BaselineError: io_error`。writer 尚未构造、stage文件0、真实 GO 子入口未 fork、未请求或观察 RF 意图。96条已观察 collector 库存及9个 Proc generation 均闭合。最后保留的文件种类是 `/proc/[PID]/comm`，但旧入口未保留原 errno／完整请求路径，不能确定为 ENOENT 或进程竞争。

该失败的 after 平台和 pending 检查未完成；状态中的 pending 表示证明缺口，不是实测 marker 存在或资源泄漏。原 FAIL/raw 保留。ROOT `1bff92` 离线核52源／3blob／实际载荷／复制／exit／private回执及两成员ZIP；[正式失败 ZIP](results/go-frequency-v46-20261002-161257-6114830f/public-result.zip)，1695B，SHA-256 `bfcfeab171bbee5cbb03fe77cb63010b94fab87c01fb06decca9d2553490249a`。

仅因该异常，随后一次独立旧 v39-r2 只读 `results/client-readonly-baseline-v39-r2-20261002-161741-37708f22` PASS：0／0、无超时、12.063秒、完整2轮、两次 pending 缺席、已观察资源关闭。ROOT `3acd14` 核实际输入／raw／ZIP；完整基线按原 Actor.key 比较与试验前 scan v46 一致，未省略任何其他网络字段。它不回填此前失败的 after，不签正式 GO 恢复。[独立只读 ZIP](results/client-readonly-baseline-v39-r2-20261002-161741-37708f22/public-result.zip)，3569B，SHA-256 `fa54d1ba393b85a15b6fd3cdbd7833ffadefcb4edce17b91b7b5e9de6ae0b8e9`。

## v47 原异常只读诊断：当前通过，旧错误未复现

隔离 v47 只将原 35 源的 Baseline 一项换为私有原异常记录；采集算法、ENOENT 拒绝、原资源／未知状态／finally 和5／10／30／45秒均不变。请求路径／flags在原票据创建后、syscall前记录，原异常强引用及 traceback／errno／filename 只进入 private raw，不入公开字段或ZIP。没有跳过进程、主动扫描、Stage／F／Parent／RF或失败重试。

四来源冻结：Baseline `593f56fd…`／30215B、35map `212caa6f…`／8095B、leaf `81559642…`／13847B、HOST `c983c6c4…`／25943B。ROOT和独立SOURCE完整窄审；默认PC `a5297a` 与35源／leaf／载荷 Python3.5 AST和原字节 roundtrip `045f25` PASS，没有PC导入候选或操作设备。

[一键PC来源检查](HOST_MTA_READONLY_DIAGNOSTIC_V47_SOURCE_CHECK.cmd)仅调用该驱动默认SOURCE模式，不执行笔端候选、ADB、扫描或无线；新增CMD未另行重复运行已通过的检查。设备模式必须另给明确transport及已审完整驱动SHA，不能从此CMD自动启动。

唯一实际只读 `results/client-readonly-diagnostic-v47-20261002-162823-a51da60f` PASS：0／0、无超时、11.547秒、完整2轮。ROOT `2b3846` 离线核实际35源／leaf／载荷／原raw／公私回执／ZIP：420个 collector 原件和20个 Proc generation 闭合、17个 datagram；两次 pending 缺席、平台前后一致，完整当前基线与上一独立只读一致。原 owner／collector／open 异常均 None：旧错误没有复现，原因仍未证实，不自动重试同一正式候选。

[v47 脱敏只读 ZIP](results/client-readonly-diagnostic-v47-20261002-162823-a51da60f/public-result.zip)，四成员3911B，SHA-256 `0b9a2441bdba41f09e05e95af4caa1bf62141a4227c99d5ec8f26608d8367cf7`。私有 raw 含设备／网络标识符和路径，不公开分享。

下一隔离候选仅将相同私有异常诊断接入正式试验的 before／after，GO17／Native／F45、generation12、原时限／额度／恢复逻辑不变；尚未执行。typed IP/DHCP v43 的20源 hash/order/Python3.5 AST在 `29da2a` 通过，但仍有旧频道前置及generation20接线，尚无HOST／设备验收。State／文件中心、正式收发和小米15 Ultra真实双向仍待，不是仅剩人工测试，目标active。
