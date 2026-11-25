# 首次基线阶段预算候选 v58

互传目标仍 active；生产收发关闭，真实手机已记为小米 15 Ultra，目前不需要手机操作。本文件区分源码、HOST 模型和 P011 实测，不把任一层检查通过称作互通完成。

## GO58 唯一实机终末 FAIL：原进程观测拒绝，非阶段超时

ROOT `054ff7` / session41741 → `fe8dca` 唯一实机结果 `results/go-baseline-budget-v58-20261002-195427-311be10d`：HOST0 / remote1、39.312秒、无超时，整轮FAIL。第一snapshot完整：boot0.01021315 / actors2.891903 / pins0.8650503 / rest0.485308，合计约4.252474秒；第二snapshot仅partial：boot0.01285511 / actors3.476561 / pins~0.773477 / rest缺席。第二轮 `_pins→_proc` 拒绝 `native_actor_unknown`，仍剩6.482050秒，不是deadline。部分pins量不能当完整耗时，原F没有导出具体Proc拒绝子条件，不能猜IO、task、history_closed或设备损坏。

实际RF intent=false、journal=None，原restore保 `reservation_or_publication_pending`；whole / full native restore=false、resource_pending=true保持。ROOT `6675e7` 已核52实际源 / 4407656 B载荷 / 6副本 / raw，842collector + 40Proc、34datagram、31writer + 2Python、6parentFD + 3childProc已观察库存闭合，完整前后Snapshot.key相等、pending前后缺席。这些父端和readonly事实不代签未导出的Native库存或整轮恢复；GO58实际原件独审已核与ROOT一致，仅原件审计PASS，整轮FAIL与未导出的Native资源未知保持。

[GO58 实机失败脱敏ZIP](results/go-baseline-budget-v58-20261002-195427-311be10d/public-result.zip) 两成员1904 B SHA `3a28ab6612f79af493a25554129e28d5b72e51d7c481ebfe424011e24e253de2`。私有childstderr实际974 B SHA `bb00b5209d2594b40654d3ef9b5bac0ad65a87e37ecf0258dc7b27dd17abd3f7`，原trace、计时和失败保持，不回写为成功。下一仅私有Proc诊断方案设计，不改原cap或执行新trial；目标active、生产收发false、尚非仅人工。

## HOST59 首次期限边界专项 PASS：仅模型层，实际原件独审已核

ROOT `6c4bdc` 唯一首测通过：0.937 秒、无超时，结果 `results/go-baseline-bound-v59-host-model-20261002-195250-e0f9b42e`。唯一方法 `GoBaselineBoundV59Tests.test_stage15_original_until_clamp_refusals_and_clock_without_radio` 在9个独立 HOST 构造域核4次实际阶段发行、7次拒绝：正常 clock1 得16，clock299夹原301；原期到期、caller stop、非法0 / 21 / bool、已发行16的 `_check` 到期和时钟回退均按原门拒绝。原 Entry 初始局部期限4保持，没有手动续期或改成11。`until301` 是固定 HOST 模型，不是实机的一次45秒活动期。

实际 GO58 Loader / F Entry / Bootstrap 构造与 `_stage`、Native `_begin` / `_check` 算法运行，但 Linux / Proc / FD / clock 是明确模型；没有 baseline snapshot、run、reserve、actors / pins、`_record` / FD factory、fork、RF 或 restore。旧 Bootstrap 仅用于 AST 单变量比较，未运行旧图 / 旧方法；只证明首 baseline10→15及其余 class 正文保持，不证明真实基线完成、性能、late `_begin` 或完整恢复。现有 scope+5 派生局部 close cap 数值随 scope 变化，不宣称所有局部 cap 数字不变或签库存闭合。

ROOT `dd6167` 与实际原件独审均已核28个私有输入快照与当前固定字节、原raw、公私字段及四成员 ZIP 字节 / CRC；仅HOST59这项模型专项与原件审计PASS，不签GO58实机通过。原stdout123 B SHA `0ff34f74ffd750626b970d5c87f9788543e9d28b482e728a92b2e5f9d99621f3`；原stderr100 B SHA `49c96d044bc42c3781628da9c34f5e7f53d9a6eb69b67d518e99630f43bf48ac`。[HOST59 脱敏结果 ZIP](results/go-baseline-bound-v59-host-model-20261002-195250-e0f9b42e/public-result.zip) 四成员6103 B，SHA `0b3a6a11cd4c4e193a5cff48451240accb5e7393bd2bcab23a28f48a5f8036e1`。ROOT此前审计 `580d42` 用LF-only断言而停止，实际stdout为CRLF；只修审计匹配为原wrapper的严格CR?LF，没有改原件或重跑方法。

[一键 HOST 模型检查](HOST_MTA_GO_BASELINE_BOUND_V59_MODEL_CHECK.cmd) 只运行电脑上的固定新方法，不做ADB、设备、服务或RF；一键尚未点击。已有通过原回执，不为补日志重复测试。v58唯一实机已终末FAIL，见上方原结果，不能由HOST59组件PASS补签设备成功。生产收发false、完整目标active，尚非仅人工；原56-r2 / GO58整体FAIL与历史原件保留。

## 依据与最小改动

[v56-r2 唯一实测](CURRENT_GO_OWNER_COALESCE_V56_FINDING.md) 仍整体 FAIL：第一轮完整约 4.306 秒，第二轮在 `_stock_status → _unix → _record → _check` 到原十秒截止，Unix socket factory 尚未调用，后续尾段未完成。失败时 -22ms 不是完成余下检查所需时间。

10 秒是项目自设的阶段预算，不是用户、内核或互传协议的硬上限。v58 只将首次 `GoBootstrap.run` 的 `observe_baseline(self._stage(10))` 改为 `_stage(15)`；原 Native56-r2、F56、Store56 均不改。不混入新 guard 或历史扫描优化，也不声称性能已通过。

| 边界 | v58 |
| --- | --- |
| 首次完整双轮基线 | 最多 15 秒，仍夹原绝对 `until` |
| 原活动会话 | 一次 45 秒，不在新阶段重新发放 |
| 原恢复 | 一次 60 秒，原取消、失败和 pending 逻辑保持 |
| 父目标 / 后置只读 / HOST | 180 / 30 / 210 秒，保持 |

原 `_stage` 仍通过 `min(self.until, now + seconds)` 截取剩余时间；所有后续阶段保持原实现。已存在的 Native 文件票据局部 close-only 上限是 `_scope + 5`，因此首次阶段对应派生数值会随之增加五秒；这不是新网络活动权限、重发 cleanup 或库存闭合缓存。

## 冻结身份与源码检查

- Bootstrap：`candidate/go-baseline-budget-v58/runtime/mta_go_bootstrap.py`，17396 B，SHA `de98101c6c56661b9557cf2f857645ff5ecefa3d7663e58c4ebe1fd16187035d`。
- 17 源 map：`host/go_baseline_budget_v58_source_manifest.json`，3957 B，SHA `0c987d6e667a0d4adce867b121493436f9bf2ba11380acc97e11efbf320a30a0`。
- Preparer：`candidate/go-baseline-budget-v58/runtime/mta_go_bootstrap_device.py`，50885 B，SHA `baceb5716d9062530fd8f1610e95e395711ec6f56149d0bfd8660163c941eab8`。
- HOST：`host/go_baseline_budget_v58_p011.py`，34810 B，SHA `44424b6b04aa97832e8dd494d2a4602756fc6d2c0acd0e18cb85545fbafd40e5`。

ROOT `df7d92` 完整读四件窄 diff、17 图仅 Bootstrap 一行变更、52 实际源的 hash/bytes 与 Python3.5 AST 均通过。把新 Bootstrap 首次 15 归回 10、忽略顶部说明后，全部 AST 正文与原 33r5 一致；原件 hashes 保持。此检查没有导入或执行业务模块，没有 ADB。

此前SOURCE制作时点：[一键 PC 来源检查](HOST_MTA_GO_BASELINE_BUDGET_V58_SOURCE_CHECK.cmd) 只运行默认 SOURCE 检查，不启动学习笔候选；新命令尚未点击。当时受影响的 15 秒夹原期限、到期、用户取消、非法值和时钟回退专项正在制作，尚无其 PASS 或 v58 实机结果；当前专项与设备终末状态见本文件最新顶段，历史原判保留。

追加 SOURCE 独审已核四件完整窄 diff / 全部 pins / 52 源 / 同宽 markers，无具体阻断。ROOT `1a5264` 默认 PC 来源检查通过；`10acd6` 核完整 4407656 B 零 token 载荷、三 blob 往返及 Python3.5 AST 通过，零 token SHA `2ee63cf491f0f207907b19f11723ee2dad8e39d8f7f7bedbc0bceb993143e216`。前一 PC 载荷审计 `a8e84d` 用错本地字典键 `READONLY_SOURCES` 而停止，正确原键为 `SOURCES`；修正的是审计查询，不是生产代码或期限。该次未做设备或目标业务调用，保留前次工具失败记录。

## 后续实际成本和安全门

首次 15 秒通过不保证下一阶段或整个 45 秒流程通过。原 `Store.reserve` 在自己的十秒 scope 内通过 `baseline_current` 再做完整双轮；watchdog `prepare_child` 和 `observe_channel` 也有相同全基线复核。它们仍须按真实 phase / trace 判断，不自动扩大所有期限，也不把某次基线保留成缓存授权。

实际部署仍要求精确审核 HOST SHA、当前独立 ADB transport 和完整 before / after，只创建新的 EXCL 候选。原厂程序、启动项、无线固件 / NV、系统分区及旧 pending 不修改。GO / typed IP-DHCP / State / 文件中心及小米 15 Ultra 原厂双向仍有自主工作，尚非仅剩人工验收。
