# GO 进程拒绝私有诊断 v60

## 最新终末：GO60 实机仍整体 FAIL；HOST61 实际原件独审已通过

ROOT 唯一 `1f7434` / session91404 → `508e30`，结果 `results/go-proc-diagnostic-v60-20261002-203634-4439fce8`：HOST0 / remote1、50.953 秒、无超时，wholeFAIL。首次 baseline15 的两条 SNAP 计时均完整，约4.284363 / 5.067999秒，第二轮结束 left5.645070；之后 `Store.reserve` 原10秒阶段经 `baseline_current → stable_snapshot → actors / file / _check` 命中 deadline。该轮 `PROC60=unavailable`，早先首次 `native_actor_unknown` 没有复现，不能宣称它已修复或原原因已确定。

RF intent=false、journal=None、`resource_pending=true`、whole / fullNativeRestore=false保持。ROOT `8fa6e8` 已核52实际来源 / 4415192 B载荷 / 六副本 / 原raw；840collector + 40Proc、34datagram、31writer + 2Python、6parentFD + 3childProc的已观察库存闭合，完整前后Snapshot.key相等、pending前后缺席。只签原件与这些已观察事实，不替未导出的子Native库存签完整恢复；GO60实际原件独审现已封口PASS，与ROOT核验一致；仅原件审计通过，整体FAIL / resource_pending=true / 完整Native恢复false不变。

私有childstderr1158 B SHA `7cd091db555322e32441530d1afd4f1ae83dde17c8adad98c4e36eaef62eb36e`；[GO60 两成员失败ZIP](results/go-proc-diagnostic-v60-20261002-203634-4439fce8/public-result.zip) 1926 B SHA `7c8176eecca2c7cea394e7187ca2d65eaf810121aea177f213b76a2e6b5d3a2c`。旧GO58和本轮原失败 / 源码 / raw保留，不重跑旧候选。下一只做源码优化方案评估，先审重复核验成本，不增加全部cap、不许自动试验或按未复现错误猜因。生产收发false、目标active，真实GO / typedIP-DHCP / State / 文件中心 / 小米15 Ultra双向仍有自主工作，尚非仅人工。

## HOST61 首次限定通过与 SOURCE 事实

ROOT `032c74` 唯一新 HOST61 方法首次 PASS：host0、0.875 秒、无超时，结果 `results/go-proc-diagnostic-v61-host-model-20261002-203439-5c4f8986`。实际 GO60 Loader / Entry / 中性 CLIENT Store / 绑定 ProcReader / Bootstrap 构造算法在明确 OS / FD / Proc / clock 模型下运行；七个独立域产生八次实际 Reader unknown → Native 原 `native_actor_unknown` 拒绝。六域保留首次原 observation / Reader，第二拒绝不覆盖；actual neutral CLEANUP 的末代 `match=0` 不代签首次原因或 GO 恢复。关闭结果未知仍保 pending / generation unknown + late，不清未知、不重试关闭。

新增纯格式化的全部 IO / clock / authenticate / owns_generation / history_closed mock 均实际调用数为零，外国对象 repr / str / bool / 字段 / pair 长度未调用；八 typed error/errno 和八坏形状仅为诊断否定数据。只抽取原 F 诊断尾部核私有 head1024 / aggregate16384 / 每次单 FD2 写出及写失败不替换 result1，没有执行 F.run / baseline / reserve / actors / pins / fork / RF / restore。until301 和 Native scope16 仅是 HOST 模型，不能当实机 active45 或 baseline15 性能证据。

ROOT `8a96e6` 与实际原件独审已核29实际私有快照、当前固定源、raw、公私投影与四成员 ZIP / CRC一致，SOURCE 独审亦已封口无具体阻断；只签此次模型专项与原件审计PASS。stdout213 B SHA `9f979131de2b3f31313397a4c96dcd7bdf7b0535b6a6e1add41f6ceaef5f358f`，stderr100 B SHA `a499c882c9bdcd655e9f95eb4d251d37727af59ff159f0472ceb68fefca36fbd`。[四成员模型结果 ZIP](results/go-proc-diagnostic-v61-host-model-20261002-203439-5c4f8986/public-result.zip) 7047 B SHA `875de4842da97fc2d706119bc13feac6eb948fa2349fbb8c43a04d6e8e27c1d4`。不签设备 / RF / 全部 Native 恢复或手机互通。

v60 五件生产来源及完整窄差异 / 17图 / 52源 Python3.5 AST / PC载荷已核，原 OR / short-circuit / 全部业务门 / 额度 / active45 / cleanup60 保持。随后唯一实机GO60已经终末FAIL，准确事实见顶部，HOST61模型和SOURCE通过不代签设备。GO58原整轮FAIL及未导出Native资源未知同样保留。以下为此前制作时点与证据，不改历史原件。

目标仍 active，生产收发关闭，真实手机已记为小米 15 Ultra，目前不需要手机操作。GO / typed IP-DHCP / State / 文件中心及真实手机原厂双向仍有自主工作，尚非仅人工验收。

## 依据与当前证据

[GO58 唯一实机结果](CURRENT_GO_BASELINE_BUDGET_V58_FINDING.md) 整体 FAIL：第二 snapshot 在 `_pins → _proc` 返回 `native_actor_unknown` 时仍剩约 6.482050 秒；这不是该阶段截止。原 F 未导出 ProcObservation 的具体拒绝原因，不能猜测 task、IO、资源历史或设备损坏。父端前后原厂/网络基线一致不替代子 Native 完整资源或互传成功证明。

GO58 的 ROOT `6675e7` 与独立离线原件审计均通过：源、副本、载荷、原始流与两成员脱敏 ZIP 一致；但这只签原件审计，整体 FAIL、`resource_pending=true`、完整 Native 恢复未验证的原结论保持。原日志不改、不重跑旧候选。

## 仅诊断的最小变更

Native 在原 `_proc` 条件判定失败后，best-effort 保留第一次的 `(实际 value, 原 Reader)` 强引用。原 OR 表达式、短路次序、采样、时钟、原件/闭合验证及 `native_actor_unknown` 拒绝不变。后续拒绝不会覆盖第一次；记录不授予网络或恢复权限。

F 新增纯格式化 `_proc_failure_text_v60(value, deployment)`，读取 exact 原类与直接保存的数据，输出安全原因、阶段、双轮次数、boot 相同与否及 Reader/末代 generation 的标志，不输出 PID、boot 内容、路径、设备名或地址。末代 `match=0` 可能来自退出清理，不能把 `latest_error` 当作首次拒绝原因。未知类型或形状固定 unavailable/other，不调用未知对象的 repr/str/bool，也不重读或调用 Reader 方法。

PROC 行限 512 字节 ASCII。既有私有诊断 head 由 512 调整到 1024 字节，因此 PRIMARY/RESTORE 两段各自可用空间相应减少；总量仍限 16384 字节、有效 UTF-8，并保持原单次 FD2 写出。没有新增 stdout、公开字段、FD 或原库存导出。

所有网络操作、恢复与截止逻辑仍来自 GO58 图：首次 baseline15、原一次 active45、cleanup60、target180、post-read30、HOST210。没有加入新的采样重试、fresh-single、A3 优化、扩 cap 或自动修复无线。

## 已冻结的生产源及 SOURCE 检查

- Native：`candidate/go-proc-diagnostic-v60/runtime/mta_go_native.py`，99087 B，SHA `221529ce74b1d6b5b08cd7cbab2fc232539d9848568852ef0534bddf37d83ae3`。
- F：`candidate/go-proc-diagnostic-v60/runtime/mta_go_executor.py`，25360 B，SHA `29fa5edba074be8fc87a50399ce24d4ee9cb5135e5ebbe41e8def9451ef723e0`。

ROOT `65b2ed` 核 Python3.5 AST、完整窄差异，并仅去除上述诊断节点后逐整个模块 AST 与原 Native56-r2 / F56 比较一致。原 `_proc` 条件、短路与其他方法正文保持；纯 helper 无源验证、IO、clock 或未知格式化调用。独立 SOURCE 阅读与 hash 核验无具体阻断。此检查没有导入或执行生产源，也没有设备操作。

追加 ROOT `0231c7`：完整读 17 源 map 与 preparer/HOST 窄差异，固定图相对 GO58 仅替换 Native/F 两项；52 个实际来源行的 hash/bytes 与 Python3.5 AST 均通过。PC 来源检查、4415192 B 零 token 完整载荷与 52 源 / 三 blob 往返通过；零 token SHA `0ea0de45f19d588beefe1871f6d3dbc5d659c1bbc708910a868e810b21f0fa6c`。没有 target 模块导入、ADB 或文件写入。

- 17 源 map：`host/go_proc_diagnostic_v60_source_manifest.json`，3956 B，SHA `c2be8155c68594d2baa863c5ff6a99b38f6e231c32eb79bb2f94aeac77a210cf`。
- Preparer：`candidate/go-proc-diagnostic-v60/runtime/mta_go_bootstrap_device.py`，50885 B，SHA `e6e3cfdec7ab7ca56b2cb9ab5cc1ebeb465d3b1d4608a7771a3a360d38b33cb8`。
- HOST：`host/go_proc_diagnostic_v60_p011.py`，34847 B，SHA `2963edbd18500d864436a4b2e4c966b1216d6b58e051a16a05c39dd247f737ec`。

[一键 PC 来源检查](HOST_MTA_GO_PROC_DIAGNOSTIC_V60_SOURCE_CHECK.cmd) 只走默认电脑来源检查，没有 ADB 或 RF。一键未点击；已有本轮完整 PC 检查，不为补日志重跑。

历史制作时点：当时完整绑定的独立 SOURCE 复审及新 v61 受影响模型专项尚在进行、专项未执行。此段原时点保留；最新专项结果见顶部，仍不把 SOURCE / PC / HOST 模型通过称为 P011 或手机互通通过。
