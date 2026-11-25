# Startup 原边界计时：隔离图生成准备

本目录目前只有生成计划，不是已生成或已测试运行图。新 helper 为 `host/generate_formal_receive_startup_boundary_timing_v1.py`，从冻结 `generate_formal_receive_startup_alias_clock_v2.py`（25645 B / a16f2416f54d477128c541c54a5e9ab569a33567485b1e828a5f0d45f3b3d669）另存。旧 helper、alias 图、失败记录与原厂文件保持不变。

唯一非机械差分来自 `candidate/receive-startup-boundary-timing-v1/runtime/mta_client_receive_factory.py`（89974 B / b4803dea9eeb9421d773a991e1fc7315dfd7990c42ae629879bfa06b912bdc81）。其 `exactsource-delta.json`（3209 B / 35981ad265cf131ade91ea6fdf422e347b11a6190ad6b4f450694c8a9853b565）顶层严格为 schema/evidence/source/candidate/replacements 五键，含五块 count=1 差分。正向和逆序逆向必须逐字节回到 actual packaged alias Factory（89379 B / 4a1043e3eb3fbcc3e80927b64640d80c350c38d4bd2c6ecf73eeff68bf15c35d）。没有沿用旧 alias spec 的十一键形状或执行声明。

预定固定运行根为 `/tmp/p011-mta-receive-startup-boundary-timing-v1`，physical 根为 `/var/volatile/tmp/p011-mta-receive-startup-boundary-timing-v1`。七个 runtime 源从 actual alias packaged 图机械派生；三项清单/定义输出为 `host/formal_receive_startup_boundary_timing_v1_definition_manifest.json`、`host/formal_receive_startup_boundary_timing_v1_private_source_manifest.json`、`host/formal_receive_startup_boundary_timing_v1_definitions.py`。共十个 fresh 输出，不覆盖旧路径。

生成器保留原 FC 模板的纯 literal 提取，不执行其 main。运行源是 alias→timing root/pin 变化；模板两 header 根则明确 FC→timing。生成的新 definitions 先调用原 alias verifier（其继续保留 FC verifier），再验证本次五块正逆差分与七源机械闭包；ORIGIN_SOURCE_PINS 保留所有旧来源、旧清单、新 spec/Factory 与冻结 helper 来源。private35 不加入 service Owner；普通35＋helper3＋private35＋WPA＋monitor仍为75，FC9独立113690 B。实际 payload bytes 必须从输出/原源逐份读取、校验并累计，不使用预计数字或仅投影标签。

原 4 MiB/FC131072、Startup10秒、600+60、Trial/协议/身份/关闭与所有原期限保持。计时标量是最近原边界 DATA，不是纯函数耗时、准入或闭合证据。没有 RF、手机、HTTP、UI、凭据或设备动作。

主代理审读后可选择以下 PC-only 入口；本次作者未执行任一入口、AST、测试或设备：

```
python -I -B host/generate_formal_receive_startup_boundary_timing_v1.py
python -I -B host/generate_formal_receive_startup_boundary_timing_v1.py --write
```

默认仅计算/检查，无写入；显式 `--write` 仅在十个固定输出均不存在时 fresh 写入，并保留 private-inputs、result.json 和 SOURCE_RESULTS.zip。生成后的 Runner/Factory/definitions 精确 pins 及实际75字节数，以原报告为准；目前尚无这些生成物，也没有 SOURCE/运行/性能 PASS。

## 2026年10月5日 09时50分 实际生成与运行状态补充

以上“目前只有计划／尚未”保留为作者提交时历史。ROOT已全文审读并唯一执行新helper的显式fresh生成，SOURCE通过：实际75角色4164961 B／4194304 B、余29343 B，FC9独立113690 B／131072 B；实际definitions、清单与七源pins已留存。一个受影响HOST合同及新根core真实暂存／启动／关闭通过，2315登记FD闭合。

交互v1因遗漏该新核心预置而在Owner创建前拒绝，原FAIL保留；预置后的独立v2仍在原10秒prepare超时0.304747秒，但取得实际五边界、四粗段。没有READY／候选UI／截图／FC／运行凭据／RF／手机文件互通。本图不是已验收release，也不是性能优化PASS；边界是最近原时钟而非精确函数wall-time，原文件／身份／FD／期限门未放宽。详见[当前状态](../../CURRENT_STATUS.md)和[脱敏实测摘要](../../results/receive-startup-boundary-timing-v1-summary-20261005-0950/public-result.zip)，旧失败与原始私有流保持。
