# 隔离 v3：保留真实 IPv6 route 重复行

仅一个实际变量：`/proc/net/ipv6_route` 允许重复，原 tuple 数量/顺序完整保留。
不是去重、不是采样、不是伪造网络恢复。原源/日志/已冻结入口均不修改。

ROOT唯一只读诊断 `f96f7a`，日志 `MtaP011-ClientBaselineDiagnostic-20261001-160630-447c18cf`：
实际越过 actor_image，Baseline 以 ipv6_format 拒绝，round 0。
ROOT `32b83f` 格式/name/宽度合法；`5f7e3d` route 4 行、unique 3、有一条重复2次；
if_inet6 1 行/unique 1。实际 route bytes SHA
`154240246c2c564b90c3f46d749d8e365a19c1dbeb9504f3e6ab3ef435a9db03`。
旧诊断结果保留。这不证明旧 r2 actor_changed 的根因；调度状态静态风险仍未实际归因。
独立 `1b73e5`、`45675b`、`0654a8` 另核同 raw、来源与重复行直接拒绝条件，无设备重跑。

## 精确 SOURCE 差异

- 新 `candidate/client-baseline-v3/runtime/mta_client_baseline.py` 从 ce8 原文复制。
  仅 `_ipv6` 唯一性门禁对固定 `/proc/net/ipv6_route` 路径例外；ASCII/width/name/
  MAX_ROWS/原 read/close 与返回 rows 全部保留。addresses/其他路径仍拒重复。
- 新 core 从 ec2 原文复制。`_rows` 默认 `_unique=True`，Snapshot 的 ipv6_routes
  唯一调用明确 `_unique=False`；其余字段仍原验证。tuple/key/codec/CAS multiplicity保留。
- 新 host 从 fc022 r2 逐字复制，仅两新 copy pin/source location、候选 kind 和日志前缀。
  保留 nlink2 F9cf/Owner219 和另外15份原源码，19模块名/typed imports一致。
- Baseline._actor_image/collect、host整个TARGET/same、core._same_journal/_ipv4/key原字节未改。
  无Actor状态归一化；原rawtaskstate和持久CAS全字段敏感性不减。
- 超时、platform/旧pending门禁、staging/单次RF-init/正常恢复流程与原r2完全一致，未开放互传。

这是功能候选，不是纯只读驱动。默认source-check不设备；ROOT审核后显式execute-reviewed
可能真实staging/RF-init；不得把源码/Fake结果写成P011通过。没有本作者设备/WSL/socket/RF，
没有checkpoint、旧pending清理、自动恢复或重试。旧actual FAIL和元件SOURCE不改。

## 新专项

唯一新专项工具 `c7b446`：
`python -B -m unittest discover -s tests -p test_client_baseline_v3.py -v`，
10方法 / unittest 0.857s / OK / host exit0（工具wall1.306s）。首批无FAIL/ERROR，无重跑。
证明合成routes重复数/顺序、key multiplicity、codec完整roundtrip/CAS原state敏感，
地址/其他路径重复及格式/宽度/name/预算仍拒；两copy精确逆向回原全字节/pin，
Actor动态函数/整个TARGET原AST或字节一致，新的PC19图完整pin及Python3.5 AST/预算。
全部为纯记录/Fake读取/PC sourcebuild，不是P011/实际网络/正常恢复验收。
没有重跑任何旧方法或全项目测试。本作者到此停止源写入，等ROOT复审/单次实机。

## 固定源 pins

- Baseline：`ed41639b1f74c096132a04f9a9a137f2ccc48ddc274c4d3786fe43d718d6c51a`。
- core：`f5ebf037743f9fc910a7107425119576acdea649e16cf9e0660c0e9e257a607e`。
- host：`518617174571a7f9b8b295083054a44212d67cac0e173340fa4bb4e47b647122`。
