# 首 baseline 固定只读诊断

这是独立诊断入口，不是 CLIENT/RF 修正版。旧 r2 的首次实际结果
`MtaP011-ClientInitNlink2-20261001-152955-73b10d31` 保留：canonical Python
完整读取/关闭后，首 baseline 以 `actor_changed` 拒绝，零 staging/RF。
旧异常在 Baseline.collect 末尾折叠，尚不能据此认定是 task R/S 改变。

## 固定源码与机械差异

- 参考 host：`client_init_nlink2_p011.py`，SHA `fc0221b52c001d4bdb3e3976046f576c01577668b0b768e0be31ad41e36054cc`。
- 仍为 r2 的19源码图：F `9cf0226e…`、Owner `219156a4…`，其余17及原STATUS来源不变。
- 原 Baseline `ce8fe17b60964cf9b421296eef033d1dde19f8a4118de12d7f3922133ee13f08` 必须先完整验 pin。
- 只在新私有内存副本的四个原 `actor_changed` 真分支登记固定 site 与原比较引用。
  原谓词、失败类型及先后顺序不变；每个替换精确一次，逆向能逐字恢复原源；派生 SHA 独立报告。
- 四个 site：`actor_image`、`self_round`、`observation_boot`、`self_final`。
  未触发仍 `not_recorded`。`snapshot_changed` 的 raw tasks 比较没有修改。
- core `_same_journal` 完整字段/CAS 相等完全不变，不把存储完整性偷换为 Actor identity。

## 唯一实际调用范围

默认只 PC source-check。只有 ROOT 审阅后显式 `--execute-readonly --expected-driver-sha256 SHA`
才走固定 ADB：platform/旧 pending 只读门禁、canonical Python 两次真实 Proc 观测及完整 ELF
读取/原关闭库存、pure assemble、executor identity、一次首 snapshot，然后立即结束。
没有目标 mkdir/staging/Store.acquire/锁/Parent/F/controller/接口增删/RF/信号；不执行旧 START。
源图虽含现有完整实现，目标 body 不调用上述动作。旧 pending 不删除或接管。

## 诊断与关闭事实

私有保存 exact collector 的 observations/raw/rounds/binaries、四分支当时引用、原 tickets、
当前 ProcReader 原 FD 库存及实际 EBADF 读回、STATUS 的 source/file/Proc/socket/rights 库存。
固定字段投影不调用 owner repr，也不再打开、重关未知 FD 或补造关闭票据。
`comm_read_count` 从真实 `_raw` 固定路径记录计数；netlink/STATUS 各用实际收包库存计数。
Proc per-call `file_count/closed_count` 与当前 retained 原 FD 分列，不称整个进程全部 FD 已关闭。
Provider 失败 row 的 `unknown=True` 原样保留。公开 `resource_pending=True` 也可能是失败观察
未知，而非已证明有一个实际未关 FD；`collector_inventory_closed` 另列已登记库存的闭合事实。
`diagnostic_complete` 只表示诊断/该库存采集完成，允许被诊断的 baseline 仍 FAIL，绝不是
snapshot PASS、原厂恢复、CLIENT 初始化、互传或手机验收。

原生/WPA/ELF 不序列化；Python 仅 digest/长度/metadata。已核旧 `_raw` 中 binary file 和
actor_image 也只有 digest/metadata。非 binary/proc/netlink bytes 用可逆 base64 私有保留。
target source 限4MiB、单行2048B；RESULT 限12MiB，为16MiB raw含完整PTY源码echo留余量。
超预算固定拒绝，不截断伪造完整 raw；原 retained 引用仍在本次私有进程中。
原 stdout/stderr/host exit/remote exit 分开保留；派生解析只剥离逐字匹配这次传入的完整echo，
随后仅允许 RESULT/OK/EXIT 三帧；自由输出、非零exit、非空stderr严格失败。
公开 ZIP 只有 result/README，无 raw、Actor、PID、路径、FD、网络标识或 traceback。

## HOST 证据

唯一首批新专项工具 `a2a296`：
`python -B -m unittest discover -s tests -p test_client_baseline_diagnostic_p011.py -v`，
15 方法，unittest 0.452s / OK，host exit 0（工具 wall 0.926s）。没有首批失败或重跑。
包括实际 PC 固定19图/sourcebuild、Python3.5 AST/行与总量预算、4site机械逆向、
真实 Baseline._actor_image/collect 方法 overFake 仍原样拒绝、读取scope tripwire、
旧 marker 阻断、失败观察/原关闭库存保留、base64可逆/ELF摘要、严格PTY帧与公开保密。
只是 HOST/Fake 与 PC 源图证据，不是实际 Proc/STATUS/socket/网络/设备证明。
没有重跑既有 r1/r2/整项目专项，没有本作者设备执行；ROOT独立实际结果须另行记录。
