# ClientExecutor recovery budget v8 — SOURCE / HOST Fake only

## 独占来源与精确改动

- 原件：`candidate/client-init-nlink2/runtime/mta_client_executor.py`，SHA-256 `9cf0226e76254639c8fb7ab2638f6270ee0091b2485d49e00c0beff47d8f8602`；原件保留。
- 新副本：`candidate/client-recovery-budget-v8/runtime/mta_client_executor.py`，SHA-256 `1b2b07f45d3564b743dfa66921bf831962ec6c3754b25e35c384ab699de362a3`。
- 全文件逆向只有两处唯一替换后逐字节等于原件：`ClientExecutor.run` 的 finally `restore(timeout=20)` 改为 `60`；`ParentExecutor.finish` 的 `_finite(timeout, 0.1, 60)` 上限改为 `90`。
- `ParentExecutor.finish` 默认 `25` 不变；未来 host 显式 `90` 不在本次编辑范围。开始/RF journal/watchdog TTL 仍为 `20`，没有延长 RF 生存期。
- 固定 19 `MODULES`、source loader、Owner、original FD inventory/once-close、短步 wait/absence/EOF、raw drain、无 kill 路径、public schema 与成功门禁均未改。没有修改 host 或外层 transport `150`。

## 唯一新增专项

`tests/test_client_executor_recovery_budget_v8.py`，SHA-256 `52bb9e0eb99fc3bb32eefbd36b3eaaf8c4358c394549b34ac6dbb1ecfbffebfa`，3 个方法：

1. whole-file 精确逆向与旧 SHA、class method AST 只有 `run`/`finish` 两项变化、固定 19 模块及 Python 3.5 AST；旧 fixture 的 module globals 不变。
2. 使用原 `test_client_executor` 的 FakeIo/fixture，仅克隆 deployment 函数 globals 绑定 exact 新 F 类。候选 `ClientExecutor.run(ttl=20)` 在原 assemble 返回的同一 lease 上调用 `start(20)` 与 `restore(60)`，保留 TTL deadline。Fake lease 发行真实 core `FinishReceipt` 类型及 Store/lease 同对象绑定；ticket auth、bridge、provider、restored 四个门禁逐一失败时仍 pending，只有全部门禁满足时 Fake 结果 done。所有发送/接收/关联/IP/phone 业务标记仍 false。
3. 候选 `ParentExecutor.finish(timeout=90)` over FakeProcess 接受新上限，仍以不大于 `0.05` 的短步调用原 wait 并要求 absence、原管道关闭和两 EOF；拒绝 `90.0001`、`91`、bool、NaN、正负 Infinity。未有 child 时 valid `90` 仍 `wait_unknown` / pending，绝不 done。

专项设有实际 `_LinuxIo`、socket、Popen、CDLL、kill 禁用 tripwire。这里只验证真实候选 Python 方法在合成输入上的行为；未验证真实 P011 Store/Owner/Provider、收据发行、资源关闭、等待/缺席或恢复。

唯一执行证据（工具 `cc806a`，host exit `0`）：

```text
python -B -m unittest discover -s tests -p test_client_executor_recovery_budget_v8.py -v
test_child_restore60_same_lease_ttl20_and_real_receipt_gates ... ok
test_exact_two_replacements_other_functions_and_python35 ... ok
test_parent_finish90_bounded_wait_invalid_values_and_no_child_pending ... ok
Ran 3 tests in 0.046s
OK
```

本专项无首 FAIL/ERROR；没有重复已通过 suite/sourcecheck 或执行 ADB、设备、网络、WSL、RF。初始同名 `test_client_recovery_budget_v8.py` 写入碰撞已发现并与协议作者确认，该路径现由协议侧独占；碰撞时未运行 F 测试，彼时读取的 `a319...` 不属于本次 F test pin，也不作为本次签审证据。协议侧三源和其测试现均未再改动。

## 准入边界

只是一份尚待 ROOT 全文审核与组合 source graph 的预算候选，不是新 tested release、实机恢复 PASS 或互传完成。本测试不证明 default/production deadline 通过；扩大恢复等待预算不代替真实 finish receipt、持久 CAS、同一 lease/Owner/F 和完整关闭证据。运行源码、历史 actual FAIL/raw、既有包保持原样。
