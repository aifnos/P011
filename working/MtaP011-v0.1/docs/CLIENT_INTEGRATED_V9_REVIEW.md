# CLIENT integrated v9 — 隔离 SOURCE / HOST 候选

## 固定来源与范围

仅新增 Provider、host、新专项及本短文；没有修改旧 runtime、旧 host、历史日志或 LATEST。

- 原 host：`host/client_init_baseline_v3_p011.py`，SHA `518617174571a7f9b8b295083054a44212d67cac0e173340fa4bb4e47b647122`。
- Provider 复制源：恢复 v8 `ae4bb7fa9dc9d030a35388f74325c0d2356b48bd62af344221cd26a29ebbf2ee`。
- 唯一替换：完整 `_caps_core` 逐字取自 caps-v7 Provider `a49ce9bc6766d6b0182b45c833a3edaad307e4c27c45069871042ae49282f7c6`；其余所有字节仍等于恢复 v8。
- 新 Provider：`candidate/client-integrated-v9/runtime/mta_client_linux_provider.py`，SHA `8bb5dfae34ab7cc4db772957781c8c9385bf6285250137351bac70de685798d6`。
- 新 host：`host/client_init_integrated_v9_p011.py`，SHA `302cfa0d0ef395f45786da5e3c04ef6c4701d78b1aae8d9fd817d0e894f87161`。

## 固定 19 源图与预算

只为 7 个模块指定候选位置，其余 12 个仍从固定 BASE/runtime 读原 pin；不复制全部 19 源。

| 模块 | 候选 pin |
| --- | --- |
| core / caps-v7 | `bb22e43ec191c04624e009539f954a9bcbb7b98520fb32adf6fd4f18f4e8139a` |
| baseline / readparts-v6 | `1df29147a9cface972c9a2f486fee45c0f33d7979c6ad49dd02cdc330fe9dcc1` |
| pending / recovery-v8 | `cfba740700268d5998eb3a91bf7cdc34d893fa8f0083377d716ea98950c3f5af` |
| Store / recovery-v8 | `2c1bcd60013e416fe4d0ef961ceef3bc700ceae6bc40c4c079bab0a663b411cb` |
| F / recovery-v8 | `1b2b07f45d3564b743dfa66921bf831962ec6c3754b25e35c384ab699de362a3` |
| Owner / nlink2 | `219156a42a6598fb3e6669f191c269bfe3ac75da8f2f95190fb23b3867794b76` |
| Provider / merged-v9 | `8bb5dfae34ab7cc4db772957781c8c9385bf6285250137351bac70de685798d6` |

host 只改变固定 pin/位置、v9 kind/logprefix、入口预算 120→165、communicate 150→195、显式 Parent.finish 45→90。
最后一次 `pending_absent()` 之后、创建 Parent/start 之前严格要求 `end - now >= 125`；不足报固定 `budget_before_rf`，不设置 `rf_requested`，不创建 Parent。
时间预算是有限等待/准入，不是抢占 OS IO 的绝对墙钟承诺；RF/start/watchdog TTL20 不变。

host `same` 改为完整 Snapshot.key 相同且双方全部 stock Actor.live；Actor.key 的 PID/start/exe/argv/TID/start 身份没有削减，raw task state 仍完整 private projection。
R/S 调度态不再当 fresh 身份，dead/key 变化仍拒绝；持久 core/codec/Store CAS 完整 raw 字段等式未改。
旧 pending 不清、不恢复、不重试；default source-only、exact reviewed driver SHA、staging EXCL、原 raw/退出/恢复层分离、公有业务能力关闭、无 timeout kill 路径保持。

## 首判与实际 HOST 批次

专项文件：`tests/test_client_integrated_v9_host.py`，SHA `1242e377ac2938d2da3ee8fefda545fddc0289446839d35dd09df13af542617a`。
首工具 `c50648`：模块加载 ERROR（caps-v7 core 依赖 `mta_ip` 不在新 test 的 HOST 搜索路径），host exit1，loader 计数1，0 个实际测试方法执行。
仅在新 test 增加 BASE/runtime 的纯模块搜索路径；Provider/host 不变，没有把首判抹去。
随后工具 `a677a7`：`py -B -m unittest discover -s tests -p test_client_integrated_v9_host.py -v`，9 个新方法，0.814s，OK，host exit0，wall1.6322331s。
没有重复任何此前通过方法或旧 suite。

新方法核 Provider 单函数/全文件逆向、host 16 处精确反向回 518 原字节、固定19源实际 PC 读取和生成的 target/Python3.5 AST。
实际执行新 TARGET over 明确合成 FakeOS/Provider/Parent，复用旧 fixture 的代码但克隆 globals 绑定新 driver、旧 globals 不改；125 以下拒绝、125 恰好与充足余量 Fake 通过。
独立用真实 core.Actor.key/live 校验 R→S、dead、TID/start/exe/argv 变化；HostAdbCall 的候选方法 over FakeProcess 核195和 timeout once/unknown/no-kill。
Fake 时长/内核/收据/关闭不当实机；源图测试只是 PC 文件读取/编译，无 ADB、设备 staging、socket、WSL 或 RF。

## 剩余准入

实际 execute-reviewed 会在门禁通过后部署并请求 CLIENT RF-init，不能称只读；本轮没有执行它。
没有 actual CLIENT init、正常恢复、手机关联、DHCP/IP、数据传输或互传验收，不开放 send/receive/production。
ROOT 全文审查、固定新身份并决定唯一实机测试；不制作 checkpoint、不改历史 FAIL 或原候选。
