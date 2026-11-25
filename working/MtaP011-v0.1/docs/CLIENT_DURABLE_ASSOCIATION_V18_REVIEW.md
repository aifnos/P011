# v18 durable CLIENT association — SOURCE / HOST Fake only

状态：隔离三组件候选，等待 ROOT 与独立 SOURCE 审核。未部署、未运行 P011、未运行手机；不是完整 v18 图、AssociationProof、DHCP/IP/endpoint 或收发能力。

## 来源与 schema

- core 基点 `candidate/client-caps-v7/runtime/mta_p2p_client_init.py`：`bb22e43ec191c04624e009539f954a9bcbb7b98520fb32adf6fd4f18f4e8139a`。
- codec 基点 `runtime/mta_client_journal_codec.py`：`17d362826a90da7fe9d77a82495a34bbc56b4c67aaca608aa5565ee1d3369f73`。
- Store 基点 `candidate/client-recovery-budget-v8/runtime/mta_client_store.py`：`2c1bcd60013e416fe4d0ef961ceef3bc700ceae6bc40c4c079bab0a663b411cb`。
- 新 envelope：`VERSION=5` / `KIND=p2p_client_association` / `MARKER=p011-client-durable-association-v18-1`；严格拒绝旧 v4，不迁移、接管或重写历史来源。
- `ClientAssociationRecord(phase, binding, executor, local_mac=None, bssid=None, frequency=None, observed_digest=None)`；phase 为 intent / confirmed / invalidated。`binding` 返回新 dict 副本，内部保存不可变 primitives；`.invalidated()` 保留全部原事实，已失效则返回同一对象。
- binding 恰九字段，与冻结 ControlBinding primitive schema 相同；operation_id 是本地操作 id，正则 `^[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z`。不导入后序 frame/protocol，不存 SSID、PSK、事件文本、网络配置或 shell 字段。
- executor 恰 core.Actor 且 recorded tasks 全 live；关联 key 包含完整 raw task 状态，不只 Actor.key。记录构造、字节 digest、live 字段和元数据相等都不是实际 OS / BLE 来源认证。
- intent 全部 MAC / frequency / digest 为 None；confirmed 必须两个实际来源待认证的非零单播 MAC6、合法 2.4GHz 频率（2412..2472 步进5或2484）及 lowercase SHA64。invalidated 仅保留完整 intent 或 confirmed 的事实形状，不填补 MAC、不猜 BSSID/GO/应用 endpoint。

## 主 journal 与实际 Store 发布

- Journal 新增 `association=None`。非 None 只可存在于 client_init_ready / cleanup_intent / cleanup_verified / reconciled；其余 stage 不可携带。cleanup / reconciled 必须已 invalidated；candidate 与 Journal.identity 一致，原 boot / deadline / Origin / children 仍由原完整 Journal 字段约束。
- Store 保存原 run_token，校验 binding.run_token；新增关联须与原 Pending 已发行 owner 的 Actor.key 相同、双方 recorded live。该 owner 来自原 Pending reader 的严格 typed / two-pass / same-boot / 完整 FD 闭合检查；不新增 OS 读取、不把 key 相等宣称实际授权。
- `Store.commit(exact_locks, current.replace(association=...))` 保持完整 canonical CAS / rename / fsync / readback。只有 ready 同主 stage 允许 None→intent→confirmed→invalidated 或 intent→invalidated；同 phase 只能完整相同，不能丢记录、重定点、重确认或变更 executor/rawtasks/binding/MAC/frequency/digest。
- 同主 stage 的其余全字段通过原 `_same_journal` 比较，包括原 baseline/child rawtasks；stage 图、原 immutable deadline、Origin/child 持久身份不放宽。
- intent / confirmed 新写入必须未过原 RF deadline；失效撤权与 cleanup 可过 TTL，但只能用原当前锁、fresh current、完整 CAS 和已有有界恢复流程，不能续期或开无线。
- core 基础 restore 在唯一 cleanup_intent 保存处显式 `.invalidated()`。原 Linux Provider/F 的 override 下一 v19 才接线，当前不声称旧 override 已可处理此 schema。
- 原 `_publish` / `_read_exact` / FILES epoch / pending / Store 60s 恢复分层、三次 fresh restore、终末 CAS / 单次 marker unlink / device-last inventory 完全保留。默认 producers 仍缺失、收发门禁仍 False。
- codec 保留 MAX_BYTES=131072 / MAX_NODES=8192 / MAX_DEPTH=24 / dict最多16；Journal12、association7、binding9，不扩大任何预算。MAC 在 private canonical JSON 内严格 lowercase hex，原 rawtasks 全量编码。

## 本轮实际 HOST 证据（历史判定不改）

- 首批命令：`python -B -m unittest discover -s tests -p test_client_durable_association_v18.py -v`。
- 工具 `a098a9`：16 新方法，14 PASS / 2 FAIL / 0 ERROR，unittest 3.735s，host exit1。首先使用新 core/codec/Store，但组合 fixture 错选 runtime 原 Pending `edd655…`、原 Coord/FILES；不把该批称最终 v15 固定依赖图验收。
- 第一个 FAIL 是断言 `b'ssid'` 误匹配正常 `bssid_hex`；仅把断言改为完整 JSON 键。第二个 FAIL 是给 finish 50s 恢复总界但 loader 选错原 Pending（原短界≤20），不是新 Store 生产预算问题；没有把50改20绕过。
- loader 改为实际固定 v11 common `1a4a52bd…` / Coord `930e56d3…` / FILES `8bb891db…`，及 v8 Pending `cfba740700268d5998eb3a91bf7cdc34d893fa8f0083377d716ea98950c3f5af`。全部在私有 import 域加载，不改生产 sys.modules / frozen module globals。
- 精确补测命令：`python -B -m unittest test_client_durable_association_v18.AssociationTests.test_codec_roundtrip_none_intent_confirmed_invalidated_full_private_facts test_client_durable_association_v18.AssociationTests.test_complete_real_store_trace_association_cleanup_finish_three_fresh -v`（cwd=tests）。
- 工具 `c34b4b`：仅上述 2 个原 FAIL 方法，2 PASS / 0 FAIL / 0 ERROR，0.546s，host exit0。其余14已过方法没有重跑；合计16个不同方法分批，不是18或最终图整套16重跑。
- 首批含 Python3.5 AST 和原 `_same_journal`、Store `_publish/_read_exact/_producer_context/_fresh_restore/_authorize_terminal_clear/finish` AST 完全相同检查。后续只修测试 loader / assertions，不改这三份候选源码。
- 测试使用实际新 core/codec/Store 与实际文件/锁组件，FakeIO / 合成 Proc / 合成 fresh issuance producer。实际 prepared→各 init stage→关联 CAS→invalidated cleanup→terminal finish / 三 fresh / unlinkfsync / 原票据 once close / device-last 在 Fake 组合中通过；不是真实 Linux syscalls、进程 wait/reap、kernel association 或手机。
- 正反例覆盖 immutable binding/fulltasks、MAC/frequency、旧 envelope / 额外秘密字段、phase跳跃、sameF/run、rawtask持久篡改、过期确认拒绝/失效不续期、一次发布未知后 sticky pending、原 journal handoff/reacquire、默认或重用 producer 拒清，以及基础 restore 在 Fake child reap 前已 durable invalidated。

尚缺：v19 的真实 sameF ConnectionObservation 发行、九字段原来源 / 当前 operation 库存、实际 confirmed digest、当前 canonical provenance 与 fresh kernel/status/readback 接线；不得从本 schema 或 roundtrip 构造全 True DHCP proof。无设备动作、实际锁/网络/进程启动、旧 pending 清理、正式 SOURCE 包或整图冻结。
