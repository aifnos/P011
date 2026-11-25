# 生产 State 无 RF 生命周期 observer

仅三个新文件，HOST 阶段；没有 checker/ADB、实际 socket/RF、设备目录、部署、冻结、UI、ZIP 或旧源修改。当前 V9 pending/原 STA 未恢复仍阻止实际 State 启动，本组件不会绕过或清理它。

## 最小 API 与真实范围

- `StateSmokeObserver(trusted_synthetic_root, pinned_bluez_helper, pinned_network_helper)` 构造仅保存引用；`open()`、`exercise(timeout)`、`close(timeout)` 为显式动作；`status()` 只复制缓存固定 enum/bool/count，不调用 State/backend/status、close、文件或用户 callback。
- trusted runner 负责新私有合成目录（16 B 文件）、完整 pins/元数据/原厂与全网络 baseline、pending 归属清理准入、进程/占用锁、当前 UI 与最终进程退出；observer 不替代这些安全门槛，不移除任何锁/journal。
- `open()` 先登记 exact `State.__new__` 引用，再调用原 `State.__init__` 与固定只读 capability probes；partial constructor 不丢对象。网络 native `receive/send=False`、生产 State receive/send=False、全 capability actor 闭合、没有 helper/key/lease/transport/active backend/STA journal，且固定全局 P2P pending 不存在，才开放 loopback exercise；不会改 scan_available 或伪造能力。
- `exercise()` 通过 loopback TCP 请求生产状态/文件/普通 cancel。普通取消可能调用原 restore_active，但严格门槛保证 active=None、pending=[]，其实际行为仅返回当前空 owner 状态。明确记录 cleanup worker skipped，不称其退出过。
- 第二阶段只用原 State 私有 `_new_operation_locked('cleanup')` 创建原 TransferSession，先强引用 exact op/session/worker/finalizer，才 start；原 cleanup task 返回无 commit/ACK 的 Outcome。这是 `SYNTHETIC_CLEANUP_NOT_TRANSFER`，从未创建接收/扫描 worker、transport 或 lease。
- started cleanup 还要求原 Session worker 的 claimed/resolved/unknown 与实际 Thread.ident 读回一致；unknown start 即使 is_alive=False 也不能标为启动完成。只读 capability process/stdout/stderr 保存 exact 引用，闭合独立核实实际 poll 和原 pipe identity/closed，不借 State 的缓存标志证明已关。

## HTTP instrumentation 边界

- 新 ObservedServer 子类使用明确复制/instrumented 的 accept/slots/Thread loop；原 minhttp 文件没改，但这**不是**未经修改的原 minhttp 循环硬件验收。State、Server ctor、Handler 授权/解析、process 及 Session 业务逻辑仍来自生产代码。
- 每个 accepted raw（含 slot 拒绝、取消后的 late accept）立即强引用；每个 request Thread 在 start 前登记 claimed/resolved/unknown；保留 serve/client Thread、listener/client/accepted raw 与全部历史 Session/finalizer。
- 不全局 monkeypatch Thread/Popen/socket。HOST 用私有命名空间加载未修改生产源，并只给该命名空间提供 fake socket/Popen/Wifi peripheral；Session 与 observer 线程为真实 HOST Thread。显式 `_host_dependencies` 必须标 HOST_FAKE_ONLY，不能当目标证据。
- 路由仅 GET status/files、exact POST `/v1/action` canonical cancel body；其它动作包括 recover/rename、bootstrap 均拒绝。保留生产 token/Host/Origin 授权与 content-type/长度/JSON解析，不以假能力阻断 RF。
- HTTP 所有 raw 仅 AF_INET/SOCK_STREAM，显式 loopback bind/source/target 读回；无 create_connection/DNS/fallback/REUSE、TLS detach、用户任意请求或系统接口。

## 闭合与未知

- close 设置停止并在锁外尝试所有 raw close、历史 Thread join；不会因为单个 close 失败跳过其它 owner。workers map 清空早于 Thread 实际退出也不能通过。未启动的 is_alive=False 不是退出证据，unknown start 保持 pending。
- 首轮 raw close 失败不会在同一次 close 中隐式重试；后半轮只处理后来登记的 exact late raw。显式下一次 close 才可对同一 owner 重核验。actual capability poll/pipe 读回在 State.lock 外，阻塞不会锁住状态读取或取消。
- 独立只读 probe cleanup 不依赖 HTTP/State.close 通过：exact 原 actor 位置、固定两条 --capabilities argv、spawn 已知结束、原 Popen/两个 pipe 全部 identity 一致，才准许动作；spawn pending/unknown、actor table 或任意原 ref 被换则整 actor 不动作，也不关闭 foreign pipe。只读 Popen alive 时只 kill 该 exact 句柄、有限 wait，再用 actual poll 核实退出；原 stdout/stderr 各自 close，某个失败不跳过另一 pipe/另一 actor。已退出/已关只读回，不重复 kill/close；同轮没有自动 retry。动作在锁外，不更新 State 缓存、不补调用 State.restore/State.close，HTTP/构造 unknown 仍 pending。
- probe ledger 保留实际 poll/exit、kill/wait 与每个原 pipe 的 close attempted/returned/actual closed 固定 bool；公开仅固定 owner 数。attempt flags 表示该 exact owner 是否曾获尝试，不是无限累计调用数。预算用完不再准入 kill/wait/pipe close；Python/OS 操作本身仍非硬抢占，失败/超时继续持有 owner。
- 没有动作/accept/构造还在执行，全部 historical Thread 实际退出后，且当前 no-RF gate 再次成立，才调用原 State.close；State.closed、两类 Session full schema、actual saved worker/全部 finalizer、probe process/pipes 以及 raw close_returned/_closed/fileno=-1 必须全部严格通过。
- generation、late socket、partial constructor、Thread.start 抛出但可能已启动、close 无效/异常、pending 再出现都保留引用/unknown/pending；不得报告完整闭合、自动重试、清 journal/锁或创建新任务。显式后续 close 仅对同 owner 重核验。
- timeout 有限且拒 bool/NaN/Inf/huge int；限制 join/阶段准入，不硬抢占已进入的生产 State.close/OS close 或 trusted constructor。阻塞期间 status 保持非 closed；不承诺硬 deadline，也不 kill 全局进程。
- 缓存状态不是新一轮被动网络核查；最终闭合要求显式 close 的实际观察，不因后来的 Thread 消失自动升级。资源 closed 与 exercise 成功字段分开，关闭未 exercise 的 observer 不等于已测 started cleanup。

## HOST 验证

测试使用 fake TCP/peripheral 与真实 HOST Thread，不创建真实 socket，不是 P011/手机/原厂恢复/UI 验收。初版测试文件含 17 个方法，独立 probe 补强后含 20 个；没有重跑全套或把历史通过项升级为最终源码的整组通过。

- 首次 focused HOST：17 run，12 PASS、4 FAIL、1 ERROR（4.443 秒），保留原失败。新 observer 错误为 HTTP/1.1 响应假设（生产 minhttp 实为 HTTP/1.0）及 HTTP partial/unknown 时过早进入空 State.close；修正后仅原受影响 5 项复测，5/5 PASS（0.924 秒），未降低断言。
- 补实际 worker.ident 与 late raw 单次 close 语义后，仅受影响 3 项，3/3 PASS（0.897 秒）。补 actual probe process/pipe proof 与 foreign pipe swap 后，仅受影响 2 项，2/2 PASS（0.893 秒）。
- 阻塞 poll 新案例首轮 1 FAIL（0.234 秒）：fixture 释放 poll 后未等 exact client 真正退出就请求关闭；补真实 join/退出断言，原闭合断言不变，复测 1/1 PASS（0.240 秒）。固定 evidence enum 防 late 注入后，同一受影响方法复测 1/1 PASS（0.230 秒）。
- 此前冻结 runtime 源码 25258 B，Python 3.5 AST PASS；该旧冻结不是本轮最终源码。
- ROOT 审读指出 known read-only capability actor 在 HTTP/构造 unknown 时缺独立 cleanup，窄补仅这三个新文件。新增 3 方法及受影响原 5 方法首次专项 8/8 PASS（1.321 秒）。含 ctor/HTTP unknown+known alive、single pipe/kill/wait fault、foreign pipe/process/argv 与 spawn unknown 门槛。
- 再补原 production ctor 的 communicate/kill 故障控制流（仅 1 known live probe、不会创建第 2 probe），只复测该受影响方法 1/1 PASS（0.043 秒）。补 actor-table unknown 拒绝迭代/动作后，只复测该受影响方法与 Python 3.5 AST 方法 2/2 PASS（0.092 秒）。本轮没有新增 FAIL，也没有运行 20 项整组；ROOT 后续统一审读/整合 HOST。
- 本轮最终 runtime 30410 B，最终源码 Python 3.5 AST PASS；target 只读 capability 实际 kill/wait/pipe 行为、真实 TCP 和设备整合均未测。

手机、原厂恢复、UI、真实目标 loopback、实际 capability pipe 关闭与最新 State 设备闭合尚未验收。当前固定 pending 未清，不能据这些 HOST 结果启动目标 State。

## ROOT 当前源码专项复核

2026-10-01 10:34，ROOT 全文审读最终三文件后，对新 independent probe cleanup 影响到的整个组件执行一次当前源码专项：`python -B -m unittest discover -s tests -p test_state_smoke_observer.py -v`，工具 `feab09`，**20 run / 0 failure / 0 error / 0 skip / 5.267s / OK / host exit0**。运行前后 runtime SHA 同为 `7d131cc5a13e6647ec29b38557c165b6d4ffb90d6e90a92888bbef8365f618e4`，tests SHA 同为 `61cd5dcb41d21162250ce2fefb68bb23a825e4e45586ce08e0a6de29097f955c`。

公开派生记录为 `results/state-observer-host-20261001-103410-feab09/result.json` 与 README；stdout/stderr 未分别捕获，因此不称独立 raw 输出。此前首轮失败和增量记录全部保留；这是当前组件20项完整专项，不是项目全套重跑，也不是设备、真实TCP、RF或手机验收。
