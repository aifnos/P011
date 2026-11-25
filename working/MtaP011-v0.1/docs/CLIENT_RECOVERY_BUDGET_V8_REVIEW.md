# CLIENT 恢复预算 v8：隔离源码候选

仅 SOURCE / HOST FakeIO。不是 P011、实际进程/锁/射频、手机或生产验收。
三个候选在 `candidate/client-recovery-budget-v8/runtime/`；原来源保持不变：

- Provider：v4 `a8ca35f57841bf75b9ea53120404a395e2ad446cb2859a16a6c5c225efbb5491`。
- Store：fresh-v5 `bbe71e419260a2f83e266a5b9fb401e9dc5e82a78c892ea4daad77f0bb8b3df3`。
- Pending：原 `edd6553b847db6dc8e5d2be48256b8e3ee706adca25cbda316bcf28f357ff7cf`。

## 准确改变

恢复一次固定绝对总截止 60 秒；`restore(timeout)` 只接受 `(0,60]`。
Journal RF deadline、启动 TTL20、初始化谓词、所有持久化阶段/CAS 不变。
Lease 的四次 `_baseline`、两次 owned Origin 完整门禁各至多 5 秒，
子进程 cleanup 合用 8 秒；其它 Provider/Bridge/锁调用传原 ≤20 秒 slice。
Store `prior_clear` 鲜读 + authenticate 合用 ≤5 秒且仍受原 start deadline20；
Store 三次恢复认证分别鲜读 + authenticate ≤5 秒，完整 tuple 身份/不重用/闭合检查不删。
普通磁盘段仍默认 3 秒，配置原上限不改；构造/IO/CAS 原资源容量不增。
Lease 在 exact Store 的同一 RLock 下保存私有恢复总期，禁止同域重入，finally 恢复。
`_begin_io` 仍拒绝传入超过20秒的 deadline，同时 clamp 该本次总期，
因此原 `current` 和 `core._save→commit` 新开短预算也不能越过总期。

第三 fresh callback 从 Pending 短提交中分离：短准入 → 真实 producer/auth → 新短提交。
Store/Coord/FILES/Pending 的 deadline 均保存、实际切换、恢复，不仅重置 Store。
每个 producer 内 Store 真实钟绑定五秒；旧磁盘 deadline 暂存，不被鲜读消耗；
如果 producer 真调用组件操作，组件仍建立原短预算且受 Store 的五秒钟约束。
回调后重新完整验证 original FD / 当前 epoch / original marker / 完整 canonical，
然后原一次 seal/unlink、parent fsync、absence/原FD nlink0/字节读回不变。
没有地址、程序或陌生 marker 的授予；没有信任 `normal_restored=True` 代替 producer。
`authenticate_finish` 另开短 slice，核心 FinishReceipt 语义和完整库存验证保留。
过期或未知保留真实引用和 pending，不重试 unlink/close，不以物理 absence 冒充 durable。

## 首次及精确增量记录

命令均为 PC `python -B -m unittest ... -v`，实际 OS default adapters 全部 tripwire，
三组件为真实方法 over FakeIO，stock/network/child cleanup 和 producer 为显式 synthetic。

- `b031c0`：首11方法，9 PASS /1 FAIL /1 ERROR，0.670s，host exit1。
  FAIL 是 FakeClock 初值1被测试少算；ERROR 在构造时旧 LaunchRegistry 绑定 original Store，尚未 restore。
- `40e7ee`：只原2失败 +1新总期边界，2 PASS /1 ERROR，0.186s，host exit1。
  第二 ERROR 为 fixture 误用不存在的 Marker `_actor`，实际 actor 属于保存的 ProcReader。
- `413c33`：只该1方法，0.355s，OK，host exit0。
  实际走完九次 full snapshot、一次 child 8秒 slice、一次 owned DELETE dispatch 和终末 CAS/clear。
  DELETE 是 Fake kernel command，子退出是 synthetic，不是实际 RF / fork / wait / kernel 证据。

- `b48a08`：因最后新增同域重入拒绝 + AST 文件名单收窄，精确 Provider 正向与 AST 两方法，
  0.478s，OK，host exit0；不是完整12方法重跑，不累计为14不同方法。

首批失败不抹除；12 个不同方法不是一次完整当前 PASS 批次。
保留5秒 producer+auth拒绝、第三鲜读后 marker变化零unlink、3秒磁盘逾期物理写入未知、
总期8秒中止、全部四 deadline 异常恢复、tuple重用/Boolean auth拒绝、默认缺producer、
raw task 状态 persisted CAS 仍拒绝、总期临界后 current/commit 零新操作等证据。

60秒是有限退出边界，不是成功 SLA：9×5 + child8 +多个短磁盘段的最坏相加可超过60。
同步 OS syscall/callback 不保证硬抢占；晚返回/未知必须继续保留资源，不能宣称超时自动恢复。
Parent90 / ENTRY165 / ADB195 / RF前125秒余量由 ROOT 另行隔离整合，本三源不改 F/host。
启动现有6次完整读取可能消耗 TTL20，此候选不扩大 RF TTL、不削减读取；初始化分层另审。
真实 P011 / 小米15Ultra / 全双向文件收发尚未验证，send/receive 生产 gate 保持 false。
