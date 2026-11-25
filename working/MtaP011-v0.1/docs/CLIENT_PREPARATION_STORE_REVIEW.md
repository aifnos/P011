# CLIENT preparation Store — limited implementation review

状态：`HOST_FAKE_ONLY`，等待 ROOT 全文复审及另行批准的真实 Linux 验证。
这不是完整 `ClientInitStore`、Executor、Owner、恢复授权或可部署互传入口。

## 本次落地范围

新增 `runtime/mta_client_store.py` 的 `ClientPreparationStore` 和
`PreparationSession`，实际组合现有 `ClientCoordination` 与
`ClientJournalFiles`，不是用一套 stub Store 替代真实组件。
默认后端仍执行这两个组件现有的 Linux 文件及 flock 操作；本次验证仅注入
HOST FakeOS，未执行默认后端。

构造与 import 不做 I/O。内部只接受既有规范 token、exact `core.Identity`；
目录仍由外层先建并审查。本层没有任意路径入口、mkdir、pending 写/清除、
lease.start、进程创建、继承/dup、wait/reap、RF、IP 或网络操作。
现有同域 `/tmp/p011-mta-p2p-device.lock` 与 `.pending` 保持原契约：
任何 pending entry 都阻断，本层不能认领旧 GO，也不能创建自己的 marker。

## 实际 API 与顺序

- `open()`：登记 session → 实际 coordination.acquire → FILES.open →
  实际锁/entry 校验；只返回本实例 exact session。
- `current(session)`：锁校验 → 实际 canonical current 读取 → 锁校验。
  已有 ready/prepared 记录仅作为私有数据，不能据此升级当前能力。
- `prepare_initial(session, baseline, deadline)`：只允许一次尝试；构造
  prepared Journal → fresh current 必须为空 → 再验锁 → 实际
  FILES.commit(None, journal) → 再验锁 → 完整 fresh readback → 再验锁。
  成功要求 canonical bytes、Journal key、完整 metadata 一致。
- `close(session=None)`：两个组件独立关闭；后续调用只观察，不再次
  close/open/flock 原资源。返回私有 `PreparationCloseObservation`。
- `status()`：固定枚举/布尔投影，不含 token、路径、进程/网络标识或
  canonical 原文；所有 Executor/sameOFD/RF/完整 Store/收发能力仍为 false。

本层 whole-method RLock 将两个 owned 组件的事务串行化；实际 flock 只协调
遵守同域的写入者。FILES 的 compare-before-publish 不是脱离外部序列化的
原子 conditional rename。本层不向 IPC 暴露组件，也不防御恶意进程内 Python
篡改其私有对象。传入 `core.Snapshot` 仅证明 schema，不认证 kernel baseline、
manifest/run/parent Actor 归属或当前 Executor。

## 异常、预算与资源闭合

所有组件操作共用真实 monotonic 外层 deadline；各组件自己的相对预算不能
延长它。类型/范围先验后才作 finite 检查，拒绝 bool、huge int、非有限值和
clock regression；prepared deadline 必须在当前时间之后且不超过 20 秒。
预算不硬抢占任意 OS I/O、回调或 RLock 等待。

异常后先独立尝试两个 exact owned 组件的关闭，不让 clock/status/审计分配
先行阻止 close。然后重新开始有限的闭合观察预算。FILES 没有 public
read_closed，故本层只读其已审核、固定依赖图中的 exact 原 ticket inventory，
核 opening_unknown/attempted/closed 与原 FD strict EBADF；不会重开、重关或
依据 fd 值推测 owner。协调组件通过自身 exact `read_closed` 原引用核查。
未知 open、未知 close、异常及原 FD 被复用均保留组件/ticket 强引用与 pending；
空 inventory 不能替代完整 coordination 闭合证明。

写入前/途中失败可能留受控临时 artifact；本层不 unlink、rollback 或 retry。
FILES.commit 已返回但后续锁/读回失败时，先保存 exact committed candidate，
并保持 `checkpoint_unverified=true`；不能把“未取得最终 receipt”解释为未写入。
FILES 自身的 `write_pending` / `published_unknown` 与本层 checkpoint 未验状态
分开保留。闭合 complete 要求两个资源观察均确认且上述未知/写入状态均为 false。
这些只证明本地文件层，不是 core.CloseProof、ExitProof、finish 或全资源消失。

## 2026-10-01 首批专项证据

工具：PC CPython 3.12，显式 `-B`；tool chunk `319a9c`，host exit 0。
命令：`python.exe -B -m unittest discover -s tests -p test_client_store.py -v`。
实际结果：29 tests，0 failure，0 error，unittest 0.108 秒，`OK`。
这是本次唯一首批运行；没有失败批次，也未重跑已通过测试或旧组件整套。

测试使用现有真实 coordination/FILES 类及真实 Journal codec，底层由
`CombinedIo` FakeOS 实现。覆盖锁先于 FILES、空 journal 首次 prepared 发布、
已有记录不覆盖、旧/中途 pending、entry 变化、shared deadline、clock 回退、
文件/目录 fsync 故障、postcommit 校验失败、metadata 变化、异常独立关闭、
unknown open、FD reuse、重复 close 纯观察与私有/public 能力边界。
同批包含 Python 3.5 AST 及无 assert/禁止操作检查，并禁止实际 os、libc、socket
调用。此 AST 不是 P011 Python 3.5 import/执行验收。

没有 WSL/tempfile/实际 OS 锁、ADB、RF、网络、Docker、全套测试或正式冻结。
ROOT 后续真实 Linux 验证必须另行记录，不能把本批 FakeOS 标签升级。

## 尚缺的真实互传链路

本层不能接 `ClientInitLease.start()`，也不继承 `ClientInitStore`。
仍缺真实 owned marker 的 first-durable 事务、manifest/run/Executor 绑定、
same-OFD 继承 inventory、C/D/watchdog 生命周期、真实 reap/ExitProof、
pending unlink 与最后 FD close 的 finish 窗口证明、CLIENT provider 与手机验收。
这些缺口不由目录名、prepared receipt 或固定 false 字段补齐。
