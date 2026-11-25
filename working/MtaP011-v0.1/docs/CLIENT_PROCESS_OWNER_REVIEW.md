# CLIENT 直接子进程所有者（HOST 组件，未接生产）

范围仅 `mta_client_process_owner.py` 与本专项测试；不改变 CLIENT 核心、Store、Provider、State 或默认能力。
没有 ADB/RF/真实 OS FD/fork/exec/wait、实际 wpa、网络、Docker 或旧 pending 操作。

## API 与真实动作边界

- `LaunchSpec(role, exe, argv, env, sha)` 是可信平台固定 manifest 输入，不是 UI/HTTP/任意命令入口。
- `DirectChildOwner(...)` 与 `register(spec, original_device_fd, deadline)` 纯构造，先保存 exact ticket。
- `launch(ticket)` 先登记每个 FD 创建票据，再实际 no-follow 打开 ELF、完整 SHA/fstat 校验；保存实际返回 FD。
- 原设备 FD 必须由调用方实际拥有；本组件实际 `dup` 并经 `fork` 继承同一 OFD，绝不接受 `same_ofd=True`。
- 本组件不证明原 FD 上的 flock/完整租约；调用者仍需自己的锁与 immutable owner 证据。
- 每次操作核对 F 的完整 `/proc` 身份；fork 前同时要求 Python 单线程与实际唯一 task。
- Dedicated F 必须禁止线程/信号处理器创建或关闭这些 FD；该检查不是内核级线程创建原子锁。
- `fork` 前登记尝试，父保存真实 PID 与实际 pre-exec Actor（仍是 F 的解释器/argv），不改称最终 ELF。
- `release(ticket, persist)` 调 exact pre-exec 回调，只有绑定同一 ticket/Actor 的 `PersistReceipt` 才写一个 gate 字节。
- 该 receipt 只证明本实例回调返回，**不证明 Store/CAS/fsync/flock 已实现或持久化成功**。
- 真执行只使用 `os.execve(verified_fd, argv, env)`；实际 `supports_fd` 不含 execve 则拒绝，无 pathname fallback。
- CLOEXEC ELF FD 不支持脚本直接执行；固定 Python ELF 的脚本/其他资产仍须未来 Provider 独立 pin。
- FD 固定执行对象避免路径替换；可信部署者仍须保证该 inode 内容在执行期间不可被其他写者改动。
- P011 没有 `fcntl` 模块/`os.get_blocking`：实际 libc `fcntl(c_int,c_int)->c_int`、Linux `F_GETFL=3` 读回非阻塞位。
- `resolve(ticket)` 用真实 ProcReader 重新观察 post-exec exe/argv；不构造或伪造核心 `Handle/ExecutorProof`。
- `wait_reap(ticket, timeout)` 仅直接 `waitpid(saved_pid, WNOHANG)`；记录实际返回和 exit code，不发信号。
- 已知实际 fork PID 即使 pre-exec 读取失败仍可尝试 direct wait；未知创建/身份事实保持未知。
- `fresh_exit(ticket)` 必须已有实际 wait，再取得 fresh 两次 same-boot absence/零剩余 task；不凭 EOF/doneEvent。
- `close_inventory(ticket)` 分别关闭本 F 的 original owned FD，每个至多一次，错误不跳过其他资源。
- 关闭之前 fresh fstat 绑定；关闭后仅严格 EBADF 读回接受，不能关闭换成 foreign 身份的数字 FD。
- 该返回只证明本模块父 FD inventory，不证明 child 已退出、调用者原 FD 已关或整个 OFD 已释放。
- `read_requests(watchdog_ticket)` 非阻塞固定 `R` 请求，累计最多 16 字节；仅被动通知，D 不自行恢复。
- 子进程 stderr/stdout/stdin 指向已确认 `/dev/null`；exec 异常只写固定 `E`，没有自由错误/路径输出。
- `status()` 被动固定 enum/bool/count，不读 proc/clock、不做关闭，不输出 PID/argv/path/FD/密钥。

## 未知、预算与生命周期

直接 POSIX open/pipe/fork 的 OSError 无返回资源属于确定负结果；BaseException/畸形返回保留未知票据与原引用。
全部关闭独立尝试；unknown/close 错误 sticky，不重 fork、重写 gate、重复关闭原 FD 或自动重试。
未返回身份的实际 child、未闭合 FD、执行路径中断不得宣告完成。
launch/release 使用原 deadline；wait/read/close 使用自己的有限观察预算，过期 TTL 不阻止后续清理。
预算仅约束阶段准入与调用者等待，不能硬抢占阻塞内核 IO/可信回调；本模块不发 kill/signal。
实际继承副本、F 死亡、D orphan 和恢复协调仍未实现；不是通用 janitor。
`complete/provider_ready/orphan_recovery` 恒 false；本组件不授予 RF/生产收发权限。

## 本轮证据

首批 `732ac3`：45 个命名方法，44 PASS / 1 FAIL / 0 ERROR，0.013s，exit 1。
唯一失败是 FakeKernel.fstat 返回共享可变 metadata，真实 os.fstat 是独立 stat_result；保留该首判。
仅改 fake fstat 使每次生成独立 snapshot，生产源码不因该失败改动。
增量 `a72812`：上述失败例加 7 个直接受影响 FD/readback/AST 方法，共 8 PASS，0.007s，exit 0。
当前方法数 45；没有重跑最终整 45，不将分批/假内核结果升级为 Linux/P011/手机验收。
Python 3.5 AST 在首批与增量都通过；实际源码 import/构造没有 IO，私有 OS seam 不授平台能力。
后续 ROOT 可在独立 Linux 用固定无网络 ELF fixture 验证实际 fd-exec/direct child/wait；本轮不执行。
