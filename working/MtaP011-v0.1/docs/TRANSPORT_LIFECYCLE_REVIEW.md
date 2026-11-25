# Transport 关闭证明：HOST 实现检查点

本轮仅修改 `runtime/mta_transport.py`、`runtime/mta_sender.py`，新增本说明与 `tests/test_transport_lifecycle.py`。没有修改 State、能力开关、scoped socket 模块、Wi-Fi/DHCP/helper、包脚本；没有设备、RF、Docker、真实 TCP/TLS 或手机测试。生产互传能力仍不因本轮开放。

## 已实现的内部 API

- Sender / Receiver 的 `close(timeout=2)` 返回验证后的 bool，预算严格为 0..2 秒；重复调用会重试未完成的关闭，而不丢弃所有权。
- `closed()` 是当前被动快照，不把发出取消、函数返回、TLS detach、`fileno()==-1` 或 join 调用本身当作完整关闭。
- `lifecycle_status()` 只提供固定计数 / bool：`closing`、`socket_records`、`sockets_pending`、`actors_pending`、`threads_pending`、`wrappers_pending`、`unknown_wrappers`、`unknown_resources`、`processes_pending`、`cleanup_pending`、`close_verified`。不含地址、路径、fd、设备名、证书或异常原文。
- `closure_snapshot(raw)` 额外返回 `recognized_raw`、`all_sockets_closed`、`all_actors_exited`；按 exact Python object identity 查找，不按 fd 数值、hash、地址或同名对象匹配。
- 这里没有依赖 `mta_scoped_sockets`。后续可信 coordinator 可以将严格快照转换为该模块的证明，但本轮没有接线或默认 proof provider。

## 资源与关闭顺序

1. create / wrap / Thread.start 的 actor 在慢操作之前登记，取消之后返回的真实对象先收归所有权，随后关闭；没有网络 fallback。
2. listener、拒绝的 accepted raw、被接受的 raw、WebSocket TLS、download TLS 都保留 exact 对象。TLS wrap 返回后同时记录 raw 与 wrapper；raw detach 只是 fd 交接，不是 wrapper 关闭。
3. wrap 异常若已 detach 且没有返回可追踪 wrapper，保留 `unknown_wrappers`，不伪造清理成功。格式不符合 close/fileno 的 factory 返回对象也保留 `unknown_resources`，尝试其 exact close 但不推断其已关闭。
4. 所有可追踪套接字都独立尝试 shutdown / close，一个失败不跳过其它连接、文件或目录清理。实际受管 close 正常返回且前后 fd 读回有效才可记录该对象关闭。
5. 关闭取消与当前函数 actor 完成不等同线程退出。owned worker 和调用这些操作的非 Main 线程身份持续保留；仅实际 `is_alive() is False` 才可消除 pending。不得 join 当前线程；当前 worker 的 finally 内不能宣布 `closed()`。
6. join 使用共享总预算，不是每个线程各等待 2 秒。没有 SIGKILL、全局 kill、网络配置或强制清空未知所有权。
7. Sender 创建的 OpenSSL process 保留 exact Popen 身份；仍存活或 poll 无法确认时不删除私有材料，也不产生 close proof。原证书算法 / 参数和原有 timeout 行为未变。

预算是可取消协议 / join 的上限，不是对任意阻塞 OS close、第三方 factory、callback 或测试 seam 的硬抢占承诺；若这些操作仍未返回，actor / resource / 线程仍 pending，不产生 PASS。后续 worker 应在外部观察者中 join 完真实传输线程后，才按关闭证明推进网络恢复。

## 私有临时文件和目录

- Receiver 的 mkstemp 在 fstat 前先记录 fd 和未确认身份，成功后保留创建时 dev/inode、regular-file type、canonical parent/path；最终 unlink 前重新 lstat，拒绝 symlink、替换对象和 parent/path 变化。
- fstat 失败、fd 被替换、身份未知、输出 close 失败或 unlink 失败均保留 cleanup pending；不能为了退出成功而删 foreign 对象或丢记录。
- Sender 的 mkdtemp 保留 dev/inode、directory type、实际 canonical temporary parent/path。rmtree 前重新 lstat/type/no-symlink/parent/path 核验；不再只以 basename 前缀判断归属。失败保留 exact owned directory 后重试。
- 单个 socket close 失败不阻止已经没有活跃文件 actor 的 exact 私有文件清理；但整体 close proof 仍 False。路径身份读回是本层删除门槛，不宣称对恶意并发 rename 的通用原子隔离；调用方须持续保护本次私有临时目录。
- 不移除收到文件，不改变存储 commit、实时 hash、文件权限、TOFU pin、peer ACK / 本地成功事实。peer ACK 失败不会抹除已提交的本地结果。

## HOST 专项证据

`python -m unittest discover -s tests -p test_transport_lifecycle.py -v`：49/49 PASS。

套接字、SSLContext/SSLSocket、OpenSSL 创建与受控 worker 是显式 HOST fake；少量实际 PC 线程用于确认线程身份 / alive 的竞争窗口。测试禁止真实 socket / subprocess；临时文件仅为 HOST 生成的小型 fixture。

覆盖：listener / raw / TLS 关闭、detach、未知 wrapper / 无 fd resource、close 异常独立清理、late / blocked factory 与 wrapper、当前线程和 pending start、总 join 预算、外部 fd -1 不伪证明、source factory 失败不回退、证书首 pin / rotation、确认阶段取消、Sender 初始 deny-all、拒绝连接不启动 TLS worker、完成结果保留、实际 Receiver.run 代码路径的 fake 双 TLS 和单 close error、未知临时 fd、foreign file / directory / symlink 替换保护、私有清理失败精确重试、固定公开字段及 Python 3.5 AST。

实际 Receiver.run 测试中的 storage commit / peer message 均由 HOST fixture 明示提供；这证明代码没有因 close error 改写已有结果，不证明真实落盘协议或手机 ACK。

既有纯内存 framing / HTTP / download 协议测试此前 7/7 PASS；其后本轮窄修仅涉及资源登记与临时清理。root 可在集成 HOST 测试时覆盖全部调用。既有 real HOST TLS 和 P011 loopback 证据属于旧源快照；本轮没有复验，不能自动沿用为新生命周期实机结论。

## 后续接线门槛

可信 coordinator 必须同时核验 exact raw 的 `recognized_raw`、`close_verified`、`all_sockets_closed`、`all_actors_exited` 和 `cleanup_pending is False`。无 raw match、活 worker、pending create / wrap / close、未知 resource、临时身份不明时，不得向 scoped capsule 提供 `TransportClosedProof`，也不得丢掉 owned network lease。

factory 在抛异常前未交出的资源仍归原 scoped factory / capsule 所有；transport 没有对象时不能替 capsule 宣告关闭。网络恢复仍需要 capsule 自身的所有 actor / handoff 关闭证明与 journal / IP / GO / station 核验。这些属于未实现的真实 worker 接线，不能用本轮 HOST fixture 替代。
