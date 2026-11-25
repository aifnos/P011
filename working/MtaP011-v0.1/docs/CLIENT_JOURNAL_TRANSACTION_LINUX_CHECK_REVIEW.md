# 隔离 Linux journal 事务检查器（待 ROOT 实际执行）

## 固定范围

- 新入口 `host/client_journal_transaction_linux_check.py` 默认仅核源码 / Python 3.5 AST，不构造实际 I/O。
- `--execute-reviewed --expected-checker-sha256 <当前完整SHA>` 必须同时提供；固定 Linux / euid0；每进程仅一次，登记 exact checker 强引用后才进入 I/O。
- 固定加载九个 runtime 源；transaction runtime `2783f66edbb545aff8adfaa2f80a77fd957c8ba5b365c90907474244b603dcaa`；另核原专项 / review 两份引用，不 import 测试 fixture。
- Coordination `6d1b3af…3079` / FILES `d95afa2…2ed3` / Pending `7197c04…d2c` 为已审 own-marker 版本；core `ec2d927…85f1`、ProcReader `2f0ef52…6591`、codec `17d3628…9f73`、IP / bundled JSON 都有完整固定 pin。

## 真实执行内容（尚未执行）

先实际检查 `/` / `/tmp` 目录 owner、nofollow identity / 权限；`mkdtemp` 在 `/tmp` 建独占 0700 fixture。
其中固定 `tmp` / `p011-mta-client-rfinit` / `client-32lowerhex` 均 rootuid / 0700。
仅将三个 **default Linux I/O 实例** 的 `open_root` 指向 fixture，其他 openat / stat / fsync / renameat / flock 使用原实现。
不会访问真实全局 pending；fixture 内 device / journal lock 均由原 Coordination 创建和验证为 0600。
无 socket / 进程 launch / RF / WSL / ADB / sysctl / 网络配置；不执行 process owner。

单线程实际 `ProcReader.read_self()` 提供当前执行者 / boot，要求两 pass、一 actual task、每个 ProcReader 文件已关。
stock hashes / stock actors / wlan / IPv4 / IPv6 等 Snapshot 字段全部 **synthetic schema**；不是完整设备 / 原网络恢复基线。
步骤：pure ctor → open+actual locks → current None → prepared commit+fsync+marker create/bind → deadline 缩短 CAS / 新 inode → 旧 exact receipt 被拒 → fresh current → fresh self → close。
过期租约并未测试；这里是 **stale generation receipt** 拒绝。
事务 `close` 内嵌 finally 独立尝试 marker / FILES / Coordination，检查器再逐个核所有原 component FD 的 EBADF。
再独立读取 marker 原 inode / metadata / 完整 bytes，必须留存且不 unlink；fixture 也保留，不递归删除 / 回滚 / 自动重试。
setup 与 retained-marker read FD 独立 once close / EBADF；未知保留 exact fixture / IO / modules / transaction 强引用，不允许二次 execute。
局部 close proof只覆盖本轮登记的 component / setup 原 FD，不覆盖全部进程 FD或 result writer。
Proc actor key 前后允许正常 task state 变化，不把 R/S 变化误当 PID 身份变化；仍不扩展到多线程。
事务每操作 10s admission budget、prepared 剩余 ≤20s；不是可硬抢占 filesystem / libc / mutex 的绝对执行时限。

## 输出 / 准入

`results/client-journal-transaction-linux-host-<UTC>-<random>` 使用 exclusive 新目录 / `xb` 文件。
public `result.json` / README 仅固定布尔、计数、阶段 / 错误类、errno 0..4095、源码 pin；不输出路径、token、Actor / boot。
完整 private Proc records / fixture 路径 / traceback 只写 `private-raw/observations.json`，0700 private 父目录；不得进公开 ZIP。
任何 FAIL 仍保存；原报告不覆盖。结果写入错误不移除 module-private checker 强引用。
`source_check_pass` 不等于实际 Linux PASS；Linux PASS 也不是 Store / RF / P011 / 手机互传 PASS。
receive / send 生产准入未改。已有 owner `69bab0` 仅 HOST direct child / OFD / waitpid 证据；旧 pending `5b45e5` 仅旧版本 create/verify/close，本入口不借它们声称新组合已验收。

## HOST 专项

唯一首批 `02d63b`：`python -B -m unittest -v test_client_journal_transaction_linux_check`。
实际 **22 方法 / 0.592s / OK / host exit 0**；工具 wall 1.0240759s。
包含固定源码 SHA / AST 3.5、默认 source-only、真实组件 API over FakeIO、CAS / stale、私有输出、强引用 / once / BaseException / independent close。
没有首 FAIL / 增量批 / 已过全套重复；只这 22 个新方法。Python 新版的 `utcnow()` deprecated warning 已保留，3.5-compatible 输出命名没有升级为实际 Linux I/O 证据。
本轮不得运行真实 Linux fixture、WSL、ADB、RF、默认 adapter I/O 或全项目 suite。

ROOT 全文审核最终 SHA 后唯一显式执行；Reviewed CLI：

```text
python -B host/client_journal_transaction_linux_check.py --execute-reviewed --expected-checker-sha256 <最终checker完整SHA>
```
