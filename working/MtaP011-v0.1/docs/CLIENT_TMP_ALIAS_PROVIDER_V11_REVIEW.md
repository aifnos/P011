# CLIENT tmp-alias v11 F / Provider SOURCE 审查

本轮仅隔离候选源码与 Fake 专项；旧 Fv8、Provider v9 和所有实际历史不改。
未执行 OS/WSL/ADB/socket/进程/RF、设备 staging、20 图正式检查或打包。

## 固定来源与接点

- F 来源：candidate/client-recovery-budget-v8/runtime/mta_client_executor.py，
  1b2b07f45d3564b743dfa66921bf831962ec6c3754b25e35c384ab699de362a3。
- Provider 来源：candidate/client-integrated-v9/runtime/mta_client_linux_provider.py，
  8bb5dfae34ab7cc4db772957781c8c9385bf6285250137351bac70de685798d6。
- 新两源均位于 candidate/client-tmp-alias-v11/runtime/；common 由另一作者负责。
- 新 F：1e8e1632b9170964f8471f106a50988e2d75ccfba7b1c5ed49a604323d481e43。
- 新 Provider：4f4cec03ddec5ec8e91f9f04ccdc91beb7e54a725a1481ba73c7045338883df6。
- 新测试：0ce5659201bdbff580e5d447cb31db9375f9ca1c3b107e4b48fb7edc81917e37。
- common 本次读入 1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f。
- MODULES 20 项，mta_client_tmp_alias 紧随 mta_ip，其余 19 名字/顺序不变。

F bootstrap 在读取 pinned common 之前只能使用标准库 metadata/readlink，
只接受已观察 /tmp→/var/tmp→/var/volatile/tmp 两条 root:root 0777/nlink1 链。
/var 要求 0755；volatile 和 physical tmp 要求 01777；/ 根禁止他人写。
alias 目录仅用稳定 dev/ino/mode/uid/gid，不因合法 entry counter/时间变化拒绝；
两 symlink 保留完整七字段及 mtime_ns/ctime_ns、actual target 前后一致。
private BASE/run 原 before[:6] 不变；不通用解析、不猜备用路径、不额外 open FD。
logical ROOT 和认证 physical ROOT 都作为 private 域：source 0400、
native 0500/nlink1，canonical 系统 /usr/bin/python3.5 才可 nlink2。
后者比旧 F non-private binary 条件更窄，是防 physical private 错分类的护栏，
不改变 actual Actor/Owner/C 的发行或比较，不将 fixture 首 ERROR 称源码故障。
logical/physical leaf 前后与 original FD metadata 相同，保留完整 sha/ELF、
实际原 FD 关闭与 fresh EBADF 门槛，不把地址替换当作授权。

Loader 与 Provider Manifest 的计划 native 为 exact physical run/native 路径；
executor/cfg/ctrl 和控制 argv 不全局重写，Owner/C/raw Actor 比较完全保留。
Provider 通过 FixedTmpAnchor 的 prepare/bind_tmp/authenticate 使用 caller
原 ledger tickets；保留 5 个 logical anchor 索引并追加 var/volatile 两个
原 FD（总 7），每次 verify fresh 核验。普通 /tmp directory 仍走原 5 FD 分支。
部分 open/unknown 不重试、不丢引用，common 不是资源关闭或 RF permission。

ROOT/Protocol 436c2b/710183 独立发现旧候选 308a 的 Provider callbacks、
anchors、Ledger close 和 live-generation 仍使用含 nlink 的六字段比较。
本次仅为固定四目录 root/var/volatile/tmp 登记最多四个 exact original rows：
Ledger 保存同 Provider / 当前 FixedTmpAnchor / 原 root 的私有 context，
root→var、exact var→volatile、exact volatile→tmp 才能登记；不是目录类型豁免。
这些原件 callback/verify/close/generation 共用 stable5，fresh DIR/root:root、
原 mode/dev/ino 和正 nlink 仍必检。partial helper 不授权 ready/RF；
已登记 known 原件可独立 once-close/EBADF，unknown/borrowed 不盲关。
ordinary、private BASE/run/ctrl、所有 file/socket 保持原六字段，库存限额不变。

除上述 bootstrap/load/manifest/anchors 及 exact alias Ledger/generation seam 外，
未改其他原方法字节。
包括 kernel/caps、控制认证、接口 CREATE/DEL、phase、restore 默认 60、
F Parent 默认 25 和 HOST 显式 finish 90、
TTL/source/public 成功门禁及原 once-close 库存；init_not_ready 在 host 保留。
本专项不装配正式 20 图，也不证明 Provider/P011 完整恢复或手机互通。

## 实际 Fake 专项

- 首 c09004：13 方法，0.067 秒，exit 1；11 PASS，2 方法 ERROR。
  两 ERROR 的 Fake ELF 使用了字面量反斜线 x7f 而非 0x7f，原 ELF 门禁正确拒绝。
- ba2cc5：仅上述两个 fixture 修正方法，2 / 0.002 秒 / OK / exit 0，未改源码。
- ROOT a14384 窄审建议只将 alias 目录 profile proof 改稳定五字段；
  00a7b1：新增目录 counter 合法变化、link mtime/target/inode 拒绝及当前 AST 方法，
  1 / 0.022 秒 / OK / exit 0。没有重新运行已通过 11 项。
- 旧 14 个不同方法分批通过，不声称单批 14 PASS；2ceffe 元数据读回 exit 0。
  来源 F 1b2b/Provider 8bb5 在 8d3626 仍原 SHA；common 仅作者稳定后读入。
- Fake 实际调用 _ReadOwner / Provider / FixedTmpAnchor 方法；7 个 original FD 的
  once close / EBADF，ordinary 5 FD、partial-prefix、foreign-ticket、same-leaf、
  private modes/nlink 和 sticky unknown 均有覆盖。未调用正式 20 图 source_check。
- 047df1：仅新增实际 Provider callback/verify/close/generation 方法与受影响
  source-boundary/AST 方法，2 / 0.076 秒 / OK / exit 0；没有重跑旧 14 方法。
  新方法涵盖四目录 counter/time/size、7 原件 once close/EBADF、partial-prefix
  known close；private/ordinary nlink、prefix ino/permission、零 nlink 仍拒绝。
  旧 308a 与 2c823 的历史证据保留；当前 15 不同方法是分批证据，不是新整批。

所有批次均禁止实际 OS/native/process/socket/RF；不重复旧 suite、不签手机或
P011 资源恢复证据。没有 deploy、execute-reviewed、清旧 pending 或隐式恢复。
