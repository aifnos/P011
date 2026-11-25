# 当前 PTY 与 exact prior-readonly actor 只读核查

本入口针对 V9 `initial_prior_journals` 的 HOSTTIMEOUT 后证据缺口，不运行/重试 V9，不修改其 FAIL。旧报告没有该步实际 RESULT/OK/REMOTE_EXIT；placeholder 数值不是远端成功。此文件只有 HOST fake 证据，ROOT 尚未执行本入口。

- 唯一执行入口：`host/device_tty_actor_readonly.py --check-readonly`。import/tests 不构造 ADB；无任意 target/command CLI，固定一次短压缩 argv `Adb.python`，调用前校验总 command <3500 bytes，永不采用长源码 stdin 分支。
- target 固定源码总预算 8192 bytes、单行 2048 bytes；Python 3.5 AST 通过。只 import os/time/可选 termios，读 fd 0 的 isatty/tcgetattr，以及两次 /proc cmdline/stat 快照。没有 tcsetattr/stty-set、signal/kill、cleanup、远端 Popen、socket、RF、设备/用户文件写入。
- exact 分类须完整五 argv：`python3`, `-B`, `-c`, `import sys;exec(sys.stdin.buffer.read(32270))`, `mta-prior-readonly`，完全字节相等。
- 同五 argv 模板但不同的规范十进制 read count 单独计 `other_read_count_actors`；任意其它 argv 中出现 exact `mta-prior-readonly` marker 计 `other_prior_marker_actors`，不静默归零。shell compound 字符串不是 exact marker argv；没有据此宣称所有 shell/系统资源不存在。
- 每快照限 4096 个目录名、512 个 numeric PID、每次 cmdline/stat read 4097 bytes、迭代间 deadline 2 秒。所有非瞬时读取/shape/截断错误令 snapshot_complete=False；ENOENT/ESRCH 最多有限忽略 32 次。限时不声称可抢占单个内核读操作。
- 已匹配 actor 读取 starttime→再次 cmdline→再次 starttime，须完全一致。两快照比较私有 PID/starttime/完整 argv/class 的 identity set，不仅比较计数。私有身份仅留 target 内存，不公开或写用户数据。
- 公共 target 仅 tty bool/None、三种 actor 的两次计数、两 snapshot 完整性与一致性 bool。无 PID、exe、argv、IP/MAC、异常文本。HOST validator 拒绝扩展字段、bool 冒充 int、缺字段、超限和不一致。
- `tty_mode_observed=True`：本次新 PTY 实际 tcgetattr 通过，icanon/echo 为实际 bool。`False`：非 TTY/观察失败，两个 flag 为 None。`None`：当前 Python termios import 不可用，固定 unsupported，两个 flag 为 None。
- 当前 PTY mode **不证明** 上轮 timed-out actor 的实际 termios。两次 actor 0 **只表示本轮范围观测**，不证明所有资源已闭合。PASS/check_complete 仅完整一致采证；另列 observed_prior_marker_actors_zero，只有全部三类在两次均 0 且快照完整一致才为 True，仍不是 RF/恢复授权。
- 原始 ADB stdout/stderr/host exit 留 private-raw；新公开 ZIP 只有 result.json/README.txt。旧 candidate/source/pins/日志不改，不混入任何 private/raw 文件。

## HOST 专项

`python -m unittest discover -s tests -p test_device_tty_actor_readonly.py -v`：14 run，14 PASS，0 fail/error/skip。目标程序只在 fake os/open/time/termios 中 exec；dispatch 只有 FakeAdb、临时 HOST 结果文件与公开 ZIP/CRC 检查。

覆盖完整五 argv、不同 read count、所有 malformed marker、同计数换 PID/starttime、读取权限/瞬时 race/过限、截断/缺 NUL、deadline、termios 缺失/失败/非 TTY/实际 flags、严格 schema、唯一短 invocation、源预算先于 ADB/输出、异常脱敏及 actor 存在不冒充 zero。

未实际 ADB、TTY、/proc 读取、设备操作、RF、Docker、全套测试或新候选 freeze。ROOT 后续完整审核并唯一实际执行后，另生成当前观测证据；不得反向升级旧 V9 FAIL。
