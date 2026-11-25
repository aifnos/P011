# HOST 隔离实际子进程登记检查器（待 ROOT 审阅）

仅新 `host/client_launch_registration_linux_check.py` / 对应 tests / 本 review；C、B、旧 core/owner 和旧 checker 不修改。本作者只 Fake 专项，不运行实际 OS/WSL/ADB/RF。此处源码完成不等于 ROOT 已批准真实执行。

## 固定来源 / 默认不执行

自包含 pinned loader：固定 11 runtime（9 个 B 依赖 + owner `0a9a02…` + C `833d46…`），完整 C test/review 两参考 pin；不 import 旧 checker，不改全局旧模块。源码/AST/顺序/额外项目导入/精确当前 checker SHA 任一不符，fixture 前拒绝。默认仅 `--source-check-only`；真实模式必须 `--execute-reviewed --expected-checker-sha256 <审查后的完整SHA>`，无任意 path、binary、argv、候选或 SHA 命令参数。同进程只执行一次，不重试/自动恢复。

## 实际与合成边界

未来明确实际模式只 root Linux：新 private0700 `/tmp` fixture，3 个 default Linux io 只逐实例 open_root 映射，真实 global pending 根绝不访问。实际 ProcReader 两 pass / same boot / full live 单 task / 文件确关闭；DirectChildOwner 保持 default os（不传 `_os` 或放宽单线程），真实 fork/dup/fexecve 门链。

固定 `/usr/bin/sleep`：root NOFOLLOW/CLOEXEC 打开真实普通 ELF，完整 SHA / size / mode / owner / nlink / FD+entry 元数据前后核验，该次 hash 固定进 LaunchSpec；两个实际 owner binary 原 FD 再核同 SHA 与初读 metadata，分别固定 argv `4`、`2` 秒。初读原 FD 单独保留和关闭，不是生产 manifest。无 PATH fallback / native WPA / RF / signal / kill。

prepared 的授权 deadline 固定为当次 clock +18 秒，遵守 B 的首次剩余时间不大于20秒合同；文件 IO / reap 预算分别限定，不延长 Journal 授权。未实际验收 RF TTL 超时。

实际 prepared / own marker → watchdog intent → 真 preexec sidecar durable callback → 门写 → 同 boot/PID/start 实际目标 exe/argv → postexec sidecar / 最终 fresh actor → watchdog saved → **合成** interface intent/owned → controller 同真实链 → saved。stock/network/baseline/interface 和 restore producer 始终 synthetic，production Provider/P011/phone/RF/production manifest 全 false。旧 ClientInitLease.start 的两阶段接口未通过本 checker 改写。

## 原资源、失败与收尾

Store、C sidecar、child owner 分别 original tickets / close 事件 / EBADF 库存。3 个 io.close 被动 observer 同时看 exact Registry rows，避免 C 关闭误被标 unknown；child 只包原 `_close_fd` 被动登记，任何 observer 异常仍调用原方法，不 patch os.close。组件原 device 关闭必须在 Store+C 关闭记录最后；child 与 sleep-pin 已先核确关闭。fixture setup / 独立终末读回 / 结果 writer 的 FD 不当这三库存或进程“全 FD 关闭”证明。

每个 known child 先实际 saved PID/start/boot + waitpid 原 child reap + fresh 两 pass absence，才 close 其余原 owner inventory；不会用整 owner.close 代替 wait。成功门后只等自然退出。门前失败仅 exact owner 的 known、未 attempted/unknown gate-write FD 可一次 close，让已登记子进程 EOF 自行 exit125；125 不是成功。unknown fork/PID/FD / parent F 变化保留 pending/strong refs，绝不猜或 kill。

门前闭合还要求 child.unknown=False，不能用仅 gate 票据已知替代整个生命周期未知。已登记但确证未 fork 的票据不计入 actual reap/absence；即便两票俱在，也不会把“没有启动”写成“两个子进程已回收”。

只有 actual child / C / sleep pin 确闭合，才允许 fixture synthetic restore producer 发本次 exact fresh tuple；实际 Store finish reconciled CAS → own marker unlink/fsync/ENOENT → 全 original component inventory/device-last。任何失败保存第一 stage/reason 和每次 private traceback；后续 cleanup 成功不将第一 FAIL 改 PASS。

fixture / sidecars / journal 留存；public 仅固定 bool/计数/enum 与 source pins，boot/PID/start/argv/路径/完整 sidecars/traceback 在 private observations。结果 xb 新目录，原始 FAIL 不覆盖。

## HOST 定向测试记录

PC Python3.12.0 `-B`，真实 OS open/mkdir/fork/exec/kill/wait/ctypes/socket/mkdtemp 全 tripwire。新 Fake fixture 使用固定加载的实际 11 个组件，不 mock 正向组件准入返回。仅本新 checker 专项 + Python3.5 AST；不重复 C/B 旧已通过方法，不项目套测。没有 actual Linux 子进程结论。

- 首批前静审修正：仅 checker 的 prepared 25→18秒；private formatter递归 list，新增1方法核实 launches/child_exits/failures 原值完整保留。未运行的草稿不是失败证据，不编造一个先前测试批次。
- 首次工具 `8371c7`：`python -B -m unittest discover -s tests -p test_client_launch_registration_linux_check.py -v`。24方法，18 PASS /4 FAIL /2 ERROR；unittest 0.924秒，host wall 1.3577228秒，exit1。6失败均被新 checker 错误查询 row.role='binary' 提前拒绝，固定 owner实际原票据是'executable'；2 ERROR是新测试未进入其注入阶段导致captured无child，不是实际设备错误。原首判保留。
- 窄修仅新 checker 的 role，及对应负例识别；同时修 known-no-fork 分支不得标两个 child reaped/absent，新增1直接分支方法。固定11 runtime无任何变更。
- 精确受影响工具 `769c18`：仅首批6失败方法＋1新增known-no-fork方法，7 PASS /0 FAIL /0 ERROR；unittest 1.016秒，host wall 1.4388807秒，exit0。首18 PASS（含 list 新例）没有重跑。不合计为31方法或整项目套测；当前25不同方法各有实际通过证据。
- `datetime.utcnow` 在PC3.12输出弃用警告，保留3.5兼容写法；不是失败/设备结论。默认实际 owner 不传 `_os`，仅 Fake fixture 的显式 private seam 使用FakeKernel，HOST测试不赋予真实Provider或P011许可。

最后变更范围仅这3个新文件。ROOT与独立审阅完成、重新核精确checker SHA后，才可能由ROOT单次执行真实隔离Linux候选；本作者不运行该模式，不归档actual PASS。
