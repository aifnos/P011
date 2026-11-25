# V9 当前状态窄只读诊断

本入口仅收集当前事实，不恢复、不清 pending、不授予删除/网络修改权限。新三文件独立；旧 readonly、V9 runtime/helper/frozen 与历史 FAIL 不改。

## 已证实的离线差异

- 固定 `091400-682a4364` 实际 05before 与 11after RESULT 全字段完全相同。旧 `full_current_baseline_unchanged=false` 是额外 Wi-Fi completed 前置 false，不是这次读回发现变化。
- 与固定 `084811-e064eae6` functional15after 相比：same boot、原网络六行 PID/starttime/exe/cmdline 身份、stock、pending 相同；STA fingerprint/frequency/interfaces/IPv4/main-route/IPv6 route 已不同。
- 两次之间 GET_INTERFACE 记录 2→0、STA completed true→false；IPv4 地址 3→1/全表路由 10→4/规则仍 3 且相同。按旧精确 ifindex 分类，原 STA 地址/路由和 owned 地址/路由均已不在新 dump；IPv6 地址 raw 相同、路由 4→3。
- 这些是读回差异，不是造成变化的动作或归因证明；不能凭此称 pending 已恢复、原 sysfs/netdev 精确删除。旧 actor 失败只有 `actors/schema_or_read_error`，没有具体异常记录。

## 固定边界

- CLI 只有 `python -B host/device_p2p_v9current_triage.py --check-readonly`。
- 固定现有 V9 candidate `1d695a9e8056e11f`、full manifest `1d695a9e8056e11f20039cd3f5b3f6982645a61993f7013fbd76d81064df8c06`、当前唯一 owned RUN 与全部八文件 pins/size/owner/mode/nlink。
- 固定 bounded reference SHA `20e816a946ff4a4470db61134ca38f22f342e3cdac55711b8ac2e0dc52b75fea`；只复用其纯 source/parser/metadata/完整 baseline/raw 保存机制，不调用旧 runner、不改旧 globals。
- 当前八文件初次及最后独立 metadata 全核对；完整当前 baseline 在前后独立读回。实际唯一执行只能由 ROOT 在审查后决定；没有 stage/push/mkdir candidate/chmod/锁/allow_rf/controller/recover/DELADDR/地址写/重试。
- 目标采用 Python 3.5/p011_json 与固定 READ_HELPERS；载荷各行 UTF-8≤2048、总量≤256KiB、AST3.5、无 assert 动作。50s 传送预算不变。

## 相互独立的两轮子观察

- journal：严格 version3/current identity/envelope，same boot、主阶段、IP 阶段、owned 有记录、原 private process 的双重 `/proc` absence 观察；异常固定 enum/errno。
- pending：只读 safe/valid/lock metadata、固定 RUN、same boot；不获取锁或修 journal/pending。
- actor：最多 512 numeric PID，每 PID deadline；非空 cmdline 必须 NUL 终止/≤64KiB，empty stat 至少 20 字段，严格 PID/comm/state/flags/starttime 范围。
- empty kernel、已确证 disappeared、empty user zombie、empty unknown、字节上限、截断、errno/opaque 分别固定 reason/count。空 user/Z/unreadable 不作为 actors/resources gone；仅已确认 `/proc` 消失计数，不推断未访问的其他资源。
- 已观察 empty user zombie 时附加一次 `/proc/<pid>/task` 数量（1..512）；未知保持 recorded=false/count=None/有限 errno，不能把 task=1 或 Z 推成全部资源释放。首因仍是 `empty_user_zombie`。
- actor private 比较只采用 PID、cmdline digest，以及 empty stat 严格解析的 PID/starttime/comm/state/flags；CPU tick 不属于 identity，未用于 equal。原 stat/argv 仅在目标观察内存，绝不进入 RESULT 或公开报告。
- owned：独立 GET_INTERFACE，固定 name/WDEV/ifindex/phy 的存在、四元匹配/碰撞/type；sysfs 存在、ifindex/flags 及 read errno 独立。无 matching row 是已观察 absent，不是恢复/删除授权；未知用 recorded/complete=false，不伪造 absent。
- 不读 carrier，不改变旧 creation/restore gate。子观察失败仍保留其他子观察；未知或 constructor/close 不可确认时 complete=false。
- GET_INTERFACE 只创建一个 exact netlink socket；partial constructor 尽量保留对象，finally 关闭确知资源；只有完整构造+强引用 socket 实际 fileno==-1 才报告 closed=true。close 无异常但未关、未知构造均失败。

## 报告语义与证据层

- `current_baseline_equal` 只表示前后完整数据相等；`before_wifi_completed`、`after_wifi_completed`、`wifi_completed_preconditions` 独立，不把 Wi-Fi false 命名成网络改变。
- `same_boot`、stock identity、原进程身份、interfaces、STA state、全部 IPv4、原始 IPv6 数据前后相等分别固定 bool；原记录/标识只存在 private raw，不公开地址/SSID/MAC/PID/argv/path。
- PASS 仅完整同次只读观察、两轮一致、exact FD 关闭及前后完整数据/metadata 一致。已知 actor presence、owned absent/type mismatch 是事实，不是安全恢复结论。opaque 子检查依旧不能给 complete。
- 永久 `network_mutations/device_writes/recovery_invoked/retry_invoked/send_available/authorization_or_lock_held=false`，历史停止原因仍 `NOT_PROVEN`。
- Linux 4.14 `exit_files` 与 `exit_notify` 的阶段不能让空 cmdline/Z 成为完整资源关闭证明。ROOT 已核对 [官方 exit.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/kernel/exit.c)；本入口不 reap、不 kill、不自行恢复。

## HOST 专项

唯一专项命令：`python -B -m unittest tests.test_device_p2p_v9current_triage -v`。

首次命令工具 `1cc876` 在 import 即 ERROR/exit1/实际 0 tests：新 HOST 引用了只存在生成 target namespace 的 MAIN_STAGES，已仅修正映射至旧 HOST 的 STAGES；错误记录保留，不改旧模块。

最终相同专项工具 `80e5f1`：15/15 HOST PASS、0 FAIL/0 ERROR、3.655s、exit0；没有重复已通过专项。覆盖 CPU tick/private identity、空 user/Z/task 未知、读取 errno/disappeared 双核对、owned absent/collision/type/sysfs、单项失败保存其他事实、exact FD 关闭、unknown schema、固定全八 pins/短行/Python3.5、超时/marker/raw 完整、Wi-Fi false 与前后相等分离。

只有 fake /proc/sysfs/netlink/ADB、固定 source/pins 静态核验。没有实际 socket/ADB/RF/Docker/完整 suite/正式 freeze/手机兼容或恢复试验。
