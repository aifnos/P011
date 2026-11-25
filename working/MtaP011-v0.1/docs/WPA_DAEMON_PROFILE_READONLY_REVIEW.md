# 原 WPA facts：source-v2 实际 root-owned 链接窄适配（作者已停写，待 ROOT 审）

仅更新这三个版本化工作树文件；不改 be59 原 checker、已冻结 source3901／f14e27、旧失败、runtime、helper、collector 或 pending。作者不执行 OS／WSL／ADB／RF／目标入口。默认 source-only，ROOT 全文审新完整SHA并新冻结后才可唯一显式执行。

## 依据与未升级的证据

ROOT 首轮 `1c535a` 原 facts：checker host1，ADB command host0／remote0、空stderr、daemon1，在 identity_before 的 `ns/net` errno2；原200 own＋12 ProcReader FD 闭合、无pending。该 FAIL 和七源冻结保持。ROOT 后续 `c02b52` 固定 kernel-profile，`762061` 核raw/public/ZIP：实际4.14.174、self ns目录稳定为 `('cgroup','mnt')`，实际 config.gz 明确 `# CONFIG_NAMESPACES is not set`／IKCONFIG=y；NET/PID/USER符号 not_listed，**不是逐项读到=n**；wlan0实际存在。以上是 ROOT 报告的独立实际层，不是本作者 Fake 测试。

ROOT `b057a9` 唯一 source3901 实际：reduced namespace／映像读取成功，但 endpoint_before 发现 root-owned 父symlink，旧DIR-only规则拒绝；203 own＋12 ProcReader 全关闭。`4727ae` 核raw/public，候选端点恰1，path depth0/1是root nonwritable DIR，depth2是root symlink；link权限777不是DIR可写性事实。`logs/…112222-53bfe993` 原FAIL及冻结保持，不能推daemon损坏或控制回复已认证。本次source-v2只修此有证据路径profile。

[Linux4.14 fs/proc/namespaces.c:13–34](https://github.com/torvalds/linux/blob/v4.14/fs/proc/namespaces.c#L13-L34) 按 CONFIG_NET/PID/USER_NS 决定条目；mnt无同样条件、cgroup由CONFIG_CGROUPS决定。[init/Kconfig:817–871](https://github.com/torvalds/linux/blob/v4.14/init/Kconfig#L817-L871) 在 `if NAMESPACES` 内定义子选项。lookup本身也可能因进程消失ENOENT，故绝不只凭缺失推禁用或同namespace。

## 机械复用与精确变化

完整固定旧 source `be59afc4ebda920db84075d509a1dec4e630a70590263eefa5754b9c13a2ad56`，path/metadata/bytes/SHA后仅新内存module域exec；旧源码/global不改。继续用旧固定三runtime内存loader、ReadFiles、Collector主体、`_remote`／空stderr／完整frame／once强ref输出。每一机械片段替换数量必须exact1，否则 source-check FAIL；新target独立AST3.5、长度／行界限仍原值。仅namespace观测、公开profile及source-v2的路径chain块变化；不改daemon选择、actualexe hash、Actor/FD、实际Unix-row/daemonFD匹配、端点唯一/原basename或原资源规则。

1. 双方actual ns目录先读，≤8个，名称仅官方固定8项、无重复，daemon/self集合必须相同；每个已存在条目实际readlink＋canonical格式＋双方一致。`pid_for_children`实际link前缀为pid。列出却缺link、权限错误、未知/多/空/改变仍FAIL；缺失不生成 `(None,None)`、假inode或假equal。
2. `full4_present`：actual目录同时含 mnt/net/pid/user，所有actual额外条目也读回；不需config，不猜其他条目。两轮目录、links与身份均稳定才profile_complete=true且namespaces_equal=true。
3. `namespaces_disabled_cgroup_mnt`：目录只允许exact `('cgroup','mnt')`，actual `/proc/config.gz` 原FD有界读回、gzip严格解压；NAMESPACES设置唯一且明确not-set。两轮actual cgroup/mnt links相同、完整decompressed config SHA相同才profile_complete=true；**namespaces_equal仍false**。不把NET/PID/USER not_listed转成已观测n。
4. gzip compressed≤256KiB、decompressed≤1MiB；要求EOF、无unconsumed/unused/trailing/串联member、CRC正确、ASCII／无NUL／末尾换行。config缺失、重复/矛盾/不支持字段或两轮完整配置改变FAIL，不 fallback。

identity私有保留实际 `namespaces` links 与 `namespace_profile={kind,names,config_sha256,config_namespaces}`；config完整compressed bytes和原FD metadata沿旧private读取记录保留。public仅新增 `profile_complete` strictbool、`namespace_profile`固定3枚举、`namespace_count`有界整数。尚未完整读取的profile是not_recorded；profile_complete不认证来源、不签namespace／reply／restore。`namespace_authenticated/daemon_manifest_authenticated/status_sent/socket_created/rf_operations/receive_available/send_available`仍false；完整IPv4/rules／P2P／手机未评估。

## source-v2：真实物理父链，不猜 fallback

`source_version=wpa-profile-v2-owned-path-links`。最多8个实际root-owned symlink（模式777不套DIR可写检查）；每个原lstat／实际readlink／再lstat一致，保存exact target与metadata。相对target从已经解析的物理parent继续，绝对target重走root；组件逐个解析，遇中间link先读实际target，再按物理stack处理 `.`／`..`，**不得先normpath消除linkComponent/..**。向上超过root、NUL、未知/多/循环/途中改变均拒绝。每级actual resolved DIR仍root且无group/worldwrite；最终actual canonical SOCK仍root且无worldwrite，原socket groupwrite规则不变。不假设 `/var/run→/run`，不修改link。

target/path≤4096B、组件≤64、lstat遍历≤256、链接≤8，同原单调budget。`endpoint.chain` 私有tuple现在每项 `(actual_path,metadata,target_or_None)`，包含重走原链／canonical socket；两轮整个chain与实际target必须完全一致。private `path_links` 保存link前后metadata，`path_observations` 保留拒绝前事实。普通项None仅表示该项非link，不是缺失namespace。kernel sock inode仍来自原Unix-row＋daemonFD，不与canonical filesystem inode比较。此链观测不认证将来STATUS回复、source producer或网络恢复。

## 入口、资源与预算

无任意路径/namespace/命令CLI。实际入口仍需 `--execute-readonly --expected-checker-sha256 <新完整SHA>`。使用未改 device_probe pin `e7a841…9348` 的 selector/Adb.run，禁止旧PROBE/run_probe/python；selector raw缺口不变。attempted只表调用，reply_confirmed仅完整合法reply＋remote0＋空hoststderr。host/stdout/stderr/exit/private traceback分开；仅新result/README进sanitized ZIP，不覆盖历史。

全部原FD只once关闭／actualEBADF、未知strongrefs／不重关等沿旧约束；新增config读同ReadFiles账本，无socket/child/锁。20秒target admission、30秒host命令及15秒selector边界仍非OS硬抢占；总读取8MiB限制不变，gzip输出额外固定≤1MiB。未认证Socket namespace或daemon manifest，也没有生产source producer装配。

## HOST 精准批次

仅新namespace Fake场景＋旧typed ProcObservation／纯模块定义复用；测试fixture旧三源SHA固定，不把fixture作生产import。真实open/kill/fork/wait/socket/subprocess/ctypes有tripwire。本批不重跑旧17／8、不运行actual checker。

首批工具 `381abc`，`python -B -m unittest discover -s tests -p test_wpa_daemon_profile_readonly.py -v`：16不同方法，4 PASS／12 ERROR，unittest 0.175s，shell 0.6198312s，exit1。ERROR统一为测试fixture把动态 `_project` 放class字段，self自动绑定多传参数；不是生产投影放宽。保留首FAIL，只改fixture staticmethod；原片段字面量改raw消除warning，生成片段语义不变。

工具 `c3b0b6` 仅12错误方法＋1直接受影响Py3.5 AST方法，13 PASS，unittest 0.122s，shell 0.5940388s，exit0。其余3首批已过方法未重复；16不同方法不是最终单批16。涵盖full4/reduced、实际额外条目、缺/多/变目录、listed link missing、config证明/截断/CRC/双member/尾bytes/超界/重复矛盾、身份改变、wlan缺失、FD unknown、私有投影及无副作用默认入口。此次是纯HOST Fake/source，不认证实际P011/profile或生产producer；完成即停写供ROOT及独立全文审阅。

source-v2工具 `0631e3`：仅10新增路径Fake方法＋3直接受影响机械source／reduced正向／Py3.5 AST，13 PASS，unittest0.127s，shell0.5996939s，exit0。相对/绝对/点组件、实际中间symlink之后..的物理语义、8允许9拒绝、cycle、foreign owner、可写resolved parent/socket、lstat变化、target跨轮变化、缺/长/超界、private不泄漏均覆盖。未重跑已过16整批，共26不同方法，不是26单批PASS。ROOT指出的先normpath风险在首次新批前即窄修，不存在被隐去的该批失败；未执行actual checker/新ZIP/设备动作。

独立终审随后指出最终 symlink target 尾斜杠的目录语义不能被空组件过滤抹掉；[Linux4.14 namei.c](https://github.com/torvalds/linux/blob/v4.14/fs/namei.c#L2125-L2189) 保留该目录要求。ROOT只增加 `target.endswith('/') and not pending` 的保守拒绝，补一个绝对/相对/重复尾斜杠定向方法。`5c827c` 仅1新增＋3直接受影响方法，4 PASS，unittest0.103s，shell0.5244822s，exit0；当前27不同方法，非最终整27套测。af8bb72a预实际来源快照与原13PASS保留，未执行该预修版本；需新完整SHA和新冻结后实际。
