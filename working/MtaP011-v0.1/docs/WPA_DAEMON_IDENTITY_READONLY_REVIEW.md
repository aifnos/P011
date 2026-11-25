# 原 WPA daemon／端点事实只读检查器（待审）

仅新增 `host/wpa_daemon_identity_readonly.py`、对应 Fake 专项、本 review。未改旧 collector、helper、runtime、原厂或 pending。作者不执行 actual OS／WSL／ADB／RF；ROOT 审查最终源后才可唯一实际收集。

## 固定来源与入口

- `device_probe.py` 完整 pin `e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348`；只使用未修改的 `select_target`／`Adb.run`，不调用旧 `PROBE`、`run_probe` 或宽松 `Adb.python`。
- target 内存加载：IP `1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5`、CLIENT core `ec2d927c50bf2946614990bdd9fe1d69ce5538047573d9a4d885a3914b0f85f1`、ProcReader `2f0ef52379be897d47b5cb311ef90f24b5c8a2c283e72780f139a8dd77626591`；SHA 后才 exec，仅纯类定义。闭合模块导入域，不使用 mutable 候选目录／sys.path／staging。
- target Python3.5.5，无 json：唯一 `RESULT=repr(primitive)`；host 精确字面量解析。完整 traceback 仅 private payload，不打印 target stderr，避免 PTY 合并污染 stdout。只剥离与当次完整 source **逐字一致** 的 echo；任意额外／截断／修改行拒绝。
- 默认 source-only；显式 `--execute-readonly --expected-checker-sha256 <最终完整SHA>`，没有路径、argv、daemon、port、接口或命令参数。同 host 进程单次，不 retry／repair。

## 真实收集与事实边界

1. 有界 `/proc` comm 选择：仅恰一个原 `wpa_supplicant`；多／无／未知拒绝。PID/start/exe/argv/完整 task 与 boot 使用固定 ProcReader 的两个 actual passes；不重写 stat 解析。前后 actual Actor 观测围绕全部 identity/endpoint 读取。
2. 同 actual `/proc/<pid>/exe` 原 FD 读取全部字节并 SHA，ELF/root-owner/不可非信任写/执行位及 FD metadata 前后相同；private 保存完整 hash、字节数、metadata，不复制整个 ELF 入日志。不得从 CLI file-only SHA 推 daemon SHA，也未把首次观测 hash 当 production manifest。
3. actual cmdline 仅解析 `-i/-C/-O/-g`，支持 getopt 连写／分写，重复／缺参拒绝；`-i` 必须唯一 `wlan0`。不读取 `-c` 配置或凭据；其 private raw 仍敏感。`-O` 只记录，不冒充接口命名空间保证。
4. actual UID/GID 四元均 root；daemon/self 的 mnt/net/pid/user namespace 标识前后相同。此为同时观测事实，不抵抗 hostile root、不认证未来 STATUS。
5. `/proc/net/unix` strict format＋exact daemon FD 的 `socket:[inode]` 关联，必须恰一个 **已观测** pathname DGRAM，basename 来自 actual `-i wlan0`，不猜 `/run` 或 `/var/run`。已声明 `-g` global socket 不当 interface endpoint；abstract、不支持形状、无／多 endpoint 拒绝。
6. filesystem pathname root→socket 每级 lstat 前后完全一致；初版仅 canonical 无 symlink profile、root-owner/非其他可写目录，socket 可 group-write、不可 world-write。symlink-profile 被记录并 FAIL，不自动 canonicalize／修改，不能称 daemon 不支持控制。metadata 在拒绝前保存在 private，便于 ROOT 决定后续严格扩展。
7. sockfs/kernel inode 对应 daemon FD；**不与 filesystem lstat inode比较**。Linux v4.14 `unix_seq_show:2664–2701` 输出 `sock_i_ino`；实际绑定的 filesystem dentry 有独立身份。[官方源](https://github.com/torvalds/linux/blob/v4.14/net/unix/af_unix.c#L2664-L2701)。这是只读归属观测，不是回复凭据认证；[WPA control 协议](https://w1.fi/wpa_supplicant/devel/ctrl_iface_page.html) 的 STATUS 不在本次执行。
8. 最后 actual Actor/boot 及完整 task 身份库存 `(tid,start)`、image/argv/UID/GID/namespaces/端点链完全一致；`Actor.key()` 不比较易变 task R/S state。`wlan_observed` 仅在实际读取接口列表后为 true；未读取不当缺失证据。已观测 `wlan0` 缺失也保留已得事实并 FAIL，不开网、不修复。不读取／修改旧 GO marker，也不推断 wlan0 的管理服务或损坏原因。

## FD、预算与证据

所有读取前登记 exact fs/path/flags/未知创建；返回原 FD 立即保留，明确 metadata 后才一次关闭，再 actual EBADF。异常/畸形返回/close未知 sticky，保留 strong refs、阻断后续新读取，不重close。ProcReader 库存闭合独立依其 actual observation；两个计数域分列，不声称进程全部 FD 已关。目标 `OWNERS` 保持 exact collector/reader/IO refs 到 Python process 结束；未知不因此升级为关闭证明或持久恢复票据。

target 20 秒 admission/读取预算，非 OS 硬抢占；read 次数≤1024、总内容≤8MiB、Unix dump≤1MiB/4096行、完整 image 上限64MiB但仍受总预算。ProcReader 自身每轮3秒/原有数量上限；两轮最多560 FD。host 一个命令30秒外层 timeout；原 selector 自身≤15秒，故不能宣称整体硬20秒。同步 listdir/lstat/readlink 的 OS 时间不能抢占。没有 child/socket/锁创建。

公开仅 fixed enum/bool/count 与固定源码身份；所有路径、PID/start/boot、argv、daemon image SHA、namespace、Unix raw/FD 表、metadata/traceback 留原 `private-raw`。仅固定 result/README 进入新 sanitized ZIP，不覆盖原 FAIL。实际 Adb command stdout/stderr/host-exit 与独立 remote-exit 保留；正常返回另要求已保存 host stderr 实际存在且为空，不因已保存 raw 容忍非空 stderr。若派生 remote-exit 写入也失败，不覆盖先前解析／host 首异常，两者 exact refs 留私有执行 registry；该情况不作成功。selector enumeration raw 沿旧 helper 未单独捕获，明确缺口。

`device_command_attempted` 只代表进入固定 Adb.run 调用；`device_reply_confirmed` 只在完整合法 frame＋remote exit0＋空 host stderr 后为 true，host 启动／未知失败不得称已送达。有效 remote reply 也不意味着 `facts_complete` 或本次 PASS。

`facts_complete` 仅本次只读事实收集完成；`daemon_manifest_authenticated/namespace_authenticated/status_sent/socket_created/rf_operations/receive_available/send_available` 固定 false。网络全 IPv4 tables/rules／原网恢复／P2P CLIENT／手机互通均未评估或未测试，不开放生产。

## HOST 分批证据（作者已停写；待 ROOT 实际审阅）

首批工具 `07ed8f`：`python -B -m unittest discover -s tests -p test_wpa_daemon_identity_readonly.py -v`，17 方法全部 PASS；unittest 0.183s，shell wall 0.615048s，exit0。该批在新增 `wlan_observed`／入口 Fake 之前，保留原证据，不伪称最终21方法单批全通过。

最终受影响批工具 `a5337b`：仅4新方法＋4受影响命名方法（missing wlan／早期失败／严格投影／Py3.5 AST），8 PASS；unittest 0.140s，shell wall 0.6062886s，exit0。新 FakeAdb 只内存路径/ZIP/raw，核单次 fixed command、精确完整 echo、stdout/stderr/host exit/remote exit 分开、未知 frame／非空 stderr 拒绝、首异常与派生输出异常 exact refs、二次执行零新命令、public pair 不泄漏 private。共21个不同方法，未重复跑原17整批。

上述仅 Fake filesystem/typed ProcObservation/clock/严格 frame/AST；真实 open/kill/fork/wait/socket/subprocess/ctypes tripwire。实际源码组件纯加载，不签真实 daemon、namespace、endpoint 或生产权限，不执行目标入口；无 actual OS／WSL／ADB／RF 测试。ROOT 得到最终 checker 完整SHA、阅读全文后才可显式运行一次，不依据本 HOST 批开放发送/接收。
