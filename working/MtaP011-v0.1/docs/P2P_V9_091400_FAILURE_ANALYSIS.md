# V9 当前只读检查失败：事实与未证原因

2026-10-01 09:25；ROOT 唯一执行 `device_p2p_v9restore_readonly.py --check-readonly` 后的离线分析。没有新的 RF、网络写入、恢复、重启、候选部署或权限修改。

## 实际结果与字段语义

固定结果为 `logs/MtaP011-V9RestoreReadOnly-20261001-091400-682a4364/result.json`，原 FAIL 和全部原始输出保留。

- 11 个远端步骤均 host exit=0、remote exit=0、结果解析有效。
- 四组固定候选的前后文件身份/元数据相同；两个精确 netlink socket 已实际关闭。
- 子观察止于 `actors/schema_or_read_error`，observations 为空。它没有完成当前 receipt/origin/IPv6/完整 baseline 门禁，不授予任何恢复写入授权。
- 两次独立完整 baseline 的实际字典 **完全相同**；query_ok、stock_valid、ipv4_complete 都 true。
- `full_current_baseline_unchanged=false` 是旧入口同时要求 `wifi.completed=true` 的复合判定结果，两端 completed 都 false；不能把该 false 解读为本次只读检查改变或破坏了网络。
- 这两次记录的 station_identity_ok=false、GET_INTERFACE 列表为空、frequency=0。它们是当前观察，不是 PHY/固件损坏的诊断，也不能由列表为空宣称所有临时资源已清理。

## 跨轮变化是真实的，但因果尚未知

离线比较 084811 功能轮的 15-after 与 091400 的 05-before：

| 比较对象 | 结果 |
| --- | --- |
| boot、原厂身份、6 条网络进程 PID/starttime/exe/cmdline、pending | 相同 |
| 原 IPv6 地址完整记录 | 相同 |
| 原 STA 连接 | completed true → false |
| station / GET_INTERFACE 行数 | 1 → 0 / 2 → 0 |
| 完整 IPv4 地址 / 全表路由 / 默认 rules | 3 → 1 / 10 → 4 / 3 → 3，rules 相同 |
| 旧 STA ifindex 的 IPv4 地址 / 路由 | 1 → 0 / 5 → 0 |
| 旧 owned ifindex 的 IPv4 地址 / 路由 | 1 → 0 / 1 → 0 |
| IPv6 route 完整行 | 4 → 3，有实际行消失，不只是计数漂移 |

新 IPv4 地址与路由都是旧记录的精确子集。变化发生于两次观察之间；没有当前证据确定时间、用户动作、原厂策略或修改的因果。没有 reboot/PID 重启证据，也没有 receipt restored、接口精确清理或 pending 清除证据。

084811 的 GO_IP_READY 与 confirmed 是事实，但 cleanup FAIL 仍是 FAIL；地址后来不在 dump 中不能把该轮补判为成功。

## 进程观察与后续最小诊断

旧 actor 检查遇到非 kernel 的空 cmdline、截断、不可读或消失 race 都拒绝；091400 没有固定子原因/errno，所以具体是哪一种仍未证明。

新独立诊断应分别保留 actor 分类计数/固定原因、journal/pending、owned 四元与 sysfs、当前完整前后相等及 Wi-Fi completed 前置；子观察失败不能遮住其它已取得的事实。没有锁或写入，不把 zombie、未知 PID 或空 cmdline 当作已退出。

Linux 4.14 上游 `do_exit` 先调用 exit_files，再由 exit_notify 置 EXIT_ZOMBIE；但线程组 leader 可为 zombie 而线程组尚非空，因此 leader 的空 cmdline/Z 不足以证明其它线程和资源都退出。[Linux 4.14 kernel/exit.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/kernel/exit.c)

固定 V9 main 的 watchdog 回调没有保存 start_watchdog 的返回 PID、没有独立 wait/reap 证据，这是后续新 owner 应补齐的静态风险，不是本次 actor FAIL 的已证原因。旧 V9/source/helper 均不修改。

当前继续暂停 RF/UI/恢复写入；不执行旧 recover、flush、按名称删接口、停原厂服务或盲重启。待固定分层只读事实明确，再决定当前同 run 的窄恢复是否仍适用。目标 active；DHCP、CLIENT、生产双向 worker 与手机端到端仍未完成。
