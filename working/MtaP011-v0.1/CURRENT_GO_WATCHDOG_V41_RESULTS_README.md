# P011 GO 看门狗实机结果（v41-r2）

2026-10-02 唯一首测通过。此结果只覆盖真实 GO17 Loader／看门狗生命周期，不代表互传功能或手机兼容验收完成。

## 结果

- HOST 和设备退出码均为 0，无超时，HOST 用时 54.718 秒。
- 新 EXCL `go-token` 目录内 17 个固定源码、私有 WPA 和正式 `deployment.json` 共 19 文件完成读回、fsync 和封存；读取实际设备 Python ELF 的身份，不使用 HOST 模型 ELF。
- 实际 fork／exec 与原绝对期限绑定；收到一次 `R`，实际 `waitpid` 退出状态 0，随后原 ProcReader 两轮确认 absence，再单独读取真实管道 EOF。
- 先关闭父端两个同 OFD 引用；独立打开的 contender 在子进程存活时实际返回 EAGAIN，退出后实际获取锁。它是私有 scratch 的 flock，不是正式全局设备 lease。
- 31 条 writer 原库存、9 条父端进程 FD 均关闭；57 个累计 Proc generation／1804 个累计 open ticket 闭合。前后两个 readonly Owner 共四轮原生采集、838 条 collector 库存闭合。这些不是同时打开的 FD 数。
- 原厂文件／进程 live identity、IPv4／IPv6／接口／Wi-Fi 基线及平台一致；global pending 前后缺席。没有无线扫描、配对、重启、原厂文件改写或网络恢复操作。

[脱敏结果 ZIP](results/go-watchdog-device-v41-20261002-141751-7960992e/public-result.zip) 共 4 成员、4709 字节，SHA-256：

`27bf6316a9bc79227e318929468e28a9892b049fcdd9137e510869a49a42e058`

原 stdout 6464566 字节、stderr 0 字节及 source payload／身份／地址／argv／FD 原观察保存在同目录 `private-raw`，不放入公开包。ROOT 已独立核对来源、payload、写入 SHA、原库存、通知／锁／退出事实及 ZIP 的 CRC／外部逐字节回读；[主审说明](results/go-watchdog-device-v41-20261002-141751-7960992e/ROOT_REVIEW.md)。

## 来源和范围

冻结 runtime：`candidate/go-watchdog-device-v41-r2/runtime/mta_go_watchdog_device.py`，48722 字节，SHA-256 `ac9f9880f1e0f7d0a2a1741469633350cd39cc8de0678d7cc443fd2fbae858e3`。

冻结 HOST driver：`host/go_watchdog_device_v41_p011.py`，29692 字节，SHA-256 `5ce917604e3838c955dec5208e3d3bbf5031336a93426c016d5542dbdf79d099`。默认仅 PC SOURCE 检查；设备动作仍须显式参数、准确 driver hash 和新枚举的明确 P011 transport。不要为生成日志重跑已通过试验。

[一键 PC SOURCE 核验](HOST_MTA_GO_WATCHDOG_V41_SOURCE_CHECK.cmd) 先核 driver hash，再使用默认无 ADB 模式；不是新实机试验入口。默认 Python 模式已验证，CMD 本身仅 SOURCE 审查、未执行，不为其重跑已通过方法。

旧 v41 未执行且保留。r2 只修 flock 紧前期限检查、25 秒子期与 20 秒等待的衔接，以及观察失败时仅回收原 direct-fork 的 stop-only 分支；本次正路径没有进入该 fallback，因此不签其实机异常验收。

GO Parent／GoStore／FD3／控制器／RF、GO-IP／DHCP、发送／接收、小米 15 Ultra 双向及原网恢复证明仍未通过，生产准入保持关闭。下一复用正式 GO17 `--go-bootstrap` 入口，在新的 EXCL 目录准备 `go.conf`，验证有界建组和其原生一次恢复；不能用本次 scratch／内存 PersistReceipt 当正式许可。目标保持 active，尚非只剩人工。
