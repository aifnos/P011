# P011 P2P V2 实机失败与恢复边界

2026-10-01，冻结候选 `f100d4ea35acf9af`（完整 manifest SHA `f100d4ea35acf9af0e46c59c537ed1148462cbae6daf5bf59860b19a81777f37`）执行一次 GO-only、TTL 20 秒试验。正式发送能力仍关闭；本轮没有 IP/DHCP、BLE、文件、UI 或手机操作。

报告：工作区根 `logs/MtaP011-DeviceP2pV2-20261001-015014-3b76e733/result.json`。本轮为 **FAIL**：没有 GO ready，远端退出 1，私有异常分类 `OSError`，固定 native diagnostics 为空，未证明 WPA early gate 已实际运行。V2 源、冻结 manifest、原始日志及 FAIL 判定保留，不回写成成功。

## 新独立恢复检查

原厂文件/进程身份、wlan0 完整状态指纹、tracked 网络进程与 cmdline 摘要、完整接口清单、boot、IPv4 路由，以及完整 IPv6 地址和路由原始字节均前后相同。没有项目 mta 接口、private WPA、trial/watchdog actor；global pending 已消失。

V2 owned journal version2、安全 owner/mode、reconciled/complete；另一个独立只读进程确认 journal 保存的接口/进程/IPv4/IPv6 基线与当前值匹配，owned 进程和接口均不存在。本轮不需要再 recover，没有重试、重启或全局清理。

恢复通过仅证明本次退出安全，不证明组网或互传成功。

## 只读定位范围

后续只读记录 `MtaP011-P2pV2ReadOnly-20261001-015309-6bf1ecbe` 只输出结构字段：owned/process 尚未保存，private.conf 和 ctrl 目录尚未建立，watchdog result 存在。

结合源控制流，初始 capabilities/snapshot 和 create_intent journal 已完成，失败窗口在 watchdog 启动、create 前 journal 锁/读回、GET_INTERFACE/NEW_INTERFACE 到保存 interface 之间；尚未进入 spawn_private。不能只凭 `OSError` 确定具体 errno、宣称驱动不支持或推断固件损坏。

下一版只增加固定 failure phase、数字 errno 和 netlink 命令枚举，不输出自由异常字符串/filename/args，不改变 binary/RF/TTL/恢复策略。必须形成新候选身份，root 重新审核后才做一次有限诊断；旧失败不可追认。
