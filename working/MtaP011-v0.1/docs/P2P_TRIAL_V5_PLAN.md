# P011 V5：私有 GO + IPv4-only 有界验收计划

状态：独立验收代码和 HOST 测试已完成；本文不是已进行的 V5 实机试验，也不把 HOST mock、旧只读 dump 或 V4 GO-only PASS 升格成 IPv4 写入通过。由主线程完整审查、正式冻结、复核 identity 后，才可串行执行一次。

## 固定范围

- 只使用项目自有接口、私有 WPA 进程与原有同一设备级 guard/journal/watchdog，TTL 固定 20 秒。
- 保留原厂 `wlan0`、STA、ConnMan、原厂 WPA、BlueZ、Z03、Weston 和固件文件。无正常重启、全局清理、服务停止或自动重试。
- 本阶段仅添加/删除自有接口上的一个冲突检查后的 RFC1918 `/24` IPv4 地址；只有精确 CREATE|EXCL ACK、读回和持久收据能授权精确恢复。没有收据时不得根据地址形状推断归属，也不得通过删接口间接删除未知地址。
- 不做 DHCP、路由写入、默认路由、DNS、TCP/UDP 应用套接字、BLE 广告、手机连接或文件传输。生产 `send.available` 保持 false。
- 创建前要求精确 owned origin、GO 类型、IFF_UP、carrier=1、fresh ifindex，随后再次读回完整 nl80211 origin。恢复不要求 carrier=1，避免把链路掉线变成无法清理的条件。

## 候选和入口

新入口为 `host/device_p2p_v5.py`；不修改 V1/V2/V3/V4 入口、冻结候选、结果或模块全局。V5 manifest 必须恰好七个 payload 加 `SOURCE.sha256`，无额外文件、重复路径、符号链接祖先或超限内容。

| 文件 | 来源 | 固定 SHA-256 |
| --- | --- | --- |
| mta_send_wifi.py | native/private-p2p-runtime-candidate-20261001-v5/runtime | 96f808a9ef7cbaf011bb3254a23c01cbda6d7e09e016ad948c5dba89b671bd87 |
| mta_ip_lease.py | runtime | 39373dba355557ee73cfac354bdbaa95eaf0ddde4e27313450edf0e74742f12c |
| mta_ip.py | runtime | 1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5 |
| mta_safety.py | runtime | 03f77794db1fa8bebf44f56a479d5feaa6aef0e0f490ad4e577ad5bb6b190a81 |
| p011_json.py | runtime | fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88 |
| mta-wpa-supplicant | native/private-p2p-candidate-20261001-v2 | e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301 |
| mta-wifi-caps | native/private-p2p-candidate-20261001-v2 | 9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6 |

`--freeze-only` 只读取主机源、校验 SHA、ARM ELF32 及 Python3.5 AST，生成新的独立本地快照，不构造 ADB。`--execute-reviewed` 必须显式提供 frozen 目录和完全一致的 16 位 candidate identity；无默认执行模式、无自动 recover。

## 真实验收硬门槛

1. ADB 通过已观察到的 P011 transport-id 唯一选择设备，不能默认选设备。完整固定原厂 SHA、PID/starttime/exe、页面/菜单安全基线先通过。
2. 历史 journal 和 pending 必须有界、私有、安全；未知版本/identity/归属阻断。已 reconciled 的 schema3 `ip=None` 只有 cleanup.ip_restored=true、ip_stage=none 且自有进程/接口确实消失才可允许下一轮；这只证明旧无 IP 副作用失败已清理，不会使当前 IP-only 验收通过。
3. 独立 preflight 要求原 STA 为 COMPLETED、可确定 2.4GHz 同频道、无 P2P/MTA 接口、无私有 WPA/试验 actor、无 pending。
4. 每次独立 IPv4 读取使用一个自有 NETLINK_ROUTE unicast socket、实际 bound port、六次递增 sequence、两个完整 GETADDR/GETROUTE(all tables)/GETRULE 视图。仅接受内核 sender `(0,0)`、非截断、无 ancillary、完整终止、默认三规则、永久无限寿命地址和两套全字段一致；随后关闭 socket。
5. IPv4 地址九字段、所有路由表十二字段、规则二字段全部纳入 pre/post 比较。保留 cacheinfo 四字段、默认 `/0`、非 main 表路由，不使用 `/proc/net/route` 的摘要替代全部 IPv4。三份 dump 并非原子快照；两个相等的视图只是有界一致性门槛。
6. 同时比较完整原 IPv6 addr/route 原始读回、原厂文件/进程、tracked PID/starttime/exe/args 摘要、STA 完整 status 摘要、频率、完整接口 origin、boot、pending。任何变化都不能 PASS。
7. 仅调度一次固定 TTL20 trial。超时、解析错误或试验失败后只做独立只读检查，不自动重试、recover、重启或全局清理。
8. 最终事件必须为 GO-IP ready → cleanup，native 固定数字诊断无错误，ip_stage=restored、ip_restored=true、ip_control_socket_closed=true。constructor failure 可没有 socket-close 字段，但仍是 FAIL。
9. 独立 schema3 journal 必须匹配固定 identity/kind/marker、同 boot、完整原基线与实际接口/PID 归属。成功需要保留合法 fsynced restored 收据、reconciled、原基线全部相等、进程/接口确实消失、pending 清除。只读 journal 检查自身不创建锁、不写 pending、不调用 LinuxBackend 或恢复入口。

## HOST 证据与公开范围

主机命令：`python -m unittest tests.test_device_p2p_v5 -v`。当前 33 项通过：真实七源 pin/AST；合成 freeze 防篡改；事件/诊断严格白名单；schema3/收据 origin/header/fsync；历史只读 2addr/9route/3rules 离线解析；全 IPv4/non-main/policy/cacheinfo 改变阻断；None 旧失败 admission 与当前成功分开；FakeAdb 单次试验/超时仅只读/无 recover；明确 CLI 模式；公开 ZIP 不含私有探测数据。

所有 HOST fake/mock 只在临时目录运行。历史 fixture 的 reply port 只用于离线解析，不冒充未来 socket 的内核 sender 验证。未执行正式 freeze、ADB、RF、实际 IPv4 写入、DHCP 或手机互传。

实机结果目录单独保存原始 stdout/stderr、remote/host exit 与私有 probe；公开 ZIP 仅包含固定白名单 `result.json` 和 `README.txt`，不含私钥、PSK、SSID/MAC、地址/接口记录、journal、候选或 raw。

TTL 正常退出和 mock 不是实际父进程被终止后的 watchdog 恢复证据，也不能证明 SIPC 命令池/固件 credit 已恢复。即使 V5 全 PASS，仍需下一独立阶段 DHCP、绑定接口的传输及手机双向互传验收，不能据此开放完整发送能力。

## 首次实机结果补充

以上“未执行”是作者完成 HOST 审查时的历史状态，保留不改。主线程随后完整审查、固定七个 payload 并独立核对 manifest，进行了一次 TTL20 试验，没有自动重试或 recover。

冻结 identity 为 0f2a45489fd3e03b，manifest SHA-256 为 0f2a45489fd3e03b0b56b9bb083cf2d978f005d8260e9148339616d7856591b8。结果为 logs/MtaP011-DeviceP2pV5-20261001-044609-c53555d6/result.json：FAIL，ip_create/lease_error/errno0，14 项原生初始化/退出事件均为 0，没有 private_go_ip_ready。门禁没有记录具体拒绝项；carrier=1 仅是下一步需要验证的假设，不是实测根因。

失败事件内 cleanup.complete=true、ip_restored=true、ip_stage=none，IP control socket 已关闭。独立检查确认完整 IPv4 地址、全部表路由和规则、完整 IPv6、原厂/STA/进程/接口/boot 全部相等；无项目 actor/接口/pending，journal 为 reconciled、ip=None。成功事件专用的公开 cleanup/receipt 字段为 false，仅说明当前 IP 成功验收没有满足，不可解读为独立恢复失败。此记录不能证明没有尝试内核写入，也没有证明地址安装成功。

下一步仅补固定枚举的拒绝诊断和脱敏只读布尔观察，不降低 creation/receipt/cleanup 门禁，不原样重跑，不接 DHCP、应用 socket 或手机。原失败记录及 V5 冻结文件保持不变。
