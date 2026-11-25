# P011：Owned IP-only 租约工程评审

日期：2026-10-01；状态：**root 已锁定1A+2A；V5独立实现完成，HOST专项通过，待root完整源审查**。本子任务未做 ADB/RF，未冻结真实 V5。

## 0. 范围与已有证据

接受既定 IP-only 范围：一个新冻结候选、同一个 DeviceGuard、同一个 TTL≤20 秒、同一套 GoLease/watchdog；不建立第二套生命周期。
V4 `43a77d612f32fba5` 的真实 `logs/MtaP011-DeviceP2pV4-20261001-030738-1772afe3/result.json` 已只读复核：GO-ready、14项固定 native 诊断、清理及独立原厂/双栈/进程/接口/pending 门槛均 PASS。
该 PASS 只覆盖 GO20 秒；没有 IP、DHCP、peer 关联、TLS、文件或 PHONE 证据，也不证明驱动 SIPC 命令池内部状态。

## What already exists：直接复用

以下行号均指 `native/private-p2p-runtime-candidate-20261001-v4/runtime/mta_send_wifi.py`（55319B，SHA256 `ef2f087444c149a988b5b3895225960e85c03d702aa5a084cef62e6222ccf334`）。

- `DeviceGuard:130–188`：独立设备锁、私有 durable pending、watchdog 继承同一个锁文件描述；保留这些约束。
- `GoLease._save:722–745`：journal 锁、私有目录、原子替换及 fsync；新 IP 状态使用同一事务入口。
- `GoLease.start:747–810`：capability/原厂/接口/epoch 门禁、先 watchdog 后无线动作；`go_ready:800–806` 是 IP 创建的前置条件，不是可发送状态。
- `GoLease._stop_locked:818–868`、`recover:870–888`、`start_watchdog:890–922`：恢复现成框架；必须在同一框架加入 IP 前置清理，不另写后台恢复器。
- `LinuxBackend.snapshot:543–574` 当前 IPv4 仅 `/proc/net/route` digest，不足以证明全地址、全部路由表和 policy rules；这是本轮需要补齐的明确缺口。
- 复用 bluez agent 新 `runtime/mta_ip.py` 的纯字节 codec、DumpCollector、IpSnapshot、default-rules/conflict/ADDR 编码；它不建立 socket、不赋予地址归属、不证明 dump 原子一致性。

## 1. 最小修改点与契约

**1A（推荐）**：只在独立新候选上补一组 IP 操作钩子及 schema3；保留 V4 私有 WPA binary、caps pins、同频 GO、原厂进程门禁和有限 watchdog，不回写 V1/V2/V3/V4/main。
不新增业务 worker；backend 负责完整 rtnetlink 读取/ACK，lease 负责 journal/epoch/归属，纯 codec 不承担授权。
这里只准 NETLINK_ROUTE 控制通道完成 dump/ADDR 操作；**禁止 AF_INET/AF_INET6 socket、listener/factory、DHCP、默认路由、DNS、NAT、BLE、用户文件**。
`SenderGoContext.status:935–937` 只能增加“实验地址已核验”；`capabilities:945–951` 的 `send.available=False` 不变，不能把 IP-ready 当互传可用。

### 新 journal 与 pending：version3，不能自动迁移

- `DeviceGuard.prepare/clear:153–176` 与 `GoLease.start/recover:767/875` 同步升3，并明确 `kind=go_ip_only`、固定 candidate/runtime/codec 身份；只用 WPA hash 不能区分同 binary 的不同租约代码。
- v3 保存完整原厂基线、原接口清单、sameboot、owned 四元身份（name/ifindex/WDEV/phy）、已保存 private process，以及单一 `ip` 子状态。
- `ip` 最少包含：exact AddressSpec/完整预期地址属性、同接口身份、baseline 无该地址证明、request seq/port/header identity、intent/ACK/readback 状态、允许的自动路由 delta。
- 地址/路由/规则是私有 journal 数据；公有结果只输出固定枚举与有界数值，不能带 IP、MAC、SSID、目录或原始异常。
- v1/v2 journal 仅只读展示/阻断新租约；v3 恢复只接受3和完整 schema。现有 V4 `recover:875` 严格拒绝3；不得删版本检查、降级 pending 或调用旧 recover 处理3。
- 损坏/未知字段、候选身份不符、sameboot 不符、未清 pending 都保持阻断；不能靠新 run-dir 绕过。

### 创建地址事务（仍使用同一 journal 锁）

```text
GO ready / same epoch / TTL / exact interface
  -> 完整基线 + 两次一致性门禁 -> durable ip_create_intent
  -> fresh identity/baseline -> CREATE|EXCL + ACK -> exact readback
  -> durable ip_owned_confirmed -> 有限观察 -> cleanup_intent
      任一步未知/过期 -> 不发布 ready；只做确证 owned 恢复或保留 pending
```

- baseline 必须覆盖所有 IPv4 地址、**所有 table** 路由、rules，加现有完整 IPv6 地址/路由、原厂进程/Wi-Fi/接口。未知 attrs、截断、dump interrupted/filtered、非默认 policy 一律在写之前失败。
- 完整原始 L3 基线在 `start:756` 的首次 RF 前保存；GO-ready 再保存 pre-IP 视图与允许的 GO link-local delta，最终恢复仍比原始基线，不把 GO 的副作用升级为“原厂状态”。
- 保留 `recover:872` 的64KiB journal上限；全量记录序列化超限必须在写前拒绝，不只保存一部分表、不临时放宽读取上限。
- 三份 dump 非原子；新 backend 取两套完整结构一致视图，并在写前 fresh 重验。若检测到变化，终止本轮而不是自动重试。设备锁不等于锁住 ConnMan 或其他 root actor。
- 默认 `/0` 仅不作为“整个地址空间都冲突”的理由；仍参加原厂基线比较，gateway/prefsrc 参与冲突。禁止因为选到私网段就忽略其它表/策略。
- cacheinfo 的递减时间不能直接 hash；保存原值并明确支持的 lifetime 语义。未支持动态 lifetime 时先停；不得仅靠排除 cacheinfo 的 structural_key 宣称一致。
- 只从显式有界候选 RFC1918 /24 选一个无冲突网段；先确认 owned GO 接口没有未知 IPv4、全局 IPv6 或非允许路由，再发送 exact `RTM_NEWADDR`，不用 REPLACE/flush。
- seq/port/kernel sender、原请求 header、ACK errno0 全核验；随后完整地址读取必须唯一匹配地址、local、prefix、scope、flags、broadcast 及 owned 四元身份；ACK 不替代读回。
- 仅允许内核因该地址产生的预期 connected/local/broadcast 路由：严格 protocol/table/type/oif/prefix/prefsrc/flags，不能把“出接口相同”当 route ownership。
- 首次 ACK/readback/durable receipt 未全部成立，不得发布 `ip_ready`；TTL 不因 IP 步骤重新计时或延长。

## 2. 崩溃窗口与清理：不假定 ACK 可以与 fsync 原子化

**2A（推荐）**：ACK→journal 的不可消除窗口保守处理，代价是极少数故障需要只读审查；不能用低维护成本的“地址长得一样就认领”换自动清理。
durable intent 先于请求，能证明本轮想创建地址，**不能证明内核已接受，更不能证明当前地址由本轮创建**。

| 最后 durable 状态 / 现场 | 自动动作与结果 |
| --- | --- |
| intent，地址不存在、无 route delta | 可进入原 GO 清理，完整读回后才 clear pending |
| intent，地址存在但无 durable ACK/readback receipt | `ip_ownership_uncertain`；不删地址、不删 netdev，保留 pending；不因 errno未知宣布恢复 |
| confirmed，sameboot/四元/属性及 route delta 完全匹配 | exact DELADDR+ACK+读回地址及自动路由消失，再 WPA→netdev |
| 任一未知地址/路由、接口替换、外部规则变化或删除 ACK不明 | `recovery_required`，停止破坏性后续、保留 pending；不得扩大到 flush/global cleanup |

- 父死或 TTL 到达：watchdog 必须先读最新 v3 journal，再获得同 journal 锁；它使用同 IP 恢复钩子，不绕过 receipt 门槛。
- 新 `cleanup_intent` 先禁止发布/新 IP 写入；取消在事务前胜出就不能晚到提交 ready，事务已提交也不能重复创建或回滚旧 epoch。
- 调整现有 `stop:843–856` 顺序：**确证 IP→自动 route 读回→exact private WPA→owned netdev**。不能先删 netdev来掩盖地址归属缺口。
- IP归属未知时，exact owned private process 可有界终止以停止 RF，但这不授权删 netdev；留 `recovery_required`，不以“进程没了”作整体恢复 PASS。
- `DELADDR` 成功/不存在错误都需读回；自动路由未消失或发生未知变更即失败，不另发泛化 DELROUTE。
- `complete_lease:832/867` 只有 process/netdev 确认消失、完整双栈地址/routes/rules/原厂基线独立相等才 clear pending；cached reconciled 同样重读，不能复用旧 PASS。

## 3. 新增 HOST 注入覆盖（计划，不冒充已运行）

既有测试使用 `unittest`；纯 bytes 由 bluez `tests/test_ip.py` 负责，下列新增 `native/tests/test_owned_ip_lease.py` 用 fake backend/clock/fsync/kernel replies 覆盖跨模块事务。

```text
admission [GAP] v1/v2/v3/corrupt pending、unknown policy、全表冲突
  -> snapshot [GAP] dump 非原子/截断/seq错/动态lifetime/默认0路由保留
  -> intent [GAP] fsync前后父死、TTL/取消抢锁、watchdog先进入cleanup
  -> CREATE [GAP] EEXIST、ACK丢失、ACK后journal失败、读回/四元替换
  -> confirmed [GAP] late ready/旧epoch、未知地址/route delta、二次stop
  -> restore [GAP] DEL ACK丢失/已无地址/route残留、全基线不等、不clear
  -> [后续 P011] 真ACK+唯一地址+内核auto-routes+watchdog+双栈恢复
```

每个 GAP 必须断言“没有多余写入/删除、pending保留或按门槛清除、public仅符号化”；父死关键点分别注入，不用一个 happy-path 代替。
**关键回归**：只 GO 路径仍走原序列；旧 recovery 拒绝3；confirmed IP未恢复不得继续删 netdev；原厂 default-route/table/rules变化不得忽略。
跨 guard/journal/watchdog 的锁共享与实际 kernel ACK 需要后续有限 P011 集成证据，HOST mock不能升级成 P011/PHONE。

## 4. 性能、分发与 NOT in scope

复用 codec 已有大小/包数/记录数上限；全部 dump/ACK/清理使用共享 monotonic deadline与有界超时，禁止无限重试和另开20秒窗口；恢复安全预算另有明确上限且不再启动 RF。
新候选冻结完整 pins/manifest，harness 独立前后采证；公有 result/ZIP白名单，私有 journal 不发布。未做本轮冻结或设备试验，不给虚构 candidate ID。
NOT in scope：DHCP/association/IP socket工厂/TLS/BLE/文件互传/手机测试/正式安装（须等 IP 租约实际验证）；policy通用支持、NAT/DNS/外网路由（扩大原厂网络影响）；旧历史候选修补（破坏归因）。

## 待 root 锁定的两项选择

1. 接受2A：无 durable receipt 的“intent+地址存在”保留 pending并需要审查；否则必须另设计可审计的存活 ACK 记录者，本轮不引入。
2. 采用1A：只有 rtnetlink 控制 transport可用，所有 IP socket/DHCP 禁止；先 HOST 故障矩阵，再冻结/独立审查/一次有限 IP-only P011试验。
评审已锁定：范围接受；复用/测试图/失败矩阵/NOT in scope已写。关键风险2项（非原子快照、ACK-durable窗口）采用显式 fail-closed，无静默默认或新的全局工具写入。

## V5实现补充（尚非P011验证）

新增 `runtime/mta_ip_lease.py` 与独立 V5 `mta_send_wifi.py`，原 V4 SHA 不变；同一 guard/journal/watchdog，version3/kind及codec/helper/WPA pins；每次 journal 写入先检查64KiB。
RouteTransport只创建 AF_NETLINK/NETLINK_ROUTE socket；同port递增seq、kernel recvfrom身份、包上限、两次完整snapshot。MAX+1 recvfrom保守拒绝超限/截断数据，**未声称检查 MSG_CTRUNC**。
首次RF前保存永久/无限lifetime且默认三规则的完整L3；原厂完整wpa stdout指纹、tracked进程身份/命令摘要、接口和IPv6在IP事务边界fresh核对。
DELADDR前重新核对完整地址属性与receipt、原始全表基线；不因内核不匹配broadcast/flags而省略这些fresh检查。未知routeflags（包括合法但初版未支持的LINKDOWN等）保留intent/pending，不扩大允许集合。
receipt_recorded需首次成功fsync，再confirmed/receipt_fsynced=true二次提交；第一步一次性故障可以停exactWPA但不删地址/netdev；持续journal不可写可能连cleanup_intent都无法保存，**不能声称立即停进程或watchdog已恢复**。
创建门禁新增owned接口IFF_UP+carrier=1、sysfs ifindex匹配及随后完整nl80211四元重验；恢复不读取carrier。原因见 [Linux4.14 fib_semantics.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/ipv4/fib_semantics.c) 的LINKDOWN路径；仍不支持非零auto-route flags，不放宽restore。
现已运行Linux HOST48项PASS（假kernel、FakeLock，但实际journal原子写/fsync）；Windows17项PASS/31POSIX skip；Py3.5 AST PASS。父死用例是同journal新实例recover，不是真fork/断电。
固定 codec SHA `1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5`，helper SHA `39373dba355557ee73cfac354bdbaa95eaf0ddde4e27313450edf0e74742f12c`；V5内实际检查两份源pin，完整候选身份仍须外层 frozen manifest，而非marker单独授权。
真实继承flock/watchdog、IPv4安装/撤销/routeflags/恢复与PHONE尚未验证。root历史只读P011两套完整dump证明socket/core读取，不能升级为V5配置成功；production send仍false。
既有Linux48结果归档于 `results/owned-ip-host-20261001-043347-0e487f/`；命令 `python3 -m unittest discover -s native/tests -p test_owned_ip_lease.py -q`。保留工具chunk `0e487f`完整合并输出/exit0；未留存分离stdout/stderr原文件，本次没有重跑。

## 主线程首次实机补充

作者上述“未冻结/未实测”保留为当时范围。主线程随后完整审阅并冻结七个payload，manifest SHA为0f2a45489fd3e03b0b56b9bb083cf2d978f005d8260e9148339616d7856591b8，进行一次TTL20试验。logs/MtaP011-DeviceP2pV5-20261001-044609-c53555d6/result.json为FAIL：ip_create/lease_error/errno0，14个原生事件均0，但没有IP-ready或有效安装收据。

原始失败事件内cleanup.complete/ip_restored为true、ip_stage=none、IP控制socket关闭；独立完整IPv4地址/所有路由表/规则、完整IPv6、原厂/STA/接口/进程/boot均保持，自有actor/接口/pending全部清理，journal=reconciled/ip=None。None只能证明现在没有已授权IP收据，不能倒推从未create intent或内核写入。成功专用public字段false不表示独立恢复失败。

具体拒绝项未记录；IFF_UP/carrier门槛仅为待检假设。下一份独立候选只补精确固定枚举诊断，不降低IP归属、routeflags、fsync收据或恢复条件。当前无需自动recover、重启或全局清理；实际父死watchdog/IP安装/DHCP/PHONE仍未通过。
