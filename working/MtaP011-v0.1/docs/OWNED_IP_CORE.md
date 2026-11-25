# 自有 P2P IPv4 核心：HOST-only 实现与准入边界

日期：2026-10-01。本次只新增 `runtime/mta_ip.py`、`tests/test_ip.py` 和本文；不改 V1–V4 冻结源、二进制、历史日志或 GO lease。没有 socket、ADB、RF、IP 写入、DHCP、默认路由、DNS、watchdog 接线或功能 available 开放。

## 结果与证据层

- Windows HOST：`python -m unittest discover -s working/MtaP011-v0.1/tests -p test_ip.py -q`，60 项 PASS。包括 600 组确定性随机字节、逐字节截断、异常属性／规则／ACK、边界网段和历史真实字节样本；没有网络 socket。
- Python 3.5 语法：同一 HOST 测试对核心执行 `ast.parse(feature_version=(3, 5))`，PASS。这不是设备解释器导入或运行 PASS。
- 历史真实样本：只读原 `logs/MtaP011-IpDumpReadOnly-20261001-032317-adba0ac0/private-raw/02-ipv4-dumps-readonly.stdout.raw`，离线解析 3 个完整 dump：2 个 IPv4 地址、9 条所有表路由、3 条默认规则，PASS。未打印、复制到公开文件或重写原 raw；没有重新请求设备。公开交付缺少此私有 fixture 时，唯一历史样本测试明确 SKIP，不伪造输入。
- root 的原只读日志已证明当时设备 `collections` 可导入；本核心仍未在 P011 实际 import。不能把旧样本、PC import、Python 3.5 AST 或 V4 GO-only PASS 当成 IP 创建、回滚或文件传输 PASS。

## 最小接口

| 内部 API | 输入／输出 | 不证明什么 |
| --- | --- | --- |
| `encode_dump(kind, sequence, port_id)` | `addresses`／`routes`／`rules`，返回 request bytes | 未发送；无内核 sender 身份 |
| `DumpCollector(kind, sequence, port_id).feed(bytes)` | 逐 datagram 核对 seq、header port、type、flags、长度、属性；完整终止后 `records()` | 3 轮 dump 非原子快照 |
| `snapshot_from_dumps(addresses, routes, rules)` | 必须同 header port、类型／顺序正确且各自完成 | header port 相等不是 authenticated kernel socket |
| `require_default_rules(snapshot)` | 精确默认 3 规则，异常时固定错误码 | 不放行自定义策略 |
| `select_subnet(snapshot, explicit_candidates)` | 有界 RFC1918 `/24`，返回 private `SubnetChoice(network, prefixlen)` | 没有 gateway／local_ip 字段，不隐式选择 `.1` |
| `AddressSpec(ifindex, address_text, 24)` | 明确指定 private 非网络／广播的 host address | ifindex 或对象类型不是 interface 所有权证据 |
| `encode_new_address(spec, sequence, port_id)` | `RTM_NEWADDR`，REQUEST／ACK／CREATE／EXCL | ACK 不是 address／route 读回或 durable receipt |
| `encode_del_address(spec, sequence, port_id)` | `RTM_DELADDR`，REQUEST／ACK，精确相同 address payload | 未授权删除；不编码 DEL_ROUTE／flush |
| `decode_ack(datagram, original_request)` | 严格关联的 `AckResult(errno, command)`，零为成功 | 不代表恢复完成或允许清 pending |

数据字段为内部 private 数据。IPv4 以整数存储，编码为 network-order；其他字段为 P011 little-endian ABI。records／choice／spec／snapshot 的默认 repr 不输出 IP 或 label；`ipv4_text()` 与 `structural_key()` 仍是 private 数据，不能写 UI／公开日志。QML／HTTP 不得直接调用这些 API，也不得接收任意 interface、IP 或 route 参数。

核心仅依赖 `struct` 和 `collections`；没有 json、ipaddress、fcntl、resource、socket、文件、进程或 shell API。异常使用 `IpCoreError.code` 固定字符串及 `errno` 数字，不拼接包内容、IP、接口名或自由错误文本。

## 严格读取与失败关闭

三个 request 均为未过滤 AF_INET dump；GETROUTE 的 table 为 UNSPEC，不能只读 main 表／`/proc/net/route`。每轮最大 64 KiB datagram、2 MiB 总字节、256 datagrams、4096 records。每条消息核对完整长度、对齐 padding、seq、header port 和预期 type；data 必须 MULTI、DONE 必须包含零状态。中断／过滤标志、OVERRUN、零 ACK 代替 DONE、错误 errno、结束后数据或重复记录均失败；collector 一旦失败，所有 partial records 不可用。

每个 datagram 先整体验证，再提交 records，避免前半成功、后半错误仍可使用部分输入。默认 3 规则为优先级／table `(0,255)`、`(32766,254)`、`(32767,253)`；local 优先级 0 允许省略，Linux 默认 `suppress_prefixlen=-1` 允许。缺规则、多规则、非默认 priority／table、有效 suppress、selector、action／flags 或未知属性拒绝。

地址保留 local、IFA_ADDRESS（point-to-point 时是 peer）、prefix、ifindex、scope、flags、label、broadcast 和完整 cacheinfo。IFA_FLAGS 为 u32 时按 UAPI 覆盖 u8 header。不同 cacheinfo／flags 不能让同 ifindex／local／peer／prefix 重复记录绕过检测。初版接受常用 scope（universe／link／host）和已知 flags；异常 scope／未知 flags 失败。

路由保留所有 table（含扩展 u32 table）、destination／prefix、protocol、scope、kind、flags、oif、gateway、priority、prefsrc 和已知 u32 metrics。初版仅理解 unicast／local／broadcast、常用 scope 和已知 DEAD／OFFLOAD／LINKDOWN flags。source-specific、TOS、multipath、mark、encap、特殊路由类型、未知属性或未知 metric 等失败，不能跳过不认识的路由后继续选网段。

默认 `/0` 路由保留并纳入结构基线，但不作为覆盖整个 IPv4 空间的子网冲突。所有非零 destination prefix 的具体路由（包括当前默认规则未选用的其他表）、现有地址的 local 和 point-to-point peer 前缀、gateway／prefsrc host endpoints 均参与碰撞。地址自身 `/0` 仍按已有地址前缀保守拒绝所有候选，不能把地址和默认路由混为一谈。

候选必须由内部适配器明确传入，1–32 个 canonical RFC1918 `/24`，非网络边界、重复或公共／link-local 子网等拒绝。按给定次序选择第一个不重叠子网；全部冲突明确报 `no_available_subnet`，没有隐藏的固定网关或失败 fallback。

## 写入编码与 ACK 限制

NEWADDR 与 DELADDR 使用同一完整 ifaddrmsg＋IFA_ADDRESS／IFA_LOCAL／IFA_BROADCAST：明确 ifindex、prefix 24、永久标志、universe scope、local=address、推导 subnet broadcast。NEWADDR 固定 CREATE|EXCL，不允许 REPLACE。核心只生成 bytes，没有 send，也不生成任何 route／rule 修改。

ACK 必须为单条 NLMSG_ERROR，外层 seq／header port 与 request 一致，嵌入原 request header 全字节一致。非 capped 的失败 ACK 还必须回显完整原 request body；成功或 capped ACK 必须只有规定长度。errno 范围为 0 或负的 1–4095，返回非负 numeric errno。未请求的 EXT_ACK／TLV、不认识 flags、额外 body、错误嵌入 request 均拒绝，不能转为成功或泄漏自由文本。

未来适配器必须在发送 bytes 前 fresh 校验 same boot＋精确 name／ifindex／WDEV／phy／实际 iftype、原厂完整 baseline、P2P lease guard 和截止，先保存 durable intent。CREATE 仅 ACK 不足以取得删除权限；ACK、精确 address＋预期 connected／local／broadcast routes 读回及 durable receipt 的关联由下一阶段 journal3 负责。没有归属凭据，不得凭“地址长得像本项目”删除地址或 netdev。

## 下阶段仍需独立验收

本核心不会因离线 PASS 自动接线或开放 `send.available`。下阶段由 root 单独锁定真实 adapter／journal3 候选与试验：

1. 真实 NETLINK_ROUTE socket 校验 recvfrom sender pid=0、单一 socket／递增 sequence、截断／残包／超时与调用 epoch。消息 header 的 port 只做关联，不等于内核认证。
2. 双份 fresh dump、完整 flags／scope／prefix／cache 生命周期策略、原厂 IPv4＋IPv6 baseline 和精确 owned origin。`structural_key()` 排除了变化的 cacheinfo（所有原 cacheinfo 仍保存），因此结构相等不是原子性／寿命／租约一致性证明。
3. durable intent→CREATE|EXCL→严格 ACK→完整 address／route readback→durable receipt，以及每个崩溃窗口的 pending 与恢复规则。失败不清 pending，不换随机接口名绕过，不升级旧无 IP watchdog 的清理权限。
4. 只撤本次 exact address，再读回自动路由消失；不盲目补 DEL_ROUTE。原 IPv4／IPv6 及原厂进程／接口／连接完整基线相等后才归入恢复 PASS。
5. 首阶段只限 IP-only；DHCP、socket factory 绑定、one-peer admission 与真实手机互传分别后续验收。没有隐式 gateway／DNS／默认 route。

## 主源与实现方式

本文及原创 core 使用 Linux UAPI 的字段／常量事实，未复制第三方实现： [Linux v4.14 rtnetlink UAPI](https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/rtnetlink.h)、[IPv4 地址字段](https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/if_addr.h)、[policy rule UAPI](https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/fib_rules.h)、[netlink header／ACK](https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/netlink.h)。

所有表 dump 与默认 3 规则的实际上游行为对照 [fib_frontend.c](https://github.com/torvalds/linux/blob/v4.14/net/ipv4/fib_frontend.c)、[IPv4 fib_rules.c](https://github.com/torvalds/linux/blob/v4.14/net/ipv4/fib_rules.c) 与 [通用 fib_rules.c](https://github.com/torvalds/linux/blob/v4.14/net/core/fib_rules.c)。这些官方主源不证明 P011 地址写入或恢复已完成。更完整的责任链沿用 `native/OWNED_IP_DHCP_NEXT_STAGE.md`；root／protocol 的 journal3 设计与实现另存新文件，不覆盖 V4 冻结候选。

## Root 后续实时只读补充（不覆盖以上作者 HOST 快照）

新候选 `92b7279adad8ad39`，core SHA256 `1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5`：

- `logs/MtaP011-IpCoreReadOnly-20261001-034723-58f50b59`：实际 P011 Python3.5 导入、两套完整稳定视图、2地址/9条全表路由/3默认规则、永久无限期、候选网段可用、kernel sender/实际 socket port/6递增seq、socket释放及原厂独立基线通过。
- `logs/MtaP011-IpCoreReadOnly-20261001-035650-66a4c890`：只读 checker 改显式判断、拒绝优化模式，避免 `assert` 在 `-O` 下消失；受影响项重新实机通过。checker SHA256 `8d2f84ab32813b912eb136c87ea0b3041e3abb50c53e6c7c7588e3b998419366`。前一次原结果保留。
- 独立前后基线包含原厂文件/进程、完整 Wi-Fi 状态指纹、接口/网络进程/boot、主 IPv4 路由及完整 IPv6 地址/路由；完整 IPv4 全地址/全表/rules 两套一致是 core 阶段内证据，不混成完整 IPv4 前后恢复。
- 两次均无 RF、IP配置、DHCP、IP数据 socket、用户文件或手机互通。仅 staged 项目源/只读请求，不能据此开放 send/receive。

一键只读入口 `DEVICE_IP_READONLY_CHECK.cmd` 每次创建新日志和脱敏 ZIP，固定 codec pin，未知原厂或 pending 状态即拒绝，不调用归档 START。
