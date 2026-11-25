# Linux CLIENT 初始化适配层复核

2026-10-01，SOURCE/HOST 范围。默认构造与 assemble 不执行真实 OS；没有 GO、关联、扫描、DHCP、地址配置或文件传输能力。本候选不是 tested release。

## 稳定实现与 ROOT 审查

| 来源 | 行数 / 字节 | SHA-256 |
| --- | --- | --- |
| runtime/mta_client_linux_provider.py | 1219 / 73888 | 8996ae6aa82e48170514f61fc301a83532cf28a20f385153ff41c1e68b236544 |
| tests/test_client_linux_provider.py | 538 / 32321 | fcde22ad67038ae82604546282082fe8c8a4b08600e3a99c382cbd020a26a37b |

作者停止修改两源；两次代理容量错误仅影响收尾文档，没有改写测试结果。ROOT 接手本说明：a70704/e0a1d0/87b563/17f5cb 全文阅读最终实现，f91082/b9bd56 全文阅读最终测试；34219d 读回两个完整 SHA。独立限定审查 91ed61/209720/c40015、末 pin 617871 核对 exact 类型链、真实 FD generation 来源和实际 caps 合同，未发现这三边界的新增静态 API 阻断；不作为 OS 或 P011 PASS。

## 实际 HOST/Fake 批次

| 工具输出 | 实际结果 | 范围 |
| --- | --- | --- |
| ed5d3c | 39 / 0.065s / exit 1：38 PASS、1 fixture ERROR | 首批；IPv6 重复路由构造放在断言外，严格 Snapshot 提前拒绝 |
| 7b7dba | 15 / 0.054s / exit 1：11 PASS、4 fixture ERROR | IPv6 修正、4 个 ctrl rmdir、caps 映射及相关方法、fresh restore tuple、4 个 Bridge 复用、assemble/AST；4 ERROR 是新 Fake 缺真实 stat_result 的 st_rdev |
| 4304cf | 5 / 0.008s / exit 1：4 PASS、1 fixture ERROR | 仅前述 4 Bridge 已通过；新增真实 ProcReader 逻辑 over Fake 误调用不存在的 complete_actor 方法 |
| a331cf | 1 / 0.003s / OK / exit 0 | 仅修 ProcReader fixture，按真实 kind/passes/actor/资源字段验证 |
| ce9511 | 3 / 0.038s / OK / exit 0 | 新 exact Provider/Bridge/Lease/Store/Owner 绑定负向、受影响 assemble、Python 3.5 AST/restore 单门禁等价 |

51 个不同方法分批覆盖，不称最终源码一次 51 项全通过；ROOT 未重复已通过的方法。全部为 PC Fake 外设，不含实际 socket、进程、WSL、ADB、RF、目标文件系统或完整项目回归。首轮 ERROR 均保留，修的是新 fixture，不修改冻结 Owner/ProcReader。

## 实现范围

- 只有固定私有 manifest、同实例 B Store/Owner/new Bridge/new Lease 才能调用实际方法；manifest 规范化本身不是来源认证。F 的固定完整来源图与实际部署准入另行核验。
- 原厂网状态由已审 authenticated STATUS 与完整 Snapshot 读取。存在私有 controller 时，仅排除本 Owner 已发行、实际身份再次认证的 controller；不按名字或缓存 PID 泛化排除。
- nl80211 只创建本轮 type-8 CLIENT，CREATE 必须取得匹配 ECHO 和 ACK，完整 phy/wdev/ifindex/name/type 及原接口集合前后匹配；DELETE 仅处理本轮精确 Origin。
- 固定 WPA 2.12 控制端点实际为 root:root/0770，只有精确 private0700 锚路径接受此模式。STATUS 校验 Unix credentials 与同一 controller 身份；拒绝 rights，先保留并一次关闭已安装原 FD，截断或未知仍 pending。
- SIGTERM 只面向本 Owner 的未 reap 原直接子进程，必须 fresh 身份、实际 wait/reap 和全任务 absence；watchdog 只通知同 F，没有全局停进程或 orphan recovery。
- 固定 WPA 正常退出可能使 type-8 DOWN 并 unlink/rmdir 控制目录。新 Lease 仅将 restore 的 origin_up 门禁替为 cleanup_origin_ready：完整原网、全部子进程退出、Bridge 闭合、精确原 Origin、无自有 IPv4及许可 IPv6均通过；目录 nlink 例外仅允许精确已退出 controller 所属目录的确定变化。DOWN 不冒充 UP。
- 新 Bridge 继承原 prepare/launch/release/resolve/cleanup 行为，不重新关闭 FD。闭合确认仅接受冻结发行者的 close-once/即时 EBADF 事实，以及当前唯一已登记原 owner 的 fresh FD 身份；未登记复用、相同元数据但无来源、未知库存均拒绝。CloseProof 统计保留的复合 owner 句柄，不冒称物理 FD 数。
- 旧 TwoPhase/core/B/Proc/Owner/C 模块未改；不自动清除或接管旧 V9 pending，不替换原厂程序、启动项、无线固件/NV 或系统分区。

## caps 的明确表达缺口

真实 ClientCapsReader.read 返回不可变 DecodedCaps，不是旧 core 字典。本适配在实际 reader 成功、socket closed、非 pending 后做精确映射，保留数量、类型、limits、radar 和 beacon_match，要求实际 CREATE/DELETE 命令，最后调用冻结 core.client_combo。

旧 core 不表达 BI_MIN_GCD 的默认 identical-beacon 约束。本候选只接受显式 BI_MIN_GCD=1 的可表达组合；缺失或其他值拒绝初始化，缺 radar 字段也拒绝。该拒绝是适配表达缺口，不能推成 P011 硬件不支持。Linux v4.14 的定义与条件发送可见 [nl80211 UAPI](https://raw.githubusercontent.com/torvalds/linux/v4.14/include/uapi/linux/nl80211.h) 4385–4445、[nl80211 编码](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/wireless/nl80211.c) 969–1027；未把缺失属性猜成 0 或 1，也没有丢限制开放 GO/关联。

## 未验层

真实 ARM OS、实际 P011 type-8 初始化/退出/网络恢复、实际 caps 可表达性、Canonical Python ELF/最终部署图与 legacy pending 准入均待单个受控实机入口验证。生产 send/receive 仍 False，Xiaomi 15 Ultra 原厂互传 NOT_TESTED，目标 active。

独立审查者曾误判 ProcReader 正常 _open_attempt 未清，f4b48c 与 ROOT 67f8aa 完整复读 finally333–334 已撤回；实际安全路径清 None，测试保留这一严格合同。这个片段遗漏及 209720 的只读区间参数错误都不是源码或单测 FAIL。
