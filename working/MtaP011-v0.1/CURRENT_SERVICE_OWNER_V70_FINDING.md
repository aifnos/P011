# v70：固定服务入口与剩余 HOST 场景的限定结果

2026-10-03。真实手机对端已记录为小米 15 Ultra，系统及原厂互传版本未知。本轮没有 ADB、设备写入、重启、无线扫描或配对；未部署候选，未开启实际收发准入。

## 本轮实现

新增固定 fresh-process 服务入口，消费封存 v69-r3 Boot 的 22 个定义及同一接收工厂，构造原 State32／Server。监听仅为 loopback；默认脚本不启动服务，显式入口需要固定私有资产及原总期限。实际 State／Server、探测对象、listener、accepted requests、线程及中途错误均保留；接受请求、开始线程、收发字节及请求分发检查原期限，清理期限只首次固定。

启动要求 Wi-Fi／蓝牙恢复 pending 明确 False；原 State.close 未返回 True、对象构造失败或关闭不确定时，不能宣告服务关闭完成。致命运行错误也不会因后来清理完成而成为成功退出。scan／receive／send 均保持 False，不以服务存在或主机通过制造无线准入。

ROOT `46664f` 全文主审与独立 SOURCE 复核封口，原 State32、Boot69-r3、Factory69-r3、Bridge69、F37 及 native 工件未改。[冻结时的 SOURCE 说明](candidate/client-service-owner-v70/SOURCE.md) 保留当时未执行事实，不回填历史。

| 当前工件 | 字节 | SHA-256 |
| --- | ---: | --- |
| `candidate/client-service-owner-v70/runtime/mta_client_service_owner.py` | 24962 | `f70046e538db7427dd0af374067f684eb41bafb2f70999a2c3deaf87e8705466` |
| `tests/test_client_service_owner_v70_r2.py` | 44635 | `dbc5e603eb41ea5587ab6334f2b62afeefb401f264ae9d5990d09caad8cc18fa` |
| `host/client_service_owner_v70_r2_check.py` | 12170 | `74e60dbfa4cf959986063c7a818e1cc3efb972a82cd9af0d6c0041cc36ea03d8` |
| `HOST_MTA_SERVICE_OWNER_V70_R2_CHECK.cmd` | 231 | `bee4338ff6fda7fe75df0d67c6e0378f652f7ee41bfe53005ea77a45ff2193c7` |

## 首测失败保持失败

ROOT `9a8092` 唯一首次 v70 checker：host／child 1，未超时，child 调用约 8.797 秒。原 unittest 为 `Ran 1 test in 8.615s`、`FAILED (failures=1, errors=9)`。正常 HTTP 场景完成，但其后九项都在 Boot 的命名空间检查处停止，没有进入各自 owner 业务。测试清域仅按 mta／p011 前缀，漏了固定定义中的 minhttp；生产 Boot 拒绝是正确的，没有放宽生产门。

ROOT `b540ed` 已核首测 28 私有快照与当前字节、raw 摘要和失败 ZIP 两成员／CRC；独立原件审核也一致。[原整体失败结果包](results/client-service-owner-v70-host-20261003-005557-1da143ab/public-result.zip)：3066 B，SHA `1d0aea6f7c16856f9caffa02b89edfac22bef88135ad4642ebc2e3ab70bdd209`。失败 raw 只私有保留。原 test `38d05c…3f599` 和 checker `c1e279…e68` 未改，不把有限 normal_http 观察提升成整批通过。

作者更早的 test `689c8036…720f1` 只在 SOURCE 主审时发现 Wi-Fi pending 关闭后验错误，从未执行；原字节保留于 `tests/source-drafts/`。后验按原 State.close 抛出 retained-owner 错误、未取得返回值修正，没有修改生产业务迎合测试。

## r2 只补测九个未进入场景

r2 新测试没有 import 原 TestCase，也删除了 normal_http 业务分支。清域只使用 Boot.MODULES、Loader 强留的模块原件及本场景 Boot／Owner 引用；当前引用被外来对象替换时保留并拒绝，清理后读回固定名称缺席，包含 minhttp。ROOT `99e802`／`46ee73` 主审新窄 diff，`d9aa8c` 核最终 pins，独立 SOURCE 复核一致。

ROOT `93ff2c` 唯一首次 r2 checker PASS：host／child 0，无超时，child 调用约 8.859 秒；唯一新方法 `ServiceOwner70R2Test.test_remaining_cases_and_exact_domain_teardown`，九个场景、旧方法 0。原 unittest 为 `Ran 1 test in 8.674s`／`OK`。九项为：活动请求到期、State 构造失败、probe unknown、Wi-Fi pending、Server 构造失败、Thread.start 前／后异常、listener close unknown、State.close 返回 False。负向场景保持原失败／pending，并非所有资源都被签为闭合。

实际 HOST State／Registry／HTTP／TCP、线程、临时文件读取及文件 FD 关闭运行；Boot 文件系统、ARM／root／权限、能力探测进程，以及 Windows socket metadata／EBADF 都是明示模型。真实 socket 原引用的 close／fileno 与 TCP EOF／reset有观察，但不代签 Linux socket inode 或 P011 内核关闭。没有执行两个 ARM helper，没有构造 Handoff／Parent、调用实际部署 Loader／工厂正向或 RF。

ROOT `3f796c` 已核 r2 28 快照逐字／大小／摘要、严格 raw、四 ZIP 成员及 CRC，旧首失败工件保持不变；独立原件审核 `fb993a` 同样通过 28 份快照／四成员及原失败工件的逐字核对。两次原件审核都没有重跑方法。[r2 四成员脱敏结果 ZIP](results/client-service-owner-v70-r2-host-20261003-010352-405083d2/public-result.zip)：3472 B，SHA `8093784bfccc85119fbbcd9de09c4c2ca2139707600523600931a71ce9fee90c`。stdout 108 B／`1df35dd0b7070402e374adde488b8e128e6b2745bf9e6c0c4d43eff0520590c4`；stderr 100 B／`a336eff69ffd8c62cb099ad88722002beb84659f6134dbff295e32104c77a7de`。CMD 仅 SOURCE 核对、未点击；证据来自 ROOT 直接 checker 调用。

## 尚未完成的设备阶段

原能力探测的 12＋3 秒仍是局部固定 timeout，不是每个 syscall 的严格总期限保证；按路径执行 helper 依赖固定私有目录／资产，不声称抵御并发 root 改写。显式服务 CLI、生产 LinuxIo 路径锚、P011 ABI／线程／触摸均未实机验证。服务资源关闭不等于无线完整恢复。

接收准入仍缺真实 producer；工厂正向、GO／CLIENT、IP／DHCP、双向实际文件传输及小米原厂互通仍待。最近只读观察中的 GO64 pending／完整恢复未证继续保留，本轮没有刷新设备状态或处理记录。正常重启及本次记录处置许可尚未收到。目标保持 active，尚非只剩手机人工验收，也未把首测和 r2 合成为十例整体 PASS。
