# GO＋IP/DHCP 编排：v72 限定主机结果

2026-10-03。对端是小米 15 Ultra，系统／原厂互传版本仍未知。本候选未部署；本页不是实际 IP/DHCP、发送 provider、无线恢复或手机互通验收。

## 本次代码进展

将 typed IP/DHCP 阶段合入当前 Native62／Store56 修正后的 GO 来源，而不是回退整套旧 v43 图。新增固定 20 源映射，保留原 Proc、所有权、期限、发布和库存规则；Loader 的执行机制未改变，只有固定模块顺序和 schema 更新。

同 worker 的 `prepare_live()` 返回同一 owner；先登记原 DHCP 构造票据，再调用构造函数并保留返回对象。IP 分别保留 intent、原 ACK receipt 和确认阶段。DHCP 准备过程中 Store 收窄局部 IO 期限后，只恢复同一个已发出的 `service_until`，不重新申请 TTL。`poll_dhcp()` 包装层不调用 stage／begin／durable；实际 DHCP server 内部仍校验同一来源并使用原 scope，不能把包装层测试解释为整条 Native 链没有 begin 或读取。

恢复顺序为 DHCP 关闭 → 原 IP 删除／确认 → 原组、子进程、接口、基线和库存检查。L3 恢复不确定时禁止组／网卡删除；只允许原对象持有的本地库存执行既定 stop-only／关闭，保留 pending。默认 `run()` 的成功判定包含恢复末门；逻辑记录为 True 不能替代 `restore_failure is None` 和 restored 阶段。

| 冻结来源 | 字节数 | SHA-256 |
| --- | ---: | --- |
| candidate/go-typed-live-v72/runtime/mta_go_bootstrap.py | 22707 | 1db6bcea1aab324ae7c21eb5d116d77728e73de01865c64a4a8fc778481b40e3 |
| candidate/go-typed-live-v72/runtime/mta_go_native.py | 126679 | 28122b8e224a76e909af9da3436b74ecf5f885da40c71f6e4cfe2ffea3bbc66a |
| candidate/go-typed-live-v72/runtime/mta_go_bootstrap_store.py | 76933 | 1a54f3d4b6f1df84fc08959b6e3dc34f83646b7a0316e4b021fa06e7c9bb76d5 |
| candidate/go-typed-live-v72/runtime/mta_go_deployment.py | 24518 | 6e1ccb8a5f492b763ce486a456a81e06aa368cc2fe8eb45bd346570feb08deaf |
| host/go_typed_live_v72_source_manifest.json | 4532 | 55801b38c3bd46e54f5742abc6afae32c69a150bd3426d471193edbae2f8d32d |
| tests/test_go_typed_live_v72.py | 42798 | 2abb15bbc4c3dadc1d8b120270aa2f529645d9ac5e25f4a350ea7f2c36451724 |
| host/go_typed_live_v72_check.py | 14478 | 62955d2fa47e351a3d5e997a6ff5ef855cb2fea985ef5e00cfabf4467944bf41 |
| HOST_MTA_GO_TYPED_LIVE_V72_CHECK.cmd | 205 | 052abcc31d9c9aeecd7c7cd58ea58547edf22373b25d08ac3b01d3eebfb0cf46 |

原来源和旧结果保留。CMD 只核源码，未点击；ROOT 直接运行固定 checker。

## 实际执行与原件

ROOT `28bfc6` 唯一首次执行：HOST 0、child 0、无超时、约 0.203 秒；唯一新增方法 `GoTypedLive72Test.test_typed_l3_same_owner_poll_and_restore`，14 个独立受影响场景，旧测试方法 0。20 源做 SHA／Python3.5 AST／合并边界检查，**完整来源图不执行**。

子进程执行完整固定 Bootstrap 的构造、owner／stage／cancel、prepare／poll／restore／run 定义，`restore` 不替换；`_stage` 只是透明计数转发，`_start_child` 是明确的惰性模型接点。Loader、Entry、Store、Native、子进程、DHCP、票据、阶段、发布计数及 closed facts 都是依赖模型。每个场景要求平台 IO tripwire 调用为 0。它证明编排顺序和拒绝条件，不证明 Native ACK、内核关闭、真实恢复、资源成本或运行性能。

场景覆盖同 owner／同 scope、构造前票据、publication 后原期限恢复、poll 不续期／不重复发布、scope／原期限引用／票据／binding 变化拒绝、poll 原错误、到期停止、L3 恢复失败禁止 RF 删除、早期没有 L3 事实时的清理顺序，以及默认恢复失败后仍有 stale logical True 时必须返回失败。

[实际 result.json](results/go-typed-live-v72-host-20261003-023037-85e3396d/result.json)；[四成员脱敏 ZIP](results/go-typed-live-v72-host-20261003-023037-85e3396d/public-result.zip)：3553 B，SHA `e64721d108f841ade344b95ff129a9f74ebfe640dfe37ceac69170878e2b9488`。

ROOT `da42f5` 和独立 formal_phase_plan 审计均核对 33 件 private-inputs 与当前来源逐字／大小／SHA 一致、严格 marker 与 Ran 1／OK、ZIP 四成员逐字／大小／CRC／testzip。stdout 100 B，SHA `7c711ede84e48d6ce65b39397f04390abe2dcae247778fa7b36bd50943bab1d8`；stderr 100 B，SHA `8cbf8ab7bfb71b99f54a75dec2d57958f78fe9da966eda791c5e692d989fc06f`。未重跑测试，raw 不因工具展示换行而改写。

## 明确仍待解决

- SOURCE 正常路径预计 21／26 次 publication；按既定调用计数估算，Store retained opens 可能为 215／216，仅余 1 个。额外一次 durable／fresh 会改变成本，不能拿模型计数签真实资源通过。
- 当前 typed IP/DHCP 保留完整快照读取，SOURCE 估算正常链约 71 轮。独立 SOURCE 审计进一步定位：从发出 service cap 至首次 poll 至少 7 次 ip_current，每次 GO fresh＋IP 双轮，共至少 21 次完整快照，还未计 durable／出版／socket 配置。20 秒 DHCP service 同时包含准备成本；尚无 v72 真机时耗，不能保证期限内完成，也不以加限或续期掩盖问题。
- 没有九方法真实 Sender provider、State 接收 admission producer、正式工具箱接线或手机收发证据。GoDhcpServer 的 ACK 发出不等于手机已配置、授权或传输完成。
- SOURCE 审查确认 `status()['restored']` 仍直接投影 Store logical 标记，最终库存门失败时可能显示 restored=True；默认 run 成功门正确。此显示缺口另做独立 v73 修正，不改本次冻结件／结果，不升级本页结论。

下一生产步骤先限定 Bootstrap／Native／GoDhcpServer 三件：明确 setup 与实际 listening 之后首次发行的服务期边界，审计同步 setup 的重复完整核验，保留真实变更前后、原 owner／canonical／FD／clock 门。不能只后移 stage 或重赋旧 deadline，server.open 也会固化 active_until 和协议核心期限。是否可删某次双轮读取尚未证明等价。

随后才接原 F 单 worker 的有限控制循环，再做真实 typed Sender adapter。当前 F 仍只调用 run；跨 State／SendWorker 直接借 Bootstrap 会违背原 worker／tasks 门。现 Sender 还硬认另一种 DHCP server、IPv4 字符串及 0.2 秒 fresh／5 秒恢复合同，实际 GATT peer lease 只有 30 秒；这些不能靠继承假类型、缓存 True、扩大 Python TTL 或改可用布尔接通。此顺序是 SOURCE 方案，不是已实现或已测试的下一候选。

本轮没有设备操作、扫描、配对、创建接口、重启或部署。GO64 整体 FAIL／旧 pending／完整恢复未证保持；正常重启许可尚未收到。目标 active，尚非仅剩人工手机验收。生产缺口参见 [CURRENT_TRANSFER_GAPS_20261003.md](CURRENT_TRANSFER_GAPS_20261003.md)。
