# DHCP 准备与首次服务期限：v74 限定主机结果

2026-10-03。真实对端为小米 15 Ultra，HyperOS／原厂互传版本仍未知。本候选未部署，本轮未操作 ADB、无线、原厂程序或旧 pending；这不是设备 DHCP、文件收发或完整恢复验收。

## 本轮实际修改

独立 v74 候选替换固定来源映射中的 Native、Store、Bootstrap、DHCP Server 四件，其余 16 件原来源逐字保留。Bootstrap 基于 v73，保留严格 restored 状态判定；Store 的磁盘 schema、CAS、阶段、发布／打开配额及既有关闭流程不改。旧 v72／v73 来源和结果未覆盖。

`setup_until` 只在原 worker 创建一次，最多 20 秒并受原 session 截断。UDP 创建、bind/readback 和两次实际文件发布均限制在该 setup cap 内。Store 的 scope 在 DHCP observation 消费前夹取；后续 `_commit_phase()`／`_save()` 不扩张该期限。

只有 Native 在最终实际 IP／UDP 原件检查后，紧邻最后 setup 时钟检查首次发行 `min(original_until, now+20)`。Native 保留原 six-tuple，Bootstrap 保留同一返回 end，Server 才 `start_service()` 构造协议 core。`open()` 只准备 socket，未发行服务时不接收协议包；启动失败、超时或原引用变化均不能重新发行。poll 不续期。

中间两次 Store observation 使用精确、瞬时的原 consumer 和一次 token；消费在可能失败的 FD 检查前登记，finally 清除瞬时 consumer。C0→C1→C2 要求实际 canonical/history 相邻出版，不接受相同值的外来原件。generic `dhcp_current()` 不走此窄消费路径，仍完整采样。

完整 IP／组／基线采样保留在 UDP 创建前、bind 后和首次服务前。源码调用推导从 7 次完整 `ip_current` 降为 3 次，setup snapshot 从 21 降为 9。**它改变了中间检查的时间点，不能称为原 7 次采样语义等价、内核原子操作或已经实测加速。** 原配额没有提高；既有 Store 打开次数余量及真机时间成本仍需测量，不能用本轮 Server 模型签成本通过。

## 冻结来源

| 文件 | 字节数 | SHA-256 |
| --- | ---: | --- |
| candidate/go-dhcp-setup-v74/runtime/mta_go_bootstrap.py | 24127 | 18973e936b1bf0df1cf8cfa1a84906a6b8612af40158be071c6047fdc4b1ca1f |
| candidate/go-dhcp-setup-v74/runtime/mta_go_native.py | 145032 | d92ebed7760f89523a3015050af0d469dfd6c5195f42c63fc36e25b029354bb0 |
| candidate/go-dhcp-setup-v74/runtime/mta_go_bootstrap_store.py | 78430 | 24620844c7d24f4777114ba9bfb4ea292ded2020a281681dd8e71fe07c7a4eae |
| candidate/go-dhcp-setup-v74/runtime/mta_go_dhcp.py | 20912 | 8ce808f217426667b7a45447a92a51f26e7021d5255bfe83c36a6906ae424290 |
| host/go_dhcp_setup_v74_source_manifest.json | 4536 | 7e1633f2365fb67ad768fe574b98cdfdb24468d116d11c4d94cfde4350b8100d |
| tests/test_go_dhcp_setup_v74.py | 29050 | 1951e0feca25380a5cf2dd88e38cd166ec558ecedb31ef736478a222006d3390 |
| host/go_dhcp_setup_v74_check.py | 14429 | 2e9a6ccf2be14e7328f168add8d6da67eb7358b517191ea3f771175c08cc64d0 |
| HOST_MTA_GO_DHCP_SETUP_V74_CHECK.cmd | 205 | 243cf0833d29212161bb946c6d98e60842a7d7915e65dc11bdf90c94575ec57c |

此 source manifest 仅固定主机审核来源；不是已经由笔端 Loader 验证、部署或运行的 release manifest。Loader72／F60 机制未修改。一键 CMD 为 PC-only，源码检查后由 ROOT 直接运行 checker，未点击 CMD。

## 唯一新增测试与原始结果

ROOT `d960cf` 唯一首次 HOST74 执行通过：host 0、child 0、无超时；checker 子进程等待阶段约 0.5 秒，unittest 原始摘要 0.059 秒，二者都不是设备性能。唯一新增方法 `GoDhcpSetup74Test.test_setup_and_first_service_scope`，七场景：delayed_setup、unstarted_server、setup_expiry、cap_not_issued、service_clamp、core_failure、setup_reference_changed。旧测试方法 0，未重放旧生命周期、DORA 或 pktinfo 测试。

子进程执行完整固定 Server74 和中性的实际 `mta_ip`／`mta_dhcp` 定义。Native binding、期限发行、UDP、canonical/source 检查及 closed=True 是明确的惰性模型；FakeSocket 没有 OS socket／FD。Linux socket 常量和 ancillary API 形状也是模型。每场景平台 IO tripwire 调用均为 0。实际 wire core 只构造，不处理 DORA 包。此测试不执行 Bootstrap、Store、Native IP/DHCP、Loader 或完整 20 源图。

[result.json](results/go-dhcp-setup-v74-host-20261003-032346-6481a0da/result.json)；[四成员结果 ZIP](results/go-dhcp-setup-v74-host-20261003-032346-6481a0da/public-result.zip)：3458 B，SHA `6ed6007bdefad8849ed4d424dd9533748e82691fed23c162561e231efb9f3be7`。

ROOT `ec0297` 与独立 `d11448` 只读审计通过：30 件 private-inputs 与当前来源的字节／大小／SHA 一致；固定 marker、Ran 1／OK 和分层 flags 一致；ZIP 四成员逐字／大小／CRC／testzip 一致。独立审核亦确认 private-input 目录无额外文件，两个 20 源图仅四行替换。stdout 90 B，SHA `b09a607c64a5d6c2553cdeb177b116b940b414d2185173762795aaa29d44ccf6`；stderr 100 B，SHA `18c7270e10aedb42830f546b30ce4fbdcc001836915b3e7bac25bc50d3f6000c`。raw 原件保留 CRLF，不按工具展示改写。本轮四源联合 SOURCE 审核未发现确定正常调用 blocker；该审核不替代 Native／Store 正向动态执行。

## 仍未完成及下一真实接点

- F60 现有原 strong ticket → `value.run()` 已能从源码调用同 worker 的 Bootstrap74 prepare／poll／finally restore，无须为这条 GO＋L3 纵片增加 callback。后续需要生成并认证实际部署来源，而不是把主机 source map 当已部署图；设备旧恢复记录和完整恢复未证仍按原判保留。
- 发送仍缺同原 F 内实际 scoped TCP／TLS producer、station＋DHCP 原件绑定和原任务／epoch 的发送 IPC。旧 SendWorker 要求的 DHCP 类型与实际 GoDhcpServer 不同，不能只改 available 或跨 worker 借用 owner。
- 接收仍缺真实准入：State32 receive_available=False，Handoff13 和 Factory69-r3 要求原同域 handoff。已有 F37 原 CLIENT／DORA／IP／peer、文件确认及 finally restore 链不能被 GO 的 IP／DHCP事实替代；真实 consent、GATT session、nonce 和回执保持必需。
- 尚未验证设备端 setup／service 时间、资源成本、实际关闭／网络恢复、手机发现／握手、双向文件 hash 和取消／失败恢复。目标继续 active，**尚非只剩人工验收，也不是互传功能完成**。
