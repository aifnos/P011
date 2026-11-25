# 互传普通加载图与固定资产来源 v91

工具箱普通加载器已接入上一轮的发送预检组件，首次主机专项通过。发送子进程的 25 源资产来源表也已冻结。这些仍是未部署的候选：没有启动 State、服务、只读采集或无线收发，不能称为 P011 与小米原厂互传可用。

## 本轮实现

Boot91 的普通角色从 26 个增加到 27 个，仅在 Publisher 前加入 Parent89，并把 Deployment、Publisher、Bridge 更新为 v90 的准确来源。其余 23 个角色的尺寸、哈希、相对顺序和路径不变；F37 仍是普通域的原执行器。Parent 自己的只读私有定义和 GO 的私有定义没有混进普通域。

Owner91 同步固定 Boot 的哈希、schema 和 27 角色合同。原加载 10 秒、传给 State 的原服务绝对期限、关闭库存及收发关闭策略没有改变。GO Loader 仍使用自己的真实 asset 路径，不伪装为 State runtime 路径。

另建的 25 行 GO 来源索引与 Deployment90.MODULES 逐序一致，当前文件长度和 SHA 全部匹配，总源码 1,039,320 B。该 HOST 索引不是 Publisher 所要求的目标 source-manifest.json；没有借它设置 BUNDLE_MANIFEST_SHA 或发行准入。

## 固定来源

| 文件 | 字节数 | SHA-256 |
| --- | ---: | --- |
| candidate/go-send-fixed-boot-v91/runtime/mta_client_receive_boot.py | 18914 | 513fb72d3be7d02b483e60b890a66c73f30180ab76228b18b972796b0bd5fb2e |
| candidate/go-send-fixed-boot-v91/runtime/mta_client_service_owner.py | 27089 | e7c108ae7346aefe3c0b56f70e197f6ed0777b825ff9ce46f14e841be5321b5b |
| host/go_send_fixed_boot_v91_definition_manifest.json | 6336 | 85db83d08153a8ca001d5f9d54b9a838b6bd4ed79e6dd2b1fa0da7291c9a14db |
| host/go_send_fixed_v91_asset_sources.json | 5621 | fae75798a88cc9dd1e64bbca0993d028c78729aef081195b3207679bb1d7ffc7 |

ROOT 与源码作者完成完整窄差分、当前字节核对及独立 SOURCE 审查。旧 Boot83、Owner88、旧来源表、v90 源码和历史结果保持不变。

## 主机验证与结果包

ROOT `91e277` 首次、单次执行唯一新方法 GoSendFixedBoot91Test.test_changed_graph_and_parent_role_identity：两个受影响域通过，child0、无超时，约 0.437 秒；原始 unittest summary 为 Ran 1 test in 0.257s / OK。

实际执行的是完整普通 Boot 的 load/authenticate 和 Owner 原 _boot_roles 校验。第一域验证新 27 角色之间的实际定义引用；第二域修改新增 Parent 的 __file__，确认 Boot 与 Owner 两处原校验都拒绝。Owner 只使用明确的构造前角色对象，没有执行其构造器或 start。

文件系统元数据、FD、PID 和时钟是明确模型；只对新 Boot/Owner 两件做 Python3.5 静态语法检查，旧方法派发为 0。没有执行 Parent.collect、Publisher.preflight、State/Server、私有 GO/RO 图、真实 ARM、目标部署或独立恢复。加载成功不替代这些验收层。

31 项输入及 plan/checker/CMD 共 34 份实际快照已核与当前源逐字节、长度和 SHA 一致。ROOT `1b73eb` 与独立只读审核者一致核对严格 raw、成员 CRC 和 ZIP 外部读回；没有重跑专项。

- [限定测试公开结果包](results/go-send-fixed-boot-v91-host-20261003-132430-66747000/public-result.zip)：4066 B，SHA-256 dd1dcce4b2fdf2f2493901748585d17e9632b7f28080874dd7f9e5e4d214130f。
- 公开成员仅 result.json 8506 B、README.txt 612 B、stdout.raw 132 B、stderr.raw 96 B；私有输入未放入公开包。
- [一键主机检查入口](HOST_MTA_GO_SEND_FIXED_BOOT_V91_CHECK.cmd)：只运行本限定专项，不调用 ADB。此次由 ROOT 直接执行 checker，未宣称人工点击 CMD 验收。

## 独立恢复的具体缺口

源码核对确定，下一终末观察接点是 State78._close_go_worker：原 bridge.close(end) 之后、Publisher/Prepared/selection 关闭之前。原 Bridge.finish_report 已能保留真实完成 DATA，包括业务失败和非零退出，不能只在 RESULT 成功时读取。

不能直接复用 Publisher 的发送前检查：原 publication20 期限、Prepared 活跃态和 once 门已不适用。Publisher.publish 已经关闭原文件库存，新增终末 Parent 必须拥有独立保留和一次收尾，不能被原 close 的 early return 漏掉，也不能重关原文件。

现 Parent 的观察预算仍夹在原 task/service 内并预留 5 秒。到期后或只剩不超过 5 秒时不能重新发行 task 期限；需要明确的 cleanup-only 只读合同，不能把清理期限冒填为新的发送期限。Parent 当前的失败 cleanup5 只是已保存边界，还缺有界 drain 和一次 wait 的失败收尾；未知 pipe、预算耗尽或未 reap 都必须保留 pending，不 kill 或 relaunch。

完整恢复还缺本次 Journal 独立读回，以及已记录子进程的独立 absence 来源。F 的 pid/start DATA 不能伪造成 ProcReader 要求的同域 Actor。终末快照 key 相等本身也不能把 native_restore_verified 翻为 true；STATUS 控制通道与 CLI 原始字节的兼容性仍需设备证据，不能删字段绕过。

## 下一步与设备边界

1. 补 Parent 异常路径的有界回收，以及终末只读观察、Journal/子进程 absence 的真实来源。
2. 生成 Publisher 所需的准确目标 manifest，制作固定资产 EXCL/readback 部署器和完整来源封印。WPA 的 PC 原件已核；Python 必须保留目标本次完整读取、ELF 和观察/二读一致检查，不能用 HOST Python 替代。第四条 wpa_cli baseline pin 是历史来源，不代表本轮设备核验。
3. 真正的接收准入、正式服务和工具箱同图接线，然后是 P011 和小米 15 Ultra 双向实测。

本轮没有 ADB、设备采集、扫描、配对、无线配置、重启、部署或清旧 pending。归档交接文件的读取输出曾截断，不能算新设备操作前的完整必读完成；下次接触设备前仍须完整读取适用交接、版本表与最新无线分析，再做当前只读基线。旧网络恢复未证和重启问题待明确答复保持，不以本 HOST 结果刷新。

目标保持 active，生产收发仍为 false，尚未达到仅需人工手机测试。
