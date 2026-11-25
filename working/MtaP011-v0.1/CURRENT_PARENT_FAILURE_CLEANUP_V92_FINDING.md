# 互传只读子进程异常收尾 v92

新增 Parent92 候选已补解析失败后的有界排空与一次进程回收，首次主机专项通过。它沿用原清理期限和剩余预算，保留首次错误；未知资源、超限或超时仍标记未完成。此候选尚未接入 Boot91，也未部署到 P011，不代表网络恢复或小米原厂互通已经通过。

## 代码改变与保留

新增三个私有方法 _cleanup_pipe_current、_read_cleanup、_cleanup_finalize。collect 保存首次异常后，在原 close 前尝试一次清理，随后仍抛出原异常。只有已经确认身份及 nonblocking 状态的原两条管道可以读取；失败后不再调用 PacketReader.feed/finish，也不发行 report。

清理共用原 cleanup_until、MAX_EVENTS 和各管道字节预算。代码只有在两条管道均读到 EOF、原 wait 尚未调用时才调用一次原 wait。等待已失败或返回都不重试；晚返回的实际回收票据先保留，再做期限后验，不能因此消除 unknown/pending。没有 poll、kill、重新启动子进程或延长任务期限。

完整窄差异经 ROOT、作者和独立审查者核对：旧 Parent 的 24 个方法只有构造器、_context、collect 改动，其余 21 个正文逐字不变，包括原成功 drain/wait、EOF、close 与 closed_facts。LinuxIo/main 不变。旧 Parent89、Boot91、Publisher90 与历史结果均保留，未把新候选冒填为普通加载图当前来源。

## 固定来源

| 文件 | 字节数 | SHA-256 |
| --- | ---: | --- |
| candidate/go-send-observer-parent-v92/runtime/mta_go_readonly_parent.py | 50693 | 417af52e6424320d1421f74110526e70edbdd0210e8f42e789ec1ed1e3b84cfa |
| tests/test_go_readonly_parent_cleanup_v92.py | 30164 | 80a0424b0e17ed7a70bccd0ca3e130a8101fd332bd63a61ec2f5f4d6444e1cb3 |
| host/go_readonly_parent_cleanup_v92_check.py | 11810 | a964f0b6418c89bd138dfddbb4c36041c94db0b57a4a449a84a5d73264ab9a71 |
| host/go_readonly_parent_cleanup_v92_source_manifest.json | 1863 | 6a1818a753638451a2b1acad37a98e6097b384559f1cbe423e8e17327909d51e |
| HOST_MTA_GO_READONLY_PARENT_CLEANUP_V92_CHECK.cmd | 282 | a472ef0454e8add889039aa86c4bdebe40637cb9bdf8cd8caca4cdada4b6c114 |

检查输入仅原纯数据五源、Entry87-r2、新 Parent92 与本测试共八件；加 plan/checker/CMD 为 11 份实际快照。仅新 Parent 做 Python3.5 AST；旧测试方法和旧 target AST 均未重放。没有加载或执行旧 41 源部署专项。

## 首次主机验证

ROOT 7aecf8 单次执行 GoReadonlyParentCleanup92Test.test_failure_cleanup_and_original_reap，通过八个受影响域、11 个独立夹具；host0、child0、无超时，child 调用约 0.797 秒，原 unittest 输出 Ran 1 test in 0.615s / OK。

| 受影响域 | 夹具数 | 本次模型验证的结果 |
| --- | ---: | --- |
| 解析失败 | 1 | 不再解析，排空两 EOF、wait 一次；本地库存可闭合，但首错误和无 report 保持 |
| 活跃期限到达 | 1 | 原读取晚返回后，仅使用已经保存的清理期限，不续期 |
| 未知管道 | 1 | 不读取、不 wait、不关闭未知 stdout，保持 pending |
| 原 wait 抛错 | 1 | 两 EOF 后原 wait 只调用一次；FD 闭合不等于进程已回收 |
| 清理边界 | 3 | 字节、事件、绝对期限耗尽均保留首错误与 pending |
| 清理 wait 晚返回 | 1 | 保留回收票据，同时 closed=False、unknown=True、pending=True |
| 子进程构造未知 | 2 | 构造抛错或返回 None 都保留未知库存，不伪造未启动结论 |
| 关闭结果未知 | 1 | 原关闭异常保留且不重试，不覆盖业务首错误 |

完整 Parent collect/cleanup 和纯 Packet/Codec 算法实际执行；文件系统、FD、ARM 元数据、管道、进程、wait 和时钟均为明确模型。没有真实 Popen、内核管道、ARM、helper、RO 采集、State/服务、目标部署或设备操作；旧 active-wait-late 分支未补签。本次模型中的本地库存闭合不是物理网络恢复。

ROOT 976ff0 与独立原件审计均已核 11 份 current/snapshot 的集合、逐字节、长度及 SHA，严格 raw、公开成员 CRC 与 ZIP 外部读回全部一致。独立审计读取实际原件，没有重跑专项、重新探测 WSL 或导入生产源码。源码停止编辑，专项不重跑。

- [公开结果 ZIP](results/go-readonly-parent-cleanup-v92-host-20261003-135615-38560c30/public-result.zip)：2684 B，SHA-256 f02b3eccb3fedab9f20c28f8a9a855357118c83f02a466d332de36a735473965。
- 成员仅 result.json 4437 B、README.txt 559 B、stdout.raw 130 B、stderr.raw 96 B；私有输入未放入公开包。stdout SHA 574854f1d135bb631bc5e94d2406716eaa6a74fd6c0ac43bca0fa847e8764052，stderr SHA 4047d1713ac4f396da6322c04df7b7cfbb6315a1e907afde2ba1a80b334a1784。
- [一键检查入口](HOST_MTA_GO_READONLY_PARENT_CLEANUP_V92_CHECK.cmd)：HOST-only，不调用 ADB。此次 ROOT 直接执行 checker，未宣称人工点击 CMD 验收。

一次额外只读哈希补查因 PowerShell foreach 管道语法报错；改为先保存行数组后核对成功。没有改变源码、重跑专项或影响上述原始结果。

## 独立恢复的下一实现接点

只读 SOURCE 核对确定：Store74 的本次 Journal 已保存 watchdog/controller 完整 Actor 五字段，来自原 ChildTicket 与 Proc 双 pass。F90 finish 仍只有执行器的 pid/start/argv_sha，缺 exe/tasks；下一最窄改动是由实际 entry.actor 经原 _actor_tree 输出完整 f_actor_data，同时保留未 fork 分支的原 ticket outcomes，不能把 None 当作未启动证明。

Body85 尚无 Journal 读取。新的终末观察需要连续持既有 device/journal 两锁，覆盖 Journal 前读、完整双 Snapshot、原 ProcReader.read_absence 双 pass 以及 Journal 后读，并重新核对 Reader 库存闭合。Journal/finish 解码出的 Actor 仅是 expected identity DATA，实际退出事实必须由原采样器发行；PID 复用、错误和不一致不能跳过。现 MAX_ROWS3 与路径表需要准确更新，不能冒称未新增观察 FD。

真实消费点仍为 State78._close_go_worker 中 Bridge.close/reap 之后、Prepared/selection 关闭之前。原 task/service 剩余不足时须明确 unavailable/pending，不把清理期限冒填为新发送期限。Core/Proc/facts/leaf 算法无需另造。快照 key 相等本身不能签 native_restore_verified，STATUS 原始字节的兼容风险也不能靠删字段绕过。

此终末恢复 producer 尚未实现或运行。还需把新候选接入准确普通加载图、目标 manifest/固定资产部署封印、真正接收准入、正式服务及工具箱，然后完成 P011 与小米 15 Ultra 双向实测。手机型号已记录，系统及互传版本仍未知。

## 设备与目标状态

本轮没有 ADB、扫描、配对、无线配置、重启、部署或清旧 pending。设备旧完整恢复未证及待明确的重启问题保持；下次接触设备前须完整读取适用归档交接、版本表及最新无线分析，再采当前只读基线，不能把曾截断的读取算完成。

目标仍 active，生产 send_available/receive_available 均 false，尚未达到仅需人工手机测试。主机源码与结果记录不改变这些状态。
