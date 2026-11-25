# 互传终末身份数据与独立观察源码 v93

完整执行器 Actor 和原始子进程启动结果已接入新 F/Bridge 候选，新增主机专项首次通过。独立终末观察 Body 与对应 Loader 已写出并完成源码审阅，但尚未运行或接入 Entry、Parent、State。生产收发仍关闭，P011 网络恢复和小米原厂互通均未补签。

## 已实现的改动

F93 保留原 GOFINISH84 私有首行和 4096 字节整包上限，数据 schema 升为 p011-go-finish-data-v93。新增 f_actor_data：原 entry.actor 经同一私有 GO 域的原 facts._actor_tree 输出完整 pid/start/exe/argv_sha/tasks，保留所有线程而不截断。before/after 由 11 项增加为 16 项，连续核原 facts 模块、字典、函数及 launcher tickets/registered 原引用。

新增 children_outcomes，逐一对照原 ChildTicket、role、原注册 tuple4、device FD 与期限。未请求 fork、fork 明确失败和已启动后回收分开记录；缺 Actor 或 None 本身不能证明未启动。正向启动仍需要原 wait/exit_verified 和原 Proc absence 发行。Bridge93 严格消费新字段、完整 Actor 的顺序/唯一线程/leader 和九种状态、启动结果与 child 对应关系。超限或来源不确定沿用 unavailable；不覆盖原业务、restore、key 或 close 错误，不新增恢复或发送授权。

ROOT 和独立审查者已核 F/Bridge 对照90的完整窄差异；原发送/恢复主体、FD2发行、Bridge双EOF/reap与tail逻辑未变。旧候选和结果均保留。

## 固定来源与验证层

| 文件 | 字节数 | SHA-256 | 本轮范围 |
| --- | ---: | --- | --- |
| candidate/go-send-terminal-source-v93/runtime/mta_go_executor.py | 62728 | f33ad96651e8aed38adab1ca931da6de7455130b8dbcedd774e1038ee39c8ed0 | 新专项 Python3.5 AST 与选定纯发行算法 |
| candidate/go-send-terminal-source-v93/runtime/mta_go_send_bridge.py | 87625 | 027be64bf7b1b4f6ae57d09921b821e4cc77db44c602b9a5d99d901ed5736f02 | 新专项 Python3.5 AST 与严格 DATA 消费 |
| tests/test_go_terminal_finish_source_v93.py | 34904 | d08732c80591327ffa700861228364aae1f444f38bdc18c20fac02c6d4a8c55a | 唯一新方法、两域18夹具 |
| host/go_terminal_finish_source_v93_check.py | 11735 | 862d1e6793019e8f127bd9098637e2fe10c612c57e8da148b9c6aae5aecfa314 | ROOT 首次运行与封口 |
| host/go_terminal_finish_source_v93_source_manifest.json | 2990 | 2ddc562a469abf2785bcb64714c773b2ce4bf2859118d78a4e16c8ebd5a1fbff | 13 个固定输入 |
| HOST_MTA_GO_TERMINAL_FINISH_SOURCE_V93_CHECK.cmd | 287 | 9593c17a16773d903ef861c6cdbb8f1b8353614c6aec38b5dda0eb2473282156 | HOST-only 一键入口，未宣称点击验收 |
| candidate/go-send-terminal-observer-v93/runtime/mta_go_readonly_preflight.py | 63261 | 2b1c4750d1ef2958c33e92c1589cd39fdb469e52da105f67bec9292a63aafccc | SOURCE；本轮未 AST 或执行 |
| candidate/go-send-terminal-observer-v93/runtime/mta_go_readonly_loader.py | 36535 | cd0a7076deb549ee04318c08167c93e55c08007e3c2837532ce2ce6c61602f4c | SOURCE；本轮未 AST、load 或执行 |

专项固定输入为纯 JSON/IP/Core28/facts28、Proc25、GoProcess33-r3、Store74、Native76、Deployment90、Bootstrap90、F93、Bridge93 共12源，加新 test 为13件；再加 plan/checker/CMD共16份实际快照。仅新 F/Bridge 做 Python3.5 目标兼容 AST；没有重跑旧84/86等测试方法。测试为选择实际定义的独立模型域，不是完整私有 GO 加载图。

## 首次主机专项与原件审计

ROOT 9b4be6 唯一执行 GoTerminalFinishSource93Test.test_full_actor_outcomes_and_strict_consumer，首次 PASS：host0、child0、无超时，child 调用约2.906秒；原 unittest 输出 Ran 1 test in 2.743s / OK。两受影响域18个独立夹具，4正向、14拒绝。

| 域 | 夹具 | 已验证的模型行为 |
| --- | ---: | --- |
| F 完整身份与原结果发行 | 6 | 全量线程与首业务错误保留；原 pure ChildTicket 的 never/negative 区分；函数身份变更、缺注册、正fork缺Actor和128线程整包超限拒绝 |
| Bridge 严格新消费者 | 12 | 正确新wire和P状态 primitive DATA接受；缺两新字段、Actor不一致、exe错误、缺leader、重复tid、假bool、正fork无Actor、role或数量不一致拒绝 |

Actual Actor/ChildTicket/LaunchSpec/GoRecord/Snapshot 纯构造、编码与新 F/Bridge 算法执行。restore 返回、canonical issuer/history、FD/锁闭合、启动状态与 reap 均为明确合成模型；每夹具平台 IO/时钟/authenticate/restore tripwire 计数为0。没有实际 fork/wait、完整私有 GO 运行、Body 采样、ARM/helper、正式服务、P011 或手机操作。

ROOT aa2e42 与独立原件审计 fb9a8a 均实际核16份 current/saved 的集合、逐字节、长度和SHA；strict raw、四成员CRC/testzip与ZIP外部读回一致。独立审计未重跑专项、checker或WSL探测。源码冻结，已通过专项不重跑。

- [公开结果 ZIP](results/go-terminal-finish-source-v93-host-20261003-143537-25e02ac7/public-result.zip)：3031 B，SHA-256 02fdaa7d4a7ca2d455b72493881dbe1a489f3170875757b0bf1cfdb2c7af54d2。
- 成员仅 result.json 5359 B、README.txt 565 B、stdout.raw 127 B、stderr.raw 96 B；私有快照未公开。stdout SHA a8fbec6093b24c43af9ee9663f1304509f370d5d0a9006548d546ac70d695f0d；stderr SHA a15d5b832e643b1555b664647c56688d26d63f9e34cfbcbe60cfee612b00bbf4。
- [一键主机入口](HOST_MTA_GO_TERMINAL_FINISH_SOURCE_V93_CHECK.cmd) 不调用 ADB。此次 ROOT 直接运行 checker，没有人工点击 CMD 或笔端验收声明。

## 独立终末观察：已完成源码，尚未执行

新 Body 保留旧 Body85 的24992字节前缀，原 ReadonlyPreflight/MAX_ROWS3/能力路径不改；追加 ReadonlyTerminalObserver(loader, observer_binding6, finish_raw93, launch_binding9)。新 imports 只用原 RO38 内的 facts、Proc、Core，未另造采样器或加载 GO Store。

新 collect 设计连续持既有 device/journal 两锁，覆盖 Journal第一次独立打开读取、实际 leaf51双 Snapshot、同原 ProcReader 的F与具名child Actor各新一次双pass absence、Journal第二次独立打开读取。TERMINAL_MAX_ROWS4=两锁加两读，不调用helper。Journal raw/SHA/完整九字段metadata必须等于原finish，前后raw一致；原Actor仅expected identity DATA，退出事实须由原reader/issuer/history恰新增generation发行。

采样后重新调用 owner._closed、reader.history_closed 和 budget.status，不能复用collect开始时的缓存。未知FD、部分构造、PID复用、采样错误或晚返回保库存/pending；已知原FD在期限后仍允许一次close，不重试。全部原本地及Proc库存闭合后才返回私有DATA，恢复/准入flags仍False。ROOT已阅读全文，独立审查交叉核actual leaf/Proc/facts，未发现确定源码阻断项；本轮未验证该实际运行行为。

新 Loader38 仅改版本说明及Body pin，原物理ROOT85、RO35 manifest、load count38、seal7和其他逻辑不变。ROOT 3fe281 完整窄差分为两处，独立源码读审逆还这两处后全文等于旧Loader，并核新Body pin实际匹配；diff exit1表示存在差异，不是执行失败。Entry/Parent/部署表仍未接新pin或终末模式，因此新Body不能宣称已经可launch。

兼容边界保持：Proc允许P，而旧Core28/33 Actor构造不接受P。Bridge仅primitive DATA接受；新Body经原facts._actor遇P会保守不可用，不修改旧Core或删字段签成功。完整STATUS原始字节/稳定键对照的设备兼容风险也尚未消除。

## 下一真实接线与期限限制

消费位置为 State78._close_go_worker：Bridge.close/reap之后，Publisher/Prepared/selection关闭之前。实际原 Bridge.finish_report、原10项身份、真实reap和双EOF必须连续保留；launch_binding9由原 binding7、原deployment候选hash和原process PID生成，不能由finish自证。

还需新增终末request/response的有界私有DATA包、Entry原collect入口、Parent输入管道/原wait库存、State同worker终末报告与外部finalizer被动消费；之后才是准确普通加载图、目标manifest/固定部署封印、真正接收准入、正式服务与工具箱。不能仅靠Snapshot key相等或JSON中的restored字样签native_restore_verified。

当前Body要求观察期限不超过原task期限，原Parent还保留5秒收尾。因此最窄第一接线仅能在原task/service剩余足够时观察。task到期后进入task+60清理区间的路径仍应 unavailable/pending，不能把清理cap假传为新task cap；若实现该路径，需专用、明确消费已固定清理上界的合同，不在poll或错误时续期。外部finalizer不得跨线程再调用Parent/Bridge/采样IO，应仅消费同worker实际保存的原事实。

## 设备与目标边界

本阶段无ADB、扫描、配对、无线配置、重启、部署或删除旧pending。旧GO64完整恢复未证及待明确的重启问题保持；接触设备前仍须完整读取适用归档交接/版本表/无线分析并采新只读基线，曾截断的归档读取不算完成。

目标active，send_available/receive_available均False，尚未达到仅需人工手机测试。真实测试手机为小米15 Ultra，HyperOS与原厂互传版本仍未知。
