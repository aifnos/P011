# GO 建组／恢复候选 r5：SOURCE 检查，不是运行验收

最新 HOST 补充：隔离 r4 完整方法首次 `1/18.080s OK`、child0/noTimeout，11显式模型流程通过，17实现定义/原期限/额度保持。ROOT核25当前/private输入和四成员[结果ZIP](results/go-bootstrap-native-v34-r4-model-20261002-132019-93dc7917/public-result.zip)，SHA256 `2526f82e9b84a5494a65217b7d8b471ce73022cf787f1166ae7d40339cc768d6`。真实子分支/FD3/watchdog/OFD/物理锁、P011 RF和手机未验，不能签设备部署/恢复/收发。下方为此前审查及诊断时点，原失败保持。

当前补充：固定17图的首次HOST方法及隔离诊断r2都已执行并失败，结果保持；r2确定首因是HOST地址夹具缺IFA_CACHEINFO，真实完整基线校验拒绝，尚未进入reserve/RF。r5实现源没有为测试放宽。后续r3仅修夹具与原身份观察，尚待首测；详细失败包与证据见[最新检查点](docs/LATEST_CHECKPOINT.md)。下方记录原SOURCE审查时点。

固定图为11个既有机械事实／会计模块、4个r3 GO模块及2个r5模块，共17个。不消费CLIENT lease/caps投影作GO授权；真实运行还需要可信部署、原锁与原任务期限。当前未启动设备GO、未改接口、未测试手机。

ROOT已完整读取r3 Native/Bootstrap、此前Store及其他模块的窄diff；r4/r5完整差异、Python3.5 AST和哈希已核。17图HOST模型方法正在编写，尚未执行。只表示源码存在及相应审查，不表示已建组、恢复或发送。

| r5文件 | 字节 | SHA256 |
| --- | ---: | --- |
| `candidate/go-bootstrap-v33-r5/runtime/mta_go_native.py` | 86024 | `839ea4dbde4e26e8387434af071b12ee0330ac653a4e043d452b78af7f28be6a` |
| `candidate/go-bootstrap-v33-r5/runtime/mta_go_bootstrap.py` | 16859 | `0b2960491717f0100882f5dac25df66669a53651adf813c0617726455b4471e7` |

其余GO沿用r3 Store `7e10b8bb…`、Deployment `2922f16f…`、Executor `0b89d734…`、ProcessOwner `78a48072…`；原r3/r4与所有失败回执均保留。

本次审查发现并隔离处理的接点：

- 合法同票CREATE ECHO在等待ACK时即保留；缺完整ACK不得发布owned、DEL接口或清pending。
- 一个原子进程清理失败仍继续另一个原子进程；实际TERM、wait、absence和原FD closure分离记录。
- raw once-close与已知原路径的首次once-unlink分离；未知unlink结果不重试，过期/外来来源不续期或删除。
- 原controller socket尚未出现时只在原stage cap内被动等待；出现后双核进程、socket inode、路径与凭据，foreign不收养。
- passive路径检查在FD factory登记前；未调用factory不会伪装成已创建但未关闭的FD。
- 第一次恢复保存原13项周期与会计/reader/RLock/epoch身份，用已有CLEANUP lane和实际Budget.cancel，不加额度。
- canonical/publication未知时只核已注册原ticket、原preexec来源和当前双轮Proc，对核实的原子进程尝试一次stop/reap/原FD关闭；不发GROUP_REMOVE/DEL、不清pending、不签logical restored。

当前纵片在确认group_started后立即自动恢复；没有持续GO服务、IP/DHCP、广播、TLS发送或手机流程。源码标签／AST不代替HOST方法或实际P011验收。生产收发继续关闭，完整互传目标保持active。
