# 恢复回执父端、完整快照入口与原服务期限接线

2026-10-03。对端记录为小米 15 Ultra；HyperOS／原厂互传版本未知，尚未要求手机操作。本阶段没有 ADB、设备采样、扫描、配对、切网、重启或旧记录清理。目标 active，生产收发仍 False，尚非只剩人工验收。

## 新实现及保留的边界

| 来源 | 字节 | SHA-256 |
| --- | ---: | --- |
| Bridge86 `candidate/go-send-finish-parent-v86/runtime/mta_go_send_bridge.py` | 75404 | `964aaa1dff1f35bf780dd03c2ae094bbedf051028a3ca85f99cff660b5f99516` |
| Packet87 `candidate/go-send-observer-entry-v87/runtime/mta_observer_packet.py` | 13223 | `6f2c882058ee30a630ac30e1a5b4e9277d04ee2e71c108b58966a0574bf74e7a` |
| Entry87-r2 `candidate/go-send-observer-entry-v87-r2/runtime/mta_go_readonly_entry.py` | 25537 | `41ec9d93147b875bb38363f15e545962459e4eaba161ccc5fb7759ce6c5c7df9` |
| Owner88 `candidate/client-service-owner-v88/runtime/mta_client_service_owner.py` | 27038 | `160d507a99ce114e005f6b21b46d1632de391c4cca32080e025a9d675dee36fe` |

Bridge86 在原 spawn、三处 wait 返回及原管道读取位置保留子进程／binding／管道原件、reap 和两个 EOF 事实。仅在同子进程、两 EOF 与原 reap 均具备后消费 F84 的 canonical 私有首行 DATA；首行4096字节、原 stderr 总16KiB不扩。业务失败／非零 exit 可以保留报告，default unavailable 不算报告；解析错误不洗 PRIMARY、key unknown、close 或 pending。新增消费没有 IO、时钟、等待、恢复或 State 清理。外层报告不可变，内层 DATA 被改后被动 accessor 拒绝。不将子进程报告当独立网络恢复。

Packet87 是独立于 Bridge8192帧的长度前缀通道：18字节 prefix、header最多65536字节、原完整 Snapshot ASCII 最多131072字节、总量最多262144字节。两 helper 原 raw 完整留为 hex，绑定原六项 DATA、RO51原manifest、既有锁metadata、payload SHA及原stable key。decode 仅返回 immutable primitive DATA／SnapshotData，不构造 Snapshot、Actor、lease、proof 或 grant。完整包超限拒绝，不截字段、不抽样；p011_json 原限制不变。

Entry87-r2 默认 `main([])` 无 IO；显式固定 `--collect` 六 binding 参数，无路径、命令或 output-fd 选择。bootstrap 从固定原 FD 读取／核 hash／once-close 后才定义 Loader85 与 Packet87；没有 sys.path fallback、namespace adoption 或 rollback。正式调用源含原 Loader38／Body85 collection，目标 stdout 固定FD1，核私有 FIFO、access、原metadata和实际 `PC_PIPE_BUF`，每块不超过原atomic cap。原返回／EAGAIN／短写／晚返回强留，已知原 FD 过期仍 once-close 并核 typed EBADF。`packet_written` 仅本地发送，不是 Parent 接受。

原 Entry87（25147字节／`873a76f042f36349c83a15a92c7a0255ae3da280731fc179b9afbc01c911b2f6`）原样保留、未执行。本轮 SOURCE 审查发现 private writer 本身缺重入门，因此独立r2只补说明、`write_attempted=False`与最前一次门；首次无效DATA／短写／超时／完成后再调用均不重发预算。这不是 r1 测试失败，也不是实机管道异常。Packet87及冻结85三源未改。

Owner88 固定 Boot83 bytes/hash，核原26角色、schema与 GO Loader 的真实 asset路径；原 authenticate 后只加纯角色核验。State78 ctor 获得同一原服务 `original_until`，不是10秒load片段；两个保存字段逐 `is` 核原引用。原HTTP／库存／期限／零operation关闭政策保持，scan／send／receive仍False；不能用旧zero-operation关闭声明覆盖未来活动worker恢复。Boot83仍固定旧Bridge79／Pub82-r2，不称新来源已合入正式部署。

## 首次唯一 HOST 验证与实际产物

ROOT `d42123` 首次执行固定 Python3.12 `-I -B` checker；三个新方法各一次通过、各child0／无超时／旧方法0。仅四份新runtime做Python3.5 AST兼容检查，不重跑旧target兼容检查或85／79／80／83方法。

| HOST 项 | 精确范围 | HOST耗时 | 原unittest |
| --- | --- | ---: | --- |
| Parent86 | 16个新独立定义域；实际selected纯消费方法，child／wait／FD／两EOF／binding明确模型；F84仅SOURCE，不emission／restore／实际drain | 0.546秒 | Ran1／0.375秒／OK |
| Entry87-r2 | 一个六定义域中的13组；四纯定义＋Packet／Entry完整定义，实际primitive SnapshotData decode；POSIX FS／flags／FD／select／write／EBADF／PID／clock模型 | 0.219秒 | Ran1／0.045秒／OK |
| Owner88 | 10个独立模型域，实际完整Owner定义；Boot／26roles／Factory／State-init／Server／threads／FS／clock模型；Boot／State合同仅SOURCE | 0.156秒 | Ran1／0.045秒／OK |

Entry容量域只核完整 framing 最大长度的留存和超限拒绝；最大包为 malformed DATA，最终 decode 明确拒绝，不能据此声称真实131072字节设备库存可装入。完整collect、Loader38 load、helper、真实pipe／Parent／State／Server、物理关闭及网络恢复均未执行。本次没有实际P011 Python3.5运行证据。

ROOT `2dea5c` 与独立只读审核 `54476d` 核59 declared／private／current输入、固定Python、三原raw及8成员ZIP完全一致。56-row source plan前39项与原定义映射逐序一致；r1 target=False，只有上述4新runtime target=True。stdout分别106／114／105字节，stderr各100字节、严格安全marker及Ran1/OK。每项dispatch1／verified1／old0。固定Python103192字节／`42ac541168e97dedb9aabd8be335539fc41c682e414b9e8d137b164fb68683b0`。独审是实际产物核对，不是测试设计独立复现；审核者也是Owner测试作者。

[结果ZIP](results/go-send-parent-entry-v88-host-20261003-110225-100ead9e/public-result.zip)：6409字节，SHA `d56e5f018227768298c87df8d04e98e9e1ffeab1ff518c3e011ea75b37b9290c`。8成员顺序／原bytes／size／CRC及`testzip()`核对通过。[电脑一键入口](HOST_MTA_GO_SEND_PARENT_ENTRY_V88_CHECK.cmd)仅本次三个HOST专项；本轮实际直接运行checker，不称人工双击或笔端部署。失败raw规则仍是只保私有，不进公开ZIP。

工具封稿：plan12472字节／`69a8ae78ee7cc3dde1e54c77d27670a443a1f19246963422dbc3c048ab1c9310`；checker10841／`f272fe9db2214cb00e790dfdfbb6c24b74d6bf4ddef4178050ecb8ac5f83e8e8`；CMD281／`0e236134df649e4ed6561dae0040199e6349c851bf935c82a0401a17e8f9b686`。raw保原CRLF；报告派生显示不改历史。

## 仍要完成的真实接线

- 固定observer资产stager、真实Parent原Popen／child身份／管道EOF／wait-reap／FD闭合与完整packet消费；当前没有实际Parent observer receipt。
- Publisher仍在mkdir前拒绝缺observer，fixed seal未开放；F reserve前还需核原preflight与本次完整新基线同stable key。摘要不是授权。
- Bridge86已SOURCE接finish尾部，但正式ordinary/private source表尚未换入新来源；还需独立终末observer读同任务20字段Journal、既有锁、完整双轮网络key、原controller/watchdog缺席等，才能解除State本次恢复待核状态。不是删除旧pending的权限。
- Owner88 cap接线仅在本轮HOST模型有限通过；正式final graph／工厂真实准入／接收准入及工具箱正式启动仍未闭合。
- P011旧pending／完整恢复未证的历史判定没有回填，本阶段没查设备；正常重启许可尚无本次明确回复。最终小米原厂双向互通、系统版本与人工体验仍待。

下一阶段先核实际固定Python／stager／Popen来源合同并实现Parent通道，不创建伪true producer，不根据文件存在、子exit0、wlan0 up或HOST模型宣布生产互传完成。既有[实施计划](docs/SEND_ADMISSION_RESTORE_PLAN_V81.md)及[上一阶段原件](CURRENT_SEND_FINISH_OBSERVER_V85_FINDING.md)保留。
