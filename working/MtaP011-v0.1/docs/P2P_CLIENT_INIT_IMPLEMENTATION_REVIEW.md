# CLIENT RF-init owner：HOST 核心实施审查

2026-10-01。本轮仅新增 `runtime/mta_p2p_client_init.py`、`tests/test_p2p_client_init.py` 与本文；不修改旧 State、生产 GO、V9、IP helper、native/build、冻结目录或历史结果。
已读 `P2P_CLIENT_INIT_OWNER_PLAN.md`、`P2P_CLIENT_NATIVE_NEXT_REVIEW.md`、`RECEIVE_P2P_PLAN.md`、`WORKER_IMPLEMENTATION_NEXT.md`、固定 2.12 源码和编译记录。本轮没有 ADB、设备/native、socket、Popen、RF、IP、Docker、下载、全套测试、正式冻结或结果 ZIP。

## 已实现层与尚未实现层

实现的是**纯 HOST 生命周期／私有记录／输入检查核心**，不是 Linux provider、磁盘 Store、真实 watchdog、接收后端或部署入口。`ClientInitProvider`、`ClientInitStore` 每个默认方法固定报 unavailable；构造/import 不调用 provider/Store/clock、不做 IO。只有显式 `start()` 才通过内部 provider 合同调用操作。
接受窄基类的内部实例，不接受任意 ctrl/shell/ifname/IP passthrough；Python 内部类类型不是恶意 Python 代码的安全沙箱，未来 State 必须只装配审核/pin 后的固定 provider，不能让 QML/IPC 注入实现或 manifest。当前 State 未接线，receive/send 仍 false。
公共证据固定 `HOST_OWNER_CONTRACT_ONLY`，公开只有固定 stage/reason/布尔；RF-init 可能有驱动/固件发射，**不能称 noRF**。association/IP/DHCP/data/phone/receive/send 全为 false。

## 独立角色、记录与 API

- `Identity`：version4、kind=`p2p_client_rf_init_only`、marker=`p011-client-rf-init-v1-1`、将来外层 manifest SHA、固定 WPA/ctrl pin；这不是已冻结 ID。
- `ClientInitLease(provider, store, identity, clock)`；`start(ttl≤20,cancelled)`、`restore(timeout≤20,inherited)`、`recover_current(...)`、`status()`。没有 SenderGoContext、凭据或关联操作，也不调用旧 GoLease。
- `Journal` 是不可变的 **version4 逻辑 schema**：identity/stage/baseline/deadline/owned/interface_ticket/controller_ticket/controller/watchdog_ticket/watchdog/ready；严格类型和阶段前提。目标 JSON 编解码、原子替换/fsync、owner/mode/nlink/noSymlink **尚未实现**，不能把 HOST Store 的 dict/对象当磁盘持久化证据。
- Actor 保存 PID/start/exe/argv 摘要和完整 task identities；Ticket 在 fork 前注册并持有强引用，InterfaceTicket 在 CREATE 前登记 boot/phy/精确随机名/seq/port，不猜未 ACK 的 WDEV/ifindex。
- 每次 `_save` 前重新核当前记录；provider 回调后的 stale current 不能被旧对象覆盖，真实 Store 还必须在同锁内 CAS。当前 journal 必须在 device flock＋journal 锁后读取，未知旧 version/kind/marker/活动 pending 不接管。
- Store 必须复用同 open-file-description 的继承 device 锁；父 active return 只实际关闭 journal 锁，保留 device 强引用。外部 finalizer 的 fresh recovery 不能关闭继承锁后再开第二把 flock；watchdog 只能请求恢复，不能调用恢复后等待自身退出。本 core 不实现 OS flock/reap，不能以 HOST FakeLock 称已验证。

## CLIENT 初始化与完整基线门禁

1. full Snapshot 包含 same boot、三固定原厂文件 pin、原 tracked Actor/task、原 wlan0 type2/COMPLETED/full STATUS 摘要/频率、完整接口及所有 IPv4地址/全部table routes/rules、原 IPv6地址/routes。
2. `client_combo()` 按完整当前 iftype counts、limits/coverage/max_interfaces 计算 STA＋新增 CLIENT8；不读 GO 派生布尔。未知 key/constraint、缺字段、重叠 coverage、software iftypes、非零 radar、beacon 条件失败关闭。空 CLIENT 无已证工作信道，不把 STA 频率或 num_channels=2 当双信道验收。
3. **真实 caps reader 缺口**：当前 `native/mta_wifi_caps.c` 的 parse_limit/parse_combination 忽略未知 child，print_caps 不提供 unknown-presence 证据；不能从遗漏推断 `unknown_constraints=()`。现有 production `LinuxBackend.snapshot` 也不含完整 IPv4；固定 V9 cfe 才有全 IPv4。未来需要独立严格只读 probe/新 candidate 与 reader；本轮不改 native，不将旧输出包装成新 complete caps。
4. 创建只请求 exact CLIENT8、CREATE|EXCL＋真实 authenticated ACK/readback；ready 必须实际 type8/IF_UP/sysfs origin/完整原网保持。没有未关联 carrier1 要求；意外9/2、不完整 ACK或复用对象不会推进或按名字删除。
5. 空配置固定 `ap_scan=1\np2p_no_group_iface=1\n`，没有 network/cred/SSID/PSK/update_config/SAVE_CONFIG/GROUP_ADD/SCAN/FIND/LISTEN。provider 私有 ctrl 目录/driver opt-in/FD3/PID release gate 的真实实现仍未写；不能给旧 GO spawn 改标签冒充它。
6. own IPv4 地址或任意 own-oif IPv4 route 都拒绝；不提供地址/route mutator。只按 exact-owned name 排除受限自动 IPv6 linklocal/64 与至多一条 canonical ff00::/8/UP/zero-source/gateway；默认、全局、重复或未知 flags 拒绝。其他原 IPv6 rows 仍完整比较，不写 sysctl/flush。

## 空配置 STATUS 源合同

固定源为 `native/private-p2p-candidate-20261001-v2/source/wpa_supplicant-2.12.tar.gz`，SHA `08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6`；精确以 `wpa_supplicant/ctrl_iface.c:wpa_supplicant_ctrl_iface_status` 为准。[官方发布包](https://w1.fi/releases/wpa_supplicant-2.12.tar.gz)
`WPA_ASSOCIATED` 以下不输出 bssid/freq/ssid/id/mode/security 块；常规 STATUS 输出 wpa_state、CONFIG_P2P 的 p2p_device_address、address、CONFIG_WPS 的 uuid，另有条件 ieee80211ac/bss_max_idle_period 等。已有 `parse_status(reply,credentials)` 必须真实 Credentials，所以本轮独立实现 `parse_init_status()`，没有假 SSID。
严格 bytes/长度/换行/重复/合法地址和 uuid；仅 INACTIVE 可推进。MAC/uuid 不返回、不进错误。IP、SSID、network id/freq、关联/密钥、未知扩展（包括此轮不支持的 ssid_verified/bigtk_set）一律拒绝。输出仅 ctrl_inactive/control_fields_only/association_verified=false；这不是 actual type8、关联或 zero RF 证明。
固定 WPA `e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301` 的源码 gate 支持初始 CLIENT8；当前没有已证必须重编的缺口。loader/控制/native 初始化仍未在 CLIENT 上实测。

## 退出与恢复的强合同

- registered ticket/实际 Handle 强引用不因晚 spawn 或异常丢掉；实际 PID 保存成功后才 release exec pipe，过期不 release。注册后超时不 launch；provider 可返回**正向 registry 的 never-forked＋FD closed**事实，不能仅从 intent 阶段推断“没进程”。
- live 与 exit 都必须覆盖整个 `/proc/<pid>/task`；leader Z 不证明其他线程已退出。当前正常直接子进程 `ExitProof` 要 fixed PID 路径确实不存在、task空、精确 actor identity、真实 wait/reap 和 exit code。存在却不可读/权限未知/PID复用/事件未置位都不是 gone；新进程不能 waitpid 已孤儿化的 actor，本版实际孤儿恢复未实现、保留 pending，不伪造退出码或 reap。
- 正常退出先锁内 fresh 全原基线＋安全 own L3，再 stop/reap controller/watchdog；只有准确 type8/origin 和全原基线继续成立才删除 exact owned iface。删除后再次无排除 full baseline、所有 registered resources 实际关闭，才能 reconciled/清 pending。`CloseProof` 为记录资源逐项 attempted/readback，不把空计数掩盖已知 Handle。
- `reconciled` 不直接 return true：current identity、接口 absence、完整无排除原 Snapshot、原 actor proof、controller/watchdog fresh exit/reap、FD closed readback 全重新核实；只调用 exit_proof/closed_resources，不再次 TERMINATE、删除或重复关闭 FD。已清 pending 仅允许进入该 fresh 检查，不是恢复授权。
- `finish()` 的真实 Store 必须同锁复核 current/manifest/pending，并独立关闭每个自身 reference，任何 close/durability 未知保留 pending。不能先清 pending 再谎报 complete；本轮仅定义/检查合同，真实 disk/FD 异常顺序及跨进程原子性仍需独立实现/审查。
- timeout 是单调准入/回调预算，不是 OS IO 硬抢占。controller/watchdog/Store 的真实有界 wait、全部 FD inventory、终止后的 thread/exit_files 读回、parent-death 实机验收尚无实现/证据。
- 当前 V9 pending/原 STA IPv4变化仍须 root 的独立诊断；本 core 不恢复 V9、不重基线、不接管旧 cleared GO journals，也不让未知旧记录启动新 RF。

## 实际 HOST 专项证据（不累计成一次“全套”）

首轮 `python -B -m unittest discover -s tests -p test_p2p_client_init.py -v`：工具 `df4eef`，**49 tests / 0.039s / OK / host exit0**。
随后仅新增／受影响命名用例：`79123e` **7 / 0.028s / OK / exit0**（3新增＋4受影响）；`ea9204` **14 / 0.032s / OK / exit0**（2新增＋12受影响）；`dec696` **8 / 0.027s / OK / exit0**（2新增＋6受影响）；`b69b9f` **6 / 0.026s / OK / exit0**（1新增＋5受影响）。未重复整个首轮49，未运行项目全套。
前次审查版本有 **57 个独立 test 方法**，均在上述首轮／增量范围执行过；不是当前源码单批57结果。该版本 Python3.5 AST/no IO/禁止操作边界用例在其最后受影响批通过；P011 import/实际 UDP/native/watchdog/磁盘 Store/CLIENT RF-init、手机均未测。
覆盖：完整 limits未知/重叠/数量、type9/2、current/pending/prior、CREATE unknown、spawn异常/迟到/注册超时、exec gate、stale current/ready覆盖拒绝、全IPv4/原网差异、leaderZ＋其他线程/reap unknown、独立FD关闭/空 inventory/Store unknown、reconciled fresh无重新动作、私有错误不泄漏。

## 固定本轮源码与后续最小缺口

前次审查版本：核心809行/47839B，SHA `d4b508c0a89aa33da03a416f25c8892696f187ce3a90daf7d3d26206255a3217`；测试518行/30091B，SHA `b3e4d7708917819530c43d3c874376b1fd58cb8c69a726161b3ff438637bf891`。旧 HOST 结果保留，不回改成当前版本通过。
只导入旧纯 `mta_ip.py`（SHA `1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5`），未导入可变 production GO 或旧回收；旧 ctrl SHA `793b784f1b39eca18001aa65a1f0d6cdbd6de466dc58b3cf2ada167f71d902b5`、IP helper SHA `39373dba355557ee73cfac354bdbaa95eaf0ddde4e27313450edf0e74742f12c`、V9 SHA `cfe24fba81332082d4033e148578ac088e07e7efce0ab037f499a40e887901fb` 均只读核对且未变。
后续依次：root全文审查逻辑合同 → 真正 strict caps/full-readback provider 与私有 Store/watchdog/FD角色实现 → 新固定候选/harness、parser-only无RF配置检查 → root唯一 CLIENT RF-init≤20s及全原网/退出读回。其后关联仍需要真实手机 GO和当前BLE/P2pInfo；DHCP/ARP/地址子租约/端点/TLS/文件验收另层，不在本 core 里伪造完成。

## ROOT 两项审查修正：executor 角色与未知锁强引用

仅改本轮三文件。私有不可变 `ExecutorProof` 包含固定 owner/external_finalizer/watchdog 角色、当前完整 Actor 和同 OFD 核验事实；真实读取器未实现，不能从 HOST bool 推断 Linux 已核验。
`start` 只接受 owner；`restore/recover_current` 在任何 acquire/close/finish 前拒绝 watchdog。外部 finalizer 必须持有已核验继承 OFD；锁内 fresh journal 还排除当前 controller/watchdog 的精确 PID/start，防止只换 role 标签绕过自 reap。拒绝不删接口、不回写 record、不清 pending。
正常 owner 或可信外部 finalizer 才能先实际 stop/wait/reap **自己的直接子进程**，然后执行已有完整 baseline/精确接口/资源退出门禁；当前核心没有 Linux 父子关系读取器，合成 waited proof 不等于真实父死恢复。
最小后续可落地拓扑只需一个固定协调者 F（正常 owner runtime），直接生出私有 WPA C 与被动 watchdog D；F 持有同 OFD，D 仅通过受限通知请求 TTL/断连恢复，F 实际等待 D/C 退出后 finalize。D 不自己 restore，不自退出假报完成，本轮不添加 janitor/launcher 链。
F 死亡后 D/C 可能孤儿化，新进程无法取得其 waitpid 退出码：本版该真实路径 NOT_IMPLEMENTED、pending 保留。下一层需明确区分“直接子 waited 证明”与“same boot/exact Actor/整个 proc task 确证消失但退出码未知”的退出证明，单独审查，不能在此模拟为 complete。
Store.finish 抛错、格式未知或 `locks_closed=False` 时，保留原 `self.locks` 强引用并公开固定 `locks_close_unverified=true`；不重新 acquire、finish 或重复 close 未知 FD。只有 Store 固定原两引用的 **只读** `closed_locks` 全 closed 回执，或 finish 的合法 true 回执才释放强引用；已 ready journal close 未知同样受门禁。
同一 lease 的 start/restore/recover 重试先只读核原 inventory；缺项、部分关闭、读回异常都保持 pending。新 Store 实现仍必须持有资源 registry/完整身份，不能靠新建 lease 对象丢失旧未知 FD 的归属。
无 record 的 start 失败 finish 分支也严格核关闭回执；取消在任何 provider/Store 回调前拒绝。已知 close 不再重做；部分 close 读回不是修复动作。

本修正实际只运行命名新增／受影响专项：工具 `794386`，`python -B -m unittest -v <30 named tests>`，**30 tests / 0.041s / OK / host exit0**（15新增＋15受影响，含改名的直接子 OFD 合同）。测试文件现72独立方法；未把历史批次累计成“本版72全套通过”，未重跑首轮49或项目全套。
新增角色专项：`test_watchdog_start_rejected_before_store_acquire`、`test_watchdog_restore_and_recover_never_self_reap_or_finish`、`test_mislabeled_current_watchdog_cannot_be_external_finalizer`、`test_current_controller_identity_also_cannot_finalize_itself`、`test_external_finalizer_requires_same_inherited_ofd`、`test_external_finalizer_unknown_wait_is_not_orphan_recovery`、`test_executor_proof_private_strict_role_live_actor_and_bool`。
新增锁专项：`test_finish_exception_preserves_exact_lock_reference`、`test_finish_exception_retry_only_reads_original_lock_closure`、`test_partial_finish_recover_retry_does_not_reopen_or_reclose`、`test_unknown_locks_block_new_start_without_finish_or_acquire`、`test_unknown_lock_readback_exception_preserves_reference`、`test_unknown_lock_inventory_must_prove_both_original_references`、`test_known_closed_readback_is_only_way_to_release_uncertain_reference`、`test_prepared_failure_finish_unknown_is_not_reopened_on_retry`。
受影响批含 constructor/cancel/unavailable、pending、ready/正常 restore、锁内 current、直接子同 OFD、wait unknown/逐项 close、reconciled 只读退出证明及当前 Python3.5 AST/no IO/禁止操作。真实 Linux/provider/Store/watchdog/orphan/CLIENT/手机均未测，receive/send 仍 false。
上次两项修正版本核心887行/52564B，SHA `57af20ee9cd2cdb9f14090a5471a1338854da86cd83163f8787789e91f948139`；测试661行/39564B，SHA `1c49acff4253e2398a8cae1b7f72f4c13988897e1c5d9d053f648c67eab5878d`；该版文档 SHA `dd02c2302bebb7ca2747d103e68c43ffa0144fa607a45d92a9db810ccfd030c2`。历史30项不改判为当前整版通过。

## 二次审查补强：整份 finish 语义与 BaseException 中断

ROOT 独立只读审查确认上版有两处静态缺陷：finish 在完整语义检查前提交 locks_closed；关闭回调的 BaseException 可跳过 unknown 状态设置。本节只修这两点，不修改旧来源、角色、门禁、基线或生产接线。
统一 `_finish_receipt()` 先核 exact key/严格布尔、complete 与本次结果相同、pending 为其反值、locks_closed=True，再核整个不可变 Journal 的 stage/identity/全部 key；全合法后返回 Journal/None，调用者才提交关闭成功并释放引用。shape 正确、locks_closed=True 但语义矛盾或 wrong stage/identity 仍保留原 exact refs。
no-record start failure 的合法 finish 唯一为 record=None、complete=False、pending_retained=True、locks_closed=True；不能用正确 shape 或 true flag 替代语义。wrong record/completeTrue 均不释放原引用、不允许下一次 acquire/finish/close。
`_active_return_lock()`、`_finish_receipt()` 和 restore 的最终引用处理用 finally 覆盖 BaseException；KeyboardInterrupt/SystemExit 允许原样重新抛出，不吞为成功。未整体验证时设置关闭 unknown、pending、cleanup=false；ready additionally 要求 not locks_uncertain，中断后的 ready stage 不误报 client_init_ready。
新9个命名专项分别覆盖 finish contradictory pending/wrong stage/wrong identity、no-record completeTrue/wrong record，以及 ready active_return／failure active_return／no-record finish／restore finish 四条关闭路径的中断。每例显式再次 start/restore/recover，检查只有 closed_locks 读回、无 acquire/finish/reclose/provider 回调、原引用仍在。中断异常自由文本不进入 public status。
本次唯一命名新增／受影响批：工具 `319413`，`python -B -m unittest -v <21 named tests>`，**21 tests / 0.037s / OK / host exit0**（9新增＋12受影响）；包含当前 Python3.5 AST/no IO。测试文件现在81独立方法，不称本版81全套通过；未重跑49/72/项目全套，未运行设备、网络、native或冻结。
当前核心909行/52982B，SHA `88f16ec4c04d0f17e90ef90b912e3b5a3b1ce1a0a01240329702f4ded796889e`；测试773行/46048B，SHA `71b46c0df2a0ebd384a131f80067c27060dd6c7e04afb418b150d27d0da2e0c3`。本文最终 SHA 由交付消息单独记录；Linux provider/Store/watchdog/orphan 路径仍未实现，receive/send 仍 false。
