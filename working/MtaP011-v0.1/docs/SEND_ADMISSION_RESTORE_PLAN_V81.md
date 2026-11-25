# V81：发送准入与独立网络恢复的最小实施计划

范围：2026-10-03 SOURCE 技术计划，不是实现或验收。实际发送仍拒绝；冻结候选、当前 P011 旧 pending 均不改，不授设备操作。

## 1. 准入允许启动事务，不要求本次 GO 先成功

准入只允许一次已审计 F 事务尝试，不是 GO/GATT ready 或 NetworkReceipt；不能要求本次 GO 先成功恢复。固定来源、当前能力、pending 缺席、原 worker/service cap 和当次基线是前置。F 内原 baseline、OFD、durable Journal/watchdog、CREATE/ACK/ECHO、group/IP/DHCP/TCP 门仍独立执行。

接点：新 Publisher `preflight()` → `publish()` → 原 Bridge；State 只允许进入前置准备，worker 完成实际 preflight 后才启动 F。原 Selection/PreparedSend 先完成并强持有，尚无 RF；不接受外部 bool、path/hash 或跨进程 Python lease。

### 单线程只读 observer 的输入、读取和输出

新增固定、sealed、默认无动作的只读子入口，复用 ReadonlyBaselineOwner51 的实际中性 Store、bound ProcReader、双轮 Collector/关闭库存。Collector L525/537/550 要求自身 single-thread，不能直接塞进 State 多线程 worker。preflight 与终末观察均不调用 GO reserve/restore。

- 输入：Parent 原 operation 的 task/epochs/absolute until；固定 Parent 发行一次 preflight nonce并保与后来 Bridge nonce 的原关联，不能声称当前 op 已有该字段。publication 后再绑定原 token/manifest。executable/角色/源图固定，无任意命令/path；局部 end 首次夹原 cap，poll不续期。
- 来源：独立 RO35 manifest `host/client_readonly_proc_vanish_v51_source_manifest.json`（8e7882ae…），leaf51（13934 B/c2052c39…）、baseline51（31338 B/e950877b…）。固定部署位置/启动 pin/reader 尚需 stager/Boot 发布；无 sys.path fallback，不混 GO24 私有域。
- 读取/readback：source/ELF/hash/目录原 inode/权限，固定 helper 当次 capability raw及真实 process/pipe 闭合；固定 `/var/volatile/tmp/p011-mta-p2p-device.pending` 缺席；stock pins、Proc identity/image、WPA STATUS、全接口/IPv4地址路由规则/IPv6/boot。只观察既有 device lock的原 inode/可取得状态，不创建锁文件。旧 `p2p_reported`/capability bool不签 GO权限。
- 输出：私有 bounded DATA，含输入 binding、source seal、helper/raw readback、原双轮 Snapshot/票据。完整 Snapshot 用独立有界通道，不扩大 Bridge 8192 B单帧。Parent 保原启动/返回/wait/reap/EOF/FD once-close+EBADF，并核 binding、原 until、双轮 key与原库存；child exit0、填入 Snapshot/bool不能代替。

同次基线：Parent 保存 preflight Snapshot；F 的实际 GoSendLaunch携 stable-key摘要 DATA，原 `observe_baseline()` 双轮后、`reserve()` 前比较，变化即拒。需固定纯 key codec，不比较瞬时 raw R/S，不把摘要作 grant。释放观察锁至 F reserve 仍有 TOCTOU，原 F再读/OFD/marker门不省。

## 2. 原 GO finish 数据与独立恢复核验

现有来源：Bootstrap76 `restore()` L269–275 的原 NativeRestoreObservation→GoRestoreObservation→Store74 `finish_restore()` 返回 GoCanonical。Store L1166–1204 核 Native/原 children，L1237–1266 写 reconciled、Journal readback、marker unlink/fsync/absence、原 FS关闭后才返回。它不是 CLIENT FinishReceipt，不能重建 GoCanonical或包装 CLIENT receipt授权。

### F export 和 Parent consumer

新 F finally强留 `finish=value.restore()`。仅真实返回且同 current/末代 issuance/issuer、原 restore observation、完成库存时导出私有小型 finish DATA：Journal SHA/metadata、facts_key、phase/generation、原 until/cleanup_until、device-lock inode与原 Actor关联。无返回/未知为 unavailable；不重跑 IO/clock补证。

F77 L527–529把 `value.failure is None` 混入 restored。新 export分离业务与恢复：保 PRIMARY/取消/非零退出，原 Store真完成时仍可有 finish DATA。Parent正常 RESULT及失败reap/tail均保留，不以业务exit0为恢复必要条件；DATA本身不清 State pending。

读取 `/var/volatile/tmp/p011-mta-go-session/go-<原token>/go-journal.json`：NOFOLLOW、root0600/nlink1、目录/文件 inode、前后stat/fstat、bounded raw/SHA、once-close/EBADF，与原 F binding/finish metadata一致后严格 decode DATA。schema=`p011-go-typed-live-v72`、20 fields。正常typed末代gen20；早失败的合法reconciled代数可更小，核原转移/finish绑定，不沿旧gen12或一律硬编码20。

### 独立采样和 finalizer 接点

F实际reap后，observer打开既有固定 device lock、核原inode并 nonblocking取得（不O_CREAT）；锁内重核 pending缺席/同任务Journal、新完整双轮 Snapshot.key==原baseline/restored。bound ProcReader核原watchdog/controller双轮absence；原GO接口/L3 delta及必要control endpoint缺席。最终重核Journal/marker/lock，once关闭observer原库存、实际reap observer。

新 State `_close_go_worker()` 在原一次cleanup end内保原件，`_restore_owner()`仅被动核worker保存的事实，不跨线程IO。Parent Bridge/key/pipes/helper闭合另核，Bridge79 key修正进入最终图。无 finish、marker/child/FD unknown或仅当前Snapshot相等仍pending；不宣称全历史Native FD export，不赋 observer恢复/删除/重试权限。

## 3. Boot26、固定 assets 与原 service until

Boot26：普通域22行增加 Prep/Publisher/Bridge/GO Loader，替换 State78/Session78；保canonical CLIENT F37。GO F/Native仍独立私有24图，不能冒普通State类型。实际认证26行及helper/observer固定来源，不按caller flag装模块。

- 普通源 `/tmp/p011-mta-state-v69/runtime`；USER `/mnt/data/p011-toolbox/user`；固定helpers在同root/native。
- 普通 Loader必须 `/var/volatile/tmp/p011-mta-go-send-v76-assets/runtime/mta_go_deployment.py`，不是State_ROOT。Pub读同assets的manifest/runtime24/native WPA。当前seal None必须待ROOT实际图封口绑定，不能绕过。
- 既有 preparation根 `/var/volatile/tmp/p011-mta-go-send-v78-prepared`；GO根 `/var/volatile/tmp/p011-mta-go-session`，只新EXCL go-token，不补旧run。
- Owner原until→State `original_service_until`→GO Session `absolute_until`；Boot10秒不作service TTL。F/Launch/服务同原taskcap，ACK allocation可收紧Pump end；observer/Parent cleanup只消费原一次cap，不续期。

## 4. 最小验收与当前边界

验收：真实source/readback；pending时0 publication/F/RF；preflight/F基线变化、wrong binding/Journal、OFD忙、child存活、close未知、过期均拒；业务失败但真实finish完成与伪restored=true分别核。HOST只签明确模型/真实FS/process范围，生产F/Parent/observer/P011/手机分层实证，计划/source seal不代签。

当前State78仍拒实际发送；Pub未seal，Boot26/preflight/finish export/observer/consumer未实施验收。GO64 wholeFAIL及旧pending保留；正常重启、记录处理、后续RF须ROOT当前授权链。有限kernelTLS、child报告或文件存在不证明GO恢复/生产发送/手机互通。

SOURCE引用：State78（84637 B/b7729b6d…）；F77/Bridge77（36974 B/c6bbf1b4…、55247 B/b5f723c7…）；`candidate/go-send-transport-v76/runtime`的Bootstrap/Native/Pub/Loader（30951 B/25247dcb…、200317 B/ee46d831…、17561 B/4dfc1fb1…、26113 B/3abac40e…）；`candidate/go-dhcp-setup-v74/runtime/mta_go_bootstrap_store.py`（78430 B/24620844…）。是SOURCE引用，非新执行图或PASS。
