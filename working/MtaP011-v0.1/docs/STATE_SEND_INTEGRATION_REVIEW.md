# State 发送编排切片（HOST，未部署）

范围仅 `mta_service.py`、组合专项及本文。复用真实 ScanSession、SendWorker、
TransferSession；没有新增生产 Provider、GO/IP/DHCP/关联/恢复实现，也未触设备。

## 能力与输入边界

- State 最末参数 `send_provider=None` 是可信内部依赖。默认 `send_available=False`
  不变；传 Provider 不会开放能力，更不能由 HTTP 参数变更。
- 原 HTTP `send` 字段仍只有 `action/deviceId/fileIds`，没有 direction、taskId、
  Provider 或 shell 门路。缺能力／Provider／完整恢复合同在文件选择和 GATT 前拒绝。
- HOST 组合明确设置模拟的平台 gate，只证明接线，不能作为平台能力／手机兼容证据。
- receive 的 Outcome、确认、接收数据逻辑和默认 Session 方向保留；纯扫描可关闭，
  没有文件送出事实时仍是 idle/cancelled，不冒充发送。

## 一次扫描到发送

- 同一个 Operation、TransferSession、真实保存线程和 helper；扫描开始时间在真实
  scan 指令之前保存。只有 native `scan/ready` 和 cached=false 的新发现可选。
- ScanSession 只签发一次 SendIntent。当前 helper／双 epoch／TTL／15 秒发现期限
  由真实 ScanSession 再读核对；State 不从设备缓存或布尔 ready 构造 handoff。
- PrivateHelper 实际发 `client_read` 前，纯 command-note 绑定 exact intent。
  原生 own_session_stopped 正确关闭扫描，但不取消合法 intent，不捏造 active=true。
- reader 仅路由原生事件至 ScanSession／SendWorker 的有界队列，及原 receive 处理；
  不运行文件、密码学、Provider、网络、close 或 restore。
- 保存 worker/factory 后才 run。每个 CreationTicket 先 claim，返回资源先保留再
  adopt；transport 与原 raw handoff 接入真实 Session。未知结果、晚生产者与异常
  票据都保留，不因字段 None 或方法返回就宣称资源不存在。

## 结果与外部收尾

- SendResult → SendOutcome，只报告实际 ZIP 字节与对端协议完成；不更新 received，
  不设置 localCommitVerified。发送终态不使用“文件已保存”等接收文案。
- ACK 等待异常只从已保存实际 worker 的完整固定 status、strict True 字节标志及
  相等有界 ZIP 计数取事实。独立保存 send_bytes_observed／SendOutcome；未知 status
  或无字节异常不上推，不补 ACK。所有闭合完成后才可标 sent_unconfirmed。
- 外部 finalizer 先确认真正 run thread 退出，再核完整 transport/raw 关闭，随后
  worker.release_scoped → worker.close_extra。State 不重复关 worker 的 helper/key/
  selection；worker 是这些资源的 sole closer。未知 scope 会阻断后续恢复。
- Provider 的网络恢复必须在独立 actor／文件／key 闭合后发生。旧 WifiBackend 的
  restore_active/recover_pending 不能冒充新发送租约的恢复。多余 recover 不把已闭合
  发送 owner 搬入旧 receive cleanup 别名，也不重关文件／helper。

## 私有恢复合同（真实 Provider 尚缺）

`SendRestoreReceipt(provider, lease, operation_epoch, task_id, baseline_verified,
journal_reconciled, actors_closed, resources_closed)` 是 exact typed 私有合同。

`restore_owned(exact_lease, epoch, task_id, 5)` 返回绑定当前 Provider/lease/epoch/task
且四标志 strict True 的 receipt。随后 `read_restored(receipt, .2)` 必须实际返回
**另一个新** typed receipt，保持全部绑定并在真实预算内读回；旧 cached receipt 拒绝。
强引用同时保留两个结果，包括畸形结果。超时、错误绑定、布尔冒充或 pending 都失败。

结构本身不认证 kernel；真实 Provider 仍须 durable journal、原厂/STA/完整双栈
baseline、实际 actors、相同锁域/归属/恢复读回，不能为通过本合同填 True。
同步预算不声称可硬抢占任意 OS/callback；迟返回仍被拒绝并保留 pending。

零网络变更分支必须 scope/extra 都 verified、所有 exact tickets 已 claimed/resolved，
未知子资源已确证闭合，并且没有 lease 票据或未知 reserve/lease 创建。仅 worker.lease
为 None 不足以跳恢复。蓝牙能力与原厂独立核验仍单独进行。

## 证据记录

组合专项使用实际 Python 线程与真实四个编排组件，文件选择、helper、crypto、
Provider、sender、scope socket 仅可信 HOST fake。OS mkdir/Popen/socket/默认密码学
与 transport 均设 tripwire。没有真实文件落盘、无线、TLS、P011 或手机动作。
固定 Worker 源为 `de0dd8c2c0fb3b45923199ccc987ae057046fa0244c6a405c3a254850f7e68e7`，
ScanSession 源为 `51af67e80cf64038160cf420ad08f4f255a15dd9577e14fdcdb44fc26711046a`。

实际命令：PC Python 3.12.0，`python.exe -B -m unittest discover -s tests -p
test_state_send_integration.py -v`。仅新增专项，不运行其它套件。

- 首批 `32a68e`：34 tests，0.047s，34 ERROR，exit 1，tool wall 0.5254548s。
  全部失败在 fixture setUp：fake os.urandom 固定返回 2 字节，uuid4 需要 16 字节；
  未进入 State 构造后的生产任务。原失败保留，工具长 traceback 输出有截断，不称
  它是完整独立归档。只改 fake 按请求长度返回及 setUp 异常时 patch cleanup。
- 仅重跑受此 fixture 修正影响的全 34 方法：`5c46f7`，34 tests，0.853s，OK，
  exit 0，tool wall 1.2262122s，含 runtime Python 3.5 AST 检查（非设备 3.5 执行）。
  一个新 wrapper 实际调用两个已有命名确认方法：
  `test_wrong_request_id_cannot_accept_new_request` 和
  `test_reject_confirmation_unblocks_without_transferring`；不额外加算为 36 tests。
- 边界包含缺平台零 IO、native ready/cached/过期、一次 intent、同 owner/真实线程、
  exact tickets/transport/raw、reader 只取消、活 worker 阻恢复、strict 恢复绑定及
  cached/预算失败、字节无 ACK、未知 status、cleanup pending、reserve/adopt/构造未知、
  sole selection 关闭失败、公开无凭据／私有 owner、旧确认及默认 receive keyset。

这些是 HOST 组合证据，不是实际 TLS／网络恢复／P011／手机验收。未知构造或 scope
会保留已知 helper 和其它 owner 等待后续可信处置，不能报告全部资源已关。

## 独立复审增量：发送已选择、工厂前取消

ROOT 独立复审发现真实竞争：send action 已保留 intent、设置 kind=send/send_ready，
随后取消先于任务线程的早检查；工厂尚未进入。旧无 worker 分支却要求 intent=None，
导致合法零执行路径也永久阻断 helper 清理，恢复分支也不能区分它与未知构造。

现在仅在实际任务的工厂前早返回处保留私有 `_SendSkipped` 记录，绑定 exact
Operation/Session/helper/scan/intent/epoch/当前真实线程；不是 caller/HTTP 传入的
布尔许可。release 与零网络 restore 共用 `_send_skip_exact`：必须是同一个当前
owner、真实保存 worker 已退出且启动无未知、factory 从未登记／进入、无构造
pending/unknown/actor_unknown、无 tickets/transport/raw/unknown owner/lease/key/crypto。
restore 还必须由既有 extra 阶段确证 helper/probes/无线闭合；不调用旧 WifiBackend。
工厂曾登记或构造未知依旧拒绝，不能靠其最后返回 None 捏造零执行。

精确 HOST 屏障把扫描命令返回卡在 send_ready 后、任务早检查之前；发 cancel，
确认实际任务还活着时不关 helper／不放行 release。任务真实退出后关闭 exact
helper 恰一次，选择/GATT/Provider 调用均零，Session 最终 cancelled/closed，非
completed。例中再验证 factory 登记或 unknown 后该私有记录无授权作用。

增量 `b3b1e6`：只 1 新屏障例＋5 直接受影响原方法（含 AST），6 tests，0.114s，
OK，exit 0，tool wall 0.5079071s。当前文件有 35 个测试方法，不声称重跑全 35。
原 `32a68e` 与 `5c46f7` 批次记录保持；无全套／OS／设备／无线动作。

生产 send 门禁仍关闭。此切片不完成真实完整发送／互传目标。
