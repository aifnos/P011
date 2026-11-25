# CLIENT durable CONNECT v19（SOURCE/Fake，尚未设备准入）

仅隔离派生三源：v16 Connection `1eaf385b…daa2e`，v15 Provider `9e6b3214…8136` 与 F `7f80b5c7…24475`。旧源码、旧日志、生产 runtime 不改。
依赖冻结 v18 core `b255e3ac…11b4`、codec `a4ddb469…86d1`、Store `5ee1c184…4426`；kernel 使用冻结 v16 `4ebfedf1…8ede`。

## 接口与顺序

- `assemble(manifest, _connect_binding=Loader原ControlBinding)` 为纯构造；不是 Caller dict 授权。
- `lease.connect_p2p(exact_ConnectRequest, _checkpoint=F._cancelled)` 保存原 request、decoder、binding，再取得原 canonical P2pInfo。epoch 来自原 binding 九字段，不猜数字。
- 同 Store RLock、原 DEVICE/OFD 与 journal handoff：实际 reacquire → current/fresh/fullbaseline → `_save(association=intent)` → fresh → 首 ATTACH/ADD_NETWORK。
- 原两套 STATUS、fullbaseline、实际 kernel+caps、drain、checkpoint 完成后，`_save(confirmed)` 实际 CAS/fsync/readback；固定 deadline 不续期。
- run 仍返回私有 `ConnectionObservation`；原 operation 另保留 exact `AssociationReceipt`。不返回 DHCP AssociationProof。
- `lease.read_association_receipt(exact_current_receipt)` 做实际新 readback。新发行使旧 pointer 失效；canonical 没改变时 receipt_id 可相同，不能据 hash 重放。

## 持久字段与私有发行

v18 `ClientAssociationRecord` 为 intent / confirmed / invalidated，保存完整 binding、原 F Actor（包括原 tasks）、确认 MAC/BSSID/frequency 与 observed_digest。
network_id 仍为原操作内存中 ADD_NETWORK 实际返回，不能用重启后的 journal 复原或猜 ID。
observed_digest 只编码固定 primitive fact 白名单：binding、deadline、原 Origin/controller、两轮核验字段、基线 key、raw caps 的受限已解析字段及完整 tasks。
不 dump `__dict__` 或 repr；SSID/PSK/rawframe/rawSTATUS/rawgroup event 不进入该 digest 输入或 journal。
receipt_id 只取实际已发行 confirmed canonical.data 的 SHA；record/digest 本身不冒充 OS 证明。
receipt 需 exact provider/operation/binding/locks/store epoch/current journal epoch、FILES issuer/generation/fullbytes/metadata、原 observation 与私有注册 ticket。
原收据与返回对象强引用保留；未知写入不重试、不自动 rebase、不重复确认。

新收据发行仅消费同run/readback同步RLock事务的原context：原 `_connection_context` 全部fresh门禁最后注册原current/canonical、locks/DEVICE、epochs/marker/binding、实际ExecutorProof/controller和私有object事务token。两个Provider指针核其exact注册，issuer一次取走并清空，包括验证失败；finally/撤权清除事务和context。原context强引用纳入收据ticket，不能拿复制dict或跨事务残留重放。没有Caller context参数或布尔通行。

原readback的首次fresh、两套STATUS/fullbaseline/kernel/caps/drain链保持；收据入口/出口只核私有原登记与当前内存canonical，不再额外重复该完整fresh链。这是同一次同步事务的新发行层收敛，不是后续命令可用的缓存授权，也没有提高FILES256上限或丢弃原票据。

## 撤权与恢复

发现 MAC/BSSID/channel/binding 变化或实际drain撤销event，在对应run/readback失败路径撤权并设failed，不自动重新确认。Provider收到同步CANCEL/EOF/TTL的request_stop时立即设cancelled并纯内存撤权；闲置期间不保证operation.failed同时变True，后续checkpoint/readback错误路径才设置failed。直接进入restore可保持failed=False，但收据已经失效，不能继续授权。
该模块不是后台持续事件监听，未经过同步新 readback 的历史 observation 不表示仍有效。
disconnect 在 DISCONNECT 前先撤权并实际持久化 invalidated；过期不能继续发送控制命令，但恢复可撤权。
restore 入口纯撤权，原 cleanup_intent 同时保留事实地 invalidated。原 60s 恢复预算、认证/CAS/OFD/完整恢复、wait/reap、库存/CloseProof、marker/device-last顺序不变。
缺真实恢复证明仍 pending，不因“关联已撤销”签恢复 PASS；不动旧 GO marker 或未知资源。
生产 send/receive/IP/DHCP/endpoint/phone 门禁仍 false。20s trial 不可伪装为 300s 互传租约；将来 DORA 的 fresh 5s producer / .2s poll 与剩余 TTL 必须单独评审。

## HOST 证据（历史不改写）

新专项固定私有 24 模块域，mta imports 缺项直接拒绝，不回退 mutable runtime。实际 v18 Store/FILES/Coord/Pending 与新 Connection/Provider、实际 kernel reader over FakeIO；init/children/baseline 已准入仅为明确合成 fixture。
首 `f000fb` / `b770ce`：14 方法，15.301s，exit1，11 PASS / 2 fixture FAIL / 1 resource_budget ERROR。
两 fixture 分别为 F 精确逆向字符串错误和 restore 返回 dict 不能直接 assertFalse；仅修 fixture，`bedcfa` 精确补原2方法，1.383s，OK/exit0。原11不重跑。
resource_budget 是 FILES 真实256票据上限触发，不冒称 fixture；仅收敛上述新发行层的重复fresh接点。原作者在续接后停于pending_init，ROOT停止该未初始化工作并接手最终测试，没有重复全部14方法。

ROOT `bdc4c9` 精准执行原真实ERROR方法 `fresh_receipt_reissues...`、新增 `once_context_original...` / `context_after_cancellation...` 两方法，以及受影响正向 `intent_actual_cas...` / `disconnect_persists_invalidated...` 两方法：5方法/7.020秒，OK/exit0。总共16个不同方法分批；原14首批、fixture补2和最后5是不同阶段，不能累计称21个不同方法或一次最终整16通过。原11的首次通过属于收敛前源码边界，不改写历史；最终完整来源图和独立SOURCE审另列。
没有实际 OS/socket/fork/无线/设备/手机执行；不把新 typed graph Fake 结果称完整部署图或实际恢复验收。
