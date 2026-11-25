# GO 同 worker 保留生命周期：v71 限定 HOST 结果

2026-10-03。这是独立源码候选与电脑生命周期模型结果，未部署；不是发送 provider、IP/DHCP、无线恢复或小米 15 Ultra 互通通过。

## 实际修改

候选 `GoBootstrap.prepare_live()` 复用原准备顺序，在原 owner／worker／绝对期限下返回同一个对象，不立即恢复。重复调用在准备前拒绝；准备中的异常留在原 owner，未知创建／发布库存仍由原对象持有。新调用方须在同一 worker 的 finally 中调用原恢复函数；这个实际调用方尚未接入。

默认 `run()` 调用新准备方法后仍在 finally 中尝试一次原恢复。除该入口编排及新增方法外，原模块其他定义／方法的 AST 均保持；原 `restore()` 未改。原 17 源 GO 图只做 pin 与定义保留检查，没有执行，也没有被 v71 替换进设备交付图。

| 固定输入 | 字节数 | SHA-256 |
| --- | ---: | --- |
| candidate/go-live-owner-v71/runtime/mta_go_bootstrap.py | 18394 | e15a99747fc6b3fd47a0c714fdec45dd815ad377737183078fbc9809d041a442 |
| tests/test_go_live_owner_v71.py | 23987 | 6b115228650b90b3acdc6a9155b1dfeddf52b2ae8b55eb00a117aadff5c42204 |
| host/go_live_owner_v71_check.py | 9788 | cb12d6c5e1109bc07844e0a49baf5b9589c15ad87d757ec3fc459f1ec83c0781 |
| HOST_MTA_GO_LIVE_V71_CHECK.cmd | 205 | 227dbc54eab31562063dd55fab7744494bc767cfd218eff7abe619b26635d8b7 |

候选 SOURCE.md 是作者冻结时的未执行状态，不重写为作者测试通过。ROOT 后续检查与结果仅由本文及实际回执记录。CMD 只核源码，未点击；ROOT 直接执行固定 checker。

## 唯一新测试与原件

ROOT `19e743` 首次直接执行 checker：HOST 0、child 0、无超时、0.172 秒；一个新方法 `GoLiveOwner71Test.test_prepare_live_and_default_restore`，旧测试方法 0。十个独立模型场景覆盖同 owner 返回、重复拒绝、worker 引用变化、同一 group 期限到期、创建未知、发布未知，以及默认正常／主失败／恢复失败／双失败。

完整新 Bootstrap 定义、构造和实际 owner／stage／cancel／prepare／run 编排参与该方法；导入依赖、child 和 restore 都是明确的惰性模型。模型中的 logical_restored=True 仅供模型返回谓词，不能签真实恢复。各平台调用 tripwire 的调用次数为 0；没有内核、无线、进程或真实文件关闭算法结果。

结果目录：[go-live-owner-v71-host-20261003-014908-caa1ac4a](results/go-live-owner-v71-host-20261003-014908-caa1ac4a/result.json)。[四成员脱敏结果 ZIP](results/go-live-owner-v71-host-20261003-014908-caa1ac4a/public-result.zip)：2885 B，SHA `eac2a8c79c56683ff5be69e0684d7e15d93245bdb27d151c9b5bdecf9dfeb1f6`。

ROOT `cd9d1e` 只读核对 22 份私有输入快照与当前来源逐字一致、输入 SHA／大小、唯一 child、严格 marker／Ran 1／OK、四 ZIP 成员逐字及 CRC：PASS。stdout 90 B／SHA `9c3323889e4cd24f4df48d5675de75efb9a685a88e9572fd5c0f83c4f8a83fe5`；stderr 100 B／SHA `a3f8db800677faa4a54e970e33e9d4f728488ca658e9e23c5b13fb6d83625a5b`。原 raw 保留；工具展示的 CRCRLF 不回写原件。独立 formal_phase_plan 对实际 22 快照／当前来源、raw、结果和四 ZIP 成员逐字、SHA／大小／CRC 核对 PASS，仅核原件、未重跑方法；两项审核只签本次模型范围。

## 尚未完成

v71 未提供新命令／RPC／九方法 provider／生产准入或可用标志。typed IP/DHCP 必须合入当前已修正的 GO 图，不能回退到旧 v43 图；实际调用方还须解决同 worker 所有权与 State 最终恢复线程不同的问题。当前 consumer 的 0.2 秒新鲜证明／5 秒恢复预算也不能靠缓存 True 或偷偷续期适配。

本轮没有设备操作。原 GO64 整体 FAIL、pending 残留与完整恢复未证保持，正常重启许可尚未收到。接收／发送仍不可用，真实 P011 和小米 15 Ultra 双向验收仍待；[生产链缺口](CURRENT_TRANSFER_GAPS_20261003.md) 未因模型通过关闭。目标 active，尚非仅剩人工手机测试。
