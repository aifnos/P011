# Fixed receive factory v69 — SOURCE-only

新增生产文件是 `runtime/mta_client_receive_factory.py`。原 State、Handoff、F37、35 源图、Loader、STATUS、Provider、Store、Receiver 及既有结果没有修改。本候选尚未 import、AST、HOST、设备或完整生产接收验证。

## 固定接口与来源

- `FixedReceiveDeploymentFactory()` 是无参纯构造：只分配空 attempt 库存，不读文件、时钟，不启动线程或进程。
- `factory(exact_handoff)` 只接受实际 `ReceiveConnectHandoff`，并在原 State lock 下消费实际 Bridge 已解密但未 claim 的阶段、原 Session worker/epoch/session/nonce/cancel、原 clock 与原 Session/Handoff 绝对期限。不得由 HOST 合成对象取得完整 Factory positive。
- 工厂模块必须先于 Bridge/State 定义加载；Bridge 的 exact type 校验是调用时 deferred import。普通 canonical running F37 原件不重新 exec。
- 固定 raw assets 来自 `/tmp/p011-mta-state-v69/runtime35` 和同根 `native/mta-wpa-supplicant`，读取时核已验证固定 tmp alias 的 physical 对应 `/var/volatile/tmp/p011-mta-state-v69`。这与 State 本身 `runtime` 的 old storage/files/transport 名称空间分开。
- 35 个源的每个 bytes/SHA 与 `host/client_refusal_prescreen_v38_source_manifest.json` 的 `0ea4db9b…19319c` 图固定绑定；WPA 为原固定 1,351,192 bytes / `e069aef7…d67f301`。源码仅作为 raw 数据复制，最终原 Loader 建私有 34 模块图并保留 canonical F37。

## 实时资料不是 STATUS/RF 授权

本轮实际读 `/usr/bin/python3.5` 的 ELF、metadata、SHA；不使用历史或模拟 Python SHA。七字段 status manifest 只由当前唯一 daemon 的 comm/stat/cmdline/status/exe、独立 live image、namespace/config.gz、Unix endpoint inode 与 daemon FD 引用生成。资料读失败、PID/start/路径或 namespace 变化均拒绝，不跳过 ENOENT、不返回 ready。

这些是 private **deployment data**，不是 `ProcObservation`、`Actor`、`AuthenticatedStatusReader` 或 RF 准入。原 v25 STATUS source 要求调用进程单线程，不适用于 State worker 的多线程进程；本候选没有改变该门、没有伪造 actor、没有新增只读 child。后续实际单线程 F 的原完整 STATUS/Proc/网络门不变。`profile_data_collected` 不等于 `status_authenticated`。

## 原期与落盘

工厂一次捕获 `min(original Session._task_deadline, original Handoff.deadline)`；准备局部期为该原期与首次 now+120 的 min，不续原网络期限。实际 Loader 还保留自己的原 10 秒局部读期限，并夹紧到相同原 parent-until。没有新的 300 秒发行、Store.acquire、Journal/RF lease、Parent、CONNECT 或 claim。

只在已存在的固定 CLIENT 根中追加一个新 `client-<32hex>` 目录；EXCL 创建、不复用 v41/GO/static 票据，不进入旧子树、不删除 partial。新 runtime/native/ctrl 目录为 0700；原固定 sources/deployment.json 使用 0600 EXCL → actual write/readback/fsync → 0400，WPA 同路径到 0500。父目录 fsync/readback与原 entries/metadata 验证均保留。固定 Received 根必须原已存在并通过原 Loader 的 0700/path 校验。

每个受管理 FD 在 open 前保存原库存票据。已知 FD 的 close-only 使用实际原 dev/ino/kind/uid/gid/nlink 与本任务合法 mode，调用 close 一次并立即观察 EBADF；过期/取消不跳过已知关闭。未知返回、身份不明或 close 异常保持 pending，不重试、不靠 GC 或历史 FD 数字重新关闭。Factory/Profile/Writer/Loader 原件与原错误强留。

## Bridge 被动闭合 ABI

`FixedReceiveDeploymentFactory.closed_publication_facts(factory, exact_handoff)` 无 clock、文件系统、进程或网络 IO。仅在该原 attempt ended 且全部原 profile/source reader、writer、Loader FD 库存 known/once-closed 时返回原强留 9-tuple：

```
(factory, handoff, attempt, bridge, session, worker, pid, closed_owners, True)
```

`closed_owners` 是原 tuple，元素为 `(exact_original_owner, tuple(original_row_references))`，可含读取 owner、writer、Loader reader；还未创建任何 managed owner 的早期业务拒绝为原空 tuple。返回前和被动复核时均比对库存每个原 row 的 `is`、closed/unknown/onceclose 原事实。此票据允许“业务失败但受管理 FD 已闭合”，不会把失败部署变成成功。

它只证明本 publisher **没有遗留受管理 FD**，不证明 Parent、State helper/crypto/Session、全设备资源、RF 或原厂恢复闭合。公开 Status 固定 `status_authenticated/rf_admission/parent_started/receive_available/send_available/restoration_verified/phone_tested=False`；partial 目录仍保留以便归因。

纯 builder/writer 组件可另在真实 HOST 临时 POSIX 文件系统验证；完整 Factory 正向必须真实已准入 handoff，不准借合成 State/Session/布尔 grant 声称生产接收。
