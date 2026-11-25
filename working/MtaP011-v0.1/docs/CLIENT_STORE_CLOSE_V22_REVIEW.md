# CLIENT Store close v22 限定回执

本件只新增 `candidate/client-store-close-v22/runtime/mta_client_store.py`、`tests/test_client_store_close_v22.py` 和本文。候选是完整 frozen v18 Store 的隔离副本，不修改 v18/v19/v21、manifest、正式 F 或历史结果，不新建资源 profile/TTL，不执行设备、ADB、实际文件系统资源、网络或旧测试方法。

## 窄修与原门槛

原 v18 `_inventory_closed` 对 Coordination 库存统一要求 `<=MAX_RESOURCES+1=7`，但 actual frozen v11 固定 tmp alias 生产者正常登记8张，exact one journal handoff 后9张。v22 只修 `n>7` 的闭合消费：必须消费 actual 同域 `ClientCoordination`、`FixedTmpAnchor`、Store 原 LockSet 与完整 ordered registry。没有 caller capacity 参数；ordinary6、第7以及已知 negative-open/partial 的原 `<=7` 门槛逐字保留，不泛化库存授权。

合法固定顺序是 `[root,var,volatile,tmp,base,run,device,oldJournal]`。核 exact owner/io/root、原绑定 callbacks、prepared/bound/unknown、固定两个 link targets、四个 anchors 的父链/名称/private/temporary、两个 prefix 的同io/原票据/role、原 issuer LockSet、Store/Coord 注册一致、完整库存逐项 `is`，拒绝 foreign/duplicate/missing/extra。闭合后不调用要求FD-live的 alias.authenticate/Coord.validate，也不重新打开或关闭历史票据。

第9张只能是 actual 已成功 active 的原 `_JournalHandoff.new_ticket`：核原 owner/initial/device/oldJournal、same binding/Store epoch、原 released/reacquired issuer/context、same device 与新当前 LockSet、原 marker binding ticket/context/journal epoch、固定 parent/name/identity。只有成功 release 而尚未 reacquire 的8张也可读出资源闭合，必须核原 released/context、无new票据/locks/receipt、old epoch，不宣称当前 Journal 已重新接通。partial/unknown handoff 拒绝。

正常 `Pending.close` 故意将 binding ticket `ready=False/unknown=True` 以封存live授权；这不是FD资源未知，因此不要求该live许可仍开启。原 `handoff.unknown`、marker `_resource_pending/_creation_unknown` 和每FD闭合事实仍分别拒绝。数字FD允许由actual new open复用，但原对象不得重复；新消费者不以FD数字不同推导安全。

新 helper 只有纯内存登记检查；`_inventory_closed` 除Coord长度消费门槛以外保持原样：每原FD bool/type/attempted/closed/opening_unknown、actual fstat→EBADF、FILES256、marker、Coord status pending/lock_unknown、Store sticky `_unknown/_close_unknown` 全不删。`_fd_closed`、`_close_components` 的marker→FILES→Coord device-last、原创建quota、预算、producer/finish/清marker及认证方法不变。

## 唯一新 HOST 证据

新私有图先整体验证 frozen v19 manifest 和其24 sources，实际只加载与本消费边界相关的10定义；唯一替换Store。codec/core/coord/files/pending/alias类同一私有域。FakeIO、synthetic baseline/Reader仅从whole-pin过的旧fixture选定定义AST重绑定；没有import或执行任何旧test方法。新图没有 production Provider、RF、恢复 producer 或正式F。

仅一次执行本新文件的3个方法：actual alias8 / released8 / handoff9 与ordinary6/7闭合正向；注册/FD/unknown的负边界矩阵及原<=7 known-negative形状；整源反向、Python3.5 AST与图同域。实际 default I/O adapters、proc、socket/CDLL/subprocess/OS open/kill/waitpid、Thread.start、sleep均有tripwire。正向核每原票据closed/fstat EBADF、device最后、无重复close/open/flock；原冻结消费方法在同一alias8/9原件上返回False，候选消费返回True。

实际命令为 `python -B -m unittest discover -s tests -p test_client_store_close_v22.py -v`，cwd为 `D:\project\P011\working\MtaP011-v0.1`。工具回执 `9b302d`：3个不同新HOST方法全部 `ok`，`Ran 3 tests in 0.884s` / `OK`，HOST exit 0。正向5个subcases、负矩阵21个subcases及原<=7形状检查不是额外的独立test methods。首次即通过，没有FAIL/ERROR或定向修复重跑；旧test methods执行数为0。

本结果仅是FakeIO上的 actual 原生产者登记和闭合消费者的HOST证据；不得推导为 P011恢复、旧v11唯一首因、baseline实网恢复或完整DORA/小米15 Ultra互传通过。完整source diff（工具 `5cacfb`，`git diff --no-index` exit 1表示存在预期差异）仅新增纯登记helper和Coord长度消费门槛；整源逆向方法通过，原创建/关闭/认证等其余文本逐字不变。

## 冻结来源

| 来源 | SHA-256 |
|---|---|
| actual 原v18 Store | `5ee1c184c3511bc3072e87409a88861713bfd249d79584df1d50fc1377964426` |
| actual 原v11 Coordination | `930e56d35ebf08d0b1c83fe7ccab843cbe6520ecd68c0799e9a07b2bbe40823f` |
| actual 原v11 FixedTmpAnchor | `1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f` |
| frozen v19 manifest | `9c547fe0b30b899dc1b11beeb67d8815c4e98bd7db8da8c12a2d12cf775beec5` |
| v22 candidate Store / 1054行 / 61184 B | `a829dfd10ed00ce4ea3fc8b4e850b917cb2e79d609de8dfa9ea096e33c2c97ab` |
| v22 new HOST test / 231行 / 14323 B | `0eb618268144848b0e719bee6e67367d32f12e99f9f84356a53d0fa8175196e0` |

本文最终SHA在本次实际回执写入后单独冻结交付ROOT（不嵌入自身SHA）。当前正式F24未替换Store，此补点仍不等于已部署或已整合恢复。FILES256/legacy request64/reader8等另有原门槛，本件不处理；DORA完整和repeat-live正向、正式长租约、IP/endpoint与双方实机仍待。
