# CLIENT own-marker 本地文件事务准入

范围只 coordination、FILES、pending 三模块和新组合专项；不是 RF/Store/Executor
准入，不接 State/Provider，不 clear/unlink/恢复旧 pending，也不晋升设备收发能力。
旧三专项及历史 review/harness/result 不修改。

## 精确接口

三组件构造新增私有 `_serialization_lock=None`。可信事务从首次 acquire/open/create
即传同一 actual `threading.RLock`；不接受 Lock、caller bool 或任意可调用对象。
未显式传入时保持组件默认域，marker 继承 coordination 域；bind 同步切换共享域。

`marker.bind_files(exact_journal_files, exact_prepared_canonical,
exact_store_epoch_object, shared_serialization_RLock)` 仅一次，返回 immutable
`OwnedMarkerBinding`。epoch 是 exact 私有 object()，不是外部 ID/路径/布尔。
私有字段：issuer/marker/coordination/FILES/initialprepared/epoch/sharedlock。

首次核 exact acquired coord+LockSet，已 opened FILES、同 run/Identity/四目录锚；
prepared 必须是该 FILES **真实公开返回并登记**的 exact CanonicalRecord，正确
issuer/current generation、prepared 非 ready、当前 full bytes/metadata/完整 Journal。
该 registry 的每次公开返回均对应一次已记录 FD 读取，受原 MAX_RESOURCES=256
库存上限约束，不是另一个无界 issuer registry；关闭不丢未知/历史原引用。
marker 已 durable 且原 FD/entry/full bytes、两次当前 boot/Actor 与原两锁一致。
prepared baseline.boot 必须匹配 actual marker 当前 owner boot。
不接受复制 equal receipt、PendingObservation、caller inode 或 fake ENOENT。

初始和发行前再次读回 prepared，实际读取 FD 均按旧 FILES once-close/readback 合同。
先登记 partial ticket；消费者安装后最后失败也保留 exact 引用、unknown/未发行，
不回滚、不盲 rebind，不将部分安装当 ready。

`binding.verify(exact_consumer, exact_epoch)` 只允许该 coord 或 FILES，核 issuer
registry、exact 两消费者/epoch/共享域，然后 fresh 读取原 marker、目录锚、原两锁
及当前 Actor，返回 private PendingObservation。caller 不能用 status 或旧观察替代。
验证失败后发行失效 sticky；marker 关闭同样失效，消费者未知/关闭也拒绝。

后续 FILES 自己的 current-generation/full bytes+metadata CAS 保持不变；可以正常
rename 后更新到新 journal inode，binding 不要求 forever 等于初 prepared inode。
FILES 已失败 write_pending/资源未知仍由原 FILES 入口拒绝，不由 binding 清除。

## 锁顺序与默认边界

所有参与者操作、被动 status、close：同一 shared RLock **最外层**，组件自身锁在内。
bind 过渡持 shared→coord 旧域/自身锁→marker 旧域/自身锁→FILES 旧域/自身锁；
旧排队操作获得内锁后检查捕获域是否仍当前，否则释放旧域并重新捕获，避免绕过共享域。
显式不同域在取得该域前拒绝。共同域序列化使 bound coord→marker 与 marker→coord
不会 ABBA；marker 原 read guard 不递归调用消费者 pending gate。
嵌套 marker 观察保存并恢复消费者原预算，不延长外层事务准入时间。
锁取得/内核 I/O 不能被 Python 预算硬抢占；预算是取得后阶段检查，不称绝对 deadline。

默认 acquire/open/commit/coord.validate/read_pending 仍遇任意 pending 即拒绝；
默认 **已 opened** FILES.read_current 的旧只读行为不改。绑定后该读也 fresh 核 marker。
coord.read_pending 在 own 分支返回 entry_absent_observed=false/own_entry_observed=true，
不会伪造不存在；默认返回 shape 原样。close 不需要准入成功，仍尝试原资源一次。
没有全局 monkeypatch/ENOENT 伪装，没有 own-marker clear/finish/RF 动作。

## 证据与未完成层

原9文件 SOURCE ZIP `SOURCE-own-marker-admission-20261001-1510.zip` SHA
`96b5f71a89a5096c32a47002af2deac8acf34bb2d7ba19eba5cfd9d77852bc59` 核匹配，保留。
唯一首批工具 `de1ada`，`python -B -m unittest -v test_client_owned_marker`
并显式选定旧三专项的16个直接受影响命名方法：**44项/0.502s/OK/host exit0**，
wall 0.9528715s；28新＋16旧，没有 FAIL/ERROR 或后续重复批，不作项目整合套测。
旧命名批为 coordination 构造/AST/validate/read_pending/release_journal/独立close六项，
FILES 构造/AST/fullreadback/代际CAS/独立close五项，pending 构造/create-close/旧entry/
owner-boot/closed-observation五项。旧测试文件不修改。
新组合覆盖：正常绑定/实际存在观测、CAS换inode、默认域迁移、已排队旧域重捕获、
三个guard并发无ABBA、未知/部分安装/预算、forged receipt/consumer/epoch、owner与
marker bytes/inode/锚/锁变化、关闭后拒绝且只关原资源一次。均为Fake，不是内核因果。
三修改源 Python3.5 AST 在新专项检查；不执行实际 OS/libc/file/flock/WSL/ADB/RF。

PendingObservation 的 durable_created/owner_observed 是当次文件观察，不证明 frozen
manifest、历史连续 flock、F-D same OFD、实际进程 launch、网络恢复或完整 Store。
full_store_implemented/own_marker_admission(平台)/mutation_admission/send/receive 仍 false。
后续组合事务与实际隔离 Linux 验证由 ROOT 独立准入；本批 Fake 不当 Linux/P011/手机。
