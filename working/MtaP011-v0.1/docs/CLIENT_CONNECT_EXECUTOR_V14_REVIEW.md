# V14 同 F CONNECT executor — SOURCE/HOST，非生产准入

## 范围与实际接口

- 新 F 来源为 `candidate/client-connect-v14/runtime/mta_client_executor.py`；逐字基于冻结 diagnostic-v12 F `549cd0652434d934134e465ddfc08c9baf7df9293acb7e567ce9c1a1285bd78f` 后作限定增量。旧 F、Provider、State、Store、Owner、v13 codec/handoff 均不修改。
- `DeploymentLoader(run_token, manifest_sha256)` 仍只从固定私有 run 读入，部署 schema 变为 exact `{version:2, provider, sources, connect_binding}`；旧 version 1、未知/缺键、bool version 均拒绝。
- `connect_binding` 为冻结 v13 `ControlBinding` 的 exact 九字段：version/run_token/candidate_sha/operation_id/native_epoch/operation_epoch/gatt_session/nonce/receive_consent。它不含 SSID/PSK/P2pInfo，仍是私有元数据，不在 public/repr 输出；run/candidate 必须与 ProviderManifest 相同。
- Loader 保存原 dict、已发行 immutable binding 和初始 canonical wire；authenticate 拒绝原 dict 变化或换对象。Binding 的形状/摘要不证明 native 来源、用户同意、kernel 或能力。
- MODULES 保留旧前18，尾序为 `mta_protocol, mta_client_control_frame, mta_client_connection, mta_client_linux_provider, mta_client_executor`，合计23；codec 还必须匹配冻结 `b20d72f17197132820d3be765cbc2e3c2a41d8256e4bdaeeb5e23f441c065b4f`。新真实23源统一域 smoke 由 ROOT 另做，不把本测试的空模块 fixture 称为该证据。

## stdin / 同 F / Parent

- `_StdinControl(io, codec, binding)` 借用原 stdin FIFO，每次读前后核原 metadata；逐片最多4096 bytes，冻结 decoder 控制总量4103、ASCII/canonical/一次 nonce。先排空当前 readable 输入再领取，所以已排队 CANCEL/EOF 优先。没有新的 reader/thread/socket/FD；secret 不保存到 `raw`。
- F ready loop 仅一次 `take_connect()`，保留 exact request 后核类型与原 binding，保留 connection creator/info/returned 票据后再校验；调用 `lease.connect_p2p(info, _checkpoint=self._cancelled)`。返回必须 exact 新 connection `ConnectionObservation`，只留 private observations。
- checkpoint exact True=取消，False=继续；stdin、原 record deadline、同 F watchdog 通知均可终止，已观察 expiry/watchdog sticky。原20秒 record deadline不更新；取消/未知不新开 DISCONNECT，仍由原 same F restore收尾。不能抢占正在执行的任意内核 I/O。
- 原 restore60、Parent.finish90 上限、实际 FinishReceipt/auth 次数、stdout exact public schema、诊断 stderr 单次有界输出与原 close/EBADF/EOF/Actor 规则不变。public association/ip/send/receive/phone 字段一律 False。`done` 仍只表示原 init资源恢复链，不表示 CONNECT成功；连接异常保留 failures，main/Parent不能因此把首次业务失败改成功。
- `ParentExecutor(..., _handoff=None, _handoff_type=None, _handoff_codec=None)` 是未来可信 State 工厂的私有登记 seam；默认未登记时 `send_connect(exact_handoff)` unavailable。只收登记的原实例/类型/worker/state/operation/实际 bound claim/check，以及原 State codec/module/protocol/binding type/encoder，不接外部明文或任意 frame。State codec.protocol 必须是原 claim 函数 globals 中的 actual protocol 对象，前后拒绝换引用。
- `send_connect(exact_handoff)` 要求实际 child/原管道与已收 ready frame、未 cancel/finish；在同 worker与 State lock 下调用实际 handoff.claim_frame(**原 State codec**, run/candidate/local operation)。先保存原返回 bytes，再读 State binding；以 Loader codec 解码原 bytes并核 full canonical metadata，保留两域原对象，binding 不要求跨域 is。只有 State codec 能按原 handoff 的 exact P2pInfo 类型编码，不能偷换协议对象或先用 Loader 域编码。只进行一次原 pipe write，short/unknown/postwrite变化保留原票据，不重试、不记录 stdin raw；CANCEL 仍走原通道。
- Parent mutex→State lock 的顺序要求未来 State 接线保持一致；现尚未接线，不可在 reader/反向持锁路径调用此方法。不能把 `_handoff_type` 登记视为不可伪造授权。
- v13 handoff.binding 仅 claim 时创建；未来 State 必须在 claim **之前**按已保存 nonce/epochs/GATT session/local operation准备部署元数据，不得提前 claim造manifest再二次claim。当前完整 State→Parent 调用链尚未实现。

## 唯一新方法与原批判保留

- 首 `f6c67f`：`python -B -m unittest discover -s tests -p test_client_connect_executor_v14.py -v`，20方法/.109s，7PASS/4FAIL/9ERROR，exit1，原判保留。
- 首失败为 HOST fixture 两处实际类型/路径问题：patch.dict退出后再次 import protocol 产生另域 P2pInfo，冻结 codec正确拒绝；alias Fake未把逻辑 native映射到同一物理 entry，Loader正确拒绝 source_changed。仅修 fixture，不改准入。
- `943e19`：原13失败方法精准复跑，13/.046s/OK，exit0；首7 PASS不重跑。
- 最后新增 exact ConnectionObservation 返回校验，先保存 returned再拒绝 malformed；`44594d` 仅1新方法+2直接受影响正向方法，3/.010s/OK，exit0。
- ROOT随后指出真实跨域：State handoff._plain 的 P2pInfo 不属于 Loader 域；改为原 State codec claim，冻结 v13仍不改。`09da98`：1新 actual State ReceiveConnectHandoff+PC libcrypto/threads 方法＋8直接受影响Parent方法＋final Python3.5 AST，10/.083s/OK，exit0；不重 F/Loader已过方法。
- 独立审查随后发现 Parent.poll 已收到ready后若又遇坏frame，旧准入未拒绝 sticky failures；只增加 `self.failures` 拒绝，不把正常 active pending当失败。`625111` 仅1新增 actual Parent.poll ready→坏frame→send零claim/零秘密write负例＋1直接受影响正向，2/.008s/OK，exit0。
- 共23不同新方法分批通过（不合称一次23全PASS）。唯一实际跨域方法确证 State/Loader P2pInfo 是不同类，实际 crypto解密后原 State编码→Loader另域解码成功；Synthetic State/session与 FakePopen/pipe/connection/status不证明生产装配、Linux/P011或手机。原22方法与首次失败记录均保留；ROOT另做的真实23源 smoke不是本作者复跑证据。
- Fake-only Tests 类 tripwire 禁实际 Popen/socket/ctypes/fork/kill/waitpid/execve/默认LinuxIo；跨域唯一方法明确复用旧PC libcrypto/线程fixture，仅使用Fake pipe/Popen，不调用实际进程/socket或设备。无 WSL/ADB/RF/正式部署、无全套或旧方法重跑。diff 工具 `703a28` exit1仅表示两个 SOURCE有差异。

## 尚未验收

ROOT 需全文审核与独立固定23真实源同域加载；BlueZ 新 Provider/connection来源已另行停写，本作者不将其作者专项升级为新证据。未运行真实 stdin/Popen、同 F CONNECT、kernel association、DHCP、IP、应用 endpoint、TLS/文件或小米15Ultra。默认 main仍SOURCE-only，production能力False，旧actual FAIL不改判。这里不扩展为HOST驱动或授权再次RF。
