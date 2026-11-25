# CLIENT 可信接收交接 v13

本组件是内部接线代码，不是已启用的互传能力；没有部署、ADB、无线、原厂或系统写入。

## 实际缺口与来源

`native/mta_bluez_helper.c:315–325` 的真实接收事件已有 `session`（uint32 单调编号）、完整私有 payload。现有 `runtime/mta_service.py` 的 p2p 分支未保存该 session，而 `receive(info)` 还存在直接提交已解密对象的内部兼容入口。v13 不把 `key=None` 或 P2pInfo.id 当握手权限，也不把 id 当尚未收到的 WebSocket sendRequest.taskId。

新增 `candidate/client-connect-v13/runtime/mta_client_connect_handoff.py`：

- 仅由原 TransferSession worker 在 key/helper 创建后构造并由 Operation 留存；原 helper reader 捕获 exact 三字段 native 事件。
- 保存真实 native GATT session，核同 State、Operation、Session、helper、reader、worker、Crypto、KeyPair、两 epoch、receive consent、取消和有界截止期。记录仅在内存。
- 严格 base64/JSON/加密 P2pInfo 范围。未加密、额外字段、异常 session、重复收件和其他线程均不能触发解密。
- 原 worker 调用实际 `OpenSslCrypto.decrypt_credentials`，调用前后核原 owner/取消；发生失败后不能退回明文或重试。没有新增读线程。
- `claim_frame` 只消费内部保存的真实解密结果，绑定原 native session、本地 operation_id、一次 nonce 与审核后的 codec；返回私有帧，由后续原 pipe owner 一次发送，不写 argv、文件、诊断或公共结果。
- 取消/过期/时钟回退/owner 改变丢弃保留引用；不宣称 Python immutable bytes 已安全清零。

这不是对任意进程内 Python 代码的沙箱。State 回调路径和 pinned codec 加载仍需实际装配；现在不对外提供这些入口。MTA AES-CTR 没有 authentication tag，完成解密和绑定来源不等于密码学发送方身份认证，更不等于可信应用端点、关联、IP或收发成功。

## 本轮 HOST 证据

`315267`：新 `tests/test_client_connect_handoff_v13.py` 八方法，Ran 8 tests in 0.031s，OK/exit0，无跳过；真实开发 PC OpenSSL/libcrypto 执行加解密，真实 Python worker/reader threads。覆盖 exact session、原key/epoch/consent改变、解密途中取消、失败无明文降级/重试、错误线程、clock回退、私密字段不进 repr/status、Python3.5 AST/no-I/O。

测试 State/Operation/Session 是显式合成 owner，未启动实际 State/TransferSession 生命周期、native helper、子进程、管道或设备。不重复旧套件；八项通过只签本组件 HOST，不能升级为 P011、真实蓝牙或手机互通证据。

`12cc5c`：仅新增第九组合方法，Ran 1 test in 0.008s，OK/exit0。真实 PC crypto 输出进入本 owner 的一次 claim，再经实际 v13 codec 分片 decode；原 id 保留、本地 operation_id 独立，已领 request 在后续 CANCEL 后立即失效。不是同 F/管道或实际连接验收；旧八方法未重跑。

独立 SOURCE `4e095b` 全读本组件/test/doc，发现私有异常 clock 的 huge-int finite溢出及构造第二次采样未验证的边界。窄修仅 range-first/finite 与复用 `_check` 的同次 `_last`，没有增加 clock calls、线程或更改来源门禁；新增专项回执另记，不改上述8+1历史。

`3ea630`：仅新增第十方法，1 / 0.006s / OK/exit0；huge deadline/clock 保持固定错误，构造严格只使用一份已核 clock sample。十个不同新方法分批通过，不称最后整批十项，旧九未重跑。

## 待装配

codec、正式同F连接和检查点取消、正式有限租约、State宿主与部署图都须接线后才测试。当前原 runtime、v12诊断候选与设备遗留stage保持不变；production gate不开放。
