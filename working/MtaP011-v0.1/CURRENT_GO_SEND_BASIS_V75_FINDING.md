# GO 实际发送凭据与 TCP 绑定底座 v75

## 本轮结果

ROOT `fdb92e` 首次且唯一 HOST75 执行通过：host 0、child 0、无超时，checker 子进程阶段约 0.203 秒。新增生产代码发行真实来源的私有 GO 凭据原件，并创建绑定原接口与 GO IP 的 TCP 对象；**尚未 listen、accept、TLS 或发送文件，也不是小米 15 Ultra 互通通过。** 本轮没有 ADB、设备无线、手机操作或部署。

主机源码图保持 20 件，仅 Native 和 Bootstrap 两行替换，其他 18 件原字节不变。原 v74 源与已通过结果均保留。新图只是主机审核来源，不是已经由设备 Loader 认证的部署 manifest。

## 实际代码改动

- `Native.issue_send_basis(end)` 在原 worker／mutex 中消费实际 serving DHCP、原 C2 canonical/history、原 IP ACK／receipt 和原 service tuple；调用实际 IP/group 当前读回，另从原控制器读取当前 AP STATUS 并核对其 SSID 与原私有 GO 事件。返回不可变私有 `GoSendBasis`，不是旧 `NetworkReceipt`，不产生 peer 或传输就绪。
- `Native.open_send_listener(basis,end)` 在真实 TCP factory 前再读实际 IP/group；先登记原资源，返回 raw 后先保留再读取 fileno。只创建 IPv4 TCP，绑定原 `SO_BINDTODEVICE`、原 GO IP 与内核选择端口，核 socket options、CLOEXEC、nonblocking、未连接／未监听及地址。返回不可变私有 `GoSendListener`；未 listen/accept/connect/TLS。
- `Native.close_send_inventory(cleanupUntil)` 保留原库存。空库存不读时钟或 IO；已知 FD 按原一次 close／typed EBADF 闭合，未知 factory／fileno／关闭结果保持 pending。DHCP 关闭、IP 清理与删除、GROUP_REMOVE、netdev 删除五个接点均先检查 TCP 已知闭合。
- `Bootstrap.prepare_send_listener()` 是显式同 worker 接点，要求调用者已有 `prepare_live()` 和原 finally restore；先保留 basis，再创建／保留 listener。默认 GO/DHCP 诊断 `run()` 没有自动调用发送 API。原 restore 在 begin_restore 后先关闭 TCP，再继续原 DHCP→IP→group／child→interface／baseline 路径。

凭据 codec 按本地固定 WPA 2.12 primary 源的事件格式处理：SSID 规范转义、passphrase 原样引用、PSK hex；同时报告两种密码时用 PBKDF2 核对一致。SSID 明确只支持有效 UTF-8，非法字节拒绝，不伪造字符串；没有用 AP BSSID 替换 GO device 地址。私有凭据／STATUS 不进入 repr、公开状态、日志或结果 ZIP。primary 归档 SHA `08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6`，成员 `src/utils/common.c:477`、`wpa_supplicant/p2p_supplicant.c:1430` 为对应来源。

原 service 20 秒没有续期，调用方只能收窄上界。发行和 factory 前的两次真实 IP/group 读回以及 STATUS／FD/options 检查仍会消耗这段时间；**没有设备耗时或性能通过证据**。post-bind 做实际 TCP/UDP options、FD、地址和原 canonical/service/cap 检查，没有新增第三次完整 IP 快照；不宣称内核原子性。

## 冻结源

| 文件 | 字节数 | SHA-256 |
| --- | ---: | --- |
| candidate/go-send-basis-v75/runtime/mta_go_native.py | 168493 | 25ba2d2b5c9f810242fe3f0e84dce891c7ac57b2ac2058af93492f247486b435 |
| candidate/go-send-basis-v75/runtime/mta_go_bootstrap.py | 26700 | d3b6b0c3787f1c82e087262c5bbb3ca7794a4357d759a035b8c0af95ec6289d7 |
| host/go_send_basis_v75_source_manifest.json | 4535 | c2ee688cdb8fbb2a6916e9a947516426a69c2e3dca267c46ea549069f130e057 |
| tests/test_go_send_basis_v75.py | 38523 | fe35bdcb1be155d6874d09952f648c243e7db67a3940470b614a31d1add614be |
| host/go_send_basis_v75_check.py | 11879 | 6bdc6e9cdcbe2125b0f0d4fab53a10a7a9e0debe9d1e143eb875753aaf73da88 |
| HOST_MTA_GO_SEND_BASIS_V75_CHECK.cmd | 205 | 76aea5d457ba07570ce19db9d7da636b4b5620d60da1f50cc90c76c66deda7c8 |

Native 相对 v74 为 357 行新增、零删除；Bootstrap 仅增加私有原件、显式接点、TCP-first 恢复和只读 observed 投影。SOURCE 联合审查未发现确定正常调用 blocker；它不等于动态完整部署通过。

## 唯一新增检查与证据边界

唯一新测试方法 `GoSendBasis75Test.test_go_credentials_and_owned_tcp`：4 组有效凭据、16 组凭据拒绝检查；14 个独立 Native 模型域、23 次原件／期限／资源拒绝检查。含空库存、17 秒子 cap、正常绑定、worker／service／canonical／basis 替换、过期、SSID 不一致、factory 负返回、fileno 未知、late bind、关闭异常及五个删除门。旧测试方法执行 0。

测试载入完整固定 Native75 定义，实际执行新 codec／发行／TCP 读回与原 FD 登记、adopt、期限、once-close 算法。旧 owner、IP/DHCP、controller、durable 等前置边界，以及 socket／fstat／EBADF 明确使用惰性模型。平台 IO tripwire 为 0。**不是完整 20 源图、Bootstrap、Store、Loader、真实 Linux socket、GATT、TLS、RF、设备、手机或物理恢复通过。** 原 Native 源码方法在专项中被复用；`old_methods=0` 指旧测试方法，不是所有旧源码方法。

[result.json](results/go-send-basis-v75-host-20261003-040711-b7528274/result.json)；[四成员脱敏结果 ZIP](results/go-send-basis-v75-host-20261003-040711-b7528274/public-result.zip)：3169 B，SHA `d64659d33fa21db192e2698a0dd5c850062ace6a1dc1c6529752c86db5a1fb6c`。raw stdout 86 B、stderr 100 B；保留原 CRLF，没有改写原始输出。

ROOT `ceb69e` 与独立 `abf06d` 只读审计均通过：27 件 private-inputs 与当前来源的 bytes／SHA 一致，固定 marker、Ran 1／OK、child0／无超时及分层 flags 一致；ZIP 四成员逐字／大小／CRC／testzip 一致。独审另核两图只有两行替换。stdout SHA `56b3e4fcbe7b47277c7632857279567b2c3a786d9b4be7720a4aef10b3fffd36`，stderr SHA `1923bd9bd000fdfb8fd3ca526f6e7a4b8887bd09b40c9ba1b18ec99a0260960f`。审计不重跑测试。PC-only 一键入口已有；ROOT 直接运行 checker，未点击 CMD。

## 仍须制作

1. 将实际 GATT DeviceInfo 对端身份绑定到 P2P station 与真实 DHCP ACK allocation，不能把 WLAN 关联当文件成功。
2. 同 worker 的有界、非阻塞双 TLS 连接推进，接上现 WebSocket／下载／确认协议；旧多线程 Sender 不能直接借用本 owner。
3. 原任务／epoch 的发送 IPC 和正式文件中心入口；不能补造旧 handoff 或仅翻 available。
4. 接收的真实一次请求准入、actual GATT ACK、现 Factory/F37 链及活跃服务关闭接线。
5. 设备端时间／资源／恢复，以及小米 15 Ultra 原厂互传双向文件 hash、取消／失败验收。

已有设备 pending／完整恢复未证及正常重启许可未回复，仍按上一 checkpoint 保留；本轮没有刷新设备事实、清记录或重试 RF。目标 active，**尚非仅剩人工手机验收，也不是互传功能完成**。
