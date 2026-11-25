# 当前 GO 关联查询器

仅 HOST 实现审阅；不是手机兼容、当前 P011 关联、生产 Provider 或互传验收。
新增 `mta_p2p_association.py`，不修改 worker、State、固定 V9/native、Store、原网络或 pending。

## 官方字段与固定源码

依据 [官方 2.12 发布源码](https://w1.fi/releases/wpa_supplicant-2.12.tar.gz)，本地归档
`native/private-p2p-candidate-20261001-v2/source/wpa_supplicant-2.12.tar.gz`，
SHA-256 `08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6`。
实现独立解析协议事实，不复制上游函数。版本不由无版本号的 STA 文本自动证明，
真实 Provider 必须核验实际已拥有的 WPA 二进制与配置来源。

| 上游路径 / 函数 | 实际输出 / 限制 |
| --- | --- |
| `src/ap/sta_info.c`, `ap_sta_set_authorized_event` | AP-STA-CONNECTED / DISCONNECTED 的首地址是 station/interface MAC；只有取得设备地址时才追加 `p2p_dev_addr`。连接事件发生在授权事件路径，但交付后可以过时。 |
| `src/ap/ctrl_iface_ap.c`, `hostapd_ctrl_iface_sta_first/next/sta` | STA-FIRST / STA-NEXT 返回当前 sta 链表 MIB；表尾是零字节。无此指定 STA / 无 AP 状态会失败，不能把 FAIL 当正常表尾。 |
| `src/ap/ctrl_iface_ap.c`, `hostapd_ctrl_iface_sta_mib` | 首行 station MAC；`flags` 可含 AUTH / ASSOC / AUTHORIZED，后面 aid / capability / listen_interval / supported_rates / timeout_next 和可选 MIB。 |
| `src/ap/p2p_hostapd.c`, `hostapd_p2p_get_mib_sta` | 仅当前 station 具有 `p2p_ie` 时才格式化 P2P MIB。 |
| `src/p2p/p2p_parse.c`, `p2p_attr_text` | 实时 MIB 的键是 **`p2p_device_addr`**，不是事件的 `p2p_dev_addr`；另有设备名、类型和 capability 等。 |
| `wpa_supplicant/ctrl_iface.c`, CONFIG_AP 分支 | 固定 STA-FIRST、STA-NEXT、STA 命令转给 AP 查询函数；不是扫描缓存命令。 |

[官方控制接口说明](https://w1.fi/wpa_supplicant/devel/ctrl_iface_page.html) 明确命令回复与
ATTACH 事件可交错，建议使用两个通道；该说明网页标记 2.5，精确 2.12 字段以固定归档为准。
本次浏览器不能直接渲染 gzip/cgit，已实际全文读取本地固定归档的相关函数，而非以 README 推断。

## 可用 API 与真实调用

`AssociationReader(control, context, ownership_lock, owner_readback, cancelled, ...)` 纯构造。
`control` 必须是 Provider 已拥有、从未 ATTACH、没有未决请求的专用 `PrivateControl` 命令实例，
借用其 exact `.sock` / `.path`。固定 V9 已有独立 command / monitor 实例，但
`PrivateControl.request` 目前 **不允许 STA 命令**：新模块只借用 command socket，绝不更改旧 allowlist。

`read(DeviceInfo.mac, budget=.2)`：同一个 owner mutex 内 PING → 完整 table A → 完整 table B →
唯一 DeviceInfo.mac 对应 station 的指定 STA → fresh owner readback。
两表比较 station/device/flags，不比较会正常变化的收发计数；最终 STA 必须相同。
要求 AUTH、ASSOC、AUTHORIZED；必须存在实时 P2P device 地址，不按名称、事件、缓存、
station MAC 与 DeviceInfo.mac 相等推断。重复 station、重复设备映射及 table 变化均拒绝。

`readback(exact observation, budget=.2)` 重新执行实际查询，核同 reader/context/control 与实际映射；
返回新观测时间，不延长任何授权期限。
`owner_readback(exact control, exact context, budget)` 必须返回现有 exact `ScopeProof`，
confirmed、fsynced、持久读回、owner/address/routes 均严格 True，GO 的 peer flags 均严格 False。
Provider 还必须在此回调核同 boot/epoch/phy/WDEV/ifindex/name、原网络、实际私有 WPA 进程、
精确 control 归属与当前 GO；typed 结构自身不认证内核。这是可信内部 API，不能由 HTTP/QML 提供。

## 资源、预算与关闭

- 不创建 socket / 控制目录、不连接、配对、ATTACH、IP 写入或 RF 操作；仅 PING 和固定 STA 查询。
- 查询前后核 retained socket / 原 fd / getsockname / getpeername / UNIX DGRAM、root 私有目录700、
  local socket600、peer socket归属及完整稳定 inode 元数据。Provider 负责目录祖先与进程来源。
- 同一 Provider mutex 必须覆盖其他命令、监控撤权、WPA 退出与恢复；本模块不能证明其他代码遵约。
- 原 timeout 逐请求保留并恢复、读回；容纳 CPython 纳秒量化误差而不扩大请求预算。
- 一次同步调用 ≤2秒预算；owner 单次≤.2秒、收包单次≤.1秒；最多32站点、8192字节回复、
 160行/1024字节单行、600000字节私有生命周期 transcript。OS / 回调不能被 Python 硬抢占，超预算失败。
- 排队旧回复、事件交错、短发送、发送/接收未知、截断/ancillary/flags、恢复timeout未知会 taint。
  taint 持久，未来 Provider 必须关闭其自己拥有的 channel；本模块不抢关 borrowed socket。
- mutex 获取结果异常/非严格 bool 时保留 exact mutex/control 引用与未知状态，不盲 unlock；
  获取已确认后 release 失败同样 sticky。settimeout 调用前登记可能改变，即便调用先改后抛也恢复读回。
- `close()` 仅本 reader 作废，不声称底层 socket/线程/WPA 已关闭；`status()` 固定字段，
  `private_raw()` 保留私有原命令回复，不入公有 ZIP / 日志 / UI。实际 producer 线程由外层 owner 跟踪。

## 限制与下一次真实装配

`AssociationObservation` 没有 expires，也不是 `AssociationReceipt` 或 mutation admission。
binding digest 只标识 control/context，不是关联世代或持续在线证明。实际 Provider 必须维护
同域连接世代、实时 monitor / readback 与失联撤销 Event，然后才能给 worker 有截止时间的 receipt；
该截止时间不能由一次查询无条件延长。DHCP 的 admit_station 也必须重新核当前映射，
DHCP ACK 不等于手机配置、MTA 端点或完成。

非绑定的标准 dot11 / dot1x 元数据只核键/重复/整体大小与文本形状，不影响 MAC/flags 结论。
未评审扩展、WPS 任意设备描述文本、group-client / MLO 格式拒绝；WPS 文本可能含未经当前
协议保证转义的设备描述，因此不为兼容放宽。上游 PENDING_POLL 文字缺右括号，本版本保守拒绝。
可选事件纯 hint 只支持 station + 可选 p2p_dev_addr，其他 IP/keyid/DPP/VLAN 扩展拒绝；
不消费 monitor、不将 hint 当实时关联。实际手机字段、超时/队列 profile、私有控制权限尚未实测。

## 本次定向证据

工具使用 PC Python **3.12.0**，始终 `-B`，仅新增文件专项、FakeSocket / FakeStat / FakeMutex / FakeClock。
没有真实 UNIX socket / 控制文件打开、WSL、ADB、RF、原网络 / pending 操作、全套回归或候选冻结。

| 工具批次 | 实际结果 | 说明 |
| --- | --- | --- |
| `581a37` | loader 1 ERROR；0.000秒；exit1 | PC socket 无 AF_UNIX，测试 FakeSocket 类在导入时使用该属性，测试方法/实际查询均未执行。 |
| `896533` | 34方法；8 PASS、26 ERROR；0.006秒；exit1 | 注入明确 Linux HOST fake socket 常量后，26个 Reader setUp 因 Windows os.path 对 UNIX path 归一化而失败；不属设备结论。 |
| `db5d94` | 仅受影响 Reader 26方法 PASS；0.013秒；exit0 | runtime 明确使用 POSIX 控制路径语义；未重跑此前8个已通过 parser 方法。含 Python3.5 AST。 |
| `a2af81` | 2新增 + 5精确受影响方法 = 7 PASS；0.006秒；exit0 | 补 unknown mutex 获取保留、partial timeout 写后异常恢复；改精确 readback mapping 断言，包含 AST 与关闭/取消受影响例。 |
| `1fd111` | 3受影响方法 PASS；0.006秒；exit0 | 仅将 HOST Linux namespace patch 改为模块 setup/teardown，退出后恢复生产模块引用；Parser / Reader / AST 精确方法验证，没有新方法或新 runtime 改动。 |

首次命令：`python.exe -B -m unittest discover -s tests -p test_p2p_association.py -v`。
后续分别 `-B -m unittest test_p2p_association.ReaderTests -v`，及7个精确命名方法；
Reader 命令工作目录为 `tests`。目前36个方法已分批覆盖，不声称一次36整批或项目整套通过。
失败批次不改写、累计次数不当新方法数。无 P011 / 手机关联或 Provider 装配验收，
`send_available` 及真实平台前置门禁保持原状。
