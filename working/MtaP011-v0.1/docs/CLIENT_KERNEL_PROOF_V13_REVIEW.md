# CLIENT kernel 角色／信道／关联读回 v13

本候选仅新增 `candidate/client-kernel-proof-v13/runtime/mta_client_kernel_proof.py`。
未改 F／Provider／connection-v2／旧 runtime，未执行设备 GET、socket、无线或重启。
默认构造无 I/O；生产能力没有开放。HOST Fake 不能证明 P011 驱动会返回字段。

## 最小接口与接线

`ClientKernelReader(exact Origin(type8), expected_boot, owner, operation_epoch, timeout=5)`
构造纯；`read()` 返回本实例发行的私有 `KernelObservation`；
`authenticate(exact owner, operation_epoch, exact observation)` 只鉴别发行来源，不签 lease／RF。
epoch 为 exact int、范围 1..2**53，按值绑定；不同反序列化对象的相同整数合法，bool 拒绝。
`private_fields()` 保留原 Origin／executor／boot／实际 channel 与 station flags；repr 不泄漏。
`public_summary()` 只有固定角色枚举、频率存在布尔、三态关联／授权／认证与计数。
MAC、frequency、原 packet、request、元数据只在私有内存；没有 IP／endpoint 认证。
消费方必须另核 role=CLIENT、实际频率和所需 TRUE flags；读成功不等于满足这些条件。

未来 Provider 在现 `_connection_context` 同 Store RLock 下，先登记 exact reader，
再读、保存实际返回值及资源库存，核 `authenticate`，把两套 kernel 读回和已有
connection-v2 的 STATUS／event／baseline 对照；不将 go_dev_addr 当 station MAC。
每次新 readback 要新 reader；旧 observation 无持续有效性承诺。
本轮未接线，因此同 lease／helper／BLE 归属仍由未来 Provider 的既有 guard 负责。

## 实际固定读路径

实际 ProcReader self 两轮 → 固定 owned name 的 sysfs ifindex → 单 NETLINK_GENERIC
socket → CTRL_GETFAMILY → GET_INTERFACE／GET_STATION dump／GET_INTERFACE／
GET_STATION dump／GET_INTERFACE → ifindex 再读 → self 两轮。
前后 boot 必须为 expected boot，完整 Actor.key/live、Origin 四元、type/freq 与
两套 peer MAC/generation/mask/set 必须稳定。非原 Origin 拒绝；非 type8 如实 MISMATCH。
flags 未被 mask 声明保持 UNKNOWN；缺 freq／flags、空表、EOPNOTSUPP／ENODATA
不从 WPA event 填入，也不把空表签成已断开。多 station 不猜主 GO，公共关联 UNKNOWN。
其中当前三次 interface、两次 station 是有限顺序观察，并非原子 kernel snapshot。

复用既审 transport 的 `_attrs/_family/_budget/_now`（纳秒 timeout 量化），
另实现只读命令白名单及返回命令 NEW_INTERFACE／NEW_STATION，允许合法空 DONE。
严格 kernel sender `(0,0)`、local port/seq、GENL version、padding、终止、重复与预算。
unknown attrs 只保留，不把它们评为并发／监管许可。异常 ancillary 保留 unknown。
共享预算默认 5s、6 条固定请求；最多 64 个 datagram／1MiB 原包／128 条 message，
每请求最多 16 行。OS 调用等待受预算准入／socket timeout 约束，不声称硬抢占保证。

原 socket／ifindex ticket 在创建前登记，原返回立即保存，元数据 generation 核验；
未知创建／数字 FD／身份不明不盲关。每个合法 original close 最多一次，实际 fileno=-1
及原 FD fresh EBADF；其它已登记对象独立关闭。ProcReader 原对象保留，读取结束立即核
它自己的一次关闭与 EBADF 历史事实，避免后续合法 FD 重用误当未关闭。
失败／未知保留 strong refs，不重试 read/close，不发清理、信号或删除接口。

## Linux v4.14 primary ABI

- [nl80211.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/wireless/nl80211.c)
  2404–2456：GET_INTERFACE 回复含实际 IFTYPE；2432–2439 只有 driver 提供
  `ops->get_channel` 且返回 0 才发 channel attrs，2376–2402 中 freq 为中心频率。
  本模块没有另发 GET_CHANNEL；缺字段保持 UNKNOWN。
  4158–4162／4222–4306：GET_STATION dump 读取驱动 station_info，flags 仅 filled 时出现，
  dump_station 缺失为 EOPNOTSUPP，不能由广告缺项推硬件不支持。
- [nl80211.h](https://raw.githubusercontent.com/torvalds/linux/v4.14/include/uapi/linux/nl80211.h)
  2650–2689／2835–2853：STA flag ASSOCIATED=7、AUTHORIZED=1、AUTHENTICATED=5，
  STA_INFO_STA_FLAGS=17 为 packed 两个 u32 mask/set；未声明 bit 不具有真／假值。
固定命令 GET_INTERFACE=5、回复 NEW_INTERFACE=7，GET_STATION=17、回复 NEW_STATION=19；
属性 WIPHY=1／IFINDEX=3／IFNAME=4／IFTYPE=5／MAC=6／STA_INFO=21／FREQ=38／
GENERATION=46／WDEV=153。仅按 v4.14 UAPI 独立编解码，未复制 kernel 实现。

## HOST 专项

唯一首批工具 `b8b824`：`py -B -m unittest discover -s tests -p test_client_kernel_proof_v13.py -v`，
16 个新方法／0.030s／OK／host exit 0，无首 FAIL／ERROR、无补跑、无旧 suite 重跑。
包含实际 ProcReader 两轮方法 over FakeFs、完整回复与 UNKNOWN、角色不符／Origin／boot／
ifindex／channel／peer 变化、重复或非法 packet、未知 ancillary、原关闭一次／sticky unknown，
以及纯构造、Py3.5 AST、无实际 OS/socket tripwire 和 strict epoch 同值绑定。
未进行 actual Linux／WSL／P011 GET、association、DHCP／IP／手机验收或 20 图执行。

源码 SHA256 `a7dcc5b39bfe166598943412a36a77dc91bbce3a5f50c3ed51f6ad25e092b1ac`
（354 行／19875B）；专项 SHA256 `98fd2429b97e281310828cb2152c96808c33deac0b4c60febc196e273e147507`
（223 行／13038B）。固定 loader 接线应保留以下实际来源，不能只依赖类名：

- transport：`df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420`
- transport caps：`c1792c2294fed5da16ec4a676423fbcbe53d44e9bc4ddadc1bc26fd45afe046c`
- ProcReader：`2f0ef52379be897d47b5cb311ef90f24b5c8a2c283e72780f139a8dd77626591`
- caps-v7 core：`bb22e43ec191c04624e009539f954a9bcbb7b98520fb32adf6fd4f18f4e8139a`

HOST fixture 用当前同域 core 类型；实际候选 graph 的 core／ProcReader 必须同模块类型域。
此处 issuer／epoch authenticate 不是部署 manifest、锁、lease 或 peer endpoint 的授权证明。

## v13 修订：STA_INFO PAD／最终 deadline

上段 16 方法结果及 a7dcc／98fd 指纹为首批原版本，完整保留，未重跑或改判。
独立 SOURCE 审查指出两个实际边界，仅本候选内修订，没有改依赖、State／F／Provider。

- STA_INFO 专用解析允许重复 kind33、flags0、空 payload；其它重复和非空／flagged PAD
  仍拒绝。原 STA_INFO encoded attrs／原 datagrams 保留完整 PAD 字节，未去重原包。
  [Linux v4.14 nl80211.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/wireless/nl80211.c)
  4076–4101 的多个 u64 使用 STA_INFO_PAD；UAPI enum 2869 的值为33。
  [netlink.h](https://raw.githubusercontent.com/torvalds/linux/v4.14/include/net/netlink.h)
  1290–1295 为条件 `nla_reserve(..., padattr, 0)`，因此合法空 padding 可重复。
- 最后 `_self(deadline)` 返回后立即 `_check(deadline)`；在发行 observation 前核共享
  外层期限，等于或超过 deadline 拒绝。原一次关闭与其它资源独立清理保持不变。

唯一新增批工具 `a7e2dd`：仅运行 3 个新增命名方法／0.013s／OK／host exit0。
无新 FAIL／ERROR、无补跑；原16未重跑，当前19方法不是单批19PASS。
正例覆盖重复空 PAD 原字节保留；负例覆盖非 STA_INFO 重复、非空／flagged PAD／其它
重复；最终实际 ProcReader over FakeFs 返回后 clock 为104.999／105／105.001，分别
接受／拒绝／拒绝且原资源实际 Fake 关闭；新增方法亦核 Py3.5 AST。
源码修订 SHA256 `14dbe98d59e8319812e62d75907196b78fbde348f40003942476ecb9ee9c0f93`
（358行／20077B）；专项修订 SHA256 `84646f200055b57a942560b3c219cb2ba3c32548d0073ca1bf16a3f6e0e68a45`
（268行／16287B）。仍未设备 GET／无线／关联／生产接线，不改变任何恢复验收结果。
