# P011 V6diag：私有 GO + IPv4-only 有界验收计划

状态：独立入口、固定 source pin 与诊断 schema 的 47 项 HOST 测试通过；等待主线程完整审查和正式冻结。本文不是已进行的 V6diag 实机试验，也不把 HOST mock、旧只读 dump 或 V4 GO-only PASS 升格成 IPv4 写入通过。由主线程审查、冻结、复核 identity 后，才可串行执行一次。

## 固定范围

本候选只增加固定原因/布尔诊断，新 `runtime_marker=p011-go-ip-only-v6diag-1`，journal version3/kind不变；不修改 helper/core/native、IPv4收据或恢复权限。未降低 IFF_UP/carrier、地址/路由、超时、guard 或原厂基线门槛。

`ip_trial_requested=true`：真实入口仍会请求 GO + IPv4-only 试验，门禁通过时可能执行 NEWADDR。不能把“诊断修改”描述为整次试验只读或无 IP 写入。本文作者仅执行 HOST 测试，没有 ADB、Docker、正式 freeze 或设备动作。

- 只使用项目自有接口、私有 WPA 进程与原有同一设备级 guard/journal/watchdog，TTL 固定 20 秒。
- 保留原厂 `wlan0`、STA、ConnMan、原厂 WPA、BlueZ、Z03、Weston 和固件文件。无正常重启、全局清理、服务停止或自动重试。
- 本阶段仅添加/删除自有接口上的一个冲突检查后的 RFC1918 `/24` IPv4 地址；只有精确 CREATE|EXCL ACK、读回和持久收据能授权精确恢复。没有收据时不得根据地址形状推断归属，也不得通过删接口间接删除未知地址。
- 不做 DHCP、路由写入、默认路由、DNS、TCP/UDP 应用套接字、BLE 广告、手机连接或文件传输。生产 `send.available` 保持 false。
- 创建前要求精确 owned origin、GO 类型、IFF_UP、carrier=1、fresh ifindex，随后再次读回完整 nl80211 origin。恢复不要求 carrier=1，避免把链路掉线变成无法清理的条件。

## 候选和入口

新入口为 `host/device_p2p_v6diag.py`；不修改 V1/V2/V3/V4/V5 入口、冻结候选、结果或模块全局。V6diag manifest 必须恰好七个 payload 加 `SOURCE.sha256`，无额外文件、重复路径、符号链接祖先或超限内容。

保持 V5 也完全不变；新 source SHA 必然产生新的 manifest/candidate目录，禁止在原目录替换源码或重写 SOURCE.sha256。当前 journal/pending/recover 只接受新 marker 与当前精确 executable。

仅 `PRIOR_JOURNALS` 可只读识别固定的已清 V5 candidate `0f2a45489fd3e03b`，完整 manifest SHA 为 `0f2a45489fd3e03b0b56b9bb083cf2d978f005d8260e9148339616d7856591b8`。registry固定旧七 pins及旧identity，先核验 canonical/private/no-symlink、完整manifest/七payload和精确旧 process.exe，再参数化历史 schema检查。未知 identity/candidate、缺候选证明、损坏或其他用户可写文件、活跃进程/接口、pending或旧原基线改变均阻断。旧V5验证不能授权 mutation、不能迁移 journal、不能接管旧recover。

schema3 自有 PID 消失不能只依靠 `_proc_identity(pid) is None`。必须两次 `lstat('/proc/<固定PID>')` 均得到 ENOENT，且中间身份读取为空；目录存在（包括不可读、非 dumpable 或 PID 复用）、权限错误和其他 I/O 错误均阻断。公开结果不输出 PID。

| 文件 | 来源 | 固定 SHA-256 |
| --- | --- | --- |
| mta_send_wifi.py | native/private-p2p-runtime-candidate-20261001-v6diag/runtime | 82bb5ba72c887608543d64018e2979cd27d6ee112036de9a701f0e5709de4faa |
| mta_ip_lease.py | runtime | 39373dba355557ee73cfac354bdbaa95eaf0ddde4e27313450edf0e74742f12c |
| mta_ip.py | runtime | 1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5 |
| mta_safety.py | runtime | 03f77794db1fa8bebf44f56a479d5feaa6aef0e0f490ad4e577ad5bb6b190a81 |
| p011_json.py | runtime | fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88 |
| mta-wpa-supplicant | native/private-p2p-candidate-20261001-v2 | e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301 |
| mta-wifi-caps | native/private-p2p-candidate-20261001-v2 | 9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6 |

`--freeze-only` 只读取主机源、校验 SHA、ARM ELF32 及 Python3.5 AST，生成新的独立本地快照，不构造 ADB。`--execute-reviewed` 必须显式提供 frozen 目录和完全一致的 16 位 candidate identity；无默认执行模式、无自动 recover。

## 真实验收硬门槛

1. ADB 通过已观察到的 P011 transport-id 唯一选择设备，不能默认选设备。完整固定原厂 SHA、PID/starttime/exe、页面/菜单安全基线先通过。
2. 历史 journal 和 pending 必须有界、私有、安全；未知版本/identity/归属阻断。已 reconciled 的 schema3 `ip=None` 只有 cleanup.ip_restored=true、ip_stage=none、自有进程/接口确实消失且完整原基线再次一致才可允许下一轮；这只证明当前可观察旧副作用已清理，不证明旧轮没有写入尝试，不会使当前 IP-only 验收通过。
3. 独立 preflight 要求原 STA 为 COMPLETED、可确定 2.4GHz 同频道、无 P2P/MTA 接口、无私有 WPA/试验 actor、无 pending。
4. 每次独立 IPv4 读取使用一个自有 NETLINK_ROUTE unicast socket、实际 bound port、六次递增 sequence、两个完整 GETADDR/GETROUTE(all tables)/GETRULE 视图。仅接受内核 sender `(0,0)`、非截断、无 ancillary、完整终止、默认三规则、永久无限寿命地址和两套全字段一致；随后关闭 socket。
5. IPv4 地址九字段、所有路由表十二字段、规则二字段全部纳入 pre/post 比较。保留 cacheinfo 四字段、默认 `/0`、非 main 表路由，不使用 `/proc/net/route` 的摘要替代全部 IPv4。三份 dump 并非原子快照；两个相等的视图只是有界一致性门槛。
6. 同时比较完整原 IPv6 addr/route 原始读回、原厂文件/进程、tracked PID/starttime/exe/args 摘要、STA 完整 status 摘要、频率、完整接口 origin、boot、pending。任何变化都不能 PASS。
7. 仅调度一次固定 TTL20 trial。超时、解析错误或试验失败后只做独立只读检查，不自动重试、recover、重启或全局清理。
8. 最终事件必须为 GO-IP ready → cleanup，native 固定数字诊断无错误，ip_stage=restored、ip_restored=true、ip_control_socket_closed=true、终端创建诊断 reason/gate 均为 not_recorded。constructor failure 可没有 socket-close 字段，但仍是 FAIL。
9. 独立 schema3 journal 必须匹配固定 identity/kind/marker、同 boot、完整原基线与实际接口/PID 归属。成功需要保留合法 fsynced restored 收据、reconciled、原基线全部相等、进程/接口确实消失、pending 清除。只读 journal 检查自身不创建锁、不写 pending、不调用 LinuxBackend 或恢复入口。

## HOST 证据与公开范围

所有 ready、constructor failed、final failed 和 final cleanup 顶层事件必须携带 `ip_creation_gate={reason,gate,observations}`，不能接受未知键或自由异常文本。

- reason 仅 `not_recorded/journal/process/interface_carrier/interface_identity/interface_l3/original_baseline/expiry/ip_transaction/unexpected_gate_read`。
- gate 是上述集合去掉 `unexpected_gate_read`。
- observations 只接受可选的严格 bool 六键：`flags_read_valid/flags_up/carrier_read_valid/carrier_is_up/sysfs_identity_match/go_identity_match`。无效/未读取 flags 时不得给出 flags_up；无效/未读取 carrier 时不得给出 carrier_is_up。整数 0/1 不是 bool。
- ready 必须是 `not_recorded/not_recorded/{}`。最早创建拒绝诊断只在进程内固定，cleanup 不覆盖它；journal、pending、nested cleanup_result 维持旧严格 schema，不添加诊断字段。

失败事件的 nested cleanup 只接受三个固定 schema（自有清理、未发生无线电变更、清理失败），分别输出 `failed_trial_cleanup_complete`、原资源恢复/读回和 socket关闭等 sanitized字段。终端失败仍是失败，不能借 cleanup.complete=true、ip_stage=none 或完整原基线恢复把 IP 功能判为 PASS。

最终 ip=None 不能倒推失败一定发生在首次 gate 前：restore可以在fresh IPv4等于基线时清除未授权intent。新具体原因与白名单bool只能反映当次门禁观察；不公开原始异常、IP、MAC、SSID、凭据或 arbitrary text。

主机命令：在 `working/MtaP011-v0.1` 运行 `python -m unittest tests.test_device_p2p_v6diag -v`。47 项测试通过，覆盖真实七源 pin/AST及新 runtime 诊断枚举一致；实际已冻结 V5 manifest/七 pins 只读核验；合成 freeze 防篡改；所有事件诊断严格白名单/布尔语义；schema3/收据 origin/header/fsync；历史只读 2addr/9route/3rules 离线解析；全 IPv4/non-main/policy/cacheinfo 改变阻断；None 旧失败 admission 与当前成功分开；旧不可读活跃 PID/权限错误阻断；FakeAdb 单次试验/失败清理独立字段/超时只读无 recover；明确 CLI 模式；公开 ZIP 不含私有探测数据。

所有 HOST fake/mock 只在临时目录运行。历史 fixture 的 reply port 只用于离线解析，不冒充未来 socket 的内核 sender 验证。未执行正式 freeze、ADB、RF、实际 IPv4 写入、DHCP 或手机互传。

实机结果目录单独保存原始 stdout/stderr、remote/host exit 与私有 probe；公开 ZIP 仅包含固定白名单 `result.json` 和 `README.txt`，不含私钥、PSK、SSID/MAC、地址/接口记录、journal、候选或 raw。

TTL 正常退出和 mock 不是实际父进程被终止后的 watchdog 恢复证据，也不能证明 SIPC 命令池/固件 credit 已恢复。即使 V6diag 全 PASS，仍需下一独立阶段 DHCP、绑定接口的传输及手机双向互传验收，不能据此开放完整发送能力。

## 主线程审查、冻结与首次入口记录

主线程完整审查新runtime差异、39项内存诊断、47项harness契约及历史schema3/七pins只读准入；052915集成606项（573通过、33跳过、0失败错误），旧HOST记录保持。正式冻结目录为 `logs/MtaP011-P2pV6DiagFreeze-20261001-052956-51ad245f/private-candidate`，七payload的大小/逐个SHA独立相符，manifest SHA-256为 `916a02d44aeeaf0dcb24a3eaa57b7762fad5f503e3dabac83bed34df10780daf`，candidate为916a02d44aeeaf0d。

053019-ffaa543c首次显式入口FAIL于prior_journals，6份历史记录中unsafe1/blocked0，pending clear；rf_trial_invoked=false，未进入RF、IP、DHCP或手机试验，也没有试验run目录。新隔离候选已下发，但原厂/旧候选未替换。随后只读观察Wi-Fi COMPLETED、无项目接口/WPA/actor/pending；由于prior阶段没有取得before网络快照，报告的独立比较false不能被解释为网络恢复失败或网络被改坏。当前新增固定原因只读检查，定位被swallow的validator exception；不删除旧journal、不迁移或接管recover、不自动重试或重启。这不是carrier拒绝或IP配置实测。

随后054328-59c5c157固定只读checker完成：三个host/remote exit均0；diagnostic_complete/check_complete PASS，6份记录中schema3第6份明确拒绝于prior_context / historical_manifest_permissions。prior_admission_clear仍false。这个固定原因涵盖普通文件、属主相等、非其他用户可写三项，尚未区分具体子项；不推断权限一定为0666或归因ADB，不删除记录或修改旧权限。该轮独立完整before/after原厂/STA/全IPv4地址、所有表路由/规则/全IPv6/原进程/接口/boot全部相等，无项目actor/接口/pending。只读采集PASS不是实际RF/IP或手机互传通过；下一步固定读取两个自有候选的权限元数据、全manifest与七pins，原harness和checker字节及各历史结果保留。

055734-dd922b01 固定候选权限checker（SHA ca2ab521dd6acc12a5f9e0ff30914917c36b2992b31393d09178768f60d1c1fa）由root完整审查后唯一只读执行。V5/V6各manifest+七payload，共16文件，实际属主匹配euid、regular/no-symlink、精确大小和完整SHA均通过；manifest与五个runtime文件均0666，两个native各0700。permissions_gate_satisfied=false，check_complete=true仅代表完成采集且完整原厂/双栈基线前后相同。未写权限、未RF/IP/恢复或重试。原始14条/后续固定退出与私有读回独立保留，不改历史结论。

接下来制作独立fixed16 fd权限规范：先完整验证pins/size/归属/nlink/安全目录与无项目actor，之后仅fchmod已打开的自有文件，manifest/runtime0400、native0500；不chown、不改内容或原厂。新试验入口不能调用旧run_reviewed的staging/native chmod0700分支，采用固定已存在候选只读验证与旧prior/preflight/TTL20/parse/JOURNAL门槛；不会放宽安全条件或把权限修正当作IP/手机通过。旧harness与frozen原字节保持不变，任何实际执行另存记录。

060853-204a0e0a后续单次权限规范已通过：root完整审查8155…工具/12项HOST及方案后实际执行，16fd预验证→16fchmod→16精确权限+身份+全SHA读回→16关闭0失败，完整原厂及双栈基线独立相同。此轮只改项目候选权限，不改内容/属主/journal，未RF/IP。新独立入口仍须审查，不能调用旧run_reviewed复写native0700或绕过prior/preflight。该权限PASS不覆盖053019FAIL或V5实际IP失败。

## 已有 V5 失败证据（不是 V6diag 实机结果）

## 后续独立入口实际结果（2026-10-01 06:17）

本追加晚于原作者的未执行说明，不覆盖原记录。主线程全文审查独立入口`host/device_p2p_v6diag_permissions.py`、15项HOST专项及固定源后，唯一执行`--execute-reviewed`。入口SHA为`3ca859043bfb5853a9a9778c45ba35d9635a41fdc74ad0206a0ad93067179311`；实际结果`logs/MtaP011-DeviceP2pV6DiagPermissions-20261001-061551-48fbed57/result.json`仍为FAIL。

两轮固定16文件门禁、完整旧引用pins、prior准入及pre-RF全部原基线等值通过。未stage/push/chmod/修改旧模块；只调用一次原TTL20，`rf_trial_invoked=true`、原生14事件均0、`early_init_success_reported=true`。`failure_phase=ip_create`、errno0、`reason=gate=interface_l3`，六项观察全部true，包括carrier_is_up；因此本轮不能归因于载波未就绪。`_only_link_local`地址条件与`_owned_routes_safe`路由条件尚未区分，下一步窄范围子诊断，不降低创建/收据/恢复门槛。

失败事件自有cleanup完整、IP控制socket已关闭、ip_stage=none。独立完整IPv4地址/所有表路由/规则、完整IPv6、原厂/STA/进程/接口/boot相等，无项目actor/接口/pending。journal严格归属、reconciled/ip=None；成功专用journal_complete/ip_receipt_restored等字段false是未取得安装收据，不能误读为独立恢复失败。本轮没有DHCP、应用TCP、BLE/UI、用户文件、手机互通、recover或retry；无需依据该结果重启或清理原网。

## 历史 V5 对照（原时点说明保持）

主线程此前完整审查、固定 V5 七个 payload 并独立核对 manifest，进行了一次 TTL20 试验，没有自动重试或 recover。V6diag 本阶段仍未进行真实执行。

V5 冻结 identity 为 0f2a45489fd3e03b，manifest SHA-256 为 0f2a45489fd3e03b0b56b9bb083cf2d978f005d8260e9148339616d7856591b8。结果为 `logs/MtaP011-DeviceP2pV5-20261001-044609-c53555d6/result.json`：FAIL，ip_create/lease_error/errno0，14 项原生初始化/退出事件均为 0，没有 private_go_ip_ready。门禁没有记录具体拒绝项；carrier=1 仅是下一步需要验证的假设，不是实测根因。

失败事件内 cleanup.complete=true、ip_restored=true、ip_stage=none，IP control socket 已关闭。独立检查确认完整 IPv4 地址、全部表路由和规则、完整 IPv6、原厂/STA/进程/接口/boot 全部相等；无项目 actor/接口/pending，journal 为 reconciled、ip=None。成功事件专用的公开 cleanup/receipt 字段为 false，仅说明当前 IP 成功验收没有满足，不可解读为独立恢复失败。此记录不能证明没有尝试内核写入，也没有证明地址安装成功。

新 V6diag 仅补固定枚举的拒绝诊断和脱敏只读布尔观察，不降低 creation/receipt/cleanup 门禁，不原样重跑，不接 DHCP、应用 socket 或手机。原 V5 失败记录、入口、源码及冻结文件保持不变；下一真实试验必须新 manifest、新目录、新 marker，并经主线程审查后一次显式执行。
