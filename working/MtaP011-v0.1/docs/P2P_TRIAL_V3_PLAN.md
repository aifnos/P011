# P011 P2P GO V3：诊断专版冻结与试验边界

新增 `host/device_p2p_v3.py`、`tests/test_device_p2p_v3.py`。本子任务完成 **HOST 检查及 freeze-only**，没有 ADB、RF、恢复、IP、DHCP、UI 或用户文件操作。主任务审核后才可执行一次独立有限试验。

V1/V2 的原脚本、冻结内容、真实 FAIL 与独立恢复记录不变。V3 不能让旧 FAIL 变 PASS，也不能证明发送已可用。V2 真实失败报告和定位窗口见 `native/P2P_V2_TRIAL_FAILURE_REVIEW.md`；V3 只补固定 phase / errno / netlink command，不换 binary、不改无线/恢复策略。

## 冻结身份

候选：**eaf5b85a187eb73f**。

完整 manifest SHA-256：`eaf5b85a187eb73fa457afdb1644b696c361492b472a9fd5340d4486fc455c8e`。

冻结目录：`D:/project/P011/logs/MtaP011-P2pV3Freeze-20261001-021806-f4c9926c/private-candidate`。

manifest 精确五 payload，目录另有 manifest 本身，禁止多余文件：

| 文件 | 字节数 | SHA-256 |
| --- | ---: | --- |
| `native/mta-wifi-caps` | 21460 | `9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6` |
| `native/mta-wpa-supplicant` | 1351192 | `e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301` |
| `runtime/mta_safety.py` | 4720 | `03f77794db1fa8bebf44f56a479d5feaa6aef0e0f490ad4e577ad5bb6b190a81` |
| `runtime/mta_send_wifi.py` | 55336 | `eacc3a3a602f2ce047106920adaaa6c45a647e1de13a9ba4e90b5858303aff12` |
| `runtime/p011_json.py` | 8061 | `fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88` |

`mta_send_wifi.py` 只来自独立 `native/private-p2p-runtime-candidate-20261001-v3/runtime/`；主 runtime 与 V2 保留 `e7222f…`，没有 V3 主生产副本。native 两文件复用 V2 审核 pins，另两份 Python 从当前主 runtime 冻结。

本 harness 独立 `_source_checks/freeze/verify_frozen/parse_trial/run_reviewed`，不覆盖 V2 globals，不调用 V2 freeze/run，不靠重新分配模块常量绕旧校验。仅复用无副作用 read-only source 字符串、目录检测及 pure independent gates。旧 V2 无法通过 V3 verify，新 V3 也不能通过 V2 verify。

输入有两次稳定读取、regular/symlink/大小检查；verify 精确长度/SHA/集合、runtime 全 SHA、Python3.5 AST、WPA 和固定 lock/pending pins、failure enum AST 常量。root 审查稳定 V3 runtime 的 native 57 项 Linux HOST 证据是另一层证据，不等于 P011/RF。

## 操作入口

仅 HOST 新建另一份 immutable freeze（不 ADB/RF）：

```powershell
python -B host/device_p2p_v3.py --freeze-only
```

主任务完整审核本 harness/tests/docs 以及上述冻结 payload 后，使用这一个已冻结身份：

```powershell
python -B host/device_p2p_v3.py --execute-reviewed --frozen "D:/project/P011/logs/MtaP011-P2pV3Freeze-20261001-021806-f4c9926c/private-candidate" --expected-candidate eaf5b85a187eb73f
```

没有默认动作。执行只使用 `device_probe.Adb` 的 observed P011 `select_target()`，不使用 default ADB；远端固定 `candidates/mta-01-16hex`，已存在候选只核验不覆盖。run 仍是 `sessions/mta-p2p-v2-日期-时间-8hex`，journal 仍 version2；与 V2 生命周期/恢复格式一致而非另开无门禁 namespace。

仅一次 `--trial --ttl 20`，host timeout55 秒。不加 TTL、不自动 retry/recover、不重启、不 link down/flush、不启动全局服务，不操作原厂无线控制或用户文件。

## 前置和独立恢复门槛

V2 全部固定门槛保留：

1. 最新 stock hashes 与原厂 PID/starttime/父进程，以及远端 manifest 和 V3 runtime pins 匹配；root / armv7l / Python3.5.5。
2. `wlan0` 当前 COMPLETED、2.4GHz；完整 stdout 私有指纹、GET_INTERFACE 身份、tracked processes/full cmdline digest、boot、IPv4 routes 与完整 IPv6 地址/路由均只读捕获。
3. 无 P2P type8/9/10，**无任何项目 `mta`+8hex 接口，包括已变 STA type2**；无 project trial/watchdog/private WPA actor。
4. 有限旧 journal 扫描，仅容真正 reconciled/complete 的 V1 和有完整接口/IPv6 baseline 的 V2；unsafe/private-owner/模式错误、未完成、有文件无 journal、进程仍在则拦截。
5. 固定 global pending 不存在；lock 若已存在必须安全。探针不实例化 DeviceGuard/JournalLock/LinuxBackend，不 O_CREAT、不 flock、不 acquire。过关后才建 0700 新 run、提交唯一有限 trial。
6. 退出后两个独立只读进程分别重读实际状态及 exact owned journal/pending。PASS 必須真实 owned PID/interface 消失、journal version2 同 boot/合法归属、reconciled/complete、saved baseline 与新读回完全相同、global pending 真实消失、所有 stock/网络进程/接口/IPv4/完整 IPv6 bytes+digest 前后一致。

`rf_trial_invoked` 仅表示主机尝试提交有限命令，不能在超时下断言实际 RF 已变或未变；仍必须上述新独立读回。

## V3 公共诊断白名单

成功 trace 为一次 ready → 一次 cleanup；失败 trace 为直接 failure 或 ready → failure。乱序、重复 terminal、同时 cleanup+failure、无 terminal 均拒绝。

Native FD3 diagnostics 保留 stage1–16固定枚举，code 是 ±4095 的整型（bool 不接受），最多64条，无 raw/额外字段。`diagnostic_invalid` 必须 false，且 init_enter / early_param / initial_type_gate / initial_mode / interface_up / driver_finish / driver_init_result / p2p_init 必須 code0且无非0实例。最终半帧 invalid 仍硬失败。

失败事件额外且精确三字段：

- `failure_phase`：仅源码固定31种阶段。包括 backend_construct、baseline_snapshot、watchdog_start、interface_create、interface_journal 等，不接受自由文本。
- `failure_errno`：int0..4095，拒绝 bool、负值、字符串、越界；**0 是未记录/未知，不猜测**，不是 errno 成功，也不能据此证明驱动不支持。
- `netlink_command`：仅 not_recorded / family_resolve / get_interface / new_interface / del_interface。

`reason` 仅 lease_error / os_error / unexpected_error；异常 args/strerror/filename 不输出。constructor 失败也只固定安全 event，不能冒充 GO ready。首次失败诊断在 cleanup 前捕获，不能用后续清理 errno 覆盖原因。

公共结果只复制这些固定枚举与数值、allowlisted native stages、固定 gate 布尔；nested cleanup/raw 从不传播。真实 failed 即使 exit0、全部 baseline 恢复也仍 FAIL；恢复成功只证明退出安全。

## 失败处理与包

解析失败/超时/RF失败后只新读 actual state / owned journal / pending。不建第二 run、不从名称推归属、不清 pending、不执行 recover。仅 exact journal 尚可审查时生成 `private-next-steps.txt` 的固定恢复建议，由 root 另审。建议路径/命令与 raw stdout/stderr/exit/IPv6/SSID/MAC/IP/PSK 不进公共包。

设备执行结果目录 `MtaP011-DeviceP2pV3-*`，`.sanitized.zip` 精确仅 `result.json`、`README.txt`。原始 CRCRLF/ANSI 保留 private，换行仅在 derived parser 归一化。不打包源码/binary/journal/raw/凭据。

## 本轮 HOST 结果

```powershell
python -B -m unittest discover -s tests -p test_device_p2p_v3.py -v
```

**22/22 HOST PASS，0 SKIP**；V3 harness/test/runtime 和三种 remote readonly source Python3.5 AST PASS；`HOST_ONLY_V3_FREEZE_PASS`。

覆盖稳定源/pins/enums、真 HOST五文件freeze、两版本拒绝混用、source变更拒绝、constructor unknown、首次 fixed failure字段/保密、旧V2failure拒绝、enum/errno越界、terminal顺序、early/invalid/非0、重复JSON/exit/无效UTF8/输出上限、项目STA/actor/旧pending拦截、唯一timeout提交且不recover、stock/进程/接口/boot/IPv4/完整IPv6变化、saved journal/pending独立核验、公共ZIP白名单，以及 GO-only/TTL20/journalv2namespace。

mock pass=true 只代表 harness 分支合同，非实机可用。**本子任务 P011/RF NOT_RUN、PHONE NOT_TESTED、send availability仍false。** root 后续实机必须另写新记录，不能修改本 HOST 结论或 V1/V2历史FAIL。
