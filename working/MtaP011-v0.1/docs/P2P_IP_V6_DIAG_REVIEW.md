# P011 V6diag IP 门禁诊断审查

状态：PC HOST_ONLY；未正式 freeze；未 ADB/RF/Docker 操作；未解锁实际 IP/发送能力。

## 基线与新身份

- 唯一 V5 实机结果仍为 FAIL：`logs/MtaP011-DeviceP2pV5-20261001-044609-c53555d6/result.json`。
- 该轮独立原厂/STA/IPv4全表/IPv6恢复成立，但 errno0/lease_error 的具体 creation gate 未知；不能把 carrier 当根因。
- 新源：`native/private-p2p-runtime-candidate-20261001-v6diag/runtime/mta_send_wifi.py`。
- V5源固定 SHA `96f808a9ef7cbaf011bb3254a23c01cbda6d7e09e016ad948c5dba89b671bd87`，不改旧候选/历史日志。
- V6diag源 SHA `82bb5ba72c887608543d64018e2979cd27d6ee112036de9a701f0e5709de4faa`，78359B。
- 新 runtime_marker `p011-go-ip-only-v6diag-1`；journal version3/kind=go_ip_only不变，六字段identity仅marker替换。
- shared helper `39373dba355557ee73cfac354bdbaa95eaf0ddde4e27313450edf0e74742f12c`、codec `1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5`、WPA pin均不变。
- marker不是代码归属的全部证据；外层immutable manifest仍必要。旧V5 journal不能被新recover接管；已清历史只能独立known-prior只读验证。
- 完整统一差异见 `docs/V5_TO_V6DIAG.diff`，不是节选。

## 诊断合同

- public ready、constructor failed、最终 failed/cleanup新增必带 `ip_creation_gate`，exact keys：reason/gate/observations。
- reason固定集合：not_recorded/journal/process/interface_carrier/interface_identity/interface_l3/original_baseline/expiry/ip_transaction/unexpected_gate_read。
- gate固定集合等于reason集合去unexpected_gate_read；它定位发生异常的尝试阶段，不包含异常文本。
- observations仅optional bool：flags_read_valid/flags_up/carrier_read_valid/carrier_is_up/sysfs_identity_match/go_identity_match。
- 未访问项缺失；flags格式无效不提供flags_up，carrier不属于0/1不提供carrier_is_up；不能以默认false冒充已观察。
- sysfs读取仍只原V5三次 flags/carrier/ifindex，随后原完整nl80211四元重验；诊断不授权。
- 原guard/GO/stock/IPv6门禁和原flagsUP+carrier1+index规则完全保留。未知异常固定unexpected_gate_read，绝不打印args/strerror/地址/MAC/SSID/PID。
- 最早creation拒绝在当时复制；cleanup/后续TTL不得覆盖。诊断不进入journal/receipt，不改变恢复权限。
- DiagnosticOwnedIpLease仅扩展原creation `clock>=deadline or fresh_gate is not True` 的短路表达式；同一次clock读、同一顺序。restore直接调用原super。
- 原transaction.create/receipt/readback/DELADDR代码来自未改helper；save包装只记录异常后原样raise。
- GoLease与LinuxBackend的restore门禁保留原函数；HOST AST比较原restore/cleanup/recover主体一致。
- helper transaction其他不够细的失败保持ip_transaction，不从自由文本推断carrier；这是明确的诊断边界。

## HOST证据与风险

- 实际命令：`python -m unittest discover -s native/tests -p test_send_wifi_v6diag.py -q`。
- 最终PC HOST39项PASS，0fail/0error/0skip，工具chunk55379f、exit0、0.075s；Python3.5 AST PASS。
- test SHA `df6bf6b5b23979da38f99f45b392e802204c64b5d5161da93645dcf148d96b6c`。
- fixture是FakeKernel/FakeLock/内存journal/假sysfs；本轮不声称real fsync/flock/forkwatchdog或P011执行。旧Linux48证据只属于V5。
- 覆盖首次拒绝（无intent）和intent后拒绝（仍无NEWADDR/DELADDR）、process复用、原网指纹/全IP基线变化、journal异常、晚expiry、carrier0/未知/flags非法、sysfsindex/四元重用、L3拒绝及清理不覆盖。
- 已有memory create+restore用例只证明代码合同；真实路由flags/carrier、收据恢复及PHONE均未验。
- `ip_stage:none` 也可能由restore清除未确认intent产生，不能据此证明从未写入；任何实际无写入结论必须来自本次现场诊断/独立证据。
- 合法但未支持的routeflags、CREATE ACK/receipt窗口风险仍存在；本候选不扩大支持范围、不放宽所有权。
- root审查新diff/源码/harness之后才能正式freeze及决定是否执行有限试验；不得自动重试、自动recover或开启发送/DHCP/TCP/BLE。
