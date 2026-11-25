# P011 owned P2P GO V2：独立冻结与有限试验门槛

此文配套新增 `host/device_p2p_v2.py` 与 `tests/test_device_p2p_v2.py`。本子任务只做 HOST 检查 / freeze-only，不执行 ADB、RF、恢复或重启。旧 `device_p2p.py`、`d7abc84e38e44a51` 候选、首轮 FAIL 及后续 owned 恢复记录全部保留，不改变历史判定。

## 已冻结的五文件身份

冻结目录：`D:/project/P011/logs/MtaP011-P2pV2Freeze-20261001-014415-4c7a06bc/private-candidate`。

候选身份：**f100d4ea35acf9af**。`SOURCE.sha256` 完整 SHA-256：`f100d4ea35acf9af0e46c59c537ed1148462cbae6daf5bf59860b19a81777f37`。

manifest 精确列出以下五个 payload；目录另有 manifest 本身，没有其它文件：

| 文件 | 字节数 | SHA-256 |
| --- | ---: | --- |
| `native/mta-wifi-caps` | 21460 | `9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6` |
| `native/mta-wpa-supplicant` | 1351192 | `e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301` |
| `runtime/mta_safety.py` | 4720 | `03f77794db1fa8bebf44f56a479d5feaa6aef0e0f490ad4e577ad5bb6b190a81` |
| `runtime/mta_send_wifi.py` | 50500 | `e7222f0ed14589789faf0fc7d6857269a664264ade9ccf0b46d2c991e9b8b3c6` |
| `runtime/p011_json.py` | 8061 | `fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88` |

运行时 `WPA_SHA256` 与新 binary pin 相符，固定 device lock/pending 路径相符；main / native V2 的 runtime 副本在冻结前字节一致。每个输入读两次，拒绝变化 / 非 regular / symlink / 超限；verify 检查源 3.5 语法、稳定 runtime 全 SHA、精确集合 / 长度 / SHA 和无多余文件。旧 V1 冻结副本不能通过 V2 verify，不会静默套用新二进制。

WPA 修改、许可证 / source transform 与 41 项 Linux HOST 证据由 native owner 另存：`native/P2P_V2_REVIEW_NOTES.md`、`native/tests/HOST_P2P_V2_EVIDENCE.md`。该 HOST 证据不是 P011 运行结果。V2 的 FD3 最终半行由 runtime 标 `diagnostic_invalid`，本 harness 对该标志实行硬失败。

## CLI：先 freeze、review，才可由 root 执行

仅 HOST 新建冻结：

```powershell
python -B host/device_p2p_v2.py --freeze-only
```

root 完整审核**新 harness 和上述 frozen 三份 runtime / 两份 binary 对应资料**后，才可明确执行这份候选：

```powershell
python -B host/device_p2p_v2.py --execute-reviewed --frozen "D:/project/P011/logs/MtaP011-P2pV2Freeze-20261001-014415-4c7a06bc/private-candidate" --expected-candidate f100d4ea35acf9af
```

默认 / import 不启动任何操作。`--execute-reviewed` 使用 `device_probe.Adb` 的 observed P011 `select_target()`，不使用隐式默认设备。新会话固定在 `sessions/mta-p2p-v2-日期-时间-8hex`；候选固定在 `candidates/mta-01-16hex`。既有候选只核验不覆盖，不接受任意 remote 目录 / shell 命令。TTL 20 秒，ADB host timeout 55 秒，保持 no DHCP/IP setup / BLE/UI/files。

## RF 之前的硬门槛

1. 五文件 frozen 身份、稳定 runtime 全 SHA / binary pins / Python3.5 源语法通过；远端 manifest 完整 SHA 相同。原厂最新 v2.4.0 hash / Z03-control_engine-weston 身份、PID/starttime/父进程及临时菜单检查通过。
2. root / armv7l / Python3.5.5；只读 `wpa_cli -i wlan0 status` 为 COMPLETED、已有 2.4GHz 同信道；完整私有 stdout 指纹保留，不自动开 Wi-Fi / 切网。
3. 独立 GET_INTERFACE 清单中 `wlan0` 为唯一指定 station；无 P2P type8/9/10，**也无名称 `mta`+8hex 的项目接口，即使已转 type2 STA**。无本项目 candidate 的 private WPA、trial/recover 或 inherited watchdog actor。
4. `sessions/mta-p2p-*` 和 `mta-p2p-v2-*` 的既有 journal 有限只读扫描：允许真正 reconciled/complete 的 V1，V2 还须保存完整接口及 IPv6 baseline；文件 / 文件夹 private owner/mode，记录进程确已不存在。异常、未完成、有文件却无 journal 均拒绝。真实接口/actor检查独立进行，不用历史 complete 代替当前无残留。
5. 固定 `/tmp/p011-mta-p2p-device.pending` 必须不存在；存在时只读保留 / 校验，不清除、不绕开。lock 文件若已存在须安全 owner/mode；探针**不创建、不 flock、不 acquire**任何 device lock，不实例化 LinuxBackend/DeviceGuard/JournalLock。真正试验里的 device lock/pending 由已冻结 runtime 管理。
6. 以上门槛通过后才建立新的 0700 owned run，调用精确 frozen `mta_send_wifi.py --trial --ttl 20`。不会将 GO-only 转成正式发送 ready 或延长租约。

`rf_trial_invoked` 是主机提交有限 trial 命令的事实；超时 / ADB 中断时不能据此认定 RF 变更已经或没有执行。完整 PASS 另要求真实 ready/diagnostics、远端 exit、journal 与全部独立读回。

## 最终 PASS：诊断、恢复和独立证据全部需要

- 唯一 remote exit=0、一次 TTL20 ready、一次 complete cleanup，没有 trial_failed；ready 不允许额外字段，cleanup 只允许固定布尔字段。
- 最后 diagnostics envelope 精确为 events / diagnostic_invalid / raw_diagnostics_not_logged；最多 64 条。stage 仅16个固定枚举，code 仅整型 ±4095，拒绝 bool / 自由字符串 / 额外字段。`diagnostic_invalid=false`；init_enter、**early_param**、initial_type_gate、initial_mode、interface_up、driver_finish、driver_init_result、p2p_init 均有 code=0，且这些 stages 没有非0值。
- 新独立进程重读原厂 hash/PID/starttime/parent、wlan0 stdout 指纹、tracked process（含完整 cmdline digest）、boot、完整 GET_INTERFACE 清单及 IPv4 route digest，前后完全相同。
- **完整 `/proc/net/if_inet6` 与 `/proc/net/ipv6_route` 原始数据**只保存在 private raw，前后原始字节与 digest 均相同；不是只检查原 wlan0 或只过滤掉残留 owned 路由。
- 无任何项目 mta 接口（含变 STA）、private WPA、trial/watchdog actor；固定 global pending **新独立读取确实已清除**。
- owned journal 精确 version2、同 boot / owner / private schema，保存接口及 IPv4/IPv6 baseline。reconciled/complete 不够：实际 owned PID / WDEV 与名称均已不存在，并由又一独立进程比对 journal 保存的接口、tracked process/cmdline、IPv4/IPv6 digest 与当前原始状态相同。marker 消失也不能代替这些读回。

GO PASS 仍不等于 IP/DHCP、手机互传、发送 service 或 PHONE 物理验收；不能将 send availability=true，也不能改旧 FAIL 为 PASS。

## 失败、超时和公共包

不自动 retry、建第二 run、recover、重启、link down/flush、全局 kill/remove 或原厂服务变更。失败 / 解析异常 / host timeout 后仅独立读取状态及 exact owned journal/global pending；owned identity 尚可审查时只输出固定 `REVIEW_OWNED_V2_JOURNAL_FOR_EXPLICIT_RECOVERY`。精确 recover 建议命令只留 `private-next-steps.txt`，必须 root 再审，脚本从不执行。

raw stdout/stderr/host exit 与 timeout partial 由 Adb 私有保存；CRCRLF/CRLF 仅派生解析归一化，不覆盖原始证据。自由 `reason` / nested cleanup raw 从不进入公共 report；异常不打印任意 error text。`.sanitized.zip` 精确白名单仅 `result.json`、`README.txt`，不包含 raw、IPv6原始数据、SSID/MAC/IP/PSK、路径、journal、建议命令、候选源码 / binary。

## 本次 HOST 验证

```powershell
python -B -m unittest discover -s tests -p test_device_p2p_v2.py -v
```

**17/17 HOST PASS、0 SKIP；新 host/test 及所有 remote source 的 Python3.5 AST PASS；HOST_ONLY_V2_FREEZE_PASS。**

tests 使用明确 FakeAdb，验证顺序/门槛/状态与 ZIP 白名单，不执行 subprocess/ADB/RF。覆盖旧 V1 拒绝、demoted项目STA和残留actor拦截、pending/journal硬阻断、超时只有一次试验提交与只读检查、IPv6及进程/接口变化拒绝、journal独立基线拒绝、诊断白名单/early缺失/invalid拒绝、重复JSON字段/exit与非UTF8拒绝、原始错误不入公共包。mock 的 pass=true 仅是 harness 合同分支，不是设备或新版本 tested release。

截至本文件提交：**本子任务 P011/RF NOT_RUN**；root 后续真实执行须另建新报告，不覆写本 HOST 结论或历史 FAIL。
