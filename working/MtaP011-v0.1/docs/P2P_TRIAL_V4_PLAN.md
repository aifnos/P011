# P011 P2P V4：仅修复私有 WPA 配置兼容

本子任务新增独立 V4 runtime / harness / 两组 HOST tests，**没有 ADB、RF、重启或最终设备试验，也没有生成真实 V4 frozen candidate / manifest 身份**。V1/V2/V3、主 runtime、native binary 与既有 PASS/FAIL 原样保留。

## 唯一变量与原因为何成立

V4 runtime 从稳定 V3 字节复制，仅删除生成 `private.conf` 字符串中的 `\nupdate_config=0`，精确删除17字节。没有其它内容变更，连源里旧 V3 诊断说明都保留，避免把注释更改混进单变量试验。

- V3 SHA-256：`eacc3a3a602f2ce047106920adaaa6c45a647e1de13a9ba4e90b5858303aff12`，55336字节。
- V4 路径：`native/private-p2p-runtime-candidate-20261001-v4/runtime/mta_send_wifi.py`。
- V4 SHA-256：`ef2f087444c149a988b5b3895225960e85c03d702aa5a084cef62e6222ccf334`，55319字节。

HOST 逐字节断言：`v4 == v3.replace(b'\\nupdate_config=0', b'')`，匹配 anchor 在 V3 中精确一次。没有 child 诊断、exec/fork、身份校验、FD3、P2P控制、TTL、watchdog、journal、恢复、IP或DHCP的新增行为。

固定 WPA 构建 `source/p2p-private-v2.config:12` 启用了 `CONFIG_NO_CONFIG_WRITE=y`。固定官方2.12 `Makefile:232–233` 定义该宏，`config.c:5844–5846` 在该宏启用时不注册 `update_config` global字段。原配置因未知字段在 `config_file.c` errors→NULL，在 `wpa_supplicant_init_iface` driver init之前返回，因此可以有已保存进程而无 `init_enter`。

移除这一行不放宽“不可写配置”：这是 binary 本来就不支持写配置的构建，不应再给它一个已从解析表删掉的指令。其余六项保留：`ctrl_interface`、`p2p_no_group_iface=1`、`ap_scan=2`、`device_name=P011`、`device_type=1-0050F204-1`、`driver_param=mta_p2p_initial=1 control_port=0`。CTRL_IFACE/P2P/WPS/file backend 均开启，字段和格式已检查。

## 已有独立 P011 parse-only 证据

主任务另执行并记录：`D:/project/P011/logs/MtaP011-WpaConfigNoRf-20261001-025636-5a66dea7/result.json`，level **P011_WPA_CONFIG_PARSE_ONLY**、PASS。

- 同一个 native WPA e069…：`-v` exit0且版本首行匹配。
- 原配置 exit255；**仅删除 `update_config=0` 后 exit0**。
- 不提供 `-i/-D/-C/-g/-u/-p/-B`，不提供 MTA opt-in 环境；调用的是上游无interface parse分支。
- 无无线动作、网络配置或用户文件；stock/Wi-Fi/进程/actors/接口/IPv4/IPv6/boot 独立基线前后不变。
- `go_formation=NOT_TESTED`，`phone_interop=NOT_TESTED`。

这证明配置解析兼容，不证明 V4 GO 建组、暖态 EIO修复或手机互传。冷V3 private_spawn与暖V3 interface_create EIO两条历史失败继续保留；基线恢复不代表固件/SIPC命令池健康。

## V4 独立 harness

`host/device_p2p_v4.py` 独立 source pin/directory、freeze/verify/parser/run 常量链，不 monkeypatch 旧模块、不变更 V2/V3 globals、不调用其 freeze/run。只复用 V2无副作用 read-only source 字符串和 pure gates。

native binary不变：

| 来源 | SHA-256 | 字节数 |
| --- | --- | ---: |
| `native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant` | `e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301` | 1351192 |
| 同目录 `mta-wifi-caps` | `9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6` | 21460 |

未来冻结仍精确五payload：三份runtime（独立V4 `mta_send_wifi.py`，主 `p011_json.py/mta_safety.py`）＋两份native，另有 manifest本身。regular/no-symlink/稳定两读/byte-limit/ARM ELF32/pins/3.5 AST/精确manifest集合与SHA、V4完整源码pin、固定lock/pending与failure枚举全部需要。旧真实V2/V3冻结副本被V4 verifier拒绝；没有在本子任务把真实binary复制为 frozen产物。

V3固定 failure_phase / failure_errno0..4095 / netlink_command白名单和reason三枚举原样保留；native FD3阶段1–16/code±4095/64事件/invalid-tail/early-init0门槛原样。成功ready→cleanup，失败单terminal，有序且不重复；自由raw/path/exception不能传播到公共包。失败即使恢复与exit0也不能PASS。

## 必须保留的设备安全门槛

1. 精确 observed P011 的 `Adb.select_target()`；root/ARMv7/Python3.5.5，原厂最新版hash与PID/starttime/parent有效，候选远端manifest/fullpins相同。
2. 原 wlan0 COMPLETED与2.4GHz；原stock/Wi-Fi完整指纹、trackedprocess/cmdline/boot、所有interface、IPv4routes、完整IPv6addresses/routes捕获。
3. 无P2Ptype8/9/10，**无任何mta+8hex项目netdev，即使已转STA**；无项目privateWPA、trial或watchdog actors。
4. 固定device pending实际不存在，已存lock须安全；旧journal有限只读审查，未完成/unsafe/有文件无journal/PID存活均拦截。probe不创建flock/pending，不实例化写backend。
5. 通过后才建新的0700run；journal仍version2，remote session仍 `sessions/mta-p2p-v2-日期-时间-8hex`，immutable候选仍 `candidates/mta-01-16hex`，已有candidate只核验不覆盖。
6. 仅一次 TTL20，host55秒deadline。无IP/DHCP/BLE/UI/files；失败只读新状态和ownedjournal，**无自动retry/recover/重启/全局服务或接口清理**。
7. 最终PASS须真实GOready/nativeearly成功、唯一remoteexit0、completecleanup、新独立ownedPID/interface/pending确已消失、journalversion2及sameboot原完整savedbaseline独立匹配，并且stock/网络进程/原Wi-Fi/接口/IPv4/完整IPv6前后完全不变。

`rf_trial_invoked`只表示主机尝试提交命令，超时不能据此判断实际无线是否变更。所有raw/IPv6/SSID/MAC/IP/PSK/路径/建议命令私有；公共 `.sanitized.zip` 严格仅 `result.json` 与 `README.txt`，日志目录前缀 `MtaP011-DeviceP2pV4-*`。

## 后续入口：本子任务不执行

root 完整 review 本5个新文件、固定native以及parse-only证据后，才能决定是否冻结：

```powershell
python -B host/device_p2p_v4.py --freeze-only
```

该命令只HOST冻结；必须先读取真实输出manifest/fullSHA/identity，不沿用eaf5 V3或自行假定V4identity。再审核freeze，root才可自行选择一次有限设备试验：

```powershell
python -B host/device_p2p_v4.py --execute-reviewed --frozen "<root实际冻结目录>" --expected-candidate <root实际16hex身份>
```

本子任务没有执行上述命令。无默认启动、无需也不自动修改发送可用状态。

## HOST结果

```powershell
python -B -m unittest discover -s tests -p test_device_p2p_v4.py -v
python -B -m unittest discover -s native/tests -p test_send_wifi_v4.py -v
```

**24/24 harness HOST PASS、7/7 native配置 PC HOST PASS，0 SKIP。** 新harness/test/native-test/runtime全部Python3.5 AST PASS；三份远端readonly source AST同样PASS。

native测试调用真实配置writer，到mock fork之前停止；Windows的fork是显式create mock，无真实fork/exec/native进程。验证整份runtime唯一17字节删除、生成配置其它六行原样、非法wlan0名字无写入、固定tar解析表与编译宏、诊断/未知errno/锁/pending/nativepin保持、send仍availablefalse。harness的freeze测试**仅假ELF/假Python输入**在临时目录，verify后销毁，不是新的真实candidate。

失败过的测试迭代已修正并重跑，以上是最终结果；不声称Linux fork/nativebinary/RF执行。P011parse-only层来自主任务独立证据，**V4 P011_GO NOT_RUN、PHONE NOT_TESTED，正式send仍false**。

## root 后续独立执行补记

2026-10-01 03:07，root 完整审查上述源码/单变量diff、最终307项HOST回归与真实冻结manifest后，执行一次TTL20 GO-only：`logs/MtaP011-DeviceP2pV4-20261001-030738-1772afe3/result.json` **PASS**。真实冻结身份 `43a77d612f32fba5`，manifest SHA `43a77d612f32fba5ecbcddfe03be5e9aca2a81f1981e2790a099f8cca5e82ae5`。14个数值初始化/退出事件全0、GOready/cleanup、独立原厂/Wi-Fi/进程/接口/IPv4/完整IPv6/boot/pending/journal门槛全部通过。

这是单独设备记录，不改写上述子任务HOST执行范围或V1/V2/V3旧FAIL。没有IP/DHCP、BLE、UI、用户文件、手机互通或额外重启；生产send仍false。后续需owned IP/DHCP和真正双向数据链，不能从GO-only PASS宣称目标完成。
