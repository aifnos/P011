# P011 owned P2P GO 有限试验计划

本脚本由主线程 **review 后运行**。本子任务只新增 `host/device_p2p.py` / 本文，没有修改 runtime 或 helpers，没有执行 ADB、RF、重启或系统服务操作。

## 已完成的 HOST 检查

- 固定两份本地 ARM ELF32 小端候选 hash，读取两次验证稳定：
  - `mta-wpa-supplicant`：`010f119b3cb9a8d7720e1ee57d83a92158628a68520d2010adde7bbe4b64518f`，与 runtime `WPA_SHA256` 一致。
  - `mta-wifi-caps`：`9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6`。
- 冻结当前 root 版 `mta_safety.py`、`mta_send_wifi.py`、`p011_json.py` 及两份 native binary，**精确五文件** manifest，不含用户文件或凭据。校验 file count、manifest 长度、每个 size / SHA、原始文件 / 无 symlink、无未列文件；runtime 与每段设备 probe / journal source 均使用 Python **3.5 AST** 完整语法校验。
- HOST six checks PASS：mock 流程/门槛顺序；既有未完成 journal 禁止新 run / RF；超时只读 journal、不重试不恢复、私有 advisory 不入 ZIP；独立路由变化阻止 PASS；异常事件 / 重复 remote exit 拒绝；review 身份不匹配拒绝。mock 仅验证 harness，**没有 P011 / RF 证据**。

当前冻结身份：**d7abc84e38e44a51**。

冻结目录：

`D:/project/P011/logs/MtaP011-P2pFreeze-20260930-204808-5a08fe44/private-candidate`

后续工作区源码更改不影响这份 frozen snapshot。不要在原目录改文件；确需改候选，应重新 `--freeze-only` 并重新 review 新身份。

## CLI

重新 HOST-only 冻结（不调用 ADB）：

```powershell
python -B host/device_p2p.py --freeze-only
```

主线程审核**上述五文件的冻结副本及脚本**后，执行固定这份候选：

```powershell
python -B host/device_p2p.py --execute-reviewed --frozen "D:/project/P011/logs/MtaP011-P2pFreeze-20260930-204808-5a08fe44/private-candidate" --expected-candidate d7abc84e38e44a51
```

仅显式 `--execute-reviewed` 会触发无线试验。入口不自动运行，不支持任意设备、任意 remote 目录、任意命令或自动 recover。目标由 `device_probe.Adb` 的 observed P011 `select_target()` 唯一选择，绝不使用隐式默认设备。

## 试验前门槛

1. 冻结 manifest / 原始 native pins / Python3.5 语法全部通过；上传到新 immutable `mta-01-16hex` candidate。既有候选只校验，不覆盖；manifest **完整 SHA** 与冻结副本一致。
2. 原厂 `/usr/bin/Z03`、`control_engine`、launch 脚本匹配最新 v2.4.0 pins；Z03/control_engine/weston 数量、exe / PID / starttime / parent 身份符合安全 gate，没有旧临时菜单。
3. 设备为 root / armv7l / Python3.5.5；只读 `wpa_cli -i wlan0 status` 成功，必须 **COMPLETED** 且已有 2.4GHz 同信道频率。不自动开 Wi-Fi、联网或切换现有 station。
4. 新独立过程通过 GET_INTERFACE 读取真实 phy / wdev / ifindex / iftype 清单：`wlan0` 必须是唯一 station；不能存在 P2P client / GO / device 或本项目 private WPA 残留进程。
5. 同脚本 namespace `sessions/mta-p2p-*` 既有 journal 均已 reconciled / complete，无 still-alive 记录进程。未完成、目录异常、无 journal 却存在残留文件均拒绝新 run。该扫描有限额，不是对任意第三方目录的全盘 journal 搜索；额外的外部 P2P 由真实接口检查拒绝。
6. 所有 gate 通过后才建立新的 owned **0700** run directory，并调用：

```text
python3 -B <frozen runtime>/mta_send_wifi.py --trial --run-dir <new owned run> --binary <pinned private WPA> --caps-probe <pinned read-only caps> --ttl 20
```

试验仅创建 owned GO / 私有 supplicant；无 DHCP/IP 配置、BLE、UI 或文件传输。现有 lease 的独立 watchdog / durable identity 逻辑不由 harness 替换，仍受已有 TTL20 与所有权 gate 约束。

## 成功所需的独立读回

程序报告 ready / cleanup 只是其中一层。PASS 同时要求：

- unique remote exit=0，观察到一次 TTL20 `private_go_ready` 与一次真实 complete cleanup；process/interface removed、baseline equal 的符号结果一致。
- **新独立进程**重新读取原厂 hash/PID/starttime/parent、完整 wlan0 status 私有指纹、route digest、tracked network processes、GET_INTERFACE 身份清单，全部与 before 相同；wlan0 仍 COMPLETED。
- 无 P2P 接口、无本项目 private WPA 进程残留；owned journal 为 safe、同 boot、结构/owner 可核实，阶段 reconciled / complete，记录的 process 与 interface 确已不存在。
- raw stdout、stderr、host exit、remote exit 单独保存；CRCRLF/CRLF 只在派生解析中规范化，不改原始证据。

只读查询失败 / baseline 变化、缺 remote exit、超时、缺 journal、错误身份或 cleanup=false 都不能报成功，也不能归因硬件损坏或原厂无线损坏。GO PASS 也**不代表** IP/DHCP 可用、正式发送可用、手机互传或物理界面恢复。

## 失败和超时

ADB host timeout 为 55 秒，partial stdout/stderr 与 `TIMEOUT` 保存在 private-raw；不把 ADB timeout 当 remote 已退出。然后只读检查 exact owned journal、PID/starttime/exe 与 interface 身份，以及前后网络状态。

不自动 retry、新建第二 run、`--recover`、重启、全局 kill/remove/flush、触碰原厂 supplicant/ConnMan 或任何系统服务。若 journal 有明确可核实的 owned identity，公共结果仅给出 `REVIEW_OWNED_JOURNAL_FOR_EXPLICIT_RECOVERY`；exact owned-only recover **建议命令**留在 `private-next-steps.txt`，需要主线程再次 review/授权，脚本不会执行。身份变化或 journal 不可核实时只做只读 ownership review，不凭同名接口清理。

在失败结果得到明确解释、owned 残留与原厂网络复核之前，不能重新执行 `--execute-reviewed` 来绕开故障。既有 unfinished namespace journal / P2P 接口是新试验的硬阻断门槛。

## 证据与脱敏

公共 `result.json` 仅固定符号、计数、布尔、候选身份和固定 stage；不输出 SSID/MAC/IP/PSK、原厂网络名、remote path、journal 内容、runtime 原始异常文字。`.sanitized.zip` 精确白名单只包含 `result.json` 和 `README.txt`；private-raw、private-next-steps、候选二进制 / 源码均不打包。

本文件截至提交时的执行状态：**HOST_ONLY_FREEZE_PASS / HOST_ONLY six checks PASS；P011 RF NOT_RUN。**
