# P011 互传网络租约（v0.1）

实现为 `runtime/mta_wifi.py` + `native/mta_network.c`，独立于蓝牙 helper 和现有工具箱。使用 ConnMan 的 GIO D-Bus 接口，不要求 NetworkManager、`nmcli`、`iw` 或新版 Python。目标 Python 3.5 使用本目录 `p011_json.py`。

## 官方接口依据

- [ConnMan Agent API](https://kernel.googlesource.com/pub/scm/network/connman/connman.git/+/refs/heads/master/doc/agent-api.txt)：`RequestInput` 返回 `Name/SSID/Passphrase`，只响应本次目标服务。未知必需字段及门户登录拒绝。
- [ConnMan Service API](https://kernel.googlesource.com/pub/scm/network/connman/connman/+/refs/heads/master/doc/service-api.txt)：`Connect` 等待连接结果；`Disconnect` 可终止尝试；`Remove` 用于遗忘服务与口令。当前地址／网关读取 `IPv4`，不推算地址。
- [ConnMan Technology API](https://kernel.googlesource.com/pub/scm/network/connman/connman/+/master/doc/technology-api.txt)：读取 `Powered`，只在已同意接收租约后调用 `Scan`。本实现绝不写 `Powered` 或 `Tethering`。

## 入口与隐私

固定 native 模式：

- `--capabilities`：仅 `GetTechnologies/GetServices`，不注册 Agent、不扫描、不启动 Wi-Fi。输出当前软件路径能力，`receiveVerified=false`、`send=false`。不能解释为硬件或手机互传验收。
- `--prepare`：五秒内从私有 stdin 接收 `cmd=prepare,journal_dir_b64,ttl=10..600`。固定使用已核查的 `/var/lib/connman` 根，不接受外部 profile 路径。读取原服务基线、唯一活动服务、Powered、ConnMan 唯一 owner/PID/starttime，先持久化 `prepared` journal 再报告 ready；**不 Scan、不 Agent、不 Connect、不修改无线**。应在发布可发现前调用，避免手机 AP 被原厂后台提前扫描后才做基线。
- 准备后的同一 helper 接收 `cmd=receive,consented=true,ssid_b64,psk_b64,timeout=10..90,ttl=10..600`，复用早期基线，不重新 snapshot；`--receive` 独立固定入口另要求 `journal_dir_b64`，上层正常使用 prepare 路径。Base64 仅是传输封装，不是加密。凭据不进入 helper 的 argv、stdout、stderr 或日志，helper 不自行写凭据文件。**ConnMan 在连接成功时可能落盘临时 profile／PSK**，正常清理通过这一条新服务的 `Remove` 遗忘；不能声称整个链路从不落盘。
- `--recover`：私有 stdin 只接受 `cmd=recover,journal_file_b64`，只恢复本项目私有 journal 指向且已证明归属的新服务；没有任意 D-Bus／shell／文件删除接口。
- 租约结束发 `{"cmd":"restore"}`；`cancel` 同样触发清理。EOF、SIGTERM、SIGINT、独立 TTL 也触发恢复，忽略 SIGPIPE，避免父进程退出时提前中止清理。
- `--self-test` 仅解析固定 HOST fixture，不访问 D-Bus。

Python 接口：

```python
backend = WifiBackend(helper_path)
caps = backend.capabilities()
# 准备 ready 最多等待 8 秒；此时尚未切 Wi-Fi，不提供 gateway/local_ip。
backend.prepare(cancelled=cancelled, timeout=180)
# 只有 prepare ready 之后，上层才开启手机可发现。
info = NetworkInfo.from_p2p_info(decrypted_validated_p2p_info)
with backend.receive(info, cancelled=cancelled, timeout=180, consented=True) as lease:
    # lease.gateway / lease.local_ip 是 ConnMan 实际报告的 IPv4。
    # 传输由上层协议模块完成，本模块不访问任意网络 URL。
    pass
```

`close()/restore()` 返回独立恢复核验布尔；context manager 未确认恢复则抛 `WifiRestoreError`。根服务清理还可调用 `backend.restore_active()`。未确认恢复时后续接收能力锁定，不能只因收到停止请求继续启动下一轮。

`backend.status()` 仅返回 `restorePending/recoveryLocked/prepared/reason`，不含 SSID、地址、profile 路径或 hash。`recover_pending()` 是固定恢复动作；timeout 后保留 Popen/PID/starttime，不杀 mutation helper、不丢失归属、不并行启动第二个恢复进程。准备阶段取消／到时只报告 `networkUntouched=true`，不把这句话伪装成原网络重新连接成功。

## 网络与配置归属

开启可发现前完整读取当前 Wi-Fi 服务基线、当前唯一连接与 Technology.Powered。超过列表上限、多个活动 Wi-Fi 连接、未开启 Wi-Fi 等均拒绝，不猜测能力。

**任何 prepare 基线 GetServices 已有的目标 path，即使 Favorite=false 的扫描缓存，也拒绝覆盖／连接并返回 `TARGET_PROFILE_OWNERSHIP_NOT_PROVEN`。**prepare 后首次出现的扫描缓存可以进入租约，但还要证明对应持久目录原本不存在；不把 Favorite=false 当作没有旧凭据的证明。

仅接受基线之外、同 SSID 的唯一新服务且支持 PSK。通过本进程 Agent 提供口令，连接成功后只把该临时服务的 AutoConnect 改为 false，随即注销 Agent、清零 native 口令缓冲。完成时校验目标身份仍一致，再 `Disconnect/Remove` **这一条新服务**，不删除任何原服务，不调用全局停止／flush，不改原 profile 属性。

之后重新连接原服务，并通过 GetServices 确认原路径恢复到 ready/online、没有额外 Wi-Fi 活动连接、临时服务不再 Favorite，以及 Powered 与基线一致，才报告 `originalNetworkRestored=true,temporaryProfileRemoved=true`。

## 持久恢复与生产安全 gate

私有 journal 目录默认 `/mnt/data/p011-toolbox/sessions/mta-network`，目录 0700、文件 0600，禁止符号链接、额外硬链接和不明文件；通过排他创建、fsync、同目录原子 rename 持久保存。内容只有 boot ID、helper SHA256、Actor/ConnMan PID+starttime、ConnMan 唯一 owner、服务路径、基线和 profile 内容 SHA256，**不保存口令、SSID 原文或私钥**。helper 对 profile 仅流式计算 hash，不解析、复制或打印其内容。

准备时先保存“尚未改网络”；Connect 前保存目标路径、Name hash 与“原持久目录不存在”的证据；连接后保存 profile hash；清理前保存 restoring。恢复只接受相同 boot/helper/ConnMan 身份，原 actor 必须已经消失（PID+starttime 防止 PID 复用）。目标不能来自基线、不能 Immutable，名字与 profile hash 必须一致；原服务身份也校验。跨 boot、ConnMan 重启、活 actor、文件被其他人改动、未完成 hash checkpoint 或厂商 storage 布局不明均保留 journal 并锁定诊断，绝不按名称强删缓存。

2026-09-30 只读 P011 核查：ConnMan `/usr/sbin/connmand` 无 storage/config 启动参数，二进制默认根 `/var/lib/connman`，根目录 root:0755；当前只有 settings 和三个扁平 root:0600 私有文件，没有 upstream 的 `wifi_*/settings` 目录。未读取任何 profile 内容。`GetServices` 正常返回空数组（Wi-Fi 服务/活动连接均 0），但独立 `wpa_cli -i wlan0 status` 为 COMPLETED；两个 supplicant 分别是 wlan0 无 `-u`，以及有 `-u` 无 wlan0。**Powered=true 不能证明 ConnMan 管理原厂的当前 STA**。

因此 native `MTA_CONNMAN_STA_VERIFIED` **生产默认 0**，`receive=false`、reason=`PRIOR_WIFI_OWNERSHIP_NOT_VERIFIED`，即使已提供 consent 也不会 Scan/Agent/Connect。HOST 私有 mock 仅通过显式 `-DMTA_CONNMAN_STA_VERIFIED=1` 验证实现逻辑；目标构建不得设置此开关，直到真实原网络归属、厂商 profile 格式与独立恢复证据齐全。prepare 可只读测试。这个 gate 只约束 ConnMan STA 路线，不能推断 P2P 不支持；独立 P2P 接收／发送仍可继续调查。

## 明确未完成／未验证

- P011 实际 ConnMan Agent、手机 AP 连接、下载期间保持网络、恢复等仍需设备验证；HOST mock 不代表通过。
- P2P／AP 发送租约与网络并发尚未验证，`send_lease/create_p2p_lease/create_ap_lease` 明确报不可用。`wpa_cli modes=AP` 或缺少 P2P socket **不能证明硬件没有 P2P**。
- 同 boot/ConnMan/helper 且有完整所有权证据的 SIGKILL 恢复已有 HOST mock；跨重启恢复明确锁定，不保证断电／跨 boot 自动清理 profile，不强删厂商配置。
- 只处理可见 WPA2/PSK STA 服务；门户登录、企业认证、隐藏网络探测与非 UTF-8 SSID 未宣称支持。

## 编译与 HOST 证据

`mta_network.c` 要链接 `mta_core.c`（Base64 解码、敏感缓冲清零）与 `gio-2.0/gio-unix-2.0/glib-2.0`。代码使用 stock GLib 2.54 已有接口；目标链接／运行仍由根任务独立验证。

HOST GIO 严格编译 `-std=c99 -Wall -Wextra -Werror -pedantic` 与 native parser 自检通过。`native/tests/test_network_bus.c` 在独立 GTestDBus、虚拟 ConnMan 上验证 12 场景：只读能力、prepare 无写/取消、早基线复用（目标在 prepare 后进缓存）、租约正常恢复、已有服务保护、Powered=false、连接后 SIGKILL 恢复、prepare 崩溃、改 profile/跨 boot/活 actor/ConnMan owner 变化/缺 hash 锁定。另用默认 production gate 构建验证 consent 也不修改无线。`tests/test_wifi.py` 共 19 项：Windows 17 通过+2 POSIX权限测试跳过；Linux 19 通过。Python 3.5 AST 通过。以上软件测试不接触真实系统总线；P011 只读事实核查不属于互传或恢复实机验收。
