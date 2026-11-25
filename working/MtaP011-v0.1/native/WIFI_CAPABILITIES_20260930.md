# P011 Wi-Fi/P2P 只读能力核查（2026-09-30）

本页是能力与实验设计证据，不是互传实机发送 PASS。没有启用 P2P、广播、扫描、热点，没有改变 wlan0/ConnMan/原厂进程。

## 实机已读到的事实

通过 `host/device_probe.select_target()` 选择唯一真实 P011 transport，其他模拟器没有被使用。在笔端临时 Python 内存代码中读取 generic-netlink `GET_WIPHY` 与 wpa D-Bus/ctrl 只读信息，没有上传/执行 RF 写程序。

| 层 | 当前结果 | 可得结论 |
| --- | --- | --- |
| nl80211 iftypes | station、AP、P2P client、P2P GO、P2P device | 驱动声明实现这些类型，不等同实际建组已成功 |
| supported commands | NEW_INTERFACE、START_AP、START_P2P_DEVICE 均有 | 内核接口有对应入口，不等同无线固件运行可用 |
| interface combination | 总数 ≤3，信道 ≤2；station/AP 合计 ≤1，client/GO 合计 ≤1，device ≤1 | 允许 STA+P2P GO；不允许 STA+普通 AP |
| 原厂全局 D-Bus Capabilities | `ap`，无 `p2p` | 按官方 2.6 源码，这个属性报告编译能力；当前原厂构建没有报告 CONFIG_P2P |
| wpa_cli help | 无 p2p_find/group_add | 客户端构建也没有 P2P 命令；仅作佐证，不能单独证明服务端能力 |
| wpa get_capability modes | AP | 该结果不能单独判定 P2P 缺失 |
| 原厂 wpa 实例 | 同一系统二进制的两个实例；一个管 wlan0 无 -u；另一个带 -u 无 wlan0 | 解释 D-Bus Interfaces=0/GetInterface(wlan0)=InterfaceUnknown；不能把 D-Bus 空接口当驱动不支持 |

公开机器结果没有 SSID、MAC、IP、序列号、网络密码。原始 stdout/stderr/host exit 保存在 `tests/private-wifi-readonly-20260930c`，只用于本机私有审计，不打入公开发布包。ADB 在发送较长内存脚本时可能回显脚本；脚本未包含凭据。

## 新增探针

`mta_wifi_caps.c/.h` 是独立 C99、libc-only 的只读探针，唯一 netlink 请求为 controller GETFAMILY 与 nl80211 GET_WIPHY dump。最多 8 PHY、16 组合、每组合 16 限额，5 秒接收期限、1 MiB 总回复限额；拒绝截断/中断 dump、异常嵌套、缺字段等，不能调用扫描/建组/改接口。

`--capabilities` 返回匿名类型/组合，不打印原始 netlink 载荷、接口硬件地址、PHY 名称或 SSID。`--ids` 只打印由构建时 Linux UAPI 头文件得到的数字供只读内存探针使用。

主机严格编译、组合限额单测与 100000 轮固定随机 malformed TLV 的 ASan/UBSan 检查通过；SDK armv7 独立链接通过。C 探针尚未在 P011 执行；笔端能力来自同协议的 Python 内存读取。Docker 主机没有 WLAN 的 ENODATA 不是 P011 失败。

## 私有 P2P GO 候选与有界试验条件

不能为发送强停 ConnMan，不能将 wlan0 改 AP，也不应直接运行全局 p2p_stop/flush。下一步使用项目私有 wpa 2.12，静态项目 libnl 3.11，始终不替换原厂二进制/服务。

上游 wpa 会把外部预建的“静态” P2P client/GO 接口在初始化时切成 STA；这与本机 STA/AP 限额冲突。项目补丁仅当显式 `mta_p2p_initial=1`、接口名严格为 `mta`+8 个小写十六进制字符、初始类型确为 P2P client/GO 时才保留模式，并让该实例不用隐式 dedicated P2P device。私有配置 `p2p_no_group_iface=1`。此适配需实机证实，构建成功不能证明无线可用。

首轮仅 20 秒：保存原厂 PID/starttime/哈希、wlan0 联网与 ifindex/WDEV 基线；确认无外部 P2P、组合容量、项目锁；创建随机命名 P2P client 自有 netdev（不碰 STA），启动私有 wpa；只在该实例 ctrl 发 GO 创建，固定当前 STA 合法信道；无 BLE、无 DHCP、无文件传输、不输出 SSID/PSK。获得 GO-started 后立即或 TTL 结束撤销。失败不回退到改 wlan0/停止管理器。

清理必须按进程 PID/starttime/exe 与 interface ifindex/WDEV/type/name 四元组核验：仅关自有 group、仅结束私有实例、仅删自有接口；名字相同但 WDEV 变化即拒删并报告 ownership lost。独立看门狗和 0600 recovery journal 不保存 PSK；若 SIGKILL 后清理没有完整确认，保留恢复待办，不能宣称原厂已恢复。

待证：驱动建/换自有 P2P 接口、原厂联网保持、GO 事件/凭据、私有 DHCP 仅该接口、手机联盟客户端接受 P2PInfo、真正文件发送/接收/取消/退出。先验证首层再启后续，根线程统一执行 RF 实验。

## 已实现的阶段一入口与证据

`runtime/mta_send_wifi.py` 稳定底层 API：`LinuxBackend(binary,caps_probe,directory,allow_rf=False)`；`GoLease(backend,journal).start(ttl=20,watchdog=...)`、`stop()`、`recover()`。仅显式 allow_rf 才允许 create/remove/私有进程动作；普通导入、capabilities、GET_INTERFACE 都不创建网络资源。

服务适配：`SendWifiBackend(helper_path,supplicant_path,run_dir,allow_rf=False).capabilities()` 返回 `send.available=false` 与 p2pDeclared；`create_group(timeout<=20)` 只供阶段一实验，返回 private `SenderGoContext`，有 interface/ssid/psk/mac，`local_ip=None`，无 DHCP。不能给 SenderTransport 当正式可用网络；收到 GO event 不等同手机文件传输成功。

根线程批准的显式 CLI（本分支未执行）：

```
python3 -B <runtime>/mta_send_wifi.py --trial --run-dir <新的0700项目运行目录> --binary <私有mta-wpa-supplicant> --caps-probe <mta-wifi-caps> --ttl 20
```

异常后的同目录恢复用 `--recover` 替代 `--trial`。不可删除旧 journal 以绕过“已有租约需核对”门禁。超时开始清理，不声称所有内核动作能在准确第 20 秒全部完成；清理 netlink 和私有进程均有界期限。创建意图已写但内核回复身份不明时只报告 recovery_required，不凭名字误删。

Wpa SDK 构建 PASS：2.12＋静态 libnl3.11，目标依赖仅 libc/librt/ld-linux-armhf，最高需求 GLIBC_2.15（本机 libc2.27）。二进制 SHA256 `010f119b3cb9a8d7720e1ee57d83a92158628a68520d2010adde7bbe4b64518f`，私有路径 `native/private-p2p-candidate-20260930`。source tar/本项目补丁/config/build脚本及静态链接 application objects/libnl archives 须随候选供源码及重链接审计，不能只发布一个 GPL/LGPL 混合静态二进制。

16 个 host lease mock PASS：journal 不含凭据，进程身份落盘后才开启 exec gate，TTL/取消/失败清理，接口与 PID 复用拒绝误删，外部 P2P 拒绝并发，原厂基线变化不报恢复 PASS，重启拒绝旧 journal，同一 journal 幂等 cleanup。独立 watchdog 与实际信号/fork/netlink RF 仍需实机，不把 mock 当试验完成。

只读笔端内存 import＋GET_INTERFACE PASS：当前 1 个 wlan0 STA、0 个既有 P2P；Python3.5 缺 fcntl/resource，已改 ctypes 调用 libc flock/setrlimit/prctl，不补装系统 Python。长源码通过压缩后的每行 ≤512 字符内存传送，避免 ADB PTY canonical 行长导致等待；首次过长行超时的原始 partial stdout/stderr 已保留，没有任何 RF 写。

### 后续接收候选

驱动组合也允许 STA＋一个自有 P2P_CLIENT。独立私有实例在同一租约接口 JOIN 手机 GO 是后续方向，不需把 wlan0 切成 ConnMan 临时 profile。需要确认上游 `ssid.p2p_group`/`params.p2p` 的真实路径：普通 network mode=0 自动使用 STA 会违反组合；不能只加 SSID/PSK 冒充 P2P 客户端。阶段一 GO 与恢复验证先做，之后独立实现 known-SSID/PSK 的 group client 语义、限额 DHCP client 与仅接口绑定路由，无全局默认路由/DNS/保存网络。

## 主要来源

- [Linux v4.14 nl80211 UAPI](https://raw.githubusercontent.com/torvalds/linux/v4.14/include/uapi/linux/nl80211.h)：supported_iftypes 与 interface combinations 不是同一含义。
- [wpa 官方 D-Bus API](https://w1.fi/wpa_supplicant/devel/dbus.html)：全局 Capabilities 与接口属性定义。
- [wpa 官方 2.6 发布包](https://w1.fi/releases/wpa_supplicant-2.6.tar.gz)：`dbus_new_handlers.c` 的 global_capabilities 用 CONFIG_P2P 添加 p2p 字符串。这里只描述逻辑，不复制该实现。
- [wpa 官方 P2P 文档](https://w1.fi/wpa_supplicant/devel/p2p.html)：GO/组创建/移除与用户层、驱动层责任分工。
- [官方 release 索引](https://w1.fi/releases/)：私有候选固定 2.12，不宣称与原厂构建相同。
- [libnl 原项目](https://github.com/thom311/libnl)：私有静态依赖 3.11.0，保留其许可证及修改来源。
