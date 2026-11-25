# 首轮 private GO 失败：只读源码归因与回收条件

对应 root 实机记录：`logs/MtaP011-DeviceP2p-20260930-205426-c3ac37fe/result.json`。本页没有执行恢复、重试或 RF 写；首阶段 frozen helper / WPA / patch 均未修改。

## 已证实与仍未证实

- root 报告 private_wpa_exit，journal 原创建接口为 P2P_CLIENT type 8，退出后同一个自有 netdev 成为 station type 2。
- root 独立检查原厂 wlan0、进程 / 哈希、wpa full fingerprint、路由保持；没有 private WPA 进程。自有接口仍残留，cleanup 没有通过，不可称完整恢复。
- 原 WPA stdout/stderr 为 devnull，无法从初始失败记录确定哪一个系统调用导致退出；不能凭源代码猜测冒充确切驱动 errno。

## 首阶段补丁实际没有进入预期初始化分支

只读固定官方 `wpa_supplicant-2.12` 源码 / 本项目候选源码得到：

1. `wpa_supplicant/driver_i.h` 的 `wpa_drv_init` 调用 nl80211 的 init2。
2. `src/drivers/driver_nl80211.c` 的 `wpa_driver_nl80211_init` 调用 `wpa_driver_nl80211_drv_init` 时，`set_addr` 与 `driver_params` **都固定传 NULL**。
3. `wpa_driver_nl80211_finish_drv_init` 先 capability / mode / interface UP。我们第一版 `if (driver_params && ... mta_p2p_initial=1)` 的条件因此为 false。
4. 外部 raw-netlink 创建的 netdev 不是由该 WPA global 创建的 `bss->if_dynamic`；不是 mesh / static AP 时，上游初始化仍选择 STATION。
5. `wpa_supplicant.c` 的 `wpas_init_driver` 只有在 `wpa_drv_init` 成功以后，才把配置文件的 `driver_param` 传给 `wpa_drv_set_param`。把 early initial-mode gate 放在 conf driver_param 太晚。

这条路径解释了为什么保留 P2P initial type 的 patch 在 supplicant 本入口未生效，以及 type8→2 可在 **initial mode set** 发生。之后双 station 的 interface-UP 因并发限制失败是可解释的候选原因，仍需新的 sanitized 实机诊断，不在此宣告已确认。

## 另一条需防范的上游类型改变

`wpa_driver_nl80211_deinit_p2p_cli` 对非动态的 P2P_CLIENT 调用 STATION；`deinit_ap` 对非动态的 GO 也有 STA reset 路径。这里的 dynamically added 指 WPA 自己的内部标志，不等于本项目 journal 拥有。主 `driver_deinit` 本身仅在 `start_mode_sta` 为真时恢复 STA。

P2P group 删除才会经 `wpas_p2p_group_delete` 调到上述 CLI/AP deinit；尚未 group_add、无临时 profile 的第一次 init 失败通常不会走这条 group 删除链。因此不能把此首轮简单归因为“退出总会硬恢复 STA”。

## 回收的对象身份与状态应分别处理

iftype 可以由同一 owned WPA 改变；对象身份仍应为同 boot 的 `name + ifindex + WDEV + phy`，不能只用名字，也不能把全部 station 接口自动视为自有。

对这一次残留，root 可先审计以下全部条件，再明确选择仅删除这一条 WDEV：

- 0600 journal / 0700目录、origin 是已 ACK / full-identity 的 CREATE|EXCL type8，新对象不在原厂 baseline。
- 当前 name / ifindex / WDEV / phy 与 origin 完全相等，同 boot；允许状态转为 type2 的判断仅限此 origin，不能作为全局站点删除规则。
- 精确 private PID/starttime/exe 已退出，没有未知管理器或进程引用该接口，没有地址或路由占用。
- 原厂接口、PID/starttime/哈希、wpa状态指纹与路由未变。
- 删除使用 WDEV，随后独立 GET_INTERFACE / 原厂 state 再核对。没有这些证据就保留 recovery_required，不能用 global flush 或停原厂管理器解锁。

旧 frozen recover 的严格 type8/9 校验正确地拒绝了这次新状态；不得静默改它并重写历史结果。下一候选可把 origin identity 与受限转换集合 {station, P2P_CLIENT, P2P_GO} 分离，但仍需要完整 ownership / controller-gone / original-baseline 门控。

## 下一候选应先补什么

1. 私有 init2 在初次 driver-init 之前拿到 explicit project gate：例如 sanitized 环境旗标 + 精确 `mta`/8hex 名称 + netlink 实际 P2P type，而不是 late conf param。必须继续保持 wlan0 / 非项目入口无行为改变。
2. 加固定符号与数值 errno 的诊断输出，限定初始化阶段、initial mode、interface-UP、P2P-init、group-add / deinit。禁止打印原始 WPA debug / PSK / SSID / MAC / hexdump。
3. 保持 CFG/STDERR/PID/Journal 私有，bounded 接收诊断；私有 binary、runtime 新身份和静态测试通过后，由 root 协调短时试验，不直接延长 TTL 或接 DHCP。

官方源码来源：[固定 2.12 发布包](https://w1.fi/releases/wpa_supplicant-2.12.tar.gz)。本页陈述控制流，无复制其实现。
