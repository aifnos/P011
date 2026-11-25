# 独立 P2P client 接收后端：源码可行路径与未验证边界

该设计不改变当前已交接的 GO 首阶段候选。没有执行 JOIN、扫描或 DHCP 实验。

## 源码证据

官方固定发布包 `wpa_supplicant-2.12.tar.gz` 中：

- `wpa_supplicant/ctrl_iface.c` 的 `p2p_ctrl_group_add_persistent` 要求本实例 network 的 `disabled==2`，经 `P2P_GROUP_ADD persistent=<id> ...` 进入 `wpas_p2p_group_add_persistent`。
- `wpa_supplicant/p2p_supplicant.c` 对该内存 profile 的 mode=0（WPAS_MODE_INFRA）进入 `wpas_start_p2p_client`；其后创建 temporary profile、复制 SSID/PSK、将 `ssid->p2p_group=1`，并 select network。
- `wpa_supplicant/wpa_supplicant.c` 关联参数使用 `params.p2p=ssid->p2p_group`，因此这是 P2P_CLIENT 的驱动路径，不是第二个普通 STA。
- `config_ssid.h` 明确 p2p_group 是内部字段；直接 SET_NETWORK p2p_group 不是可依赖的公开配置入口。

`persistent` 在这个 API 中选择配置语义，不等同必须保存磁盘。候选编译 `CONFIG_NO_CONFIG_WRITE=y`，不调用 SAVE_CONFIG，profile 只建立在私有 wpa 的内存中并随实例退出丢弃。不得写原厂配置或连接系统 ctrl socket。

## 后续有限实现顺序

1. 完成根线程 20 秒 GO 创建/退出实机试验，确认 private initial mode 补丁与 owned netdev 回收，原厂 STA/PID/starttime/哈希/路由保持。
2. 从经过协议验证及 ECDH/AES 解密的 private P2PInfo 取得 SSID/PSK/端点；不信任 UI 任意字符串，不记录凭据。长度上限 SSID 32 字节、PSK 8–63 字符或明示的 32 字节原始密钥；ctrl 参数用十六进制，拒绝换行/任意 command。
3. 与 GO 相同的 netlink 租约创建自有 P2P_CLIENT，保留 wlan0 与原厂管理器。私有 cfg/ctrl 将该实例的 ap_scan 改为 1（GO 阶段的 ap_scan=2 不直接复用）。
4. 私有 ctrl ADD_NETWORK，设置 ssid/psk/key_mgmt=WPA-PSK/proto=RSN/pairwise=CCMP/group=CCMP/mode=0/disabled=2。不直接 ENABLE_NETWORK 普通 STA；调用 `P2P_GROUP_ADD persistent=<id>`。
5. P2PInfo 的 MAC 字段必须对照协议：GO device address 不总等于 GO BSSID。未确认时不强填 go_bssid；凭唯一 SSID＋高熵 PSK 受限搜索，并核对实际连接目标的加密握手和协议端点。驱动可声明双信道，但固件实际并发/互操作仍需验证。
6. 确认 P2P-GROUP-STARTED client、wpa_state COMPLETED，ifindex/WDEV/type 与租约一致后，仅给该接口申请租约地址。不安装系统默认路由/DNS，不运行系统 udhcpc 脚本、不全局 flush。
7. socket 使用 SO_BINDTODEVICE（该私有接口）与精确端点/subnet；接收结束先关应用 socket、删除自有地址与路由，再停 private wpa、验证后删自有 netdev。接口或进程身份变化则 ownership lost，拒绝误删。

## 当前不可宣传的状态

该标准上游调用路径说明“软件可以实现”的方向，尚不证明 P011 联网不掉线、手机 GO 能 JOIN、DHCP 成功、TCP/TLS/文件传输可用。`receive.client.available` 与 `send.available` 都应以实际安全租约＋数据通路证据开门，不能用 nl80211 类型标签或上游函数存在自动放行。

来源：[官方 wpa 发布包](https://w1.fi/releases/wpa_supplicant-2.12.tar.gz)、[官方 P2P 控制文档](https://w1.fi/wpa_supplicant/devel/p2p.html)。本页只陈述控制流，不复制其实现。
