# Native helper 主机证据（2026-09-30）

## 后续 Wi-Fi 分支补充（主机与只读设备层分开）

- `mta_wifi_caps.c` libc-only host/SDK arm 严格编译通过；`test_wifi_caps.c` 组合限额 + 100000 固定 malformed TLV 的 ASan/UBSan 通过。
- `test_send_wifi_lease.py` 16 个纯主机 mock 测试通过；没有打开 radio/system bus，也不是手机互传验收。
- 私有 wpa 2.12 + 静态 libnl3.11 的 SDK ARM 构建通过；固定候选 SHA、许可证、源码与重链接对象见 `WIFI_CAPABILITIES_20260930.md`。
- P011 只读内存 nl80211 GET_WIPHY/GET_INTERFACE 与 wpa Capabilities 查询完成；目标 Python 缺 fcntl/resource 的兼容处理验证了导入和只读 netlink。没有在本分支执行 P2P RF 写。
- 本页原有 BlueZ 主机记录保留；根线程后来执行的 BlueZ/广告/扫描实机 evidence 应以根线程独立日志为准，不能反向把此前 mock 标为硬件 PASS。

## 已通过

1. Windows MinGW gcc，`-std=c99 -Wall -Wextra -Werror -pedantic`：便携核心编译与 `test_core` 执行通过。
2. 构建容器 `p011-bili-build-20260923`，Ubuntu 宿主 GLib/GIO：完整 `mta_bluez_helper.c + mta_core.c` 同等级警告编译通过。
3. 同容器私有 `GTestDBus` + 模拟 BlueZ：`test_gatt` 通过；测试不连接 system bus、不打开 MGMT socket。覆盖本地 GATT ObjectManager、状态偏移读取、device/owner 校验、prepare 拒绝、顺序分片与超时；MTA BLE 扫描过滤与仅自身 session 停止；远端 GATT 状态读取/写入；不主动断开原先已连接的 peer；Stop 后迟到 Connect 的有界清理；未读取输出管道时非阻塞失败关闭。
4. Ubuntu host `-fsanitize=address,undefined -fno-omit-frame-pointer`：`test_fuzz` 10 万轮固定种子畸形输入通过，未报告 sanitizer 错误。
5. `test_gatt` 再以 AddressSanitizer/UndefinedBehaviorSanitizer 编译运行通过，未报告 sanitizer 错误。

测试输出中的 mock phone、`{"x":1}` 和 `{}` 均为合成数据，不是真实设备、地址、密钥或密码。

## 尚未由本文件证明

- ARM 目标完整链接/动态符号兼容（主线程另行构建与记录）。
- P011 的 MGMT 内核权限、Add Advertising 行为、扫描响应无线输出。
- P011 原厂 BlueZ 5.48 的 GATT 服务注册、实际 ATT 长写与取消行为。
- 手机原厂互传发现/凭据交换/文件传输/完成回执。
- 原厂蓝牙、Wi-Fi 共存与退出恢复实机验收。

不得将上述主机结果升级为 P011 实机通过。见 ../README.md 的私有 IPC 与广播所有权边界。
