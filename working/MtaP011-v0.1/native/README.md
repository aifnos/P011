# P011 互传 BlueZ 5.48 原生辅助进程

这是新写的实验候选，不是已实机通过的版本。依赖 Linux socket 头文件、GLib/GIO（不需要 BlueZ 开发头文件、json-glib/libbluetooth 链接）。协议加密、SSID/PSK 校验、网络连接和文件接收由上层进程负责。

## 构建与无设备测试

Linux 构建：`make`，便携核心测试：`make test`。交叉编译时必须使用与 P011 相容的 sysroot 和 pkg-config 配置，不能将宿主 Linux GLib 库误链接进 ARM 程序。

Windows 便携核心测试：

```powershell
gcc -std=c99 -Wall -Wextra -Werror -pedantic mta_core.c tests/test_core.c -o tests/test_core.exe
& tests/test_core.exe
```

该测试只覆盖 IPC 白名单、严格 base64、MGMT 字节格式及有上限的顺序长写，不证明内核、BlueZ GATT、蓝牙广播或手机互通。

`make test-gatt` 在构建机启动一个独立私有测试总线和模拟 BlueZ（需要构建机的 dbus-daemon），不访问 system bus 或蓝牙控制器；覆盖服务对象/读取偏移/调用者与连接校验/分片、超时、BLE 扫描、远端 GATT 读写，以及不删除既有连接。`tests/test_fuzz.c` 可配合宿主 AddressSanitizer/UndefinedBehaviorSanitizer 做 10 万轮畸形输入测试。

## 模式与私有 IPC

`mta-bluez-helper --capabilities hci0` 只读 BlueZ 属性、MGMT Read Controller Information 和 Read Advertising Features，不开蓝牙、不注册 GATT、不扫描、不广播。输出不含地址或设备名。

`--serve hci0` 必须由上层创建私有 stdin/stdout 管道启动。不能将其 stdout 直接归档到诊断日志：`p2p` 事件的 base64 是敏感数据的传输编码，不是脱敏。

serve 模式拒绝普通文件/终端输入输出，输出设为非阻塞且单条事件不超过 PIPE_BUF。上层必须持续读取 IPC；管道背压/关闭时辅助进程失败退出并清理，不能让协议处理阻塞蓝牙事件循环。

进程禁用 core dump 并设置不可转储，避免崩溃时将私有 IPC 数据写入普通故障归档；上层仍须独立实施密钥/凭据生命周期和日志脱敏。

允许的命令（ASCII JSON，每行一个，拒绝额外/重复字段和 JSON 转义）：

```json
{"cmd":"listen","adapter":"hci0","status_b64":"e30="}
{"cmd":"advert","adapter":"hci0","adv_b64":"AgEG","scan_b64":"AgEG","ttl":20}
{"cmd":"set_status","status_b64":"e30="}
{"cmd":"scan","adapter":"hci0","ttl":20}
{"cmd":"client_read","peer":1}
{"cmd":"client_write","peer":1,"payload_b64":"e30="}
{"cmd":"stop"}
```

上述广播字节只是 IPC 格式示例，不是互传协议广播，不能作为手机发现验收材料。生产调用应由协议层构造完整 MTA 主广播和扫描响应。

- `listen`：当前蓝牙已开启才注册 `9955` 主服务、`9954` 只读状态和 `9953` 写入特征；状态最长 512 字节。注册是异步的，收到 `listen/ready` 后才可 `advert`。
- `advert`：主广播/扫描响应分别最长 31 字节，数据必须是完整 AD TLV；TTL 为 1–600 秒。仅使用 Add Advertising 的 connectable 实例标志，不改全局 Connectable/Discoverable/Powered。
- 精确原始广播模式还要求已有 BR/EDR 设置开启；Linux 4.14 在关闭 BR/EDR 时可能自动前置 AD Flags，不能默默接受 31 字节主包溢出或重复 Flags。本辅助进程只拒绝该状态，不会自行开启 BR/EDR。
- 写入 `9953`：调用者必须是启动时取得的 BlueZ 唯一总线 owner，`device` 必须是所选适配器下实际已连接的 Device1；只允许单 peer，有速率/总长度/10 秒超时限制。offset 必须连续，offset=0 开始新值。BlueZ 已合并的 ATT 长写可作为单个完整值接收；显式 prepare-authorize 会拒绝，未宣称可靠写/取消行为已经手机验证。
- 完整 JSON **包络**才发 `{"event":"p2p","session":1,"payload_b64":"..."}`，该检查不等于完整 JSON/加密认证校验。上层必须在执行任何网络操作前进行完整协议字段和密码认证验证。JSON 对象非法但括号平衡的消息仍会到达上层，不能据此自动连网。
- 上层退出、stdin EOF、SIGTERM/SIGINT、10 分钟 GATT 租约到期都会清理本进程资源。不会删除锁文件（避免并发 inode 竞态），不会删除系统目录或停止原厂服务。
- `scan`：1–60 秒的 BLE-only MTA UUID 过滤扫描，按 BlueZ 的调用者 session 启停，不停止其他客户端的扫描。`discovered` 事件给出本进程单调递增匿名 `peer` 编号、base64 显示名和协议 service-data；不输出蓝牙地址。缓存快照明确标记 `cached:true`，新事件标记 false，不把缓存冒充本轮无线发现。
- `client_read`：只能选择当前发现表内的 MTA peer，等待 ServicesResolved 后匹配 `9955/9954/9953`，通过 `client_status` 返回状态包；不能传任意路径或地址。30 秒空闲会释放本进程建立的临时连接，已存在的连接不由本进程断开。
- `client_write`：只能向已就绪 peer 的 `9953` 写入上层产生的协议包。`accepted_by_bluez_not_file_transfer_complete` 只表示 BlueZ 接受 GATT 写入，不表示对方完成解密、网络连接或文件接收。
- `stop` 返回资源释放/清理报告，不等于整个设备恢复验收；扫描启动或连接仍在回调等待时返回 `pending_cleanup`。上层须继续等待相应回调或结束辅助进程，再独立读取 adapter、广告实例和原厂网络状态。

## 广播所有权的已知边界

BlueZ 5.48 MGMT Add Advertising 是按实例编号新增或**覆写**，没有原子 create-if-absent，也没有 socket 归属。因此本候选保守拒绝已有 BlueZ/MGMT 广播的环境，使用最高空闲编号，并监测同编号的外部 Added/Removed 事件；观察到所有权丢失就不再删除该编号。

这不能完全消除与其他进程同时 Add Advertising 的竞态，**不能宣称支持任意外部广告并发**。可写试验必须先确认没有其他广播操作者，并独立核对退出后实例列表。内核 TTL 在辅助进程崩溃或 Add 响应超时时提供有界兜底；MGMT readback/Remove 的结果单独报告，不将发送请求当作恢复成功。

## 源资料与许可

程序是本项目独立编写，没有复制第三方实现源码。线格式参考 BlueZ 5.48 官方接口文档：

- https://github.com/bluez/bluez/blob/5.48/doc/mgmt-api.txt
- https://github.com/bluez/bluez/blob/5.48/doc/gatt-api.txt
- https://github.com/torvalds/linux/blob/v4.14/net/bluetooth/hci_request.c

MTA UUID/行为互操作参考 cattysend 固定版本 `540b49e8e3799b796e9114d1241006d325b3884b` 的 GATT 服务；没有直接复制该 Rust 实现。本目录不是对协议兼容性或安全性的保证。
