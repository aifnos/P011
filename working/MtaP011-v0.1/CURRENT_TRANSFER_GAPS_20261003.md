# 互传生产链路缺口与当前实机前置

2026-10-03。对端已确定为小米 15 Ultra，HyperOS／原厂互传版本仍未知。本文是本轮只读设备观察与 SOURCE 审计，不是新候选、测试通过报告或实际手机互通验收。

## 当前设备观察

ROOT `c763bd` 重新枚举并核 ADB 工件 SHA，与此前固定工件一致；P011 为 transport 1，模拟器为 transport 2。以下只选择 transport 1。

ROOT `81d2ed` 的固定标准库只读查询：Linux／armv7l／uid 0，原厂 Z03、control_engine、zyb_z03_launch.sh 三文件分别与升级后 v2.4.0 pin 一致；wlan0 operstate 为 up。`/tmp/p011-mta-p2p-device.pending` 仍为 340 B，SHA `80dae11a3a8b19e9c799058598b86ace18072e4ff8afe7128297adce9dd8a818`，打开及读完后的元数据检查一致。HOST 0，远端 `REMOTE_RO_ID_EXIT=0`。

ROOT `47fd67` 观察到 Z03／control_engine／connmand／bluetoothd／wpa_supplicant 五个既定名称的进程，各自 PID、PPID、starttime、exe 的两次窄读一致。ROOT `9e97c1` 另读 Z03 父进程，原厂启动循环脚本参数存在。两查询均 HOST 0／远端终末标记 0。过程探针的 `RACES=158` 实际只是枚举全部 PID 时先读取 exe，遇到 ENOENT／ESRCH 的计数，可能含无 exe 的内核线程；不能解释成 158 次进程消失，也不能签完整 actor inventory。control_engine 父进程被观察到，不据其简称声称完整原厂循环认证。

这不是完整前后网络 Snapshot、D-Bus、路由、共享租约或恢复证明。记录内容相同也不是清理权限。GO64 整体 FAIL／恢复未证保持；未启动候选、扫描、配对、创建网络接口、删除记录、刷写或重启。

首次较长查询 `fbef10` 被 ADB 以 shell command too long 拒绝，HOST 1；没有远端终态，不能算设备通过。随后缩短的两项查询只证明各自实际输出。工具 stdout 展示含 CRCRLF，本文是派生摘要，未另称原 raw 已导出或 ZIP 已生成。

## 缺口不是 available 开关

ROOT 读取实际接点，并由 formal_phase_plan／final_cap_tests 两项独立 SOURCE 审计交叉核对。没有重跑已通过的 HOST70/r2、Qt 或旧设备试验。

| 接点 | 当前真实状态 | 最小后续工作 |
| --- | --- | --- |
| 服务／工具箱 | Owner70 只接受 receive/send=False 并强制 scan=False；现有 mta_toolbox_session 仍构造旧 State，未接固定 Factory/provider。 | 独立正式服务生命周期接线，先无 RF 验证真实启动、Qt endpoint/token、文件目录与关闭；不能把 Owner70 直接改成无线 owner 后沿用其旧关闭结论。 |
| 接收 | State32 已有 Session→Handoff→Bridge→Factory→Parent/F37→peer/TLS/SafeZipReceiver；没有真实 admission producer/consumer。 | 解决受控 CLIENT 启动／恢复前置及事实消费点；生产会话夹同一服务绝对期限，使用真实手机 CONNECT／授权，保持未知恢复禁止下一轮。无需另造接收器。 |
| 发送 | State/SendWorker 已有调用点，但尚无完整九方法的真实网络 provider。旧 SendWifiBackend、v43 GO/IP/DHCP 试验不是这个 provider。 | 复用 GO、typed IP、DHCP 的真实拥有租约，实现 reserve/activate/read_network/wait_association/read_association/close_extra/extra_closed/restore_owned/read_restored，再接原 SenderTransport/TLS／完成消息。不能拼造 NetworkReceipt 或把存在 GO/DHCP 当发送完成。 |
| 文件中心 | Received 打开按钮与选择文件接口已存在；v67 UTF-8 与 v68 页面竞态修正是独立候选，未纳入当前 Boot 的生产来源。 | 纳入同一固定交付来源，真实中文文件接收／读回／选择发送／返回验收。旧 HOST 有限结果不升级设备。 |

接收前置环须明确解决：State32:244 固定 receive=False、:381 在建立 Operation 前拒；Handoff13:104 又要求同一 State 的 receive=True；Factory69-r3:155 起需要正在运行的 Bridge 与已解密、未 claim 的真实 Handoff。F37 Loader:404 起只接受 version3，:441 建立必须含真实 consent/session/nonce 的 ControlBinding。因此无 CONNECT 的 CLIENT 启动预检不能填假 GATT 绑定借工厂发布。Parent 的旧无 Handoff HOST 分支也没有正式 State 的原 cap，不是现成的生产准入收据。

真实 admission 应来自同次来源／boot／原厂与网络基线、当前共享 pending 缺席、实际 CLIENT init-ready 及原 Store 的认证 FinishReceipt／资源闭合，并绑定当前 State／worker／epoch／原 until。GO 是发送路径证据，不替代 CLIENT 接收证据；HOST70 只验证其限定服务生命周期，不授权 RF。

## 当前推进边界

正常重启许可尚未收到。若获准，先正常重启并重新做只读基线；重启本身不当作恢复证明，也不预授权删除残留记录或开启无线试验。记录若仍在，应保留原件，另按实际权属和最窄恢复方案取得方向。

目标保持 active、尚非仅剩手机人工验收。无需现在操作手机；后续真实兼容验证再确认 HyperOS 和原厂互传版本。没有把服务闭合、原厂文件一致或主机通过写成互传功能完成。
