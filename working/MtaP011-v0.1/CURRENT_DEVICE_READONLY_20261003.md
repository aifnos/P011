# 2026-10-03 P011 窄只读续查

这是本轮工具观察的派生摘要，不是原始日志导出包、完整基线或恢复验收。没有以旧 HOST 通过结果代签设备。真实手机型号已记录为小米 15 Ultra；系统及原厂互传版本尚未知。

## 当前观察

ROOT `b318ad` 重新枚举 ADB：P011 与 Android 模拟器同时存在。后续窄查询明确选择 P011 的 transport 1，没有操作模拟器。ADB 工件 SHA-256 为 `b4a6b455702684652cccf7b46258b29e653538904359a58fd4931cf3ef286b3f`。

ROOT `acfd1f` 仅执行原生 Python 标准库固定只读查询。HOST 返回 0、远端固定终末标记通过、stderr 为空，没有超时。

| 观察项 | 本轮结果 |
| --- | --- |
| 系统身份 | Linux / armv7l / uid 0 |
| `/usr/bin/Z03` SHA-256 | `cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a`，与 v2.4.0 原厂 pin 一致 |
| wlan0 operstate | up；不等于已联网或完整无线恢复 |
| 本次临时占用记录 | 仍存在；340 B |
| 记录原字节 SHA-256 | `80dae11a3a8b19e9c799058598b86ace18072e4ff8afe7128297adce9dd8a818`，与此前 GO64 窄查相同 |
| 记录打开前后元数据 | 本轮 dev / inode / uid / gid / mode / size 等检查一致 |

查询对临时记录使用 NOFOLLOW / CLOEXEC，核对普通文件、大小上限及打开前后身份，读取既定长度后关闭。原 stdout 的 CRCRLF 只在工具的派生展示中解释；此文件不声称拥有原 stdout.raw / stderr.raw 副本。没有写入设备状态文件。

## 不可从上述结果推出的结论

- 未做完整原厂进程、路由、ConnMan、BlueZ、命名空间或网络基线复验。
- 本輪没有重新哈希 control_engine / startup，不能把旧 pin 写成本轮新观察。
- 记录内容相同不代表完整旧租约权属仍成立，也不是删除权限。
- GO64 的整体失败、resource pending 和完整恢复未证保持不变。
- 未扫描、配对、建 Wi-Fi 接口、启动候选、刷写、清理记录或重启。正常重启及本次记录处理许可仍待。

## 自主制作方向

### 追加：当前 proc 路径形状

ROOT `fbb255` 通过同一 P011 transport 1 的固定标准库只读查询观察：Linux / armv7l / uid 0；`/proc/net` 是指向 `self/net` 的符号链接；当前查询进程的数值 PID 下 `net` 是目录，`net/unix` 是普通 proc 文件。此观察只支持工厂数据读取路径的窄修正，不验证工厂正向发布或互传准入，也不读取设备名称或地址。

此前同项查询的 `8c8bc1` 因主机引用转义产生远端 SyntaxError，不能因 HOST exit 0 视为通过；`213e45` 的 stdin 查询没有返回证据，已中断 HOST 调用，不算通过。成功观察以 `fbb255` 的七项实际输出为准。上述没有写入、扫描、配对、重启或处理临时占用记录；本文件仍仅是派生摘要，原工具输出保留在本轮记录中，没有另称 raw 文件已导出。

正在补齐 State32 → 可信接收部署工厂 → 实际 F37 Loader 的生产接线，固定来源、原任务期限和失败 FD 库存保留。该工作不会翻转 receive_available，也不会启动 Parent / RF。接线 SOURCE 与 HOST 验证必须与真实 P011、手机原厂互通分别记录。

### 追加：本轮重新连接后的窄核查

ROOT `c763bd` 重新枚举，仍明确选 P011 transport 1。`81d2ed` 本轮实际读取原厂三文件 hash，均与升级后 pin 一致，wlan0 up；临时占用记录仍为原 340 B／`80dae11a…8a818`，读前后元数据检查一致。HOST 0／远端固定终末标记 0。`47fd67` 与 `9e97c1` 又观察到五个既定原厂／网络进程及 Z03 父启动循环参数，但不是完整 actor 或网络基线。进程查询的 RACES 数字仅为读取 exe 的 ENOENT／ESRCH 计数，不可当成实际消失次数。

较长查询 `fbef10` 被 ADB 拒绝为 shell command too long，HOST 1，没有设备通过证据。后续缩短只签各自范围。没有 raw 文件或新 ZIP 导出，没有扫描／配对／候选／清理／重启；GO64 整体失败与完整恢复未证保留。[本轮详细观察、真实接收／发送／工具箱接线缺口及下一步边界](CURRENT_TRANSFER_GAPS_20261003.md)。
