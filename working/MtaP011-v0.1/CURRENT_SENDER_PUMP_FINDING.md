# 发送数据面：真实 HOST TLS 首测结果

2026-10-03；本次只完成组件实现与主机测试，未部署或访问 P011。真实验收手机为用户指定的小米 15 Ultra；HyperOS 和原厂互传版本仍未知。

## 已实现

- `PreparedSend` 从实际 `FileRegistry.open_selection` 的原持有句柄生成 stored ZIP，核对资源归属、CRC、尺寸和前后文件快照，不重新按来源路径打开文件。使用本次私有目录中的固定 OpenSSL 子进程生成 TLS 1.2 证书，保持同一归档句柄。
- `SenderPump` 在构造时的同一 worker 中以非阻塞 TLS/select 同时推进 `/websocket` 控制与 `/download`，没有自己的发送、监听或连接线程。SSL 短写按实际成功字节计数，WantRead/Write 保持原重试片段；缓冲和单轮工作量有限。
- 完成须满足实际全部归档发送、EOF/归档身份确认、下载连接闭合、正确任务完成状态以及完成 ACK 真正发送。提前完成、任务不匹配、取消和超时不能得到成功结果。
- 临时进程、管道、归档和连接保持原件库存；不能确认关闭的资源不冒报成功。准备器只精确删除自己的已确认输出，不递归清理，也不关闭借用的文件选择。原绝对期限不续期。

这些是普通数据面组件，不是 Native GO 权限或设备可用凭证。`PreparedSend.communicate` 的 16 KiB 输出限制是固定可信工具返回后的检查，不是对恶意替换工具的硬内存上限。生产 OpenSSL、路径、系统调用成本与资源余量仍须真机验证。

## 唯一首次执行

ROOT `5b299d` 调用固定 Python 3.12，以 `-I -B` 运行新主机 checker。host exit 0、child exit 0、无超时，child 调用一次，elapsed 3.156 秒。七份 runtime 源在该 checker 内通过 Python 3.5 语法检查；实际运行环境仍是 Windows/HOST Python 3.12，不是 P011 Python 3.5。

唯一新测试方法 `SenderPumpTest.test_tls_download_and_terminal_boundaries` 包含六个独立场景，全部通过：

1. 正常并行 WebSocket 控制与下载。
2. 透明截短实际 SSL.send 输入，验证真实短写及终末 ACK 分段发送。
3. 对端取消，确认取消 ACK 和无成功结果。
4. 下载前提前报完成，拒绝而不 ACK 成功。
5. 错误 taskId，拒绝而不 ACK 成功。
6. 原绝对期限到期，任务失败并关闭原库存。

每例实际执行 `FileRegistry → PreparedSend → OpenSSL/ZIP → SenderPump`。手机模拟端只有一个线程，使用真实 loopback TCP/TLS、masked WebSocket 和 HTTPS；正常/短写场景比较完整 ZIP 字节/hash、CRC 和解包后原文件字节。服务侧另起线程被明确禁止。准备目录在总测试目录清理前已独立确认消失；归档/选中文件关闭有实际 EBADF，借用选择在准备器关闭后仍能读回，随后由夹具自己关闭。

未重放旧测试方法。没有 Native/权限/IP/DHCP 成功模型来替代本次数据面结果，但 loopback owner 只签 Windows HOST socket 事实，不签 Linux SO_BINDTODEVICE 或 Native socket ownership。

## 固定来源与结果包

| 本次新文件 | 字节 | SHA-256 |
| --- | ---: | --- |
| runtime/mta_sender_pump.py | 33455 | 81c3d7ff98ab71cde2ac2858daaffd267f129033b28ebde1dbd2f13f19ff447c |
| runtime/mta_send_preparation.py | 28532 | 0e92fc68947601d0517cfe64a22d90d50b9952529c4594a6a189970420f69814 |
| tests/test_sender_pump.py | 34154 | 7c803767b357cf91ceac7e64bb255805ddf0ce257893344e2bc756b0e4bbd3b7 |
| host/sender_pump_source_manifest.json | 1588 | 91a5265b71d0bbdbda000fed9a771d3674056b20b1a66e0438ba78950bb86cd0 |
| host/sender_pump_check.py | 8326 | e939fc28fe98df7da758836fa1fd80fef88fa7d4f819cd92a98faf757f25ce74 |
| HOST_MTA_SENDER_PUMP_CHECK.cmd | 199 | 79138e07a89283659c164f1b4969db161c70bc05ab7401fee80f99ef486ad99e |

一键入口 `HOST_MTA_SENDER_PUMP_CHECK.cmd` 仅 PC 测试，无 ADB/射频参数。它依赖开发电脑现有固定 Python 和 Git OpenSSL；CMD 本身只做源码检查，未点击执行。实际执行的是其相同 checker。

结果：[public-result.zip](results/sender-pump-host-20261003-044806-ab1e5e1a/public-result.zip)，2216 B；SHA-256 `cb3887629f16824c22fcf0e4709773e69e72fec0ab398558ae7313f1737aeb35`。

ROOT `9f1740` 已只读核对 11 份输入快照与当前原件、严格 stdout marker/Ran1/OK、四个 ZIP 成员逐字节/CRC/testzip。独立审查者另用只读 PowerShell/.NET 完整解压逐字节核对、计算全部 CRC，并核 OpenSSL/输入快照及原件，审计 PASS；没有重跑测试、AST 或导入生产源。公开包只有 `result.json`（3122 B）、`README.txt`（563 B）、`stdout.raw`（89 B）、`stderr.raw`（100 B）；不含测试文件内容、证书、私钥或设备标识。ROOT `44c761` 另核本次只在状态/检查点顶部追加，剥离新段后与旧75全文 SHA 一致，历史日志未改。

## 尚未完成的真实接线

- Native75 的实际 listener 仍仅 bound，尚无 pump 所需的 listen/accept/TLS 包装与精确关闭 owner 接线；这两件新源尚未加入固定 GO 部署图或 F60 执行流程。
- 实际 GATT 选中手机身份、原 task/操作期限、同一手机的 P2P station/DHCP ACK 和连接接纳尚未完整贯通。可使用真实 STA-FIRST/NEXT 的 `p2p_device_addr` 关联 station MAC，但不能猜两者相等或把缓存当活 GATT。
- 父 State 的实际文件选择/归档、task 和原 GATT 数据，需要通过窄 IPC 与继承 FD 交给同 worker GO 子进程。不能重建 caller FileSelection 或复制 Python lease 对象作为权限。
- Native 当前原 20 秒 service cap 没有被本次测试延长；生产握手与传输期限、接收 admission、正式服务/文件中心接线和网络恢复仍需完成。
- 没有 P011 运行、无线、手机原厂双向互通或物理恢复结果。旧设备 pending/完整恢复未证的历史结论保留，本轮未刷新设备或处置该记录。

`send_available`、`receive_available`、device/phone/physical restore 均未升级。目标仍 active，尚不能称为只剩人工手机测试。
