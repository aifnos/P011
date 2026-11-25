# CLIENT 本次 pending 文件层

2026-10-01 14:33。新增实际文件组件 `runtime/mta_client_pending.py`；不是完整
ClientInitStore，也没有挂到现有 FILES/Coordination 的 pending 准入例外或生产能力。
已有原厂/无线/旧 pending 的设备判定完全不变，本轮没有 ADB、P011、RF 或网络操作。

## 实现与限制

构造无 I/O。只接受已经 acquire 的 exact ClientCoordination/LockSet，不能以
同路径、相同字段或 caller bool 伪装锁。操作期间串行持有双方内部 mutex，核原
目录锚、device/journal 原 FD 及当前 entry 身份。现有协调器实际 flock 的可信
生命周期仍由调用者持有；本组件不证明 F/D 同 OFD、跨进程继承或完整 manifest。

`create()` 仅一次：fresh ProcReader 双观察当前调用进程/boot/全 task身份且
proc文件闭合明确 → 固定 `.pending` absence → 登记原 FD ticket →
O_RDWR|CREAT|EXCL|NOFOLLOW|NONBLOCK|CLOEXEC，0600 → 有界完整写 →
file fsync + parent dir fsync → 原 fd/full metadata/完整 bytes/entry 读回 →
再观察同一当前进程。新 envelope 只存本次规范 run、Identity、boot、当前 F
Actor完整 stable key；不是旧 GO/CLIENT schema迁移，没有旧文件 decode/接管。
任何既存 entry（包含未知/旧 GO/非 regular）拒绝，不读取其内容、不覆盖。

`verify()` 只读自己原 FD、同 inode/完整 metadata、完整 bytes及 fresh 当前
Actor；换 inode但相同 bytes、同 inode不同 bytes、PID/start/boot/task变化都拒绝。
观测不签未来永久状态，不延长授权或证明 manifest/实际 RF 恢复。

`close()` 永久封印，只独立关闭本组件一个 original FD 最多一次，正常 None
返回并 EBADF读回才已验证；错误/中断保持 sticky unknown，不重关后来复用数字。
**没有 unlink/clear/finish API**，文件和失败的部分文件均保留。关闭不关闭借用
coordination 的目录或两锁；可信外层按顺序关闭它们。本组件未知引用保持强 refs。
status.marker_state 是最后本组件观测，不是关闭后的新目录读回。

生产发送/接收仍 false。下一装配仍需实际 pin/manifest/owner/F-C-D、完整
Store typed own-marker admission及三阶段 terminal/clear；不能把本组件的
durable_created或 PendingObservation当普通 Boolean capability。

## HOST 批次（不手工累计为整合套测）

- 首次工具 `b6bc1c`，host exit1：Windows test setUp试图 mock不存在的 os.fork；
  同时全局 os.stat tripwire使 unittest自身 traceback格式化异常。首方法没有
  进入组件创建/测试体；没有完整 tests-run summary，不填“11 errors”。原失败保留。
- 修测试隔离：仅 tripwire目标默认Linux I/O adapter/ProcReader/native/socket，
  不 patch unittest自身依赖的全局 os.stat。工具 `7b104a`：11项/.023s/OK/exit0。
- 后增六项仅运行六个命名新用例，工具 `9025fa`：6项/.010s/OK/exit0。
  当前17方法并非最终单批17；runtime未在后一批改动。Python3.5 AST在首通过批核验。
- 用例为 synthetic FakeFS/ProcObservation；覆盖旧entry、EXCL竞争、相同bytes换inode、
  原bytes改变、锁entry改变、owner/boot改变、预算、fsync中断、未知open及sticky close。
  typed synthetic process观测不升级成真实进程或锁证明。

## 隔离 Linux 真实文件 I/O

ROOT工具 `5b45e5`：WSL现有 kali-linux 的独立 root Python3进程，host exit0、
wall1.9433822秒。唯一 override 为协调器 open_root指向新私有 fixture root；
其余 marker文件/fsync/lseek/read/fstat/close及 ProcReader均实际 Linux I/O。
未接触真实 `/tmp/p011-mta-p2p-device.pending` 或设备 gate，未启动 Docker。

实际 create、file/dir fsync、原文件bytes/inode读回与两次 current-owner观察通过；
verify通过；marker关闭后 coordination关闭，六协调组件FD＋一个markerFD共7个
original均明确 closed/EBADF。重复close未重复调用原FD。关闭后同文件inode/size
仍存在，私有合成fixture保留；没有 unlink。计数不包含import/fixture/proc reader
内部其它FD，更不是整个主机或目标进程的全资源恢复。

8依赖源码在前后hash一致，Python3.5 AST通过；marker SHA
`cc90ea2a631d074c87f0ca04068c78871dedc110a5bb8fef0340565f104c181a`。
该次core快照为 `ec2d927c50bf2946614990bdd9fe1d69ce5538047573d9a4d885a3914b0f85f1`，
当时新 finish专项仍在最终审查，不是已部署/晋升的core；本文件试验只用Identity/Actor类型。
WSL输出有systemd user session警告，与成功Python结果分列；未修复主机服务。
工具输出为merged通道，无单独stdout/stderr原始归档，公开result只是DERIVED摘要。

未验证：P011 Python3.5/libc/filesystem/actual gate、own-marker准入与清除、完整
Store/原网恢复、F-D inherited OFD、手机发现/双向传输。目标 active，不声明仅待人工。
