# CLIENT init/restore 单入口（SOURCE/HOST；未执行设备）

## 固定范围

`host/client_init_p011.py` 默认仅读取 PC 来源、固定历史事实和 SHA，并做 19 模块的 Python 3.5 AST 检查，不枚举 ADB、不创建部署、不联网。完整目标源码生成及预算校验只发生在显式执行的准备阶段或专项 HOST 方法中；默认检查不冒称本轮重新生成了完整目标。`HOST_CLIENT_INIT_SOURCE_CHECK.cmd` 只运行此默认行为；没有 RF 双击脚本。

ROOT 已审批的新 Provider 固定为 `8996ae6aa82e48170514f61fc301a83532cf28a20f385153ff41c1e68b236544`，F 固定为 `79c633998bf3029b4fa2722605667ef01062fe6bdfebc6c13d83bd0bf4fbf134`。其余 17 模块、原 STATUS source driver `99362b…`、目标选择 helper `e7a841…`、私有 WPA `e069ae…` 均逐文件核验。固定实际 CLI SHA 为 `e5d7e23dd0eef64dcc37fa379eedd4bba5e453a10b0b35a3c1e1efabaa34c849`；未猜测 Canonical Python。

仅 `--execute-reviewed --expected-driver-sha256 <本入口完整 SHA>` 才可请求实际轮次，仍需 ROOT 全文审定。没有任意目标/manifest/path/命令参数，没有旧 START、recover、pending 清理、signal、重试或 timeout kill。当前尚未冻结或运行这个入口。

## 唯一实际执行链（待 ROOT 准入）

1. 固定 helper 唯一选择 P011 transport；保留本次 exact HOST Popen 与每条 original pipe。不使用旧 `Adb.run` 的 timeout-kill 包装。
2. 目标首先核 Python 3.5.5 / Linux ARM32 little / root 与真实 ABI，固定 global pending 任意 entry 或无法确证 ENOENT 均在 staging 前阻断。没有锁取得、marker 清理或旧 GO 接管。
3. 当次两遍 Proc Actor 同 boot/PID/start/完整 argv、单线程和真正已关闭 reader；原 canonical `Actor.exe` 全 ELF、ARM architecture、root 非可写完整路径/原 FD/entry/hash 核验。该 Python pin 是本轮实际观察，不标成独立已审批生产 pin。
4. 固定 manifest 19 模块与 native 全 SHA、accepted original daemon/endpoint/namespace 来源、三 stock+CLI 和新真实 Provider 全 baseline 均核验；预观察原资源全关闭。此时仍未 RF。
5. 仅 fresh private ROOT/run/runtime/native/ctrl，目录 0700，EXCL 新文件完整写/fsync/readback/fchmod/fsync；源码/manifest 0400，native 0500，目录 fsync。没有覆盖、回滚覆盖或删除旧路径；现存非空 ROOT 保守阻断。
6. staged DeploymentLoader 核真实 19 源、WPA、Python、deployment；另候选 JSON 原字节与 SHA 重读。第一和最后完整原 baseline 相等、pending 再次缺失，才调用 ParentExecutor 一次 `start(ttl=20)`，后续 `finish(timeout=45)` 只请求同一 F 恢复/实际 wait/EOF/closure。
7. 真实 init-ready、F done、Parent waited/absence/local closure、完整原 baseline、pending absence 和新 fresh 原 Provider closed proof 全合取才 PASS。Parent/RF 请求不是已创建/关联事实；caps 拒绝或未初始化仍 FAIL，不冒称硬件不支持、恢复完成或互传。

所有源行 UTF-8 ≤2048，完整源码 ≤4 MiB；不会再触发旧 PTY 单行截断形状。candidate SHA 对应本轮 exact JSON 原字节（Base64 分段），不依赖两端重编码巧合。

## 证据与未知

完整 target 源、原 stdout、stderr、HOST exit、独立 remote exit、首 HOST traceback 保存于 private-raw。target 私有记录保留原 Python/Parent Actor、原 pipe 库存、F 帧和字节、原 baseline 与 staging 票据；强 owner 引用保留到本次程序退出。公开 report 仅固定 bool/enums+源码/candidate SHA，不含 PID/路径/IP/MAC/argv/凭据；sanitized ZIP 仅 `result.json` 和 `README.txt`。

HOST communicate 超时保留 exact process/返回票据/partial raw，绝不 kill/terminate/再次 communicate；此时不推断 remote exit、F gone 或恢复。正常 communicate 后必须 actual wait returncode、三个 original file-wrapper closed/ValueError 与原 raw FD EBADF；负 wait 状态只记实际 reap，不签业务成功。目标创建/close/观察未知仍 pending，不释放 unknown 引用或盲关借用 FD。IO 预算不宣称可以硬抢占任意 OS 调用。

PC `_read` 保留 dev/ino/size/mtime 的 FD+entry 对照以及 path ctime before/after；CPython 3.12 Windows 的 path-stat/FD-fstat legacy ctime 实际不同，不把两者等同。非 Windows 仍加 FD ctime 相等检查。

## 实际新增验证（无 OS staging / ADB / socket / WSL / RF）

使用 `C:\Users\P011_USER\AppData\Local\Programs\Python\Python312\python.exe -B`（PC Python 3.12）：

- `daf0c5`：首 discover 仅 1 loader ERROR /0.000s/exit1，新 host 拼接括号 SyntaxError，任何方法和设备均未执行。只删多余括号，历史不改。
- `41870f`：26 新 Fake/静态方法 /.282s/OK/exit0，包括目标 Fake 文件系统链、旧 pending-before-stage、read failure 强引用、ready/restore 分离、closure、Popen/partial timeout/不 kill、严格帧和默认 source-only。
- `eec6e4`：新增实际 PC 源图只读方法 1 ERROR /.001s/exit1；发现 Windows path/fstat legacy ctime 不一致。`9f79fa` 只读确认 dev/ino/size/mtime 与路径前后均一致，只有跨 API ctime 不同，无设备调用。
- `5a9c10`：只复跑该 1 失败 +新增 1 ctime 回归，2方法/.436s/OK/exit0；实际 PC 固定 19 图+native 构建，目标 Python3.5 AST/4MiB/2048 字节行门槛通过。不是生产装配或设备证据。

`c24912`：最后 Parent 私有 actor/原 pipe/spawn 诊断字段只更改新入口及 Fake，直接受影响两方法/.033s/OK/exit0；不重跑已过 26 或旧 F/Provider 测试。`3c7b9a` 仅最终新增 HOST 入口+目标源码 Python3.5 AST/行预算的受影响单方法/.025s/OK/exit0。当前共 28 个不同新方法，不称一次整批 28 PASS。

全部真实 P011/创建/恢复/手机验证尚未运行。send_available、receive_available、phone_tested 始终 False；本入口仅 CLIENT init/restore，不做关联、DHCP、IP、BLE 数据或传文件。
