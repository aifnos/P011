# CLIENT F executor：待 ROOT 审阅

这是新固定 F 入口与父进程封装的源码／HOST FakeIO 层，不是 P011 RF、手机互传或生产可用验收。默认 `main([])` 只输出 source-only，不加载部署、不启动 Provider。没有修改 State、旧 core/Store/Owner/TwoPhase 或已通过的 STATUS。

## 固定部署与来源

- 唯一根：`/tmp/p011-mta-client-rfinit/client-<32 个小写 hex>/`；目录由外层审阅后的部署器预先创建，本模块不 mkdir、chmod、写 pending 或清理旧 run。
- `deployment.json`：root-owned regular、nlink=1、0400；根/run/runtime/native 私有目录 0700。源文件 `runtime/<固定名>.py` 为 0400；私有 WPA 固定 `native/mta-wpa-supplicant` 为 0500。
- JSON exact keys：`version`（strict int 1）、`provider`（ProviderManifest 的 12 个固定字段）、`sources`（19 项按 MODULES 固定顺序的 `[name, sha256]` 列表）。不能缺项、重名、加任意路径。Provider 字段为 version/run_token/candidate_sha/ifname/baseline_manifest/status_manifest/wpa_exe/wpa_sha/python_exe/python_sha/executor_path/executor_sha。
- 完整 JSON SHA 由固定私有 CLI 传入 `--manifest-sha256`；`ProviderManifest(..., _manifest_sha256=SHA)` 接受的是该外层文件实读 hash，不在 JSON 内放循环自 hash。
- `p011_json` bootstrap 固定 SHA 为 `fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88`。逐项读取完整 source、核 SHA/FD/entry/父链；全部源读取后才执行纯模块装配，并用私有 import 表拒绝其他 mta/p011 模块与相对 import。源/打开调用未知均留原引用，无重试。
- Python 必须是实际 Proc Actor.exe 所得 canonical 普通 ELF，不把 `/usr/bin/python3` 链接名当实际映像；root/nonwritable/nlink1/完整 ELF SHA 写入 manifest。私有 WPA SHA 由 Provider 的 core.WPA_SHA 再严格核验。candidate SHA、部署 hash 和 root 私有文件本身不是手机协议或 RF 准入认证；部署图仍须 ROOT 固定审定。

## 运行与恢复

固定 entry 参数为 `--execute-client-init --run-token TOKEN --manifest-sha256 SHA --ttl N`；N 有界且不超过 20。F 在开始装配前实际两次 proc 观察：同 boot、单 task、实际 Python exe 与完整固定 argv SHA；不是把 pre-exec Python Actor 强装成 WPA Actor。

`assemble` 的 exact tuple5 为 provider/store/owner/Provider.LinuxDirectChildLaunchBridge/Provider.LinuxClientInitLease。新两个 exact Provider 类按 ROOT 审定窄适配实际 generation FD 复用与 deinit 后 DOWN 恢复；没有放宽原 Store/Owner/完整 finish 核验。F 在调用前登记 creator ticket，返回值先强引用再核对象关系；未知创建不能冒称无网络变化。真实 start 仍由既有 B/C/Owner/TwoPhase/Provider 完成。F 只读取固定 stdin 管道的 `CANCEL\n` 或 EOF；未知命令拒绝。TTL 或同 Owner watchdog 的通知也只让同一 F 进入 restore。

watchdog 使用固定 `--ttl 20`，仅验证实际单线程/固定 argv/继承 device 与 notify FD 后，到期向原 notify 写 `R`。它不打开 Store、不控制 WPA、不恢复、不自称孤儿回收。提前取消的实际子停止／wait/reap 由 Provider 和原 Owner 完成，不靠 parent 的 kill/terminate。

F 的 `done` 是完整清理观察：exact issued FinishReceipt、Store.authenticate_finish、完整 durable terminal/marker absence/fsync、bridge 全 child+registry 原库存闭合、Provider 新 CloseProof、所有原 ProcReader 库存 fresh EBADF 均通过。start 失败即使清理成功也不算初始化成功；CLI 不返回业务成功 0。读取/控制的原异常保留私有 failures，清理不改写初始业务判定。restore 未完成时报告 pending，保留实际 assembly/receipt/票据；不重新启动、不调用外部恢复器。

## 父进程实际边界

`ParentExecutor.start` 只使用固定 Popen 参数，不 preexec_fn、不 fork、不 shell、不 signal/kill/terminate。原 Python ELF 打开/hash后以 `/proc/self/fd/N` 和 pass_fds 执行；creator/process/pipes 均先登记后核验。固定环境传入 `P011_CLIENT_EXECUTABLE_FD=N`。F actual argv 已核后，用 Loader 原完整 hash/FD/entry metadata 严格匹配继承的 Python ELF copy，预登记一次 close+EBADF；未知保留原票据并 pending。不能依据任意 env FD 直接关闭。watchdog 经 Owner 的 CLOEXEC ELF 路径启动，不要求这个父 Popen 的独立继承接点。父允许自身多线程，但子必须实际单线程，公共操作由同一个 RLock 串行化。

stdout 只接受固定最多两条 `MTA_CLIENT_F ` JSON；stderr/raw 只留私有。ready/done 输出不代替父证据。`finish` 只准入一次，在同一个有界 deadline 内边排空 stdout/stderr 边调用实际 Popen.wait；只有原 Popen TimeoutExpired 的已知未退出结果允许本轮继续，不重新启动 finish 或未知 wait。reap 后继续两路读到实际 EOF，严格总 MAX_RAW、余字节与 deadline；不以一次 2049B read 冒称完整 raw。随后核同 boot/原 PID/start Actor 两次 absence、原 pipes/binary/readers 闭合。stdin EOF 是给同 F 的退出请求，不是 restoration proof。所有 Popen Python file 的 `.close()` 后必须 `.closed is True`、`fileno()` 为 ValueError，并核原 numeric FD 为 EBADF（不能使用 socket 的 fileno=-1 合同）。创建/close 未知不能重试或由 GC 清除。负的 strict int returncode 表示 POSIX actual reap，可进行 absence/local FD 收尾，但绝不升级成业务或恢复成功。

父成功还要求实际初始化 ready 帧、最后 restored 帧、业务 exit=0；child pending、业务 exit=1、部分 frame、未知 status 或只 reap 不恢复，均不能被本地 FD 闭合升级。ProcReader 每次为独立原 owner/call ticket，不复用重置旧 FD 库存。

## 当前测试证据

首批工具 `cd0a8c`：PC Python 3.12.12（固定 `python.exe -B -m unittest discover -s tests -p test_client_executor.py -v`），38 方法，0 FAIL/0 ERROR，unittest 0.062s，host exit 0；含 Python 3.5 AST。没有原失败批，也没有复跑旧项目套测。

后续 ROOT/独立审阅的具体增量：继承 ELF FD 闭合、wait 期间 drain、reap 后两路真实 EOF、negative wait。工具 `c2b3b0` 仅 8 新＋16 直接受影响＋1 AST＝25，0 FAIL/0 ERROR，0.021s，exit 0；工具 `58071d` 仅 1 negative-wait 新例＋2 直接受影响＋1 AST＝4，0 FAIL/0 ERROR，0.014s，exit 0。随后 exact 新 Provider Bridge 对齐，工具 `e9d8cd` 仅 1 新拒绝例＋3 直接受影响＋1 AST＝5，0 FAIL/0 ERROR，0.013s，exit 0。现有 48 个不同方法，不是最后一批整 48 运行；首 38 判定原样保留，无初次失败被改写。

这些是 FakeIO/FakeProc/FakeProvider 的接线与拒绝边界：真实源码文件读取仅用于 HOST 测试夹具，source loader 的角色组件替身不构成生产图认证；typed FinishReceipt 正向来自明确 Fake issuer，不宣称 kernel 恢复。尚未实际验证 Popen、真实 parent Actor/wait、目标 F/WPA init、自然 deinit、设备恢复或手机。

当前尚待收敛的实际接点：固定 Provider 源图 final pin／部署清单与 ROOT 父入口实读 canonical Python pin。生产 send/receive 仍 False，未接 State，不能复用本 HOST 结果开放能力。
