# 隔离 CLIENT init nlink2 r2（SOURCE/HOST，未执行设备）

## 来源与范围

新入口 `host/client_init_nlink2_p011.py` 机械复制原 `host/client_init_p011.py`，原完整 SHA `fda0e8b97122c7b29d3d6a2a6ab35e2e708d88c77eafc3f52b5e0e92eb36d49a` 未改。旧首轮 82fd70 在 canonical Python 读取阶段拒绝、无 staging/RF 的结果保留，不重判为通过。

ROOT ba4cb9/32403e 的只读观察为 `/usr/bin/python3.5`、root:root regular 0755、5568 B、nlink2；不是私有候选文件。原 F 的通用映像读取和原 Owner 的 watchdog `_binary` 都强制 nlink1，所以只改 host 的一次读取不能解决完整启动链。这里仅采用另一个 agent 已停写、待 ROOT 最终审批的两份隔离候选，不改任何原 runtime：

- `candidate/client-init-nlink2/runtime/mta_client_executor.py`：`9cf0226e76254639c8fb7ab2638f6270ee0091b2485d49e00c0beff47d8f8602`。
- `candidate/client-init-nlink2/runtime/mta_client_process_owner.py`：`219156a42a6598fb3e6669f191c269bfe3ac75da8f2f95190fb23b3867794b76`。

F 的新谓词只允许 nonprivate binary 的 nlink2，原 regular/root/nonwritable、完整路径、原 FD/entry、长度、ELF 与全 SHA/readback 不变；本入口该非私有二进制输入仍只来自实际 canonical Actor.exe。Owner 另严格限定 watchdog、`/usr/bin/python3.5`、root:root、nlink2，controller/其它路径/nlink3不享例外。两个谓词的候选作者专项/逆向字节复原证据由其独立交付，此文不冒称作者再次运行了那些方法。

## 新入口的最小差异

1. 固定 `SOURCE_LOCATIONS` 只覆盖 F/Owner 两项，19 个目标 runtime 名称和导入图不变，其余 17 项仍来自 `BASE/runtime`。
2. 原 STATUS driver 仍按 `99362b8c…` 从 `BASE/host/client_wpa_status_readonly.py` 载入，它的原来源图保持不变；不替换其 global pins 或复用隔离 Owner/F 改写原 STATUS 观察。
3. Python 读取的 finally 在真实一次 close 后，私有 `python_files` 保存原 ReadOwner 每条 path/FD/metadata/unknown/attempted/closed 的实际投影，包括读取被拒时已有的 fstat。即使 close 本身异常也先尝试保留投影；不把投影或 closed 布尔当恢复许可。
4. 仅当公开 stage 为 `python` 且异常 exact type 为本图 `f.ExecutorError`、code=`source_invalid` 时归类 `python_invalid`。原异常 class/完整 traceback 保留在私有 errors；别的阶段和 OSError 不误归为该原因。
5. r2 结果目录使用 `MtaP011-ClientInitNlink2-*`，不覆盖 r1 日志。公开 bool/enum shape、能力关闭、actual candidate 原字节身份、严格帧和 public-only ZIP 不变。

`HOST_CLIENT_INIT_NLINK2_SOURCE_CHECK.cmd` 默认只 `python -B host\client_init_nlink2_p011.py`，无执行标志、不枚举 ADB、不创建 target 文件、不请求 RF。显式 `--execute-reviewed --expected-driver-sha256 <新入口实际完整 SHA>` 才可能进入原有 staging/F 链，仍须 ROOT 全文审查；本轮没有调用这一模式。

新入口未改变 pending/非空私有 ROOT 阻断、caps 并发约束、完整 baseline、Owner fork gate、原线程/Actor、marker/terminal/device-last、once close、timeout unknown 或 RF TTL。SOURCE 检查通过不保证这些下一阶段门槛通过。尤其 Provider 仍保留无法表达的 BI_MIN_GCD/相同 beacon interval 约束拒绝，不能据该拒绝断言硬件不支持。

## 本轮唯一实际专项

PC `python -B -m unittest discover -s tests -p test_client_init_nlink2_p011.py -v`：工具输出 `4f98cb`，9 个新或直接受影响的方法，unittest 0.498 s，HOST exit0，首批全部 OK；没有首轮测试失败，也没有重跑原 28 项或项目全套。

覆盖 exact 2 pins/2 locations、17 BASE 来源、原 STATUS 读取路径、默认 CMD/main 不执行、Python source_invalid 归类、其它阶段与 OSError 区分、私有 metadata/关闭票据、公开 shape/能力不变、6 个复用函数 AST 不变。实际 PC 文件读取核验了新 19 图+native，并生成完整目标源码，Python3.5 AST、总量≤4MiB、每行≤2048B通过；源码生成不是执行。

目标编排方法使用明确 HOST FakeOS/Fake ReadOwner/Provider/Parent，合成 nlink2/FD77 的记录只验证诊断投影，不是 OS close/ELF/caps/RF/恢复的内核证明。专项对实际 Popen/socket/kill 设 tripwire；未启动 ADB、WSL、F、Owner child、watchdog 或网络操作。shell 元数据清单的一次 PowerShell 空管道 ParserError 不涉及源码或单测，随后只读哈希命令正常完成。

## 最终入口身份及仍未验证层

- 新 host：`fc0221b52c001d4bdb3e3976046f576c01577668b0b768e0be31ad41e36054cc`，533 行 / 33245 B。
- 新 tests：`526a91b34b05d4a07f3b478321c4c2bd0bb452a3a3df9e4563b38cf2cd5472b5`，173 行 / 10127 B。
- source-only CMD：`41b07582101f21f1674fb397ace43a46403493711bed7ce32bb813fc52e71dc7`，4 行 / 87 B。

没有生成 SOURCE 发布包、实际部署或 r2 设备结果。原 runtime/host/STATUS/历史不变；当前只是 ROOT 可审的隔离来源入口。P011 CLIENT init、normal stop、完整 restore、孤儿恢复和手机互通未由本轮验证；send_available、receive_available、phone_tested 始终 False。
