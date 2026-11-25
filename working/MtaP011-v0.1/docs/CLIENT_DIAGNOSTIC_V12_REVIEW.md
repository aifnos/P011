# CLIENT v12 非秘密诊断隔离候选

本次仅 SOURCE / HOST Fake。v11 实机 FAIL、ready=false、done=false 的历史结果不改判；v12 未部署、未运行 P011、未验手机收发，生产 send/receive 门禁仍 false。

## 来源与范围

- F 副本：`candidate/client-diagnostic-v12/runtime/mta_client_executor.py`，来源冻结 v11 `1e8e1632b9170964f8471f106a50988e2d75ccfba7b1c5ed49a604323d481e43`。
- Phase 副本：同目录 `mta_client_two_phase_lease.py`，来源冻结 v10 `cc402317c4d07a37d82f2209f32bc688a212d04a1a3ec8fccdc95aa6ce6209d1`。
- 只增被动诊断；原 F 的 20 模块名称/顺序、Parent、Loader、watchdog、main、stdout `_public` schema 未改。
- Phase.start 原调用/短路/资源登记/锁/准备20秒与 RF TTL20 顺序未改；restore、Bridge、`_role` 不改。Provider 专用 restore 诊断由另一作者提供，不能把本批 Fake 视为该真实组件整合测试。

## 私有被动合同

`_diagnostic_start` / `_diagnostic_restore` 的 exact dict 只有 `site, stage, error_group, error_code, result` 五键。site 是对应流程的固定枚举；stage 是 core._STAGES 或 none/not_recorded/other；result 是 not_recorded/returned/raised/passed/rejected。none 仅表示确实无 Journal；other 表示未知形状；未访问不补假 False。

异常分类使用已固定 Provider 的纯 `_diagnostic_error(error)` / `_DIAGNOSTIC_GROUP_CODES`，按 exact 类型及对应固定 codes；F 的 exact ExecutorError 另有本地白名单。Phase 的 exact ClientInitError 使用 core._CODES。冻结 Owner 无安全 code 字段时不读 args，回落 other/not_recorded。任意子类、自由字符串、未知代码不能透出；没有 str/repr、traceback、errno 原文、路径、PID、MAC、SSID、密钥或 Actor 标识。

F 在 restore 前复制启动五键及白名单 reason，后续 mutable Phase 原对象/reason 变化不能覆盖首因。启动未完成、restore 返还、restore 抛错、`_complete` 首拒绝谓词分别记录；returned 并不证明恢复完成。诊断不构造 FinishReceipt，也不签内核/网络事实。

`_complete` 只将原 or 短路链展开，保存正在检验的固定 predicate；每个原谓词仍至多执行一次、同顺序，原 authentication、clock、CloseProof、Owner/Proc/继承 ELF 的 EBADF 观察没有减少或增加。False 与异常分别为 rejected / raised，既有 complete/pending 判定不变。

## stderr 与失败边界

恢复尝试结束后，仅一次既有 stderr FD=2 的 write：至多 start/restore/complete/final 四个 ASCII 行，每行含换行最多384字节，总计最多1536。短写/抛错不重试、不新增 FD/socket/thread；全部诊断错误单独吞掉，不加业务 failure、不阻此前恢复、不改业务成功帧。Parent 仍完整排空原 stderr，仅将其作为证据，绝不将它当 stdout 成功协议。

内存/输出诊断不是崩溃持久日志。loader/bootstrap 在原 try 外失败、进程在恢复后输出前死亡、诊断本身无法构造/输出时，仍可能没有这些事件；不能由 missing 倒推未发生 RF/持久化。最终 restore_pending 仍不足以断言内核/设备故障。

## 真实测试批次（不重复已通过旧套）

PC CPython3.12，`python -B`；仅新 `tests/test_client_diagnostic_v12.py`，使用固定旧测试夹具但调用新隔离类，FakeIO/FakeKernel/合成 Snapshot/私有 classifier seam；不是实际 Linux Provider 或20图部署验收。actual Popen/socket/CDLL/process/默认 Linux I/O 均 tripwire 禁止。

1. `40e800`：早期 AST 检查发现新增多行三元表达式漏括号，SyntaxError；该 shell 后续 rg 使整体 exit0，不记为 AST PASS。修括号后 `1415fb` AST3.5 PASS/exit0。
2. `f6bf50`：首次新22方法，1.043s/exit1：10 PASS、12 ERROR。12 个 ERROR 全在 F 测试 FunctionType 夹具漏原默认参数，未进入 F 业务。通过的 Phase5、SOURCE4、default1不重跑。
3. `ac4aec`：精确重跑命令的 PowerShell quoting 解析 SyntaxError，0方法/exit1；保留，不算单测或设备失败。
4. `31e2c0`：仅修夹具 argdefs，精确12受影响 F 方法，0.020s/OK/exit0。包括 stdout/clock/auth/closure 对照、首因冻结、restore/complete 分离、短路、诊断异常/短写与隐私拒绝。
5. `213ff2`：将未知诊断 group 明示 not_recorded 而非 none 后，仅1个受影响 schema 回归，0.004s/OK/exit0；无业务门禁修改。

共22个不同新方法已分批通过，不称最后整批22通过，不累计为35个方法，不重跑项目/旧TLS/设备测试。AST 检查证明 Parent/Loader/watchdog/main/public 不变；Phase.start 剥离纯诊断赋值/记录后与原算法 AST 一致，restore 和 Bridge 字节一致。

本次没有 SOURCE 图检查、打包、OS/WSL/ADB/RF、挂载/权限/系统链接修改、旧 pending 操作或手机试验。最终 SHA 由交付读回工具列出，等待 ROOT 与独立源审后才决定是否整合。
