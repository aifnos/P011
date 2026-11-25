# CLIENT Provider v12 被动诊断（SOURCE / Fake）

本候选仅来自已冻结 v11 Provider `4f4cec03ddec5ec8e91f9f04ccdc91beb7e54a725a1481ba73c7045338883df6`。
原 v11 源、实机 FAIL 和日志不改；不补签恢复，原实际 IPv4 私有投影缺口仍保留。
本轮没有设备、ADB、WSL、socket、RF、20 图组合、正式 source-check 或打包执行。

## 最小差异

- 模块增加纯 `_diagnostic_error(error) -> (group, code)` 与固定枚举；Provider 以 staticmethod 暴露同一函数。
- Lease 构造只增加五键 `_diagnostic_restore`，初值全部 `not_recorded`。
- 仅实际 `LinuxClientInitLease.restore` 原 try 内标注静态 site，原 except 内保存首个 raised；正常返回不覆盖首错。
- 五键固定为 `site / stage / error_group / error_code / result`。本 Provider result 只产生 `not_recorded / raised / returned`。
- try 外原预算、sealed、无 bridge、旧 recovery budget 门禁不扩大 except 范围，保持 `not_recorded`；F 另负责原外边界诊断。
- site 是静态位置而非每个 syscall。`origin_ready_delete` 保留原 ready/delete 的 OR 短路表达式，不能仅凭该 site 判定哪一项失败。
- stage 仅取当前 exact Journal 的已存枚举；无记录为 `none`，未知为 `other`。不新增网络、快照、认证、时钟、thread 或 close 动作。

## 固定分类与秘密边界

批准 exact 域错误：core、provider、store、proc、coord、files、pending、launch、owner、alias、baseline、caps、status。
仅读取 exact 类的 `.code`，并与该已 pin 模块的固定白名单匹配；不读取 args，不 str/repr，不保存异常对象或自由类名/trace。
冻结 ProcessOwnerError 没有 `.code`，故落 `other / not_recorded`，不把 args 当固定 code。
caps 的 60 个 literal codes 来自固定 transport `df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420`，不运行时扫源码。
Python 3.5 的固定 16 个 builtin OSError 族 exact 类型固定 `os / io_error`，自定义子类落 other，不读取 args/errno；精确 KeyboardInterrupt/SystemExit/GeneratorExit 固定 `interrupt / interrupted`；未知/坏 code/诊断自身异常一律安全 fallback。
没有异常时为 `none / not_recorded`；公共五键不包含 PID、路径、FD、地址、SSID、密钥或凭据。
`returned` 只说明控制流返回，绝非网络恢复、marker 消失、原件关闭、INIT READY 或手机互通证明。

## 实际 HOST 证据（不重复旧批次）

首批：tool `5853e0`，`python -B -m unittest test_client_diagnostic_provider_v12 -v`。
10 个不同方法，5 PASS / 5 方法 ERROR（19 个主/子 ERROR），0.114s，exit 1。
错误均为旧 Fake Store 没有 v8 `_recovery_deadline` 初值；原 v11 restore 在同 fixture 也失败。
仅修该 Fake 初值为 None，并在受影响方法核最终 test Python 3.5 AST；Provider 源未因首批失败修改。
精准第二批：tool `1b455f`，只跑上述 5 个失败方法，5 PASS，0.014s，exit 0。
因此共 10 个不同方法分批通过，不是最终一次 10 PASS，也不把 patch 锚拒绝当单测/硬件失败。

首批已通过固定 60-code 比对、批准 exact 域类、纯默认构造、未知/秘密错误安全投影、Python 3.5 AST。
去掉诊断 Assign/Expr 后 restore 与 ctor AST 完全等于原源；其他既有方法字节完全相同。
真实 restore 方法 over 明示 Fake callbacks 核首错 sites、sticky first-error、BaseException 重抛、原预算 finally、旧/新调用顺序与 clock 数相等。
Fake `returned` 用例仍 cleanup_complete=False；Fake Store/reader/bridge callbacks 不是真实发行者、内核或生产恢复证据。
没有读取或模拟原 ELF/网络来构造 P011 PASS，send/receive 默认门禁仍关闭。
独立审查后仅将 OS 的 isinstance 分支改成固定 builtin exact tuple；tool `99783d` 只重跑该秘密分类方法，1 PASS，0.016s，exit 0，含 builtin PermissionError / 自定义 OSError 子类和最终 Python 3.5 AST。
10 个不同方法数量不变；前两批历史保留，没有第三次全批重跑。
LinuxLease 自有 ctor 绕过 Phase ctor，未初始化 `_diagnostic_start`；实际 start 的记录 setter 可产生该值，未访问时 F getattr 默认安全 not_recorded。此轮不补启动初值，不把“尚无记录”伪造为已观测错误。

## 冻结点

初次交审 Provider `1bf7cae3...343dd0`、专项 `aed81810...fcc7e` 为窄 OS 修正前快照，不作为当前源码 pin。
最终 Provider：`17e09c40d4c04c048b46e50de1151a97726086c0b43cace8a0c7e5fd3d7eb288`（1421 行）。
最终专项：`e51e4a17f1aba2969802d2c77962e7e9ef9eacf0a29c618b8f21b5e383f7238a`（271 行）。
F/Phase 由 Protocol 独占，本文件不替代它们的 SOURCE 审核、有限 stderr 上限或后续设备验收。
