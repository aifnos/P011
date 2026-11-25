# v17 只读 STATUS source 首因注记（仅 SOURCE/Fake）

## 范围与真实来源

新增 `host/client_readonly_diagnostic_v17_p011.py` 与 `candidate/client-readonly-diagnostic-v17/status_source_notes.py`。
不覆盖冻结 v6 driver `dc876207…a5c39`、profile `c2077c…9a3c`、reference `518617…7122`、任何原 runtime、旧候选或 actual raw。
主机通过这三份固定 SHA 的纯定义复用原 19 图；STATUS 原源固定 `4f0fa751…af742`，notes 自身也先整字节 SHA 验证。

19 PINS、ENCODED 全源字节、LOADER、baseline 六 note、查询/预算/原资源/CloseProof/unknown/public schema 不变。
这不意味着整个 SOURCE 不变：新 TARGET 增加诊断安装片段与一行 private 投影；candidate kind、HOST evidence/README 标签及日志前缀明确改为 v17。
没有第 20 个源模块，没有 staging/Store acquire/CAS、F/Parent/init/restore/RF 或新设备入口。
默认 SOURCE only；实际只读仍必须显式 `--execute-readonly` 配实际新 driver SHA，须 ROOT 全文/交叉审后另授权，本文不授予执行权限。

## 最小精确增量

1. `_ReadFiles._open` 与 `_read_file` 的新内存包装保存进入前的原 ticket 数；同 args/kwargs 仅调用一次原方法，返回原引用，异常注记后 bare raise 原异常。
2. 从 SHA 固定原源码抽取 `LinuxStatusSource.read_source` 一个方法；只在原 `except BaseException as caught` 中、原 `error = caught` 前增加 `_v17_record(...)`。
   生成时检查注入点唯一、文本完整逆向及 method AST 逐项相等（除函数私有重命名及唯一 note expression）；原 finally、返回/发行引用、CloseProof、pending/错误覆盖仍原样。
3. 诊断最早保存 exact original exception 强引用与 exact original ticket 引用，仅存在运行中的原 `_ReadFiles` owner；不会把对象直接塞 RESULT。
   首 note 不被后续 read/source/close 异常覆盖；关闭失败仍可把业务异常改成原 `close_unknown`，首诊断保持原 cause，绝不改为成功。
4. private `status_readers[].source_first_failures` 按原 source `_files` 顺序一一投影，字段只含：

   - `builtin_class`：固定 builtin class 对象以 `type(error) is cls` 匹配的固定名；别名/伪装类不能升格，非列表 exact builtin 一律 `NON_BUILTIN`。
   - `errno`：仅已确认 exact builtin OSError 的原 exact int / 0..4095，否则 None。
   - `phase`：`file_open`、`file_read` 或 `source_before_finally`；未知 note 用固定 `not_available`。
   - `path_family`：固定 proc comm/cmdline/status/exe、proc directory/net unix/config、daemon image、proc other/other/not available enum。
   - `ticket_ordinal`：本调用新建原 ticket 的一基序号；无新增原 ticket 不借用前一票据，投影再核 exact 引用成员，否则 None。
   - `note_unknown`：仅诊断格式/成员证据不完整，**不参与任何 authorization、pending、闭合或成功门禁**。

`NON_BUILTIN` 不访问异常的 errno/filename/字符串；所有新 note 不包含 error str、实际 pathname/PID、地址或 argv。
保留原异常指针不等于公开 traceback；它不序列化。新注记不增加 IO、clock poll、重试、close 或清理，不吞原 OSError/BaseException。
原 source try 之外的初始化/前置 guard 异常不在此次单点注记覆盖内；无 note 不代表无错误或 STATUS 已验证。
诊断分配失败不替换原异常，尽可能标 note_unknown；它不是完整调试框架或资源恢复 authority。

公共结果继续使用既有固定 reason 码，不发布 class/errno/phase/路径族/序号；公开 ZIP 仍 exact result.json + README。
继承的 private raw 仍包含原观察/身份等私有数据，不能因为新 note 匿名就把整个 raw 当公开材料。
double exit/raw/150s HOST transport/no-timeout-kill/未知原件强引用保持；diagnostic_complete 仍不是 baseline PASS 或恢复 PASS。
原 IPv4 typed 投影到 {} 的限制未修，不签完整当前网络、干净新 boot、DHCP、手机或互传。

## 首次与精准补测（不合并批次）

首批 `8911d0`：`python -B -m unittest discover -s tests -p test_client_readonly_diagnostic_v17_host.py -v`。
8 新方法 / .895s / exit1：5 PASS、1 FAIL、2 ERROR；首结果保留。
两个 ERROR 是 Fake stat_result 缺 st_mtime_ns/st_ctime_ns exact int，被真实 metadata 拒绝；FAIL 是 fixture 字符串匹配内层 finally，不是外层 finally。
仅 tests 改成完整 Fake metadata，并精确匹配外层 finally；候选 notes/host 无修订。

定向 `67c8cc`：只跑 read-error、source-success、exact-graph 三个受影响方法，3 / .500s / OK / exit0。
8 个不同新方法分批通过；不是一次全 8 PASS，也不是 11 个不同方法。另 5、原 v6/STATUS/基线套测均未重跑。
覆盖 actual frozen definitions over FakeIO 的原 open/read exception identity、无 FD 的原 ordinal、once-close、close 覆盖前保首因、source body errno、成功原发行引用与 CloseProof、nonbuiltin spoof/privacy、SOURCE/19图/AST/严格公共 schema。
Fixture 的 source-key/actor/endpoint/namespace seam 明确为 Fake，不签实际 source/auth/socket/Proc/STATUS。
socket/Popen/open/mkdir/unlink/kill tripwire；仅内存定义和 Fake，未执行 TARGET、ADB、设备、WSL、RF、init 或恢复。

## 固定源码与停写

- Notes：`7a77e35788c9294fd38591a7797139ddf77d0cda1dfd65d6a9fdf8008711e334`，110 行 / 5335 B。
- HOST：`e2bd556d9d10fb80aeb2a2748837991336a0ba88f802635fad97d03d2cfa9a11`，121 行 / 6499 B。
- Tests：`4b65b48e0e6de119d9c37da04a636232099dac2aa30ae291e3423622046d0c40`，223 行 / 14488 B。

`83b737` 完整 readback/整 SHA 确认以上三源及 v6/profile/reference/原 STATUS/Provider 未变。
四份新文件停写交 ROOT 完整审查；无设备验收、无首因已实际取得、无恢复或新 boot 准入结论。
