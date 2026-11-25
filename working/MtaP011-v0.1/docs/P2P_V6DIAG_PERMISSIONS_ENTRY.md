# V6diag 固定权限规范后的独立试验入口

本文件是新入口的工程边界，不是 V6 GO/IP 实机成功报告。

## 已有事实

- 原 V6diag 候选仍为 `916a02d44aeeaf0d`，runtime SHA 为 `82bb5ba7…`。
- `053019-ffaa543c` 原试验在 prior journal 门禁失败；`rf_trial_invoked=false`。历史 FAIL 保留，V6 尚未真正调用无线试验。
- `054328-59c5c157` 只读检查完成，但 admission 仍为 false；原因是固定历史 V5 manifest 权限不符合要求，而非已经证明 carrier 失败。
- `055734-dd922b01` 只读检查确认 V5/V6 全16文件内容 pins 正确，但 manifest/runtime 为0666，native 为0700；原网络未变。
- ROOT 报告 `060853-204a0e0a` 单次固定16文件规范已完成：manifest/runtime0400、native0500，16完整 hash/identity 读回与 FD 关闭，完整原厂/双栈基线未变。它不含 RF/IP 验收。

## 为什么不再调用旧 runner

`device_p2p_v6diag.py:run_reviewed()` 把候选暂存、可能的 ADB push 与 native chmod0700 混在 RF 编排内。直接重用会破坏0500门槛；代理 Adb 或改旧模块 globals 也会改变历史执行语义。

新 `host/device_p2p_v6diag_permissions.py` 只重用旧纯函数、固定源和只读载荷：`verify_frozen`、`probe_source`、`PRIOR_JOURNALS`、`PROBE`、`JOURNAL`、`preflight_ok`、`parse_trial`、`add_independent_gates`。没有调用旧 `run_reviewed()`，没有 stage/push/chmod/chown、恢复、重试或旧全局变量修改。

## 固定身份

- 原 harness：`97f00ca99947d284921a4f382ee7c47199e40bf8e5c8de5c7cf71a33e373a93c`。
- 原 prior checker：`3e8192c9396b50e5432e21bf1754ef7bc6e3104d45af215d6591a0a120c7e617`。
- 原 permission readonly checker：`ca2ab521dd6acc12a5f9e0ff30914917c36b2992b31393d09178768f60d1c1fa`。
- 完整 V6 manifest：`916a02d44aeeaf0dcb24a3eaa57b7762fad5f503e3dabac83bed34df10780daf`。
- V6 runtime：`82bb5ba72c887608543d64018e2979cd27d6ee112036de9a701f0e5709de4faa`。
- 固定 FROZEN 为原 `052956-51ad245f/private-candidate`；V5 验证仍沿原固定 historical registry，无新迁移或恢复授权。

任何引用字节、manifest、runtime pin 或固定引用常量变化，会在构造 ADB 之前拒绝。新入口自身最终 SHA 由 ROOT 外部审查确认并在结果中测量，不以自引用摘要伪造固定代码证明。

## 唯一执行顺序

1. HOST 验证以上源、原 V5/V6 payload 与冻结身份，生成不可变 tuple capsule。
2. P011 上独立只读验证16文件：fixed exact pins/size、euid owner、单链接 regular、canonical/no-symlink、manifest/runtime0400、native0500。
3. 原 prior journal/pending 门禁，再取完整真实原厂/STA/进程/IPv4全部表和规则/IPv6基线。
4. 只创建一个全新、canonical、owner0700的 session；不创建或重推 candidate。
5. 再独立验证16文件，要求文件元数据身份摘要与首次相同，并确认本 capsule 的新 session 仍为空。
6. 再执行原 prior 门禁与完整基线；最后 fresh 基线须与首次**全部字段**相同。这最后一份才作为进入 RF 前基线。
7. 唯一调用原 V6 runtime 的 `--trial --ttl 20`，原 native pins、journal3、pending、IP creation diagnostic、地址收据和恢复条件不变。
8. 无论门禁失败、解析失败或超时，finally 仍独立读取原完整基线及**仅该 capsule session**的 `JOURNAL`；不以缓存 PASS 或 stop 请求替代恢复读回。

FD 读取使用 O_RDONLY|O_NOFOLLOW|O_NONBLOCK，前置 regular 检查、fstat、精确有界读取及额外1字节、最终 fstat/lstat 身份检查，finally关闭。NONBLOCK 防止 lstat/open 窗口被换成 FIFO 时阻塞；不是放宽文件类型。

身份摘要包含文件 dev/inode/mode/uid/gid/nlink/size/mtime/ctime；不包含会因读取变化的 atime。该摘要只用于私有 gate 比对，不发布原始元数据。

完整源载荷拒绝优化解释器。任何 FD 关闭不确定、额外文件、mode不符、journal不明或网络基线变化均拒绝 RF。目录只读验证包括项目根、candidate父目录、session父目录和各固定候选子目录。

## 命令与验收层级

ROOT 完整审查后唯一设备入口：

```powershell
python host/device_p2p_v6diag_permissions.py --execute-reviewed
```

无 `--output`、`--frozen`、任意 candidate、destination 或 command 参数；测试私有 `_output` 仅用于 HOST temporary fixture。

结果包含原解析/恢复门禁和新 permissions/reference/完整基线 gates。未来若 PASS，也只证明本轮有限 GO+IP；不证明 DHCP、BLE、文件收发、手机兼容、真实父死 watchdog 或驱动命令池健康。生产 send 仍为 false。

入口只写公开 `result.json`、`README.txt`，私有 raw 保留本地，不生成 ZIP。不得把 HOST fake 返回当实际设备结果。

专项测试命令：

```powershell
python -m unittest discover -s tests -p test_device_p2p_v6diag_permissions.py -q
```

HOST 测试覆盖 FD16、mode/owner/nlink/链接/FIFO/身份变化/完整pin/关闭失败、future引用拒绝、两轮门禁失败不RF、最后全字段基线变化不RF、原成功/失败解析与独立恢复门禁、单次TTL20、超时无重试、capsule限定journal及CLI拒绝任意输入。它们是 FakeOS/FakeAdb 与合成旧协议输出，不是 POSIX FD/真实设备/RF 验收。
