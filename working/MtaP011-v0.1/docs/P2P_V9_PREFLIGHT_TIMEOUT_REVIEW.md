# V9 首轮 pre-RF 超时：只读因果审查

范围：只读 ROOT 实际 `logs/MtaP011-DeviceP2pV9MRoute-20261001-082419-8c70df17/result.json`/README、固定 codechain 和 private raw；仅新增本文。不改 source/pins/runner/timeout，不 ADB、RF、retry 或 recovery。

## 确定的观测

- 实际 FAIL 位于 initial-v9-prior-journals，rf_trial_invoked=false；owned run 尚未创建、journal absent，新八文件权限/readback 已通过。没有本轮 GO/地址写；全部独立 original/STA/完整 IPv4/IPv6/boot/接口/进程/actors/pending 保持通过。
- `host/device_prior_journal_readonly.py:224..235` 实际显式调用 `Adb.run(timeout=50)`，不是 `device_probe.py:50` 默认 30。私有 16 host-exit 为 TIMEOUT；15/16 文件写入时间差 50.045792 秒，是日志时间佐证，不是独立 remote stopwatch。stderr 长度 0。
- 16 stdout 33068B；仅将 CRCRLF/CRLF 归一化后为 32270B，**逐字符等于完整 V9 input payload**（source32244B＋追加 print READONLY_OK）。没有首次内容不等点，末尾就是 payload EOF；399 行均为输入 echo。
- 实际整行 `RESULT=`、`MTA_READONLY_OK`、`MTA_REMOTE_EXIT=n` 均 0，无 Traceback。源码里的 print 字符串不是执行结果。HOST 只读比对工具 `428937`，marker/时间比对 `eb700f`，原 raw 不改、不公开内容或网络标识。
- 旧 V8 同一生成框架 source31122B、最大单行3375B。新 V9 source32244B，仅第113行 PRIOR_CANDIDATES repr 超4000B，内容4500B；不是总源码超过32KiB（source本身未超过），而是单行变长。

## 优先因果与未证明部分

Linux 4.14 官方 [n_tty.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/drivers/tty/n_tty.c) L1555..1559 明确 canonical 单行上限4096（含结束字符），4095以后继续处理但不保存；L1596..1604 实现 overflow，L1277..1294 等路径处理 echo。因此完整输入 echo 与 consumer 丢字节并不矛盾。这是 primary source 行为，不是本轮已读取的 termios。

remote helper 的命令先 `exec(sys.stdin.buffer.read(payload_length))`。若这次 PTY 为 canonical，4500B内容行可能丢405B，read(32270) 在 **exec之前** 等不足字节；这精确解释“全输入echo＋50秒timeout＋零实际marker”。实际 ICANON/接收consumer字节或远端栈尚未采证，所以称最强可证伪假说，不断言已执行到 historical journal/无线模块，更不归因 radio损坏。

## 固定 PRIOR 调用链的真实成本与边界

`host/device_p2p_v9mroute.py:134..173` 生成新 pins/IDENTITY/四候选 registry，复用 V6 `PRIOR_JOURNALS`；不实例化 LinuxBackend/GoLease。`device_p2p_v6diag.py:548..590` 扫 session（最多512 names、128 matched rows），读 pending，创建一个 nl80211 reader并GET_INTERFACE；每个记录独立验证。

历史 v3 每记录 `prior3_context`（486..505）再校完整 manifest/七payload SHA，随后 `prior_baseline_matches`（508..518）重复 /proc identities、wpa_cli status、IPv4双快照与所有原基线。每个 matched journal，而非每个 unique候选，都会重新做；四 registry 项不等于只有四 journal。当前没有实际 RESULT/阶段，不能知道处理了几条或哪个子步骤耗时。

nl80211 `_request`（V9 runtime681..737）每次5秒、数据/报文数量上限；IPv4 readonly（V6 helper342..375）同socket六sequence/两完整view共8秒。`process_absent`（378..388）仅两次 lstat/identity，不 sleep或waitpid，不是进程退出等待。普通文件SHA读无整个探测 deadline；station_readonly（474..484）communicate有5秒，但 Timeout后kill后的communicate无timeout，是另一个静态风险，不是本轮已证明触发路径。整个 journal循环没有合并总deadline；即使修框架，重复读取的累计时间仍须实际测量，不能靠加host时限假放行。

## 超时后的资源事实

`device_probe.py:50..62` 只保存 HOST TimeoutExpired partial stdout/stderr/TIMEOUT，没有 remote wait/exit 身份证明。Python subprocess超时处理结束HOST adb不等于远端python/shell退出；本轮缺 remote exit marker。

既有 `actors_and_network` 的 project_trial_actor筛选只识别 candidate脚本argv＋--trial/--recover，不覆盖 `python3 -B -c ... mta-prior-readonly`。因此独立 no_project_trial_actors_after=true 不能单独证明该只读producer gone。下一次任何运行前，应由 ROOT 只读核明此 exact readonly命令/候选context 的 PID/starttime/exe及线程/子进程已退出；未知live actor保持阻断，不 global kill、不从名字猜归属。

## 最小安全下一方案（尚未实现）

1. 独立新 HOST入口/只读probe，不改旧314d7c入口或3e819 helper，不修改50秒预算、任何 exact pins/registry/PRIOR/恢复门槛。仅将四 registry 的 Python literal序列化为确定性多行；AST literal_eval须逐字段等原对象，marker/current/历史权限语义不变。
2. 生成程序与追加 completion payload 每一 UTF-8行明确限≤2048B（留低于canonical4096余量），总bytes仍限；超限在HOST拒绝，不自动truncation。覆盖所有pins/identity/registry表达式，不仅当前4500B行；格式化不可引入device新依赖或自由代码。
3. HOST证明全源码 AST3.5、原literal值及七pins完整相等、旧globals不变，并建 canonical4095内容截断模型：旧payload少405B、新多行payload无丢字节。模型是HOST证据，不能当P011 ICANON实测。
4. ROOT 先独立只读原producer gone，再用新多行 **noRF** prior probe取得唯一 actual RESULT/OK/REMOTE_EXIT、计时/固定阶段计数及全部原基线；还未到允许RF。若仍timeout，保留事实并定位实际子阶段，禁止简单加时限绕过；任何后续真实功能试验需重新完整初末门槛。

原082419 pre-RF FAIL永久保留；没有将它改成PASS或认作V9 GO-IP实际测试。本文仅源码/日志审查，不实现/执行新方案。
