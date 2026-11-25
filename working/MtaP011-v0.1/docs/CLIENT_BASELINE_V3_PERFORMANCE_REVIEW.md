# v3 首 baseline 固定只读耗时取证

旧v3唯一actual `bace0b/165a08`、日志 `MtaP011-ClientInitBaselineV3-20261001-162402-917fdb03`
以 BaselineError deadline 拒绝，writes0/parentNone/staging/RFfalse。它不是accepted baseline；
没有再出现 ipv6_format，也没有实际证明旧r2 actor_changed 的根因。旧结果/源保持原样。

## 仅此新入口的差异

- 逐字复制已审5f诊断，再引用新v3host518、original Baseline ed416。
  同19图，F9cf/Owner219/coref5eb；旧原STATUS来源/transport/full pins不变。
- 私有内存派生原4个actor_changed真分支注记照旧，再给两个snapshot_changed真分支
  添加 `snapshot_identity`、`snapshot_tasks` 与exact两Snapshot引用。原谓词/返回/失败不改。
  每个替换唯一一次，反向能逐字还原ed416。没有改变raw state或core持久CAS。
- 只在这个只读TARGET将 Provider已有 `_collector_factory` seam设为固定实例
  `pm._AuthenticatedCollector(p,10)`，caller snapshot now+10。原Provider min5和原host期限不改。
- 该实例固定包装 collect/_proc/actor_image/actors/interfaces/status/ipv4/ipv6，
  binary _read_file 前4项manifest、后4项rehash；非binary comm读不逐条计时。
  记录真实单调begin/end/elapsed及returned/raised，原返回对象和异常不改变。
  至多128条；时间异常/超限会使timing无效，不伪造耗时或观察成功。
- 计时是nested inclusive：actors包含其actor_image/proc，collect包含全部读取和finally关闭，
  不把嵌套阶段相加冒充total，不把elapsed解释成CPU time或优化后的速度。

## 安全与证据边界

默认PC source-check；仅ROOT审核新SHA后显式execute-readonly才固定ADB一次。
范围仍platform/旧pending只读门禁、canonical Python完整ELF/readclose、pure assemble/executoridentity、
首snapshot后立即结束。无mkdir/stage/Store.acquire/锁/Parent/F/controller/interface/RF/信号。
原raw/关闭库存/failedrow unknown如5f保留；公开只有固定bool/enum/count，耗时毫秒是实际计数。
私有保存有限阶段时间及原两Snapshot/观察。key同/identity同/live/rawtasks不同分别报告；
任何记录都不等于baseline accepted、正常恢复或互传/手机验收。
源4MiB/单行2048，raw16MiB/RESULT12MiB及严格PTY完整echo/3帧沿5f不变；native/ELF只有摘要。

## HOST

唯一首批工具 `fb1c7b`：
`python -B -m unittest discover -s tests -p test_client_baseline_v3_performance_p011.py -v`，
5方法 / unittest0.428s / OK / host exit0（工具wall0.847s）。首批无失败，无重跑。
包括6site精确逆向、真实collect方法overFake的两snapshot失败分支仍拒绝、
factory固定10s与嵌套timing保留原返回/异常、PC19图/source生成/Python3.5 AST/无mutation，
默认source-only与旧5f/8996全pin、原生产min5不变。
这是纯SOURCE/Fake证据，不是实际耗时/STATUS/网络或P011结果。
无作者设备/WSL/实际socket/RF，不重跑旧专项，不checkpoint；此后停写待ROOT审/一次取证。
