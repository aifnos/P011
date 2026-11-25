# Readparts-v6 readonly 接线（未实际性能验收）

新 `host/client_readparts_v6_readonly_p011.py` 逐字复制固定 `802d3b93846f0e56e8c0c96469d6fa6a27cd833c1b71c64eeb4eeb1c5bceb4f3` 的 v5 wrapper，只作四个替换：头部版本、Baseline 路径、Baseline SHA、日志前缀。
Baseline 固定 `candidate/client-readparts-v6/runtime/mta_client_baseline.py` / `1df29147a9cface972c9a2f486fee45c0f33d7979c6ad49dd02cdc330fe9dcc1`。
原 802d、固定 c207 timing profile 和 518 reference 不改；19 源图只切换 Baseline，其余 18 pins 不动。
原两 site 的 predicate 及六 notes、TARGET/time10、parse、只读库存、默认 source-only、显式 execute-readonly + 实际 wrapper SHA 的前置门禁原样继承；没有 RF/初始化/锁/部署接口。

## 唯一 SOURCE/Fake 专项

工具 `239a1f`：`python -B -m unittest discover -s tests -p test_client_readparts_v6_readonly_p011.py -v`。
3 个新方法 / .400s / OK / host exit0 / wall .7725177s；首批无 FAIL。
覆盖四替换逐字逆向恢复 802d、新文件自身 driver SHA、19 源图固定 pin/path、六 notes 逐字逆向、实际内存模块引用及 Python3.5 AST/源码长度界限。
没有重复旧 wrapper 5 项、v6 10 项或其他套测；内存源图只导入定义、不执行 TARGET。socket/Popen/mkdir tripwire，仅读取主机固定源码。

## 最终 pins 与未验证层

- Driver `dc876207d674e950c888e7f40bd8b3dce88949e720a40fa17d0a70c5fb4a5c39`，89 行 / 4636 B。
- 新 tests `288a805614cbe8921c883fb0e8405fb94a67513ca8817f3e865aebd6b5e1debb`，85 行 / 5486 B。
- 原 802d 与 Baseline 1df 全 SHA 读回不变。

没有实际 ADB/P011、STATUS、完整基线、性能提升、恢复或手机互通新证据。该只读入口仍只输出诊断完成，不把诊断完成视作基线/恢复成功；生产能力保持关闭。
三文件停写交 ROOT 全文审阅，单次实际只读执行由 ROOT 决定，不在本专项执行。
