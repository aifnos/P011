# Actor-v5 固定只读入口

`host/client_actor_v5_readonly_p011.py` 默认 PC source-only。只有 `--execute-readonly` 与人工审定的完整 wrapper SHA 配套才能执行一次；不提供 init、staging、Store.acquire、私有子进程、接口变更或 RF 模式。

## 复用与来源

- 固定复用 host518 (`client_init_baseline_v3_p011.py`) 的 19 模块、源读取与 transport，和 profilec207 (`client_baseline_v3_performance_p011.py`) 的只读 TARGET、采集、时限、严格解析、资源库存与日志输出。两个文件全 SHA 验证，原文件不修改。
- 每次 reference 实例只覆盖 `mta_client_baseline` 的 SHA/路径为 actor-v5 `3e1575d94020bf9e1e54a9fca2ca35876efbcb1385a15dd0bc0bfdf8ac8736ea`；另外 18 项不变，包括 coref5eb、Provider8996、Storec6d4、F9cf 和 Owner219。未混入连接模块或 RESTORE-only v4；本入口不会进入这些尚缺集成的 RF 恢复流程。
- 两个 changed predicate 的注记片段按 v5 修正；六处失败分支仅保存实际比较引用，能反向还原完整 v5。原始状态不改。`snapshot_tasks` 是沿用的诊断 site 标签，在 v5 该条件实际比较稳定 key/live，不能按旧标签推断当前谓词。
- shared profile 的内部 kind 仍是 `client-v3-baseline-readonly-performance`，表示复用的计时配置，不是 baseline 源版本；actual sources/BASELINE_SHA/candidate SHA 全部按新 19 图生成。wrapper __file__ 用于该新入口完整身份 pin，不假称原 profile 字节已变。
- 仅此诊断仍为 collector/caller10秒；原 production min5、TTL20、资源/输出预算不变。输出另用 ClientActorV5Readonly 新唯一目录，原日志和 ZIP 不覆盖。

## 已有 HOST 证据

ROOT 唯一首批 `2c1010`：5 个新方法，0.950 秒，OK/exit0。覆盖唯一 baseline override/18旧pins、6注记精确逆向、实际内存19imports/exact types/raw状态、原TARGET/schema/10秒配置不变、Python3.5 AST/源4MiB和行2048限制、wrapper身份/default不执行/错误SHA在transport前拒。没有重复原 transport 或 Baseline 已通过测试。

Actor-v5 自身作者唯一 `eb16cc` 的7方法属于真实方法 overFake，不是设备读取。SOURCE 来源不同层分别记录；是否完整两轮 baseline、STATUS 和全资源闭合必须看下一次实际 raw，不能从这些测试推断。

目标仍 active。此入口不会证明 CLIENT/GO、地址、DHCP、端点、双向传输或手机互通；生产收发仍关闭。
