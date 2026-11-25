# CLIENT readparts v6：两处线性汇总

## 固定来源与范围

仅新增 `candidate/client-readparts-v6/runtime/mta_client_baseline.py`，从固定 v5 SHA `3e1575d94020bf9e1e54a9fca2ca35876efbcb1385a15dd0bc0bfdf8ac8736ea` 复制。
ROOT actual `e55241` 完整 collect 为 4.572720683s；raw `6bc57d` 的 actors 约 2.4s（含 proc/actorimages 约 1.145s），manifest+rehash 约 .5856s。
这些是已观察阶段耗时，不足以证明 CPU bytes-copy 是瓶颈；本轮没有新设备测量或改善幅度结论。

只改 `_read_file` 与 `_actor_image` 两个循环：先建立 `parts/total`，再打开原 FD；每块校验后保存引用、累加长度，完成后一次 `b''.join(parts)`。
先分配 parts 是避免新增列表分配落在原 FD 创建与 try 之间；append/join 在原 try/finally 内，原已登记资源归属保持。
每轮 `_now`、exact bytes / count、`limit + 1 - total`、超预算拒绝、完整内容及 EOF、前后 metadata/parents、digest、raw、retain 和 FD finally 不变。
所有四个 manifest 源的初读及最后完整再哈希、两个 round 中的 actor image 完整重读均保留。没有缓存、减读、新进程、新接口、超时放宽或 STATUS 管道改动；默认预算仍为 5s。
分块引用列表和最后 join 仍可分配失败；该算法不是恒定内存或实际资源关闭证明，原失败/once-close 语义不被改为成功。

## 实际专项：首批与增量分列

首批工具 `99805f`：

```text
python -B -m unittest discover -s tests -p test_client_readparts_v6.py -v
Ran 10 tests in 0.031s
OK; host exit 0; wall 0.4743432s
```

当时 SOURCE SHA `2be0abeb9436484945c9e930a6d9b98f25e789d5a50014432bcaa8a24306090a`，tests SHA `18a65aed0c5176b9159aa4cea3a07c163c186d9d68ca33c8e953b406954c5353`。
随后只有 parts 初始化先于 open 的顺序更正和对应 exact-reverse fixture 更新；没有任何首 FAIL 被覆盖。
工具 `5b7910` 仅重跑受影响的源码逆向/AST/预算及异常/retain/once-close两个命名方法：2 项 / .020s / OK / host exit0 / wall .4372571s。
当前有 10 个不同新方法，不把首 10+增量 2 称为 12 个不同方法，也未重跑旧套测或其余 8 项。

覆盖真实两方法 over FakeIO 的多块/空/limit+1/exact 类型/超 count/metadata 变/digest 变、OSError/BaseException、retain/原 FD 一次闭合；一个新完整 collect 方法核四源初读+再读和四次 actor image。
另有精确源码逆向恢复 v5 与 Python3.5 AST。合成映像使用既有明确 Fake hash seam，所有 OS/proc/socket/Popen 路径 tripwire；不能升级实际内核、映像、FD 或性能层。

## 最终固定版本

- SOURCE：`1df29147a9cface972c9a2f486fee45c0f33d7979c6ad49dd02cdc330fe9dcc1`，543 行 / 29412 B。
- `tests/test_client_readparts_v6.py`：`7f9be6c122745cd2ad086be3232d91a301207f25ee41e84873ee899db207af0b`，200 行 / 11919 B。
- 原 v5 3e1575、core ec2d927、ProcReader 2f0ef523 全 SHA 读回未改。

仅 SOURCE/Fake，未创建 host 入口、未设备/WSL/ADB/socket/RF、未新性能或恢复验收。三文件停写交 ROOT 审阅，原生产门禁不变。
