# Startup 固定路径 anchors 专用钟隔离运行图

本目录已由ROOT执行一次fresh SOURCE生成，不是已实机验收版本或性能结果。helper为 `host/generate_formal_receive_startup_anchor_clock_v1.py`，从实际冻结boundary timing v1 helper（25279 B / 21e3b120007d9d4efb93ed1573c6c1a954b8facfa3a2356fddb99eaa2ae39a1a）派生；原helper、图、失败和实测记录均保留。

实际来源 definitions 固定为 `host/formal_receive_startup_boundary_timing_v1_definitions.py`（14907 B / 56e0483b0af1c9490b4415fac6f98f7e679ddf76b3db67c7bdbd1a7c88413f0b）。七个 runtime 源的前代 pins 只能从该实际 definitions 与 manifest 读取，不假定候选大小或预计 payload。

## 实际 SOURCE 输入与输出

Factory与spec已读回并绑定真实pin：

- `candidate/receive-startup-anchor-clock-v1/runtime/mta_client_receive_factory.py`：91907 B / bd6e8f65ad03bf1e18594979af21699dd97813502c4f5b6211eb6b05f026fcf5。
- `candidate/receive-startup-anchor-clock-v1/exactsource-delta.json`：5343 B / 23187b91b1aa63f851ac6b1e31517accaf197bc55b15d19350d6e896ef6eaaf5。

ROOT全文审读业务差分并绑定上述实际输入后，唯一显式生成通过。读出84份输入，10份fresh输出、8份Python源码按3.5语法解析；七源机械正逆和业务单块正逆通过。实际75角色共4166862 B／4194304 B，余27442 B；FC9保持113690 B／131072 B。没有执行运行图、旧测试、设备、无线、手机或测量性能。

实际spec顶层严格为 `schema/evidence/source/candidate/replacements` 五键，schema为 `p011-startup-anchor-clock-source-delta-v1`，只含一块anchors全文before/after及name、count=1。helper的business_factory和生成后verifier都要求一块，实算forward与逆序inverse精确回到实际packaged boundary Factory；不拿声明代替源码比较。

## 固定机械范围

实际alias根为 `/tmp/p011-mta-receive-startup-anchor-clock-v1`，physical根为 `/var/volatile/tmp/p011-mta-receive-startup-anchor-clock-v1`；输出runtime前缀为 `candidate/formal-receive-startup-anchor-clock-v1/runtime/`。新三项定义/清单使用 `formal_receive_startup_anchor_clock_v1` 名称，共十个fresh文件，不覆盖旧路径。

运行源由实际 boundary 图按 root/pins 机械派生；纯 FC 模板的两个 header 根单独 FC→anchor 替换，再插入新 verifier。make_source 从实际 boundary definitions 提取源码，不执行旧 helper 或旧 main。新 verifier 先保留 boundary→alias→FC 原验证链，再核单块源码差分及本层七源机械闭包；ORIGIN_SOURCE_PINS 继承所有旧来源、清单和冻结 helper 输入。

private35 只机械更新 executor 一条及 previous_manifest_sha256，不加入 service Owner；普通35＋helper3＋private35＋WPA＋monitor仍为75。实际字节数逐份读出、pin 核验后累计，4 MiB 原门不变，不写预计数。FileCenter 九源独立113690 B/131072 B，旧 Trial、身份、IO、10 秒 prepare 与父 cap、600+60、关闭、计时五标量和异常传播应由单块实际差分审阅保持，生成器不授予 RF/UI/手机/网络资格。

本次生成物的[原SOURCE报告](../../results/receive-startup-anchor-clock-v1-source-a8d8414d9e234f468ce569f1/SOURCE_RESULTS.zip) SHA-256为 `419d783f12417dbd4faf2ffcc6cc76c8b1ba56f4c8571d0bfedff408c8b9b8fd`。新core及独立UI薄载体各自默认SOURCE通过，ROOT唯一受影响HOST fixture也已通过。2026-10-05 10:25先行core已stage实际75及资源闭合，但在原末端prepare门FAIL；10:27新独占UI本轮真实Startup／Receiver＋FC／READY1／20秒／原关闭PASS，五原边界9.152052秒。两路径差异未定位，原core FAIL不改、不签稳定性能或手机修复；截图只读观察已查看，触摸／Files导航／完整互通仍待。实际结果统一记录在[当前状态](../../CURRENT_STATUS.md)，SOURCE仍不代签任何设备层。
