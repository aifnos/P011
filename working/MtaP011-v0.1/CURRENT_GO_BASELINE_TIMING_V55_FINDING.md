# GO 基线耗时诊断（v55）

当前互传仍不可用，目标 active。小米 15 Ultra 是最终手机验收目标，但真实 GO、typed IP/DHCP、State 与双向文件链路尚未全部通过，不是仅剩手机人工。

## 为什么新增诊断

GO52 唯一实机整体 FAIL：HOST0/remote1、42.250秒，无超时；真实子入口进入后，原 stage10 的 `_snapshot_once → _pins → _proc → _check` deadline 拒绝，RF意图未观察、journal缺席。前后完整原厂/网络Snapshot.key一致、pending缺席及已观察资源闭合；未导出的Native库存不代签完整恢复。[原始分层结果及脱敏ZIP](CURRENT_GO_PIN_DIGEST_V49_RESULTS_README.md)。不原样重复该试验，也不先放宽期限。

## 诊断源码与范围

新增 Native `7251616e…`/93118 B、实际 F45 executor `400b369b…`/19893 B、17map `32d1721d…`/3951 B。主线程完整窄diff和独审通过；ROOT `e14635` 核实际17源SHA/bytes与Python3.5 AST。只替Native/executor两个源，其余15源、schema、顺序与原r5 Bootstrap保持；还没有新的建组或恢复通过证据。

Native只记最早两轮快照、每轮最多五次原时钟采样，私有保留原scope/until及当前/失败分段。不改原last、期限、额度、授权、读取、关闭门；业务原异常bare raise。F只格式化留存的有限单调样本，到已有512 B私有head及16 KiB FD2错误写中；不新增IO、public字段或readiness。观察增加少量时钟/格式化开销，elapsed包含被调用方法的关闭时间，rest合并后续步骤。

`SNAP55#1/2`：boot/actors/pins/rest分别为启动身份、进程采集、原厂文件与映像核验、网络快照尾部。`~`是失败前部分耗时，`-`是缺样本；失败阶段不是完整阶段耗时。

ROOT `0a513d` 新PC隔离诊断专项八例PASS：实际AST提取两诊断helper和一个纯formatter，仅OS clock/owner shape为明确模型；2rows/10clock总采样、last/scope/until不改、坏时钟不替换异常、partial/missing/nonfinite/regression、最坏示例head372 B。没有import目标模块或运行Native业务/旧测试/RF/设备，不能用此PC结果证明原业务流或设备十秒性能。

正式preparer `e1680d9a…`/50881 B、HOST `ce921bc1…`/34799 B已主审完整窄diff和独审；ROOT `b170ba` 默认PC通过、`a55c6e` 52实际源/2Python blob的Python3.5 AST与3blob整个载荷往返通过，4398406 B，零token SHA `f0877162c6d2511e0d5071788417e30f9bb45d570ac2462d869434fbe06adc40`。只更新两源绑定和同宽55标签，readonly51及gen12/原180/45/60/30/210/failed/finally/pending/DENIED保持。

唯一新实机 `274afd` 已开始，尚待终末。一键 [GO55 PC来源检查](HOST_MTA_GO_BASELINE_TIMING_V55_SOURCE_CHECK.cmd) 不调用ADB或设备；尚未点击重跑该一键项。所有历史失败与私有raw保持。

静态分析发现Native累计comm票据门有O(P²)成分，典型短comm直接路径展开约38次固定Loader认证/12次clock；实际认证没有重读源或再SHA。fresh Proc后还扫描累计关闭历史，baseline阶段GO Store库存为空。以上只是源码复杂度/调用计数，不是已证明的十秒首因；不据此删除fresh Proc/tasks/FD metadata/EBADF/clock/cancel或缓存ready/closed=True。

## 唯一实机结果：第二轮 pins 阶段超时

ROOT `274afd → 3d1a4c`，`results/go-baseline-timing-v55-20261002-181919-2ecdaadd`：HOST0/remote1、42.000秒、无超时，整体FAIL。20个新候选文件／实际子入口／wait exit1与独立absence已核；仍未观察RF意图、journal缺席，原stage10 deadline与restore pending保持。

| 私有测量（秒） | boot | actors | pins | rest |
| --- | ---: | ---: | ---: | ---: |
| 第一轮，完整约5.209秒 | 0.014206 | 3.601481 | 1.017338 | 0.576297 |
| 第二轮，pins中失败 | 0.015110 | 3.975919 | 部分0.800325 | 未执行完／无样本 |

第二轮`fail=pins`，结束采样相对原截止`left=-0.004024263`秒。两个actors阶段合计约7.5774秒，是本轮十秒检查中的主要时间段；该耗时含实际进程/文件系统操作及纯校验，不能据此断言全部来自Loader或库存扫描。partial pins不是完整核验时间，rest缺样本不能当零耗时。F输出的原clock/caps显示值用科学计数，有舍入；分段与left保留记录精度，不据显示end/now相减另造精确时长。

ROOT `3ae010` PC-only终核整个4398406 B原载荷／52源／三blob／六私有父件／raw/公私投影、840collector票据／40Proc generation／34datagram／31writer和2Python票据／6父FD／3子Proc generation已观察闭合。before/after各完整两轮、完整原厂及网络Snapshot.key一致、pending前后缺席；新comm缺席票据0。原整轮resource_pending=true／remote_closure_verified=false／GO=false保持，未导出Native库存不能代签完整恢复。

[GO55实际失败脱敏ZIP](results/go-baseline-timing-v55-20261002-181919-2ecdaadd/public-result.zip)：两成员1903 B，SHA `ad34a2369483d7b058082668384dbf582dbc0a7424faa43de45c715faae7f2c0`。私有原trace／耗时行和标识不进入公开ZIP。

下一新增隔离56：只拆分同一同步纯身份块的重复Loader认证，Standalone wrappers仍完整认证，Store `io.pid()`之后的原Entry认证仍保留；不跨IO/clock缓存、不减fresh Proc/完整任务/FD/EBADF/取消/期限/额度。需源码双审及新组件HOST后再实机测，不宣布性能收益或互传完成。
