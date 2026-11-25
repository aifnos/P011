# GO 重复来源检查优化（v56 / v56-r2）

最新后续（2026-10-03）：v58只调首基线内部stage10→15，其唯一实机已终末HOST0 / remote1、39.312秒无超时整体FAIL；第二partial `_pins→_proc` 的 `native_actor_unknown` 剩6.482050秒，非deadline，原F没有导出具体Proc子原因，不能猜IO / task / history_closed或设备损坏。ROOT已核完整前后基线 / pending缺席及已观察库存闭合，但RF intent=false、journal=None、resource_pending=true、whole / fullNativeRestore=false保留，58实际原件独审已核与ROOT一致，仅原件审计PASS，整轮FAIL及未导出的Native资源未知保持。下一仅私有Proc诊断设计，不改cap、不执行新trial。

HOST59期限边界唯一方法9case / 4发行 / 7拒绝首次PASS，28快照、raw和四成员ZIP已经ROOT与实际原件独审核。until301为HOST模型，不证明实机45秒baseline、性能、late_begin或restore，不能补签GO58整体通过。[后续单变量范围与准确回执](CURRENT_GO_BASELINE_BUDGET_V58_FINDING.md)。原56-r2 / GO58实机整体FAIL与本文件历史记录保持，不跨层合成成功；生产false、目标active、尚非仅人工。

互传目标仍 active，生产收发仍禁用。最终手机已记录为小米 15 Ultra；目前不需要手机操作，实际官方互通尚未验收。

## 已有实机依据

GO55 唯一实机整体 FAIL：HOST0 / remote1、42.000 秒，无主机超时；原 stage10 第二轮 pins 在截止门拒绝。第一轮完整约 5.209 秒，两轮 actors 分别约 3.601 / 3.976 秒。actors 包含实际 IO 与纯校验，并未证明全部耗时来自来源认证。[GO55 测量、恢复边界与脱敏 ZIP](CURRENT_GO_BASELINE_TIMING_V55_FINDING.md)。本阶段不原样重复 GO52 / GO55，不先扩大十秒期限。

## v56 源码检查：不是性能通过

17 源图只变 executor、Store、Native 三行。ROOT `cbac41` 完整窄 diff 与精确 SHA/bytes 读回；`07e21c` 核 17 实际来源的 Python 3.5 AST、原 Entry / Store 检查正文的 AST 等值，以及 standalone wrapper 原认证保持，均通过。未 import、执行目标业务或部署 v56。

该冻结源码为 Native `da39f571…` / 97764 B、executor `c6d9f6be…` / 20295 B、Store `52f1b8a7…` / 66301 B、map `b314af3f…` / 3951 B。旧稿 `7045d8b5…` / `b82c9630…` 从未执行，不作验收依据。

优化仅拟合并同一同步纯身份块里两次重复来源认证。原 predicate 正文、fresh Proc / tasks、FD metadata / EBADF、时钟 / 取消 / 截止 / 额度不减；Store PID 查询后仍保留完整 Entry 重新认证。独立 Entry / Store 调用仍各自走完整来源 wrapper，不缓存 ready 或 closed=True。

## 独审发现及 r2 修正范围

最终 SOURCE 独审发现具体实例方法替换缺口：v56 guard 检查 Budget 与 Reader 方法，却没有检查 Entry `_context` / Store `_owner` wrapper 是否仍是原 bound 方法。快路径因此可能绕过原 B 调用，并把实例 override 延迟到 PID 查询后的 D；D 也不再保证实际完整认证。该反例属于实例方法连续性，不应归为任意全局篡改。

v56 保留冻结，不执行。另建 v56-r2 Native 与 map，复用冻结 executor / Store；仅把上述两个 wrapper 原函数在定义时保留，并在纯 guard 核 exact bound 方法、`__self__` / `__func__` identity。未知对象或方法替换仍回到旧完整路径，不增加权限、不改原错误或失败顺序。本修正尚待最终 SOURCE / AST / 新 HOST / 实机；不能宣称优化收益。

追加 r2 SOURCE：Native `429e0638dd82836d573a8744ca58b4cd2758cc4af24185015fa3fee66fc08787` / 98562 B；map `a7d6e6704b04cd606b3a1da7c48ca7b5fe86eb118a934686cb96fd6beba862bf` / 3954 B。ROOT `4f1f9c` 完整对 v56 窄 diff、17 实际源 / 三行变化 / Python3.5 AST 通过；独审复核原件、正文、bound 方法 guard 及失败顺序，无新的确定阻断。原时钟 / 取消 / scope / quota / Proc / FD / closure 代码不变，未知形状仍旧 wrappers；正常实际 Native owner 静态认证 4→2，standalone 保持。新增 `O(R+G)` 遍历，不消除已有库存遍历；未 import / HOST / 设备，不承诺任意 class / globals 篡改等价或性能收益。父入口与新 HOST 在制。

追加父入口：preparer `b04ee838…` / 50879 B、HOST `85d663aa…` / 34785 B 经 ROOT `f51330` 完整窄 diff 与独审。readonly51、gen12、180 / 45 / 60 / 30 / 210 秒、原 baseline10、失败 finally / pending / DENIED 不变。ROOT 默认 PC `097c90` 与 `154bd5` 的 52 源 / 两 Python blob AST、三 blob 全载荷往返通过；载荷 4406921 B、零 token SHA `dd3ba5e497539179e96736a9fa788f0dc5bc0ccc6101ab9efa779bdae81ffab1`，没有 ADB 或目标模块业务执行。

新增 [r2 一键 PC 来源检查](HOST_MTA_GO_OWNER_COALESCE_V56_R2_SOURCE_CHECK.cmd) 只做来源检查，不调用设备或重跑 HOST 方法；一键文件尚未点击。

## HOST57 首次整体失败：保留原判，只补四子例

最终 test `152ed70e…` / 22460 B、checker `3ffcac9d…` / 21868 B 已 ROOT 全文 / `6cca8a` PC AST 与独审。唯一首次 ROOT `3d4337`：exit1、无超时、3.578 秒，结果 `results/go-owner-coalesce-v57-host-model-20261002-190354-cb8c0df6`，整体 FAIL。

私有原 stderr 4536 B、SHA `9633a4d717ea5c594298a91a62a14a018af0b6b3b4bd451c56ff9834433a9a77`：两域 `store_rows_changed` 实际原 `GoStoreError: wrong_owner` 未被只捕获 `GoSourceError` 的测试夹具接住；两域 `pid_changes_source` 漏了已准备 hook 的分支而落到 `HOST unlisted case`。最后汇总为 42 != 38。其余 38 子例完成有限模型断言，包括正常调用次数与动态 wrapper 回调；未形成整批 PASS，不回写原结果的 false 字段。

ROOT `b8f7da` 核 30 私有原件快照 / 当前字节、两实际 map / 20 distinct 生产源、stdout / stderr / 公私字段及 ZIP；独审正在复核。失败 [脱敏结果 ZIP](results/go-owner-coalesce-v57-host-model-20261002-190354-cb8c0df6/public-result.zip) 两成员 6050 B、SHA `220dbb48f8404f2c427961d775421191652293c38016d16b2dff2cbb3d08be1b`；异常路径与 raw 留在本地私有层。

追加独立离线审计已完成：30 私有输入与当前冻结字节零 mismatch，ZIP 两成员字节 / length / CRC 及 stdout / stderr SHA 相符。原 whole false、计数 null、平台 / RF / 恢复 / throughput false 保持。38 已完成是每域 19 个有限模型子例 / 合计 36 个拒绝后验，不是唯一方法 PASS；Store 两原拒绝已出现但后验未完成，PID 两例在业务调用前停止。未执行或重跑方法。

生产 56-r2 原件与父入口保持不变。另制 HOST57-r2 仅补这两个受影响 case × 两域 = 四子例，不重跑已完成 38 子例或旧方法；尚待冻结、双审与 ROOT 首测。新四例不能包装为新 42 全套通过。笔端候选暂未启动。

## 历史下一步及测试边界（v57 首测前，非当前计划）

新 HOST57 将用两套独立实际源图和真实来源认证的透明计数转发，对照正常调用次数与拒绝顺序；明确 OS model，不冒充 P011 IO。覆盖实例方法替换、动态 ticket / Budget / Reader / equality 回调、PID 回调后来源变化及原 clock / deadline / cancel。仅执行一个新增方法，不重跑旧方法，不运行 Bootstrap.run / reserve / 无线。

通过组件检查、父入口双审与完整载荷预检后，才进行新的有限笔端候选对照。原厂、网络、已观察资源和未导出原生库存分别报告；前后基线相同不代签完整恢复。真实 GO / typed IP-DHCP / State / 文件中心 / 手机双向仍有自主工作，尚非仅剩人工。

## HOST57-r2 前置期限夹具失败：四个受影响调用未到达

ROOT 唯一首测 `5b8555`：host1、无超时、0.515 秒，结果 `results/go-owner-coalesce-v57-r2-host-model-20261002-191245-6648b4ee`，整体 FAIL。四个子例都在前置 `original_io_deadline` 断言停止：期望11.0，实际4.0。F._entry 已执行原 observe_self，固定 clock1 的局部片段是 `min(original_until, clock + 3)`；并未进入 `_begin10`。因此四个受影响 Native._owner 调用均为0，不能由这次失败推生产缺口。原 r2 test / checker / raw / FAIL 全部保持，不重设字段或延长期限来满足夹具。

## HOST57-r3 仅四受影响子例 PASS：不重跑已完成38例

隔离 r3 仅把上述前置期望改为原 Entry 的局部 deadline4，保原后验与固定 GO55 / GO56-r2 两实际图、20 distinct生产源、30私有输入、HOST120。唯一方法 `GoOwnerCoalesceV57R3Tests.test_store_rows_and_post_pid_refusals_preserve_original_entry_slice` 完成4 affected / 4 refused，经 ROOT `8ff62c` 和独审核验 PASS。

两种 case 各在两图运行：Store rows替换精确拒绝原 `GoStoreError / wrong_owner`；PID case只安装并真实forward原model io.pid，后续原Entry D认证拒绝来源变化，旧4 / 新2实际authenticate calls、一次PID / 一次mutation及原失败原件均保留。没有run / reserve / actors / pins / RF / 恢复，Linux / FD / Proc / clock仍是显式HOST模型，不是实机十秒性能、物理闭合或完整恢复证据。

原stdout112 B SHA `c26d617c167a5d86f0e16aa38d8ed6903c3dda670bd69b53432e495778f151eb`；原stderr100 B SHA `a2c5f428cb5ce87f089e0b1fdcdd6fdb124ad8f3b24d2c86ab22f461f260ac81`。[r3脱敏结果ZIP](results/go-owner-coalesce-v57-r3-host-model-20261002-191704-13b1777f/public-result.zip) 四成员6442 B SHA `ed77dfeb816aebfc857d872676f38472623305cd4531a6deff42b38cbd6a43d8`。原首57整体FAIL与r2前置FAIL分别保留；首57完成的38子例未重跑，不合成新42全套PASS。

## GO56-r2 唯一实机终末 FAIL：第二轮尾段未完成

唯一ROOT `bd8705` / session54795 → `5a669f` 实际结果 `results/go-owner-coalesce-v56-r2-20261002-192232-e005dcae`：HOST0 / remote1、41.094秒、无超时，整体FAIL。第一轮完整私有计时为 boot0.01046304、actors2.933919、pins0.871657、rest0.4899021，合计约4.30594秒，left5.691508。第二轮在rest达到原baseline stage10截止，left=-0.02203603；实际链为 `_stock_status→_unix→_record→_check`，在Unix factory调用前拒绝，第二轮tail不完整。该负余量不是完成全部剩余校验所需时间，不能表述为“仅差22ms即可完整通过”，也不据此承诺十秒性能。

ROOT `075b7f` 已离线核52实际源 / 4406921 B载荷 / 6副本及原raw；840collector + 40Proc、34datagram、31writer + 2Python、6parentFD + 3childProc已观察库存闭合；完整前后Snapshot.key相同、pending前后缺席。独立SOURCE / read / hash / ZIP / raw审计也已核52源、载荷三blob及原资源库存一致。只是实际原件审计通过，整轮FAIL和完整Native恢复false均保持。上述已观察父端及readonly事实不代签未导出Native原件库存。实际RF intent=false、journal=None、resource_pending=true，whole / full native restore=false保持。

原私有childstderr1097 B SHA `c628341cea2aee1d9b321fcc1398ac78fc5718d163da3f9cc766e98901706eb3`；[56-r2实机失败脱敏ZIP](results/go-owner-coalesce-v56-r2-20261002-192232-e005dcae/public-result.zip) 两成员1903 B SHA `c1bda5e9fec55bf5b6f3f01aa12acdc14825eddd809d5a85d0fe6a3a5d3582ef`。没有改写旧源码、FAIL或raw，不将基线相同包装为完整恢复。

## 当前后续范围

下一方案仍待性能与资源预算评估，不承诺原10秒可达，不声明某一新候选已经决定或正在制作。目标active、生产收发false；真实GO / typed IP-DHCP / State / 文件中心 / 小米15 Ultra原厂双向仍有自主工作，尚非仅剩手机人工。以上HOST组件、实机入口、只读基线、已观察关闭与未导出原生恢复分别验收，不跨层合并成功。
