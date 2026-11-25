# 接收部署工厂 v69-r3：源码及定义启动的有限 HOST 结果

2026-10-03。真实对端已记录为小米 15 Ultra；系统及原厂互传版本尚未知。本文不把模型、服务存在或工厂存在当作无线准入、生产收发或手机互通成功。

## 本轮新增

新增 `FixedReceiveDeploymentFactory` 生产候选：消费实际接收 Handoff 的原引用和期限，收集固定来源及实时部署数据，在既定私有根下 EXCL 发布本次部署，保留实际 F37 Loader、返回值与自身文件句柄库存。部分发布失败不清旧目录、不覆盖旧候选。Bridge 只新增 Parent 尚未启动时对本次工厂库存闭合的被动查询；原 Parent 恢复分支不变。

ROOT 主审时修正三项确定的源码问题：先保留迟返回 FD 的初始身份，再检查活动期限；旧尝试存在未闭合库存时拒绝复用并聚合 pending；未返回 FD 的错误必须有原始整数 errno 才能视为已知无句柄。这三项包含在 r2，尚无工厂正向运行证据。

ROOT 本轮只读 P011 确认 `/proc/net` 是 `self/net` 符号链接，原候选的严格逐层目录门会拒绝该路径。r3 仅改为原 attempt 的数值 PID 下 `net/unix`，不放宽 symlink 门或后续原 F STATUS 门。[当前只读观察及查询失败边界](CURRENT_DEVICE_READONLY_20261003.md)。实时 profile 数据不等于 STATUS 认证；实际单线程 F 后续认证仍保留。

## 当前冻结来源

| 工件 | B | SHA-256 |
| --- | ---: | --- |
| `candidate/client-receive-factory-v69-r3/runtime/mta_client_receive_factory.py` | 54158 | `29265227937c2191e8af7a90a25ee518c87e6cb2a28162a99f883196bd9d7329` |
| `candidate/client-receive-factory-v69-r3/runtime/mta_client_receive_boot.py` | 17973 | `1c3d05c3bf588aa2b6438e6d940fd5e36e467860c1b183305566a18ed69695aa` |
| `candidate/client-receive-factory-v69/runtime/mta_client_state_bridge.py` | 21283 | `17d3c5339c1e68bf5eb68308858144d687b1b17616cbeaa0817bad91bd33b8fd` |
| `host/client_receive_state_boot_v69_r3_source_manifest.json` | 5146 | `d9d3967e05fc768cf73ad1fade16ef3fd03c0d717afc64bcfafa3bcaeaee3af9` |
| `tests/test_client_receive_boot_v69_r3.py` | 20357 | `347823f3833b02dd111ef175fd7a684804ea57f1a0bbb8ed9135a9e9d408d1a6` |
| `host/client_receive_boot_v69_check.py` | 10252 | `80dcffa2bb394648413f419d88ae5615a507a1435e17a55bac7b27689c76deb6` |
| `HOST_MTA_CLIENT_RECEIVE_BOOT_V69_CHECK.cmd` | 225 | `a33e0f3bbb105b350030b6e08724f138e58f995c71494f660e4a90d5ec3223f2` |

原 Factory69/c793、r2/5036、Boot69/1ff、旧测试/5a1c、Bridge37/0f7a、State32/c27a、F37/f3f7 和旧来源图均保留。未执行原 r2 工厂正向或旧测试，不将它们补记为运行失败。新 boot 使用固定 22 项来源，在单一 canonical F 同域内仅加载定义和纯工厂；目标根及模块名保持 v69 ABI。

## 唯一首次 HOST 专项

ROOT `32e17c` 直接运行新 checker：HOST/child exit 0，无超时，child 调用约 0.453 秒。新方法 `ReceiveBoot69Test.test_actual_fixed_boot_definitions_and_refusals` 共八个显式 HOST 情形，旧方法 0；unittest 原始输出为 `Ran 1 test in 0.274s` / `OK`。

八项为：正常固定定义加载与纯工厂构造、拒绝外部 canonical F、拒绝来源内容变化、拒绝来源模式变化、原期限到期、close 返回不确定时保留库存、不允许未列出的 mta 导入，以及拒绝同 owner 第二次启动。正常项另验证实际工厂对异型 Handoff 在进入发布前拒绝，没有伪造实际 Handoff 来取得正向发布权限。

文件系统、ABI/PID 和时钟均为明确的 in-memory HOST 模型。只运行实际 boot 定义与工厂纯构造；不构造 State/Handoff/Parent，不调用 DeploymentLoader 或工厂正向，不启动服务、进程、socket、RF、手机或设备。没有部署候选；不能以此结果签 r2 三项生产修正的运行验收、实际 ARM FD、P011 发布时间/性能或完整恢复。

ROOT `564256` 已读取实际 25 份私有输入快照并逐字/大小/hash 与当前来源核对，读取 stdout/stderr 原件、ZIP 四成员逐字及 CRC 无误；原件核对 `601493` 亦确认旧冻结来源未漂移。独立只读原件审计同样 PASS：25 项零漂移、四成员及中央/本地 CRC32 均一致，原 stdout/stderr 与旧冻结来源无变化。独立 SOURCE 审核也核最终 checker/test/boot/map 接口一致。两类复核均没有重跑方法，不扩大 HOST 结果边界。

[四成员脱敏结果 ZIP](results/client-receive-boot-v69-host-20261003-001159-e1f0b248/public-result.zip)：2977 B，SHA `9c238be31ac1841305fba997dc6030ef744200acddc9af9fd09c5a719af34e1f`。ZIP 包含结果、边界说明和本次严格白名单 stdout/stderr；私有输入不打包。CMD 已 SOURCE 检查，未点击；上述证据来自 ROOT 的一次直接 checker 调用，没有为审计重跑方法。

## 尚缺的真实接线与设备许可

State32 的构造参数已经接受工厂；Server → action → Operation → Handoff → Bridge → Factory → Parent 的源码调用链已有。当前仍缺固定 fresh-process 的 State/Server 启动 owner，消费同一 boot 域和同一个工厂；不能复用旧 test-user/旧 runtime UI 入口冒充生产启动。

State32 第 244 行仍无条件 `receive_available=False`，全文没有开启它的真实准入 producer。补启动入口、工厂存在或 HOST 通过都不能自动翻转该门；Handoff 同样要求实际准入。这不是已经可用的生产接收版本，尚非只剩手机人工验收。

GO64 整体失败、pending 及完整恢复未证保持不变。本轮窄只读确认临时记录仍在；正常重启及仅处理本次记录的用户许可仍未收到，不清记录、不重试 RF。真实 GO、IP/DHCP、P011 生命周期、双向文件传输及小米原厂互通仍需独立验证。目标保持 active，未标完成。
