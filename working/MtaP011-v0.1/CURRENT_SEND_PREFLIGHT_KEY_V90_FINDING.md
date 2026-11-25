# 发送前任务绑定与新基线对照：v90

本轮补上了只读预检到正式发送进程之间的源码接线。它仍是未部署的候选，不是可用互传发布版；生产发送、接收和独立网络恢复验证均未开放。

后续真实手机验收对象为小米 15 Ultra。手机的 HyperOS 和原厂互传版本尚未确认，本轮不要求手机操作。

## 新增实现

- Publisher 在当前 State 的原发送 worker 中，保留并调用固定 Parent89 的原对象和 collect 方法；保留实际返回的报告、两个 EOF、一次 wait/reap 及闭合事实。观察先于原来的 20 秒本地出版期限，不续发该期限。
- 完整网络快照继续留在专用 Packet 通道。正式发送的 START 只加入最多 2048 B 的任务绑定与稳定键对照数据，不把大快照塞入原来的 8192 B 消息帧。
- 观察通道的随机标识与发送通道的随机标识分别发行，按同一个 task、epoch 和原 task/service 期限建立对应，不伪造二者相同。
- GO 私有加载图加入原 Codec85，使用 GO 自己的 Snapshot 类型。发送进程实际重新读取基线后，以原完整稳定键编码计算摘要；只有匹配才进入 Store.reserve。编码后的期限后验仍使用同一次原 baseline15 期限。
- 两次实际 Python 文件读取要求完整内容一致，且摘要与原 Parent 观察相同；装载后的 manifest 也须保持同一摘要。新增预检编排的拒绝会保留首次原异常。
- 构造结果未知、子进程未回收或关闭失败仍保留 pending，不删除历史记录，不翻转 ready 或 restored。

这些是数据对照与生命周期接线，不发行 RF、接收准入或网络恢复许可。网络字段、原厂文件摘要、完整 IPv4/IPv6 记录和 STATUS 摘要没有被删减；真实两种 STATUS 读取形式是否产生相同原始字节，仍需设备层验证。

## 冻结源码

路径均在 `candidate/go-send-preflight-key-v90/runtime/`。旧 76、82-r2、84、85、86、89 源码和旧测试结果保留。

| 文件 | 字节数 | SHA-256 |
| --- | ---: | --- |
| mta_go_send_publication.py | 45133 | 1f9d4f771d998d24677a6bc276526acaa96362a2ed508595690ad6ba19173f96 |
| mta_go_send_bridge.py | 84603 | 454bf63707c6a947b4267e7097de8ccff0d44b12b57b1b86b7f42a67956bba5a |
| mta_go_executor.py | 57481 | f2d724f8402a86490c23a698614eec7b9e8cbd1b2720e92d9b96a84192c08444 |
| mta_go_bootstrap.py | 31964 | 93bc97ccb9d83d5727c2f528f0a2934f09d8cae093591821a9bf5ad60f425697 |
| mta_go_deployment.py | 26543 | e8dc91c0a44a48d6cecf066257e79185fe590385f98300d01835edddb8114efe |

ROOT 与源码作者完成窄差分读取，独立审查复核 Publisher 和 Bridge 合同及实际 Parent 原件消费。两处发现的源码缺口在首次运行前修正；SOURCE 审查不等于运行验证。

## 验证状态

两次新 HOST 执行及结果原件审核已完成。第一次整体失败原件保留，第二次仅补测六个未触达的分支；不把两次结果合成九域整体 PASS，也不回放已走完的场景。

| 执行 | 实际结果与范围 | 原件位置 |
| --- | --- | --- |
| R1，ROOT `a0af85` | 一个新方法、九域；child1、无超时，约 1.891 秒。六个 ERROR 均是测试模型遗漏 `watchdog`，在进入新基线比较前阻断。整体 FAIL 保留；五件新 runtime 的 Python3.5 静态语法检查通过。 | [R1 失败结果包](results/go-preflight-key-v90-host-20261003-125414-5fee016b/public-result.zip) |
| R2，ROOT `0542a4` | 新的唯一方法仅补测两域、六分支；child0、无超时，约 0.516 秒。测试模型仅补上实际构造器已有的 `watchdog = controller = None`；生产五件源码未修改。目标语法检查数为 0，旧方法派发数为 0。 | [R2 限定通过结果包](results/go-preflight-key-v90-r2-host-20261003-130413-4b189ad0/public-result.zip) |

R2 实际执行原样键、route 变化、actor 变化，以及到期、取消、Codec 原函数变化六个分支。新消费与比较方法、纯 Codec/Packet 算法实际运行；Parent 进程/管道/EOF/wait/回收、平台/FD/时钟和旧 Native/Store 基线来源仍是明确模型。不能用这些模型代签实际 ARM Python、完整观察采集、真实 GO、独立恢复或小米原厂互通。

两次均各保存 16 份实际输入快照，并核与当前冻结源码逐字节、长度、SHA 一致。ROOT 和独立只读审核者核对原 raw、严格 marker、unittest summary、ZIP CRC 与成员读回，没有重跑测试。

- R1 ZIP：2609 B，SHA-256 `76bdd45be2876ac82aeab4f11e4ade1b36e4726fbd065531e170287c96f12e86`；公开包仅含 result.json 与 README.txt，失败 raw 留在私有结果目录。
- R2 ZIP：3028 B，SHA-256 `e69c445e4367142f9f03b12028b319118f53866ad3b736d30398bdc2b4e280e1`；公开包含 result.json、README.txt、stdout.raw、stderr.raw。stderr 原件为 `Ran 1 test in 0.388s / OK`。
- R2 只读原件审核：ROOT `b0af98` 与独立 `5b1823` 一致。原 R1 整体 FAIL 和旧源未改。

[一键 R2 主机检查入口](HOST_MTA_GO_PREFLIGHT_KEY_V90_R2_CHECK.cmd) 仅执行上述限定专项，不连接 ADB，也不是设备 START 脚本；本轮由 ROOT 直接运行 checker，未宣称人工点击 CMD 验收。

## 尚未完成

1. 普通 Boot 加入 Parent 角色、最终 25 源 GO 资产表和完整来源封印；`BUNDLE_MANIFEST_SHA` 仍为 None。
2. 发送结束后的独立终末恢复检查，以及 Parent 异常路径的有界回收。
3. 真正的接收准入、正式服务和工具箱同图接线。
4. P011 的旧网络恢复记录处理及实机验证，随后才是小米 15 Ultra 的原厂双向互通。

本轮没有 ADB、扫描、配对、无线配置、重启、部署或删除 pending。旧设备状态不能据此刷新；正常重启许可尚待原问题的明确答复。即使获准重启，重启本身也不构成恢复通过。

目标保持 active，尚未达到“只剩人工手机测试”。
