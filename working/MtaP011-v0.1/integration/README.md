# 工具箱互传接入候选

只新增 `ToolboxMta-v0.1`，保留 `ToolboxNext-v0.5.1-native` 与 Bili 的全部旧文件。`materialize_toolbox.py` 仅 PC 机械复制 20 项明确源码/网页依赖；已存在的新复制件不覆盖。不运行任何归档 START、设备命令、旧 session 或共享字体。

接入结构：

```text
ToolboxMta-v0.1/device/ExtensionPage.qml
  ├─ FilesPage.qml ── Received 浏览/预览；手机互传入口
  ├─ GamesPage.qml / DashboardPage.qml（原代码固定复制）
  └─ MtaEmbedded.qml（外层无 header、无 y106、无旋转）
       └─ ../../../device/MtaHost.qml
            ├─ MtaPage / project keyboard
            └─ /v1/files 不透明 fileIds 选择
```

宿主提供两个独立 loopback 服务。新工具箱同原合同：`nextEndpoint/nextToken`（或实例 endpoint/token），复制 runtime 的 `mta_toolbox_server.State(root)` 使用 **同一个 `AREA/user`**，增加 Received 白名单目录；手机互传继续使用根 MTA `State(user_root=同一AREA/user)`。两服务 token 不能混用。复制模块均命名空间化为 `mta_toolbox_*`，不覆盖根服务的不同版本 `minhttp/p011_json`。

`ExtensionPage.qml` 的新增属性为 `mtaServiceUrl`、`mtaAccessToken`、`mtaBootstrapAllowed=false`、`hostPreview=false`，可由 context `mtaEndpoint/mtaToken` 提供。只有提供合法 loopback endpoint 和 token/明确 bootstrap，页面才接通；这不代表网络发送/接收能力通过，MTA 后端能力仍按真实结果禁用。`biliAvailable/biliRequested` 原可选接入保持不变。

`mtaHostSource` 默认引用本项目根 `../../../device/MtaHost.qml`；部署须保留该目录结构，也可由宿主明确设置受控的本地 QML URL。wrapper 通过 Loader 初始化宿主而非写死静态 import，避免不存在的父目录导致页面整体无法加载。

首页横向滑动四/五项入口；手机互传作为独立整页 800×268，文件中心新增 Received 和手机互传大按钮。MTA 内部选择文件只从根 `/v1/files` 获取不透明 id，不允许 UI 提供磁盘路径。收到目录的“文件中心”返回同用户 Received 文件浏览，音频/文本/图片仍走复制工具箱的既有受限接口。

MTA 页面离开和“文件中心”共用同一门槛：每次先调用固定 cancel，必须收到成功回复后，再读取一次新鲜 status。只有明确静止的终态、可发现/扫描/恢复均为 false、无待处理请求与网络恢复锁，才允许导航；unknown、旧 idle、连接中断、恢复 pending 都继续留页并提示。每次退出用独立 generation，endpoint/token 变化用 epoch 作废在途回调，不能用取消前的 GET 或旧凭据回复批准离开。取消失败可重试；无法确认恢复时保留页面，由外层精确 session STOP 处理，不把返回当作恢复成功。原外层 header 不与 MTA 双叠。

`TOOLBOX_SOURCE_PINS.json` 保留原复制输入 SHA256；新修改件的独立 SHA256 manifest 由 `verify_integration.py` 校验/导出，包含根 MTA QML 固定依赖。复制 runtime 不包括原 session、radio bridge 或启动脚本。目标整合 session、ARM 服务/播放器和真实设备验收由根任务接入，HOST Qt 不代表这一层通过。

2026-10-01 接入视觉修正：首页标题首先检查 `pageName===""`，即使 Loader 暂时保留旧“手机互传”项也显示“工具箱”；标题控件 `objectName` 为 `toolboxHeaderTitle`，可由实机试验断言。文件大小小于 1024 使用 B，其余自动用 KiB/MiB/GiB，不再把 16 B 显示为 0.0 KiB。

HOST 验证：`preview_integration.py` 使用真实根 MTA HTTP 服务（无 radio/network helper，能力如实禁用）与命名空间化工具箱服务，24 项检查通过，10 张 800×268 页面截图。此前整体页面已逐张检查，本次受影响的已收到文件列表与互传返回首页截图再次人工查看，QML 警告/运行错误为 0。覆盖横向首页、文件中心大按钮、同用户 Received、全内容区 MTA、不透明 fileIds、已收到返回、原游戏/仪表盘，以及旧 idle、延迟 cancel、凭据切换的退出竞态。新增首页标题、保留旧 Loader 项、仪表盘/互传返回标题、小文件实际字节与单位边界检查。静态复核 20 项原来源 SHA 不变、无共享字体、Python 3.5 AST 通过。

## P011 无 RF 页面实机证据

| 轮次 | 候选 / 原始报告 | 已确认与缺陷 |
| --- | --- | --- |
| 首轮，2026-10-01 00:51 | `0507562a70a02b1a`；项目根 `logs/MtaP011-ToolboxUi-20261001-005146-c7a4f3d2/result.json` | 自动试验 PASS、8 张 Qt 内容截图、服务与原厂独立核对通过；随后视觉检查发现返回首页图标恢复，但标题仍“手机互传”。首轮没有标题断言，不能据该 PASS 宣称全面视觉通过。原报告和图片保留，不改写。 |
| 修正版，2026-10-01 01:01 | `af24c3fe42891a33`；项目根 `logs/MtaP011-ToolboxUi-20261001-010106-8862ad20/result.json` | 自动试验 PASS、8 图；新增返回首页“工具箱”标题与 16 B 显示断言，03/08 受影响截图已查看。ui_exit=0、两个 loopback/两个服务资源退出、原厂 hashes/processes 与独立 before/after 全部一致；未信号原厂进程、未广播/扫描/切网。 |

实机试验范围是 Qt 5.10/Wayland 的合成用户目录页面与资源退出。截图来自 Qt 内容项，不是光学全设备照片，不证明物理触摸、手机发现/握手、Wi-Fi 关联、DHCP 或文件互传。两轮 `phone_interop=NOT_TESTED`；真实收/发能力安全 gate 仍关闭，不为补 UI 验收而启用网络。

## 后续人工手机验收清单（能力门槛通过后才做）

- 原网持续联网与独立恢复证明通过后，再由用户明确同意一次有界无线试验。先确认开页不会自动广播/扫描；“开始可发现”后手机才看到本机名；退出、取消和到时后确实不可发现。
- 真机扫描列表只显示本轮新鲜发现；离线项变灰且不能发送，历史缓存不冒充本轮设备。设备名与中文/英文输入显示正常；名字更新只在无 RF/传输/恢复时允许。
- 收到真实手机请求时，对照文件数和总字节；确认前不下载。拒绝、60 秒确认超时、重复/旧 requestId 都不会落盘或推进新请求。取消按钮可按、状态连续更新，恢复 pending 不误报成功。
- 接收单文件/多文件与中文文件名，笔端文件中心 Received 可见，大小不为假 0；独立文件内容/hash 与手机原文件一致。已存在同名文件不覆盖；大文件、空间不足、断连保留明确失败并只清理本次临时文件。
- completion 拆分核对实际落盘、协议 ACK、手机 UI 完成提示与独立网络恢复；ACK 丢失/恢复失败不能诱导重复发送或抹去已落盘事实。
- 长文件名、较多文件、上下滚动、两侧大按钮、弹窗/键盘取消和返回层级在真实触摸下可用；返回工具箱/文件中心保持 fresh cancel→status 门槛，标题/布局不残留。后台退出后原厂菜单、触摸、电量与网络由用户最终确认。

当前可安全做的是页面/只读能力和网络路径研究，以上人工清单不是已通过项，也不授权执行无线操作。

白名单交付证据为 `../results/toolbox-integration-static.json`、`../results/toolbox-integration-ui/` 及上述两轮根任务 `.sanitized.zip`。子任务未操作设备；根任务无 RF 页面实机已验证，真实手机互通或发送/接收实传未验证。
