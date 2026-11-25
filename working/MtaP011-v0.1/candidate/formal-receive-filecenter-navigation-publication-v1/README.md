# Publication 导航窄候选（仅源码准备）

本目录从 current navigation-anchor 候选机械派生，不覆盖旧候选、失败 CONTROL 或旧日志。
本作者仅完成 apply_patch、实际源读回、字节数/SHA 与纯文本正逆核对；未运行 Python AST、
SOURCE、合同、旧 main、构建、WSL、ADB 或设备。后续执行仅由 ROOT 负责。

## 实际绑定

- GUI20/session：a87de5c1d0e0b90b35bb2a91；复用已冻结的 Navigation GUI 与 ui_assets.py，
  不重建 ELF/QRC、不复制 validator、不新增字体、不更改 800x268 布局。
- ordinary graph：formal-receive-publication-anchor-clock-v1；defs 15660 /
  8a7ab2f16aca4b9af2660c2eb9331e9883e7f7f165e14deaf16db1195a9b68b4。
- graph75 实际 4169378 B / 4MiB；69 个实际 ORIGIN_SOURCE_PINS 按原 pin 全部读回，
  FC9 仍为独立 113690 B / 131072，不新增生产角色。
- UI Runner 85546 B：current UI Runner 85538 B 的 7 个全文字面 row / 8 处根与 pin 变更；
  原 6300 B cancelled-empty 被动 observer 字节不变。分别去掉这个方法，
  旧/新 UI Runner 精确等于各自真实 ordinary Runner 79238/79246 B。
- UI Worker 95260 B：仅实际 RUNNER_PIN、STATE_ROOT、STATE_ALIAS、CONTROL_NAME 四字面；
  CONTROL 使用新的 -formal-receive-filecenter-navigation-publication-v1，
  SESSION、validator、原 finally 与导航观察算法不变。
- exactsource-delta.json 固定 5 来源、2 候选、11 个字面 row；
  新薄 HOST 先验证真实 ordinary 图，再单独验证 UI overlay 正逆，不向原图注入虚拟源字节。

## 薄 HOST 与诊断

host/device_formal_receive_filecenter_navigation_publication_v1_check.py 仅选择旧导航
HOST 固定常量与 10 个原纯定义，不调用旧导航 main。所选函数内只改三处候选标签/CONTROL/
wire 与一处公共 README 元数据，并保严格逆 AST。真实入口仍为原 Receiver carrier 的
受限 derived main，原 GUI20 native 20/40/28、51 字段、一次 QtTest Item 点击/原取消/
新状态/Received 当前代 listing/stability、原 stock/finally 与 READY 后真实 watch/DRM
验收门保持。

仅在原 worker.run_fixed 返回后，按 generic -> 新 deadline -> 新 boundary 拼接有限
DATA 诊断。两个新 helper 仅将实际 post-import traceback 行锚 1305 改为 1336，各一次，
完整源正逆；check_active504、_fail514 保持。投影不调用 clock/业务方法/IO，不延 10s，
不续期、授权或代签运行资格。unknown 保持 unknown，不把最后边界残差叫纯 import 耗时。

默认 CMD 仅 SOURCE；TEST CMD 显式 --navigation-test。载体也保原显式 --stage-device
参数，但本次 GUI 已 stage，不建议重复。保 20 秒显示、600+60、60+60/alarm180、bootstrap2MiB、
wire6MiB 与 HOST26KiB 原预算。无自动发现、RF、claim、Session、文件打开或音频。
SOURCE 不等于 P011/导航/触摸/手机/完整网络验收；上一 core Startup 拒绝原样保留。
公共 ZIP 仅 metadata/README；私有输入、原 raw、凭据与截图不进入公共 ZIP。
