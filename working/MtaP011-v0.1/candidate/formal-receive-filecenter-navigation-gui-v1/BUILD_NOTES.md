# 导航 GUI builder 源码候选

## 2026年10月5日 11时06分 ROOT 执行补充

以下是源码作者交接后的新证据，不改后文历史作者记录。ROOT 已完整审读新 builder、旧纯算法入口和三份 QML；默认 SOURCE 与唯一 PC build 均通过，没有执行旧 builder 的 main、Docker 或设备 GUI。

实际新 bundle 为 `out/mta-ui-receive-filecenter-navigation-gui-v1-a87de5c1d0e0b90b35bb2a91`。20 文件共 **4191494 B／4194304 B**，余 2810 B；SOURCE 清单 1691 B，NAV 使用 1567 B／1580 B；原 ELF 定长和其余 399 项 QRC 逐字保持。新 Validator、Runner、Worker 已完成独占源码绑定，但此时尚未执行新界面暂存或导航。

|证据层|结果|ZIP SHA-256|
|---|---|---|
|唯一新 builder 默认 SOURCE|[PASS](../../results/receive-navigation-gui-v1-source-20261005-104938-245f7a8c/public-result.zip)|`5f6c35956042b194554dfac68fadce891866125ade5f2ca45550a97b206c83c6`|
|唯一新 PC build|[PASS](../../results/receive-navigation-gui-v1-pc-build-20261005-104944-c9676942/public-result.zip)|`095e3a25e183b44ce5b2132e045a9b3d1c5e2c11ff527241311f943775f4e664`|
|系统 QtTest 文件只读清单|[PASS](../../results/navigation-qttest-inventory-v1-device-20261005-104558-ad9747e5/public-result.zip)|`c7a3e779171154778f484d365624d9ab45933e44c6ef84ff7c479b04ed3aacc0`|

QtTest 只读清单确认 `/usr/lib/qt5/qml/QtTest`、qmldir 和 libqmltestplugin.so 存在；没有导入或发送输入，因此不签插件运行、页面、触摸、Received 或手机通过。11:01 两次无线只读观察有效且相同、原厂有限前后一致，连接／广播实例 0，pending 不存在且未处置；未启动无线。这些结果不改变手机旧“连接失败”或完整恢复待验收状态。

## 历史源码作者记录

本批只新增隔离的 PC builder 源码和本文，不改已冻结 QML、19 资产、旧 builder、Factory、业务图、Worker 或 validator。作者没有执行 AST、SOURCE、测试、构建、Docker、Qt、ADB 或设备动作。下列命令仅供主代理审读后唯一执行，不是已通过的证据。

## 固定来源与最小差分

新入口 `host/build_formal_receive_filecenter_navigation_gui_v1.py` 固定读取旧 Receiver builder `host/build_formal_receive_filecenter_ui_v1.py`（16372 B，SHA-256 `a86df45cec0b15ebac54fc77fe49873bfd701528fa720d6d9f26d2bcf0fe99a3`）。只选它的固定常量及 `require`、`algorithm_source`、`pure_algorithms`、`source_inventory` 四个定义，不执行旧 imports、build、main、graph 或 suite。

沿原纯 helper seam 复用 sender-v5 的 `read_pinned`、QRC enumerator、`patch_factory_ui`、`render_template`、`write_new` 等。保持原 ELF、NAV 1580 B 槽、400 QRC 中其余 399 项逐字不变检查，以及原显式 `vk` Bridge。原几何仍由父页面拥有 800×268 区域；不加 rotation、字体或权限。

原 16 份 UI 源中仅替换 `FormalEntry.qml` 和 `toolbox/FilesPage.qml`，增加 `NavigationTest.qml`：17 源（15 QML、2 JS）加原 Bridge、原定长 ELF 共 19 payload，再加 `SOURCE.sha256` 为 20 staged files。目标仍只有 root、`mta`、`toolbox` 三目录；源候选本身只有 root、`toolbox` 两目录，二者不会混用。

这三份既有源码固定 pin：

| 源码 | 字节 | SHA-256 |
| --- | ---: | --- |
| FormalEntry.qml | 5696 | `41dc132f5a99adf05d6d1a8b363d652d2d4d7968f47d441e402cadbcad8a732a` |
| toolbox/FilesPage.qml | 11973 | `4d4deb4c57a0e90360e2f95b9ee55dfcf43e0cbe464e3441823418a43feff867` |
| NavigationTest.qml | 8731 | `efb77831d309e2deba30f646521be8d747efb8e4e05cfc72d25b8e3da0df2216` |

## 后续 PC 命令与预算

在 `D:\project\P011\working\MtaP011-v0.1` 下：

```powershell
python -I -B host/build_formal_receive_filecenter_navigation_gui_v1.py
python -I -B host/build_formal_receive_filecenter_navigation_gui_v1.py --build
```

默认 SOURCE 只核固定输入、Python 语法、17 源闭包及按实际占位符长度计算的 20 文件预算；不生成 session、不改 ELF、不新建输出。它的语法检查只针对 Python，不宣称 QML/QtTest 解析或设备通过。

只有显式 `--build` 才生成 fresh 24-hex session，且拒绝同 session 的已有输出，以独占创建新 `out/mta-ui-receive-filecenter-navigation-gui-v1-<session>`。输入全量固定 pin 读回、实际原 QRC patch/readback 和字节预算通过后才写文件。若输出中途失败，不删除或覆盖部分输出，不复用该 session。

源文本仍上限 262144 B；SOURCE 清单仍上限 4096 B；目标总资产仍上限 4 MiB；NAV 槽仍 1580 B。不放宽任一旧预算。源长度推算与最终实际渲染/清单大小必须严格相等。PC `NaviPanel.embedded.qml`、`stage-manifest.json`、`build-result.json` 不进入 target inventory。暂存不含凭据，文件模式仍文本 0400 / ELF 0500 / 目录 0700。

## 尚未接装或验收

本 builder 不接装新 validator、stage helper、Worker 或 HOST 图。既有 Worker 尚未将 `--p011-mta-navigation-qt-test-v1` 加入实际候选 argv；新 session/20-file validator 和导航 Worker/core 图绑定仍待独立授权完成。不得把 builder 的资源检查当成真正导航验收。

`NavigationTest.qml` 仅在该精确 argv 存在时才被 Loader 导入；实际 `QtTest 1.2` / `TestEvent` 插件与原 Z03 对附加 argv 的处理仍未验证。它用 actual Item 的 native `mouseClick`，不直接调用业务函数、不伪造 list 成功，不提供猜坐标或缺插件回退。

新的 PC_BUILD_ONLY 结果不签 Owner、凭据、RF、phone、物理触摸、Received 列表或原厂恢复 PASS。新 bundle 必须单独接入原受限载体及真实恢复门；本批不增加 Trial 资格，也不自动无线、音频、媒体或 dummy 文件。
