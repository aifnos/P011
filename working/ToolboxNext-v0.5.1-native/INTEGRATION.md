# v0.5.1 原生试用入口与安全生命周期

## 显示契约

device/ExtensionPage.qml 继承 800×268 父内容区，不加 y=106 或旋转。只有独立 runtime/NativeTrial.qml 的外层窗口为 800×480，并把内容放到 y=106，匹配当前设备。小游戏使用完整 268 高度，合并返回/选游戏/分数/暂停/重来栏，两侧 136px 控制区、中间 480×192。

参考本机 v2.4.0 的颜色/尺寸：#0f0f0f 黑底、#12cfa7 强调色、#3c3d42 按钮，主字号 28、标题 36、图标 96。引用现有 Source Han Sans SC，不捆绑字体。没有导入原厂 Style.qml，其中初始化包含亮度/设备控制副作用。

## 启动与退出

1. 主机检查唯一 ready ADB 目标；只在工具箱 candidates/sessions 目录创建内容。清单 SHA-256 决定候选路径，存在时逐文件核验，不覆盖冲突内容。
2. 设备监督进程核验原厂哈希、唯一 Z03/control_engine/weston、原厂父循环和没有旧临时菜单；原厂程序不暂停、不替换、不接收信号。
3. 后端只绑定 127.0.0.1 随机端口。本地启动者开放 30 秒一次性握手；QML 用自定义请求头。LAN、普通网页导航/表单无权取得令牌，不开放预检/CORS。令牌不写 argv、环境变量、URL 或日志。
4. ctypes 仅调用现有 quick_test_main 导出函数，不构造 Qt 私有 C++ 对象。子进程调用 Linux libc setrlimit 关闭自己的 core 输出，替代缺失 resource 模块，不更改系统设置。
5. QML 最多 600 秒正常结束；设备监督进程另有截止时间，只持有自有 Popen 子进程。USB 不在计时链路中。Stop 标记使监督进程关闭自己的 UI。
6. 退出时关 HTTP、等待 accept 线程结束、实际探测端口关闭，再关闭 LAN/音频/采样；核验原厂文件及服务/父进程，保存结果并释放自有锁。Stop 请求或 PID 存在不等于物理功能恢复。

## 固件门禁

- /usr/bin/Z03：cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a
- /usr/bin/control_engine：364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d
- /usr/bin/zyb_z03_launch.sh：7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b

哈希变化或锁残留必须检查，不能直接放宽 gate/清锁重试。新版资源重新解析了 qRegisterResourceData 和 400 个 qrc 条目，不复用旧偏移。可选 host/inspect_v240_elf.py、export_native_style.py 依赖本项目备份和 PC 私有分析包，不是普通启动前置步骤，也不进入设备依赖。

## 本轮发现并解决

- Qt 5.10 软件渲染的 Item.grabToImage 离屏路径发生垂直翻转/文字异常，用户确认物理显示正常。改用 QtTest 窗口内容截图并先完整重绘，不旋转真实 UI，不后处理截图掩盖问题。
- 一次端口关闭检查早于 accept 线程退出，结果明确记为失败。改为 join 自有线程后再探测；原始失败日志保留。
- 加入中文测试后设备 ASCII locale 导致模板读取失败，改成显式 UTF-8 读写；没改系统 locale，失败日志保留。
- 自动化使用会话独立合成文件与分数目录，人工试用使用正式用户目录；不自动截取访问码页面或用户内容，只记录固定页面事件。
- 短 POST 分包时提前拒绝导致 TCP reset；最多预读 4 KiB、四秒截止后再处理，其余上传保持有界流式，并补充分包拒绝回归。

## 未覆盖

手机至笔 LAN、真实音视频与自然结束、长时稳定、原厂所有业务、常驻入口。此包不是蓝牙修复或固件刷入。

官方接口：[Qt 5.10.1 quicktest.h](https://raw.githubusercontent.com/qt/qtdeclarative/v5.10.1/src/qmltest/quicktest.h)、[QtTest grabImage/save](https://raw.githubusercontent.com/qt/qtdeclarative/v5.10.1/src/imports/testlib/TestCase.qml)。
