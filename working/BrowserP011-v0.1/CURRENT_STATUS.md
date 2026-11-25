# 当前试验状态

2026-10-20，状态：`LEGACY_BROWSER_FORMAL_INSTALL_PREPARING`。

用户最新明确“算了，不用新的了，直接用之前的老内核即可，正式安装上去”。Qt6 路线已取消并停止构建，源码/对象/原日志保留，完整 Qt6 浏览器没有编成或安装。当前改用设备原有 Qt 5.10.1 / QtWebEngine 1.4，在设置末尾第 17 项增加“浏览器”，直接加载 root 持有的外置 QML 页面，不新增 controller、SysV 服务、系统运行库或 vendor startup。旧 Qt6 菜单候选 `b5683da9…` 不安装。

旧内核新菜单候选为 `b7d3ae6d7696364970613f0a23f8eeabec39f90bdb6f807ccb6c59221b4e70d8`，以当前正式 Bili Z03 `3526b379…` 为输入，仅修改 SetMainPage 的一条 QRC 记录。前 16 项、现有 Bili 反馈入口、其余 399 条资源及记录外字节保持。外置页面路径为 `/mnt/data/p011-browser/settings/legacy/BrowserPage.qml`。当前仍在准备正式安装事务，尚未部署。安装与恢复入口位于 `settings/old-kernel/`。

用户已授权在连接的 ADB 设备上直接尝试独立浏览器，保留原厂环境。12:05 重新连接后的显式 transport 为 1；执行时仍必须重新核对设备和本轮基线。它的 boot_id 与 09:48 不同，三文件哈希一致；不跨 boot 沿用旧进程基线。

已完成的本轮设备检查：

- v2.4.0 / Linux 4.14.174 / ARMv7 / glibc 2.27 / Python 3.5.5。
- 当前 Z03 SHA-256 为 `3526b379c4083092c9c282d4d749d2e5c72d89e56730bf08c975e3222ed42896`，与现有 Bili 正式安装清单吻合；control_engine 和启动脚本哈希与 v2.4.0 记录相同。
- Z03、control_engine、Weston、ConnMan、BlueZ 等进程身份已采集；wlan0 为 up，两服务均有 D-Bus 名称归属。这不等于连接业务或无线物理验收。
- 当前 Wayland 暴露 wl_shell / xdg_shell / zxdg_shell_v6，没有 xdg_wm_base；Qt 6.8.5 官方源码仍含 wl-shell 客户端插件。
- CONFIG_NAMESPACES 未启用，低 uid namespace 探测 exit 1 / EINVAL；SECCOMP_FILTER 已启用。后续必须保留沙箱尝试与受限离线实验的区别。
- 设备 Python 中 ast / ctypes / socket / subprocess 等监督依赖可导入，json / resource 确实不可导入。
- 当前采样 MemAvailable 718040 kB，数据区约 416 MiB 空余；它们是采样值，上传前须重查。
- 29 项目标库已只读拉取到 PC 并逐项核对大小与 SHA-256，用于真实 ABI 交叉构建，未替换设备库。

已取消的新内核尝试及历史主机状态：

- 六份 Qt 6.8.5 官方源码包已下载并通过官方 SHA-256 核验。
- 独立 browser685 构建镜像已生成；GCC 11.4 target libstdc++ 已针对旧 glibc sysroot 编译，最高 GLIBC 版本要求为 2.18。新的 C++17 ARM 动态运行库探针已在本轮 P011 低 uid 65534 执行通过，实际报告 glibc 2.27 / 32 位，iostream 和动态字符串分配通过、child exit 0 / stderr 空，原厂文件及进程身份前后相同。这不是 Qt 或 Chromium 验收。
- Qt 6.8.5 主机工具及目标 Qtbase / Wayland / Declarative / ShaderTools / WebChannel 已实际编译安装。首次目标 Qt Core 构建发现 standalone libstdc++ 漏检 POSIX gthreads，`std::future` 不完整；旧日志与无线程 prefix 保留，线程版使用新 prefix 和全新 target v4 builddir，避免混用对象/PCH。
- 新线程版 C++ 运行库在 12:06 的新 boot 基线上再次由低 uid 65534 实测：thread join、promise/future、async 返回 685，child exit 0 / stderr 空，原厂文件、核心及父进程身份本轮前后相同。此轮同样没有运行 Qt/Chromium。
- Qt 6.8.5 独立 GUI / Wayland / GLES 已实际在笔上通过：uid 65534 / primary gid 44、空 supplementary groups，窗口 exposed、context created/current、Mali-T820 / OpenGL ES 3.2、GL error 0 / swap called，正常退出、私有进程为空，stock 本轮前后相同。它不包含 WebEngine、没有网页，也没有物理屏幕采集。
- 首次 GUI 以 gid 65534 失败在 EGL_NOT_INITIALIZED；固定 native EGL 对照中，root 和非 root + video(44) 均可初始化，两种 EGL API 均通过，普通低 uid/gid 则失败。仅后续子进程使用 primary gid 44；未改账户、全局组或设备节点权限。
- 首次上传在启动前因旧 Windows ADB 实际赋为 0666 被拒绝；先核对全部源 SHA，再收紧 staging 文件权限，显式恢复原上传成功进入 Qt。旧失败 ZIP 不改写。第二轮 GUI 使用逐项核验的同源硬链接建立新候选，未重复占用约 16 MiB 数据。
- 完整 WebEngine 6.8.5 / Chromium 122 未编成，按用户最新决定已停止；首次 Chromium 122 网页没有在笔上执行。最后 v9 日志同时记录了取消前的 cc1plus Killed / OOMKilled 和随后精确 Ninja SIGINT，不把整个失败都归于主动停止。原始双流及实际退出码保留在 `E:/P011-browser-build/logs/20261020-130401-207821-qt-target-webengine-v9-j12-detached/`，源码、对象及工具链未删除。
- 12:31 用系统 Python、uid 65534 / gid 44 对百度/B站做无 Cookie 的证书校验 HTTPS HEAD，TLS1.2 / HTTP200；这只证明设备当前上游网络可用，不能代替 Chromium 页面兼容、JS、视频播放验收。
- 最初本地 app 的两项 HOST_ONLY 检查通过（16 条源码边界和 4 个合成 DOM 场景），仅覆盖当时源码。后续固定公共站点、数值 DOM 指标/应用截图已加入 app/host/runtime；按用户“不要做过多测试，自己推进”，未运行新写的公共模式套件，只做必要语法检查，后续以实际编译和页面验证为准。不得把旧源检查扩大为当前 app/QML/Chromium/P011 已通过。

结果证据：

- `logs/BrowserP011-Preflight-20261020-094824-382921.private.zip`
- `logs/BrowserP011-SandboxCapability-20261020-094935.private.zip`
- `logs/BrowserP011-TargetDeps-20261020-095124.private.zip`
- `logs/BrowserP011-PythonCapability-20261020-095329.private.zip`
- `logs/BrowserP011-ABI-20261020-095752-392122.private.zip`，SHA-256 `f722bbdf819fd1e3037a8025fad2a8b33a088aaa2298b81982dcfddfdfc720f0`；原始设备执行成功，首次 HOST 把两行固定 JSON 当单对象解析而失败，仅在 HOST 读回同轮 raw 后派生确认，未重跑设备。
- `logs/BrowserP011-TargetDRM-20261020-100730-633317.private.zip`，只读补取 Mali 依赖 libdrm，SHA-256 `1d7953a6deb75ee40e410e90ef4328cba4476ba48235e10bf5b6a9d204f65a85`。
- `logs/BrowserP011-Preflight-20261020-120558-998803.private.zip`，新 transport/boot 的只读基线，SHA-256 `d7b4e4c78c6f18f7f7289066d5d4d6ba220382d952a9c5cf2c29bc2bda2cff4d`。
- `logs/BrowserP011-ABI-20261020-120640-761064.private.zip`，线程版 C++ 低 uid 实机通过，SHA-256 `c831eb5d84be76eda8ed1f205b5620b410c98da3476bb7131561d7df6e8b14e7`。
- `logs/BrowserP011-GUI-20261020-121530-670821.private.zip`，上传权限门阻止启动，SHA-256 `a06765103a03e9cef166e38e84dcf11b91d6a6746c5b726424ead97a4c8b0470`。
- `logs/BrowserP011-GUI-20261020-122042-461617.private.zip`，恢复同轮上传后真实 Qt6 / Wayland 成功、EGL 3001 / exit 2 / 进程已关闭，SHA-256 `b9fa911fbe826cc1ff55334d54400ca3ef44b2de6c507666a40e75ddab049e61`。
- `logs/BrowserP011-NativeEGL-20261020-122526-083512.private.zip`，root / 普通低 uid / video gid 的有限 native EGL 对照，SHA-256 `6b856eb33083cdb25c38ce0b5151e142d4182e40060a802a642e0a753021cbb6`。
- `logs/BrowserP011-GUI-Reuse-20261020-122724-585256.private.zip`，真实 Qt6 / Wayland / GLES 通过，SHA-256 `f890c432aca302164862ebd5f574aa8fec0f1cbf80bb3473e88aaa091109f7f6`。
- `tests/results/HOST_ONLY-4eae4026a124/host-results.json`

历史失败保留：首次 preflight 在 /proc 进程退出竞争时解析失败，原始日志保留在 094805 目录，修正空值处理后新轮通过。094824 原始 snapshot 的 platform.libc_ver 曾报告 2.4，这是 Python 可执行文件符号推断值；后续 os.confstr 实测为 glibc 2.27，原始文件不改写。

当前待完成：旧内核设置入口的正式安装、打开及退出返回检查。Qt6 构建/新内核升级已取消，不再属于待执行工作。按用户要求不扩展长时或额外测试矩阵，已通过的 Qt6Gui 不能当作新内核浏览器升级成功。
