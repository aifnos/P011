# Qt 6.8.5 低权限图形运行：只读审阅记录

记录日期：2026-10-20。本文是源码/ELF 及已采集权限的分析，不是新 P011 设备测试。未执行 ADB、改变用户/组/设备节点权限，也未修改其它 writer 的构建脚本。下一步由 root 先执行有限的真实 Qt6Gui/Wayland/GLES 探针，再进入 WebEngine；具体权限问题按实际 errno 判定。

## 1. 低 UID 与 DRM 节点

按 root 已采集状态，`/dev/mali0` 为 0666，`/dev/dri/card0` 为 root:video(44) / 0660，没有 renderD128。当前 `runtime/guardian.py:65-67` 在 browser child 内清 supplementary groups，再 setgid/setuid。

在没有额外 ACL 或预先传入 DRM FD 的普通 DAC 条件下，uid/gid=65534 且 supplementary groups 为空，无法直接打开 card0。它仍可按 0666 权限打开 mali0。**这不等于已证明 video 组必需**：必须先看到真实运行路径确实自行打开 card0，并记录 EACCES/相关 DRM 初始化失败；仅凭厂商库 NEEDED libdrm 无法证明每条 EGL Wayland 路径都会打开该节点。Wayland 连接 FD 的预连接传递也不自动授予 card0 的打开权限。

目标 ELF 在本轮 `E:/P011-browser-build/target-deps/usr/lib/`；身份记录在同目录上级 `device-manifest.json`。只读导入副本位于独立 Docker volume `browser685-build-20261020:/browser-work/prefix/lib/`。对该副本的 readelf/objdump 观察：

- libmali.so.0.28.0 依赖 libdrm.so.2、libwayland-client.so.0、libwayland-server.so.0，导入 drmOpen/drmGetMagic/drmAuthMagic 等。
- `alloc_device_handler`（ELF 地址 0x000e55e0）内存在 `drmOpen@plt` 调用；这是可能涉及 DRM 节点的真实代码线索，尚未证明首轮 Wayland EGL 实际进入该分支。
- 同一厂商 libmali 自带 gbm_create_device、gbm_bo_create/import/get_fd 等导出。不能据此把独立 Mesa libgbm 混入候选；厂商 GBM 对象与 EGL 的配套 ABI 需要保持。

本文不提出自动加组/chmod 或 root browser。若实际出现节点权限拒绝，应先保留默认低 UID 失败证据，再由 root 决定精确的 child 权限方案，不改变全局系统账号或设备节点。

## 2. Qt Wayland wl-shell 路径

官方 Qt Wayland **6.8 分支**源码仍包含 deprecated wl-shell feature；配置条件为 wayland_client。插件输出名为 `wl-shell-plugin`，插件类型为 `wayland-shell-integration`。默认 shell 列表含 xdg-shell、wl-shell 等；`QT_WAYLAND_SHELL_INTEGRATION=wl-shell` 可明确选择这条路径。见 [client/configure.cmake:31-34](https://raw.githubusercontent.com/qt/qtwayland/6.8/src/client/configure.cmake)、[wl-shell/CMakeLists.txt:42-50](https://raw.githubusercontent.com/qt/qtwayland/6.8/src/plugins/shellintegration/wl-shell/CMakeLists.txt)、[qwaylandintegration.cpp:364-388](https://raw.githubusercontent.com/qt/qtwayland/6.8/src/client/qwaylandintegration.cpp)。

这些引用是可访问的官方 6.8 分支，不冒充已核对的 v6.8.5 精确 tag。最后必须检查本轮构建 summary 的 wayland-client-wl-shell=ON、候选插件文件及其 ELF 依赖。Qt 版本字符串本身不证明插件已打包。该分支 shell 列表没有 xdg-shell-v6；runtime CLI 允许该字符串不代表存在对应插件，不能把历史 compositor 暴露 zxdg_shell_v6 当作可用 fallback。当前首选仍是已采集 compositor 支持的 wl_shell。

Qt Wayland-EGL 的 6.8 分支实现使用 wl_display 选择 EGL Wayland platform（优先平台接口或 EXT，必要时 eglGetDisplay），然后 eglInitialize，并用同一 EGLDisplay 创建共享 EGLContext。见 [qwaylandeglclientbufferintegration.cpp:37-74,113-118](https://raw.githubusercontent.com/qt/qtwayland/6.8/src/hardwareintegration/client/wayland-egl/qwaylandeglclientbufferintegration.cpp)。因此“建立 Wayland 连接”“成功加载 shell”“建立 EGLDisplay/context”“能展示帧”仍是不同门。

## 3. 已下载 QtWebEngine 6.8.5 的实际 GL 集成

以下是新 volume 中 `/browser-work/sources/qtwebengine-6.8.5/` 的本地源码行号，不是引用其它 Qt 版本的通用说明：

|文件与行号|观察|边界|
|---|---|---|
|src/webenginequick/api/qtwebenginequickglobal.cpp:29-55|QtWebEngineQuick::initialize 在 QGuiApplication 前建立可共享 GL 配置，必要时选择 OpenGL graphics API。|app/main.cpp:144-146 已按 AA_ShareOpenGLContexts → initialize → QGuiApplication 排序；不能据此推断驱动共享实际成功。|
|src/core/web_engine_context.cpp:400-443|共享 context 为 OpenGLES 时选择 EGL；global share context 无效时退到 disabled 路径。|这版 Linux EGL 路径不能直接套用新版本文档中“默认 ANGLE”的描述。|
|src/core/web_engine_context.cpp:1051|加入 in-process-gpu。|不能把本版 GPU 工作假定成一定存在独立 GPU helper；renderer 后代仍需正常监督。|
|src/core/ozone/gl_surface_egl_qt.cpp:43-47,68-99|复用 Qt 的 EGLDisplay/EGLConfig，初始化实际扩展，并探测 surfaceless context。|没有 renderD 并不单独构成这条共享 EGL 路径的必然失败；厂商实现内部是否需要 card0 仍待实测。|
|src/core/ozone/gl_share_context_qt.cpp:34-40,67-76|通过 QNativeInterface::QEGLContext 获取共享 native handle；缺失时终止。|Qt6Gui 单个窗口成功不等于 Chromium/Qt 跨 context 共享、pbuffer/offscreen/fence 都通过。|
|src/core/ozone/gl_context_qt.cpp:303-320|DMA-BUF 优化需 isGbmSupported，并同时存在 import、import_modifiers、MESA_export 扩展，还会进行实际小 buffer 导出验证。|不能仅凭 dmabuf protocol 或 EGL_EXT_image_dma_buf_import 一个字符串就宣称零拷贝可用。|
|src/core/ozone/gl_surface_egl_qt.cpp:57-64|按 EGLHelper 的结果统一关闭不满足要求的 DMA-BUF 扩展路径。|默认允许实现自行关闭优化；不应先强制 GBM/zero-copy/忽略 GPU blocklist。|

已采集 libmali 的静态字符串含 EGL_KHR/EXT_platform_wayland、EGL_EXT_image_dma_buf_import、EGL_KHR_fence_sync/wait_sync、EGL_KHR_surfaceless_context，并导出 eglGetPlatformDisplayEXT、eglCreateImageKHR、eglCreateSyncKHR。未在此次静态摘录看到 import_modifiers/MESA_export。**推断**：DMA-BUF 优化可能关闭，普通共享 EGL 纹理路径更值得先测。静态字符串与导出不证明当前 EGLDisplay 实际返回这些扩展，也不证明 fence/上下文共享/格式互操作正确。

## 4. 首轮结果后的具体排错顺序

1. 保留当前 uid/gid、空 supplementary groups、sandbox 请求和默认 wl-shell 的实际结果；先按缺库/插件装载、Wayland连接、shell、EGL/context、WebEngine 逐层识别第一处失败，不同时改多个环境开关。
2. 若 platform/shell 失败，先核验 payload 的 Qt Wayland platform、wl-shell 和 wayland-egl client buffer 插件及 ELF 闭包。需要时仅对这个有限 probe 增加 Qt plugin/Wayland 分类日志，不以加组处理插件缺失。
3. 若 eglInitialize 或 context 创建失败，先核实实际加载的是本轮同源 vendor EGL/GLES/libmali/libdrm 与 Qt6 私有库，保留 EGL error。若能观察到 card0 open 的 EACCES，再区分权限门；若是 EGL_BAD_MATCH、共享句柄、格式或扩展错误，不把它直接解释成组权限问题。
4. 先用真实 Qt6Gui/Wayland/GLES 探针确认当前低 UID 的显示、GL context、帧与退出，再用本地 WebEngine fixture。现 app 的共享初始化顺序已正确；若 QtGui 已过但 WebEngine 失败，重点读取 globalShareContext/QtShareGLContext/offscreen/surfaceless 及 Chromium GPU 日志，保留默认路径原件。
5. 后续若需软件对照，可分别区分 Chromium `--disable-gpu` 与 Qt Quick software backend；两者作用不同，任何对照都作为新候选/新轮证据，不把软件成功扩签为 Mali 硬件路径通过。具体试验与环境变更由 root 根据首轮错误决定。

全过程不需要修改 Weston、原厂 Qt、Z03、内核或全局设备权限。上述顺序是排错建议，当前笔上的图形运行结论仍待 root 的真实探针结果。
