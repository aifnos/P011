# P011 PlayLab 1.2：显示布局修复与截屏记录

适用对象：已验证 root ADB 的碳氧 P011，固件 `z031_v2.1.2-20221124_143128-user`。
电脑工作目录固定采用 `D:\project\P011`。设备端只使用 `/tmp/p011-playlab-v12`。

## 1. 安装与本轮测试

把整个 ZIP 解压到 `D:\project\P011`，使本文件位于 `D:\project\P011\PlayLab\README.md`。
用新包完整覆盖旧 PlayLab 目录中的同名文件，不要仅替换 PS1。
固件备份和已有 logs 不会被此包自动移动或删除。旧版 Demo 如仍运行，先等待其退出。
不需要重新安装驱动，不关机进入 AutoD，不安装 Python 模块。

```powershell
Set-Location 'D:\project\P011'
$lab = 'D:\project\P011\PlayLab'
$run = [scriptblock]::Create((Get-Content -LiteralPath "$lab\P011-PlayLab.ps1" -Raw -Encoding UTF8))
& $run -Mode Calibrate -WorkRoot 'D:\project\P011' -PackageDir $lab -Seconds 90 -Rotate 0 -Fit p011 -RecordEvery 10
```

校准页只是应用内的显示/点击测试，不修改触摸驱动或校准参数。
四个角标 1/2/3/4、外框、顶栏应完整可见；点击角标会变绿。
点“返回”可进入时钟/计时器/贪吃蛇。顶栏“截屏”保存当前帧；“退出”只结束本程序。
程序约 90 秒自动退出，额外本进程 watchdog 在卡住时退出；不结束 Z03、Weston 或其他 Python 进程。
结束后自动把截屏及日志拉回电脑，最后显示 `ZIP:`。

正常 Demo 可改用 `-Mode Demo`。`-Rotate auto` 在此版本对 P011 固定选择 0，不再依据窗口宽高猜测角度。
`-Fit p011` 沿用 800×480 画布中的 800×268 活动区，y=106。该布局来自原厂资源，不意味着已经完成实机可见区域验证。

## 2. 修复内容

旧版只在 `SDL_PollEvent` 循环之前查询一次 `SDL_GetWindowSize`，由该尺寸永久计算缩放和目标矩形；它不查询渲染器输出像素大小，也不随窗口配置更新坐标。
收到的旧日志是 `DISPLAY=480x800 ROTATE=0 FIT=p011`，而照片显示界面缩小并被裁切；旧日志没有后续尺寸或 viewport，不能单靠旧日志确定最终帧尺寸。

新版：
- 使用 800×480 的逻辑画布作为窗口申请值，而非把原始 480×800 输出模式直接等同于最终窗口；全屏最终尺寸仍由 SDL/Wayland 决定。
- 先分派窗口事件，每帧重新读取窗口大小和 `SDL_GetRendererOutputSize`。
- 尺寸变化后重算目标矩形、重设 renderer viewport/scale。
- 使用同一份 Geometry 对象计算绘制与触摸/鼠标坐标的逆变换。
- 记录原始显示模式、实际窗口、渲染器、viewport、resize 事件和应用内点击坐标。
- 自动截图在首次稳定显示、页切换、点击及定时发生；上限 40 次、约 64 MiB 图片数据，每次间隔至少 0.9 秒。

这修正了已确认的代码缺陷；P011 的最终物理输出和触摸仍需实机验证。

## 3. 应用内截屏：默认开启

每次截图包含：

|文件|来源|
|---|---|
|`*-render.png`|SDL_RenderReadPixels 读取的渲染器像素，位于 RenderPresent 之前|
|`*-canvas.png`|缩放/旋转前的应用画布|
|`*-ui.png`|应用内容区域，便于检查画布是否完整|
|`*.json`|该帧的窗口、渲染器尺寸、目标矩形、截屏原因等|
|`events.jsonl`|应用窗口事件和应用内点击/映射坐标；不记录全局键盘|
|`latest-geometry.json`|最近一组绘制参数|
|`index.html`|离线截图相册，双击打开|

重要：render 是真实的应用渲染器读回，不是“重画的预览”，但它仍发生在 Weston 合成之前，无法证明最终屏幕的硬件旋转、裁切或其他窗口叠加。
canvas/ui 更不能用来证明物理屏幕显示正常。文件名与相册明确标明这一差别。

图片位于 `D:\project\P011\logs\PlayLab-模式-时间\screenshots`。
Demo 的终端输出在程序结束后取回；等待期间没有输出不等于卡住。

## 4. 在电脑上手动截取当前 PlayLab

在 Demo/Calibrate 正在运行时，用第二个 PowerShell 窗口执行：

```powershell
& ([scriptblock]::Create((Get-Content -LiteralPath 'D:\project\P011\PlayLab\P011-Screenshot.ps1' -Raw -Encoding UTF8))) -Source App
```

它向已确认的本实验进程提出截图请求，不创建新的空窗口冒充截图。
程序必须已经运行；退出后此入口会报告没有活动会话。
也可直接调用主入口 `-Mode Capture`。截图在下一帧由渲染主线程完成。

## 5. 独立的 fb0 屏幕读取工具（实验性）

不依赖 PlayLab 窗口，可在原厂界面或 Demo 运行时尝试：

```powershell
& ([scriptblock]::Create((Get-Content -LiteralPath 'D:\project\P011\PlayLab\P011-Screenshot.ps1' -Raw -Encoding UTF8))) -Source Framebuffer -Shots 1
```

连续三次，每次间隔 5 秒：

```powershell
& ([scriptblock]::Create((Get-Content -LiteralPath 'D:\project\P011\PlayLab\P011-Screenshot.ps1' -Raw -Encoding UTF8))) -Source Framebuffer -Shots 3 -Interval 5
```

只对 `/dev/fb0` 执行 O_RDONLY 打开、FBIOGET_VSCREENINFO/FBIOGET_FSCREENINFO 查询和有边界的读取；不 mmap、不取得 DRM master、不写设备节点、不修改显示模式。
按驱动返回的 stride、x/y offset 和 RGB 位域解码。只支持标准 truecolor 16/24/32 位；其他格式停止并保存元数据，不乱猜。
本机使用 DRM/Wayland，旧 fbdev 接口可能没有当前画面，因此可能失败、黑图或旧画面。
`READ_OK_SCANOUT_UNVERIFIED` 仅表示缓冲区读出并解码，绝不当作最终屏幕已验证。原始方向不自动改动。
没有成功读到就返回失败和说明，不改 framebuffer 参数来强行截图。
截图可能包含原厂界面上的个人信息，分享前检查。

## 6. 提前结束实验

```powershell
& ([scriptblock]::Create((Get-Content -LiteralPath 'D:\project\P011\PlayLab\P011-PlayLab.ps1' -Raw -Encoding UTF8))) -Mode Stop -WorkRoot 'D:\project\P011' -PackageDir 'D:\project\P011\PlayLab'
```

仅核对并结束 v1.2 实验进程；不 killall、不修改系统。

## 7. 测试边界

已完成 Python 3.5 语法检查、几何正反映射测试、主机 SDL dummy 实际绘制/PNG 读回、480×800→800×480 的窗口尺寸变更回归、RGB 位域解码测试。
主机动态变更后 render.png 与完整 canvas.png 的像素逐点一致（0°、800×480）。
测试环境不是目标 ARM/Mali/Wayland。PowerShell 启动器做静态检查，没有在此环境实际执行 Windows 版本。
新版本尚未在用户 P011 上实测；详见 `evidence/regression-results.txt`。

## 8. 外部参考（不替代 P011 实测）

- SDL_GetRendererOutputSize: https://wiki.libsdl.org/SDL2/SDL_GetRendererOutputSize
- SDL_GetWindowSize: https://wiki.libsdl.org/SDL2/SDL_GetWindowSize
- SDL_RenderReadPixels: https://wiki.libsdl.org/SDL2/SDL_RenderReadPixels
- SDL_WindowEventID: https://wiki.libsdl.org/SDL2/SDL_WindowEventID
- SDL 2.0.8 Wayland configure: https://github.com/libsdl-org/SDL/blob/release-2.0.8/src/video/wayland/SDL_waylandwindow.c
- Linux framebuffer GET API: https://www.kernel.org/doc/html/latest/fb/api.html
