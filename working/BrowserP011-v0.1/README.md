# P011 浏览器

用户最新决定使用设备原有 Qt 5.10.1 / QtWebEngine 1.4，正式增加“设置 → 浏览器”。当前交付入口在 `settings/old-kernel/`，使用原系统运行库，页面位于 `/mnt/data/p011-browser/settings/legacy/`。正式安装只在当前 Bili Z03 的设置网格末尾增加一项，保留既有入口；有独立备份、安装记录和精确恢复链。具体实际状态见 `CURRENT_STATUS.md`。

以下独立 Qt6 目录为已取消的新内核尝试，源码、对象及原始日志保留；没有编成或安装完整 Qt6 浏览器。旧内核正式版不调用这些试验启动器。主机源码检查、设备安装、网页渲染、物理触摸与输入法分别判定。

## 目录与唯一写入范围

- `app/`：Qt 6.8 独立程序及自带本地网页探针。
- `runtime/`：Python 3.5 设备监督与身份核对；仅管理本次浏览器进程。
- `host/`：显式 ADB transport、原始双流、远端/主机退出码与结果归档。
- `tests/`：PC 源码与合成 DOM 检查，不能当作 Qt/Chromium/P011 验收。
- `build/`：PC 交叉编译定义；大源码、构建目录位于独立 E 盘目录或 browser685 专属 Docker volume。

设备写入限定在 `/mnt/data/p011-browser`。已有目录或候选不匹配时停止，不自动删除或接管；候选由内容清单确定身份。每轮冻结当时的三文件哈希、核心服务和父进程 PID/starttime/exe。保留已有正式 Bili 安装及其数据，不套用旧 ToolsTest 的启动脚本或 v2.1.2 哈希。

## 试验边界

独立窗口为 800×480，唯一可见内容区是 y=106 的 800×268；不对嵌入内容重复偏移或旋转。页面不连接 WebChannel、原厂控制 IPC 或任意命令桥；权限、证书错误、下载和新窗口默认拒绝。首次只运行自带离线页面，不输入账号或读取用户文件。

设备内核没有启用 CONFIG_NAMESPACES，低权限 user namespace 探针返回 EINVAL。正常沙箱启动和显式 `--offline-no-sandbox` 是两次不同试验：后者仅限低权限、自带 qrc 离线页面，不允许外网 URL，也不构成安全通用浏览器验收。不会通过改内核、修改账号、放宽系统目录权限来处理此限制。

控制目录由 root 持有，浏览器以非 root uid 65534 / primary gid 44（video）运行，仅能写自己的 `session/app`。这是子进程凭据，不修改系统账户、组成员或设备节点权限。普通 gid 65534 的 EGL 初始化实测失败，video 组的 Qt6Gui / Wayland / Mali GLES 探针实测通过。Wayland 通过监督进程预连接的 FD 传递，不修改 `/run/user/0` 或系统 socket 权限。Stop 是请求，必须有完成标记、结果、私有进程关闭与原厂身份比较才能确认退出。

## 已可使用的只读检查

```powershell
python -B host/audit_device.py --transport 1
```

transport 必须以当次 `adb devices -l` 为准（12:05 当前为 1，09:48 的 17 已失效）。每次检查生成新的 `D:/project/P011/logs/BrowserP011-Preflight-*` 和 `.private.zip`，保留原始 stdout/stderr 与 host/remote exit；不运行设备候选、不启停无线或原厂程序。

后续试验控制器为 `host/trial.py`。只有真实 ARM 产物、源清单、ELF/GLIBC/动态依赖、磁盘预算通过后才上传运行；设备需保留至少 128 MiB 数据空间。缺少产物时不能以 PC 预览或旧原厂浏览器代替 Chromium 122。

## 设置入口与交互浏览

`settings/` 准备了原设置网格末尾的“浏览器”选项和独立定点安装事务；候选基于当前正式 Bili Z03，保留原有入口及其余资源。它不由试验脚本自动安装，具体状态见 `CURRENT_STATUS.md`。交互 app 的 `--interactive` 模式提供地址、前进/后退、刷新、主页、键盘及退出，HTTP/HTTPS 页面在独立 Qt6 进程中运行，最长 30 分钟后关闭本轮会话。交互模式不做自动网页正文采集或截图。

原厂内核缺少 namespace 支持，因此设置启动必须显式配置 `interactive_no_sandbox=True`，监督器只接受 `--interactive --interactive-no-sandbox` 配对；不会从沙箱失败自动切换。浏览器依旧使用低权限 uid 65534 / gid 44、私有会话和 offrecord profile。独立原生 controller 的 token 文件只允许 root 读取，接口只有固定的打开、状态与关闭，不能传 URL 或命令。原生设置页心跳失联 15 秒或原厂 UI/父进程身份改变时，请求监督器关闭本会话。
