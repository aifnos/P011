# BrowserP011 限时运行组件

此目录只提供 Python 3.5 兼容的独立浏览器试验监督和只读原厂快照。它不替换原厂程序、不改启动项/用户账号/系统权限，不启动归档 ToolsTest/Bili awake 脚本。

`p011_json.py` 原样复制自项目 `working/ToolboxNext-v0.5.1-native/runtime/p011_json.py`，保留其全部源说明。它只有输出编码功能。baseline 使用 UTF-8 纯 Python 字典 literal，通过 `ast.literal_eval` 读取，不使用 `eval`，不依赖目标缺失的标准库 `json`。

入口：

```
python3 -B snapshot.py
python3 -B supervisor.py --candidate /mnt/data/p011-browser/candidates/browser-685-<sha16> --session /mnt/data/p011-browser/sessions/YYYYMMDD-HHMMSS-hex8 --seconds 30 --baseline /mnt/data/p011-browser/sessions/YYYYMMDD-HHMMSS-hex8/baseline.py --uid 65534 --gid 65534
```

`snapshot.py` 只读固定三文件哈希、核心进程 PID/starttime/exe/父身份和 boot_id，向 stdout 输出 `RESULT=<repr>`。原厂进程要求 Z03/control_engine/weston 各一，另记录存在的 connmand/bluetoothd。baseline schema 为 `p011.browser.baseline.v1`；也兼容主机采样的 `p011.browser.readonly.v1`（comm/ppid/starttime:int/parent:dict），比较前统一字段。不会读取 `/proc/*/cmdline`、环境或账号数据。

HOST 负责先创建并设置以下目录，runtime 不改变系统用户或任意目录所有权：

- candidate 及 session 控制根归 supervisor 所有，不可被 group/world 写；所有祖先 canonical、无 symlink。
- AREA 根的 `.area-owner` 必须为 supervisor 所有、0600 regular 文件，精确内容为 `p011.browser.area.v1\n`；runtime 不自动接管既有陌生目录。
- session 根可供 child 遍历，baseline/owner/result/日志在控制根，child 无写入权限。
- `session/app` 及 `app/tmp`、`app/cache`、`app/config`、`app/data`、`app/runtime` 均归指定非零 uid/gid，权限 0700。应用自行在 app 中创建 captures 等文件。
- candidate 包含 `bin/p011-browser-probe`、`libexec/QtWebEngineProcess`（真实可执行文件）、`lib`、`plugins`、`qml`、`resources`、`translations/qtwebengine_locales`；HOST 必须先核对完整候选 manifest。

supervisor 启动 detached guardian，guardian 启动独立 session/process group 的 browser，基本参数固定为 `--session SESSION/app --seconds N`，只有显式固定站点模式额外传 `--public-site baidu|bilibili`。app 内部映射固定 HTTPS 首页，不接受 URL 或任意命令入口。seconds 范围 1..120。浏览器自身按 seconds 退出，guardian 留 3 秒退出余量，再向身份仍匹配的自有组依次 TERM（5 秒）/KILL（3 秒）。guardian 每 100 毫秒跟踪已证实 parent/group 链的候选进程；Chromium 后代若 setsid 离开原组，按已跟踪 PID/starttime/exe/uid 重新核验后逐个 TERM（3 秒）/KILL（2 秒）。设备清理余量为 20 秒。supervisor 的 HOST 等待上限为 seconds+30，不把超时当作退出证据。guardian 的设备期限不依赖 USB 继续连接。只在本轮 session 根创建空文件 STOP 可请求提前停止。

`/mnt/data/p011-browser/leases/<candidate-name>` 是 candidate 独占租约，由 guardian 原子 mkdir 获得。旧租约不自动清除。只有自有 group 和候选私有进程均关闭后才核验 owner 并释放；不能证明所有权的进程不会被强杀，结果报告未闭合且保留租约以阻止下一轮抢占。

guardian 在降权前只连接固定 `/run/user/0/wayland-0`，通过 `WAYLAND_SOCKET` 传入已连接 FD，不改系统 socket 或 `/run/user/0` 权限。浏览器只继承固定 allowlist 环境，私有库、插件、QML、resources/cache/data 均限定候选和 app；默认保持 Chromium sandbox，并禁止以 uid 0 启动。root supervisor 只在新 child preexec 中清补充组、setgid/setuid，以 libc setrlimit 禁止 core dump，并将每个 child 输出文件限制为 16 MiB（同样约束继承的 stdout/stderr）。不依赖固件缺失的 Python resource 模块。 同一 child preexec 在降 UID 前仅向自身 `/proc/self/oom_score_adj` 写入固定 `500`，由 Chromium 后代继承，内存紧张时提高本轮浏览器被 OOM 结束的优先级；不写原程序 PID 或全局 sysctl。打开/写入/关闭失败或短写均中止 child（exit 125），不会静默忽略。结果记录请求值 `child_oom_score_adj_requested=500`，只有 Popen 成功 exec 后才记 `child_oom_score_adj=500`；启动前失败保持 null。此优先级不能保证原程序永远不会被 OOM 影响。

默认 Qt Wayland shell 为 `wl-shell`；可显式选择 `--shell-integration xdg-shell-v6` 或 `xdg-shell`。此开关只选择已打包的 Qt 插件，不证明对应协议或 GPU 路径已成功。

`--offline-no-sandbox` 是独立且显式的本地探针选项：仅运行默认 qrc fixture、保持非 root uid、不提供 URL 参数，不自动由 sandbox 失败回退。它设置 `QTWEBENGINE_DISABLE_SANDBOX=1`；结果明确 `sandbox_enabled=false`、`sandbox_runtime_verified=false`、`offline_local_fixture_only=true`。普通模式保持 sandbox 请求，但同样不声称内核已提供实际隔离。两模式均关闭 Chromium background networking/component update/sync 等；本地页面 CSP 由 app 控制。此选项不构成在线浏览器验收。

在线兼容性试验必须同时显式提供 `--public-site baidu --public-no-sandbox` 或 `--public-site bilibili --public-no-sandbox`，并保持非 root 浏览器 UID。两个参数缺一、与 `--offline-no-sandbox` 混用、任意其他站点或 `--url` 均拒绝；不会因启动失败自动启用。guardian 只向 app 传固定标签；app 仅将 `baidu` 映射到 `https://www.baidu.com/`、`bilibili` 映射到 `https://www.bilibili.com/`。每个站点需由 HOST 发起新一轮限时试验，不复用本地结果。此模式设置 `QTWEBENGINE_DISABLE_SANDBOX=1`，结果明确 `public_site` 为固定标签、`public_no_sandbox=true`、`sandbox_enabled=false`、`sandbox_runtime_verified=false`、`offline_local_fixture_only=false`；它只提供指定公共页面的兼容性证据，不能证明内核沙箱隔离成立。默认及本地模式的 `public_site=null`、`public_no_sandbox=false`。

公共页面同样使用本轮新建的私有 `session/app` 作为 HOME，XDG config/data/cache/runtime/tmp 均指向其中独立子目录。环境 allowlist 不继承原账户 token、代理、Qt 路径、Chromium flags 或旧 profile；app 的 off-the-record WebEngine profile 另外保持空白会话。此设置不读取或导入原浏览器登录态，但无沙箱模式和低 UID 不能等同于完整的文件系统隔离；UID 可访问的其他文件仍取决于原系统权限。

输出分开保存 browser/guardian stdout 和 stderr 的原始字节。root-owned result.json/result.py 在完成原厂前后核对、组/私有进程收尾后写入，最后发布空 COMPLETE 标记，供主机判断是否完整。`passed` 是兼容别名，与 `lifecycle_passed` 相同；它只代表该轮 app 正常退出及运行生命周期/原厂保持。`page_passed=null` 留给 HOST 按 fixture 事件、版本身份和应用窗口 PNG 独立判定，不替代物理 scanout、触摸或用户体验验收。

HOST 检查命令为 `python -B -m unittest discover -s runtime/tests -v`（在 BrowserP011-v0.1 根运行）。这些检查不连接 ADB，不产生 P011 实机 PASS。
