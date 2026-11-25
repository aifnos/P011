# P011 v0.4 工具箱空白：日志核对与 v0.4.1 修复

## 结论
根因是新 ToolboxPage.qml 把 Qt Quick Item 的默认 `data` 属性重声明为业务数据字段。主页面实例创建成功，但视觉子项没有成为其 visual children，`parent` 为 null，页面只绘制背景。不是屏幕旋转或 ADB 密码问题。

## 本次输入
用户上传的 logs.zip 包含四次电脑操作：Run 03:08、Run 03:10、Collect 03:11、Stop 03:11（电脑日志时间）。ZIP 完整性校验通过。原文件保留不动。

## 1. 直接证据
- candidate.log 第 93–104 行：进入工具箱，出现 `toolbox_ready`，随后 ToolboxPage.qml 第42、64、65、69行反复报 `TypeError: Cannot read property of null`。
- 后续三次进入仍出现相同错误，并非某一次加载慢。
- 最完整的一组有9张800×268 PNG；逐张解码后每张只有一个RGB颜色 `(15,15,15)`，确实只有背景。
- tools-snapshot.json / battery-samples.jsonl 存在有效采样。工具服务最终记录48个请求；因而不能把空白归因于后端完全未启动。
- 此轮没有进入六个子页面，不能把子功能判为失败或成功。

## 2. 代码根因与实际主机复现
旧代码：`property var data: (...)`，后续 `data=d`。Rectangle 继承 Item 的默认 `data` 子对象列表，不能拿这个名字重声明业务状态。
在本机安装的 Qt 5.15.15 中用真实 QQmlEngine 做了两组复现：
1. 最小相同写法：children=0，两个子控件 parent=null；改名 telemetry 后 children=2，两个 parent 非空。
2. 实际工具箱代码（测试夹具替换为本地 Style 和假数据服务，手动注册 Qt 模块）：旧版 children=0，截图单色；修正版 children=7，截图有按钮和标题，并成功创建 ADB、电池、无线电、SSH 四页。
测试使用 Qt 5.15.15，不是设备的 Qt 5.10.1；主机替换只在测试夹具中，发布QML继续使用原厂 qrc Style、图标和 QtQuick 2.10。主机缺原厂图标，测试日志中相应图标不存在是夹具限制，不是目标固件新错误。WebEngine/QtMultimedia 页未在此主机完整实例化。

v0.4.1 统一改名为 telemetry，修改关联字段及 onTelemetryChanged，子页用 Loader.setSource 的初始属性传递 app，加入视觉子项数/布局日志。六个入口保留，未删减功能。

## 3. 同时发现并处理的问题
### Windows 结果打包
原辅助函数叫 H，但 PowerShell 默认 H 是 Get-History 的别名，日志证明 HTML 拼装调用进了 Get-History。改成唯一的 ConvertTo-P011HtmlText 名称。原 New-P011Result 返回字符串而入口期待 Zip/ReportHtml/Summary 对象，现统一返回对象并给恢复状态固定机器码。增加接触设备前自动执行的 Windows 打包夹具测试；主机HTML失败仍尝试打包纯原始日志。

### Stop 未完成恢复
Stop 包的 finished 文件实际是 RECOVERY_NEEDS_ATTENTION，不是 RESTORED。错误为 `Candidate PID was reused/exec changed; no broad cleanup`，没有原厂循环恢复记录。现有日志没有记录当时 /proc 快照，不能断言真实发生PID复用，也不能断言只是退出竞态。
旧 process() 先读stat，再读exe；exe在退出时消失会留下旧的活跃状态和空exe，引发上述误判。修正为前后stat复核、有限重采样，并处理主线程退出但仍有其他线程的情况；真实身份不符仍拒绝误杀，无法确认时保存快照并停止恢复。即使候选清理失败也会尝试关闭本项目服务、恢复本项目的USB配置。不会强行启动第二份原厂程序。

### 提前结束误报
03:08 的Run在候选运行约40秒后进入finally，仍报CHECK_OK；日志未说明退出原因。修正版从发起试验开始就标记正在试验，不再沿用CHECK_OK；正常进入finally而未取到恢复标记时会做有限Stop/状态检查。无法保证强制关机、终止所有监督进程或内核卡死下恢复。

### ADB配置解析
本机USB配置中多个模式段都有debug字段，旧版全文件要求只出现一次导致saved=null。修正版只定位唯一[property]段中的debug，不修改后面的模式模板，并用原机两个INI模板完成字节级变更/恢复测试。

### SSH公钥准备
日志中有SeSecurityPrivilege异常，导致本次未提供SSH公钥。改为构建仅含Owner/DACL的新文件安全描述符，不携带审计SACL。Windows上的实际权限行为仍待本轮验证；失败继续明确报告，不要求关闭系统保护。

## 4. 先恢复当前设备，再测试新版
本次日志最后未确认恢复原厂，因此首次重试前建议按日常方式正常重启学习笔、回到主页，确认ADB连接。不要重复旧START，不要rm -rf或按进程名killall。
若重启留下了指向已经不存在旧/tmp会话的菜单链接，新版在确认原厂程序和启动循环正常、哈希匹配后，仅清理符合本项目精确路径及旧启动条件的符号链接；不会清理目录、仍活动会话或其他路径。

## 5. 使用
完整解压新版到 D:\project\P011，更新 P011-Tools-Test 文件夹。双击 START.cmd，窗口应显示v0.4.1。十分钟临时测试范围与此前一致；第一次先确认工具箱有六个按钮和返回，再逐页点开。需要提前结束用STOP.cmd。
结果仍在 D:\project\P011\results；详细日志在logs。没有自动上传。私钥/API token不打包，网络信息仍应分享前查看。

## 外部参考（仅解释机制，不替代P011日志）
- Qt Item 默认data属性：https://doc.qt.io/qt-6/qml-qtquick-item.html#data-prop
- PowerShell命令优先级：https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_command_precedence
- Linux /proc/pid/exe：https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html

Windows启动器和P011新版本仍待实机验证。当前已完成的主机测试详见本包v041验证记录，不将“数据存在”或“页面加载”当作媒体播放、SSH登录和原厂业务均已通过。
