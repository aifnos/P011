# P011 MenuLab v0.2：原厂菜单的限时测试

适用固件：`z031_v2.1.2-20221124_143128-user`。仅适用于已开启 root ADB、原版 `/usr/bin/Z03` 及启动脚本哈希匹配的 P011。

**v0.2 新增 Windows 测试启动器和设备端恢复监督进程。原厂菜单候选的资源补丁与 v0.1 完全相同；四个外置 QML 原型只增加诊断日志。** 不包含整个修改后 Z03、外部字体或刷机镜像。

## 测试策略与边界

- 原版 `/usr/bin/Z03` 和 `/usr/bin/zyb_z03_launch.sh` 始终不覆盖；不重挂载、不改开机项、不使用 AutoD。
- 在电脑上由当前原版生成候选副本，推送到唯一的 `/tmp/p011-menutest-时间/`，不运行来历不明的外部 FDL。
- Trial 前识别唯一原厂 Z03 和它的直接父进程，确认父进程是已核对的 `zyb_z03_launch.sh`。
- 先在学习笔上启动独立恢复监督进程，再暂停启动脚本的循环；对原厂 Z03 发 SIGTERM，等待其退出。原厂进程不在 8 秒内退出时不强杀、不启动候选，恢复循环并停止测试。
- 原厂退出后才启动一份候选 Z03，沿用原来 HOME、Wayland 环境与工作目录。避免两份原厂应用并行争用硬件。
- 正常到时、候选退出、工作进程崩溃或 Stop 请求：结束候选和已识别的私有会话子进程，移除临时菜单路径别名，恢复原厂循环，再检查原版 Z03 是否重新稳定运行。
- **这是恢复进程和临时路径，不是用户数据快照。** 候选仍运行原厂原生业务代码，可能联网、记录历史、更新普通配置。不要在试验期间升级、恢复出厂、改 ADB 或测试服、接打电话、进行重要录音。
- USB/电脑窗口意外断开时，已经启动的监督进程仍在笔上计时。但内核卡死、硬件故障、所有恢复进程同时被杀等情况不能靠脚本保证恢复；正常重启是最后回退方式。

设备的临时页面别名为 `/mnt/data/p011-menu`，仅指向本次 `/tmp/.../pages`。该路径已存在时拒绝覆盖。正常恢复会删除自己创建的别名；异常重启可能留下无效别名，先保留现场，不要用 rm -rf 清理未知目录。

## 1. 解压到工作目录

ZIP 顶层是 `MenuLab/`，解压到 `D:\project\P011`。如果已修改旧包的示例页，先另存旧目录，不要直接覆盖自己的代码。

```text
D:\project\P011\MenuLab\
    P011-MenuTest.ps1
    runtime\menu_trial.py
    runtime\menu_policy.py
    runtime\p011_json.py
    examples\device\*.qml
    patch\...
    docs\...
    tools\...
    tests\...
```

保持正常开机、停在主页、亮屏、USB ADB 连接。关闭此前 PlayLab；不关机、不进入下载模式。只连接这一支学习笔。

## 2. 先检查，不切换原厂界面

```powershell
Set-Location 'D:\project\P011'
$pkg = 'D:\project\P011\MenuLab'
$test = [scriptblock]::Create(
    (Get-Content -LiteralPath "$pkg\P011-MenuTest.ps1" -Raw -Encoding UTF8)
)
& $test -Mode Check -WorkRoot 'D:\project\P011' -PackageDir $pkg
```

Check 自动从设备拉取当前原版、校验，保存 `D:\project\P011\backups\Z03`（已有不同备份则停止，不覆盖）。它构建、推送临时候选并检查实际进程关系、Python 模块、文件哈希、Wayland socket 和临时空间。

Check 只在实验临时目录写文件，不暂停/结束任何原厂进程，不实例化新 QML。看到 `CHECK_OK` 和 `RESULT: CHECK_OK` 才进入 Trial；否则发这次 ZIP，不要手工拼 kill 命令。

目标固件缺少标准库 json，因此使用项目的输出模块。此次也不依赖缺失的 python-resource 扩展；禁用候选 core dump 通过已存在 ctypes 调 libc，只作用于实验子进程。

## 3. 启动 180 秒临时菜单测试

在同一 PowerShell 窗口执行：

```powershell
& $test -Mode Trial -Seconds 180 `
    -WorkRoot 'D:\project\P011' -PackageDir $pkg
```

Trial 会重新检查，并要求输入 `TESTMENU`。确认前结束正在进行的业务、回到主页。确认后原厂应用将退出再切换候选，可能短暂黑屏。

典型输出：

```text
GUARDIAN_ARMED
RESTART_LOOP_PAUSED
ORIGINAL_TERM_SENT
CANDIDATE_RUNNING: PID=...; test window=180s
...
RESTORING_STOCK
RESTART_LOOP_RESUMED
RESTORED_STOCK_PROCESS
FINISHED: RESTORED
RESULT: TRIAL_FINISHED_STOCK_RESTORED
```

`CANDIDATE_RUNNING` 只证明进程存在，不证明菜单已显示。`RESTORED_STOCK_PROCESS` 只证明原版进程恢复、文件哈希没变；物理界面和触摸仍需要你确认。

## 4. 笔上验收顺序

1. 在答疑主菜单横向滑到最右端，设置后应多一个“工具箱”。第一版复用设置图标，按文字辨认。
2. 打开工具箱，进入时钟，确认时间显示，再“返回”。
3. 打开计时器，测试开始、暂停、重置；它只在当前页面存活期间计时，不是后台提醒。
4. 打开设备信息，检查固件版本，再返回主页。
5. 切换到查词主菜单，滑到最右端，检查同一个工具箱入口和返回。
6. 打开原厂设置首页再返回；第一轮不修改升级、恢复出厂、ADB/测试服或相机校准相关设置。
7. 到时恢复原版后，工具箱入口应消失。这正是临时试验，没有永久安装。

本輪不要求测试来电、复杂识别或长期待机；先验证菜单和纯 UI 子页。成功后另行做硬件业务回归。

外置页面日志含 `P011_MENULAB: toolbox ready`、`child ready`、`back` 等标记。新页故障需要结合 `candidate.log` 判断，不能看到进程运行就算验收通过。

## 5. 提前结束与取回日志

在另一个 PowerShell 窗口执行：

```powershell
& ([scriptblock]::Create(
    (Get-Content -LiteralPath 'D:\project\P011\MenuLab\P011-MenuTest.ps1' -Raw -Encoding UTF8)
)) -Mode Stop -WorkRoot 'D:\project\P011' -PackageDir 'D:\project\P011\MenuLab'
```

不要用 killall Z03/killall python3、结束 Weston，或关闭 ADB 开关来停止。Stop 向本次监督进程发停止请求；如果监督进程已死亡，则使用本次保存的 PID/starttime/boot-id 做受限的恢复。

同样的命令可把 `-Mode Stop` 改为 `-Mode Status`（查询）或 `-Mode Collect`（只取回日志）。如果电脑窗口被关掉，重新连上同一设备后用 Collect。

设备临时目录会在重启后消失，所以优先在重启前取回日志。若系统卡住、监督恢复失败，保留错误原文，按平时方式正常重启；不要执行擦除/格式化/覆盖原版程序。

## 6. 输出位置

```text
D:\project\P011\logs\MenuTest-Check-时间\
D:\project\P011\logs\MenuTest-Trial-时间\
D:\project\P011\logs\MenuTest-Trial-时间.zip
```

ZIP 只放日志，不重复打包原厂 ELF 和候选程序。重点文件：

- `report.txt`：电脑端过程。
- `device/inspection.json`：哈希、实际父子进程和少量显示环境；不保存完整进程环境。
- `device/trial.log`：暂停、运行、恢复的阶段。
- `device/candidate.log`：Qt/QML/原厂程序的原始输出。
- `device/worker.log`、`guardian.log`：实验进程与恢复进程的异常。
- `device/finished`：恢复检查是否完成。

adb pull 对目录的落地结构可能多一层 logs，文件名不变。原厂日志可能带设备标识、账号或网络信息；分享前先检查。

## 7. 测试范围说明

本包已完成：原版资源补丁与哈希重验、Python 3.5 语法检查、Linux 主机上用模拟应用/启动脚本进行超时结束、候选崩溃、Stop、工作进程被杀、监督进程被杀后的恢复、原厂不退出、候选不理会 TERM、原有路径冲突和错误父进程等测试。

**未完成：Windows PowerShell 启动器实机执行，P011 上的候选运行与 Qt 5.10 编译/实例化、设备服务/触摸/显示验证。** 主机恢复测试不替代设备验证。Linux 4.14 没有 pidfd，PID/starttime 复核降低误发信号风险，但不应被描述为无限可靠的恢复机制。

无永久安装功能。试验成功后再讨论持久化；不要把运行中的候选直接复制到 `/usr/bin/Z03`。
