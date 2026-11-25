# P011 v0.4.2 本轮结果分析与 v0.4.3 修正

## 本轮事实

来源：P011-ToolsTest-Run-20260915-132430083.zip。ZIP 完整性正常，证据清单内 39 个文件的大小与 SHA-256 全部一致。

- 电脑压缩/报告自检已通过：`RESULT_HOST_SELFTEST_OK`。
- ADB 正常，`id -u` 为 0，设备退出码为 0。
- 已拉取原版、构建候选、推送两份样片和本次临时会话文件。
- 停止阶段是 `DEVICE_PREFLIGHT`，不是 QML 页面运行阶段。
- 实际错误：`/mnt/data/p011-menu already exists. Nothing will overwrite that path.`
- `start_attempted=false`，本次没有暂停原厂循环、没有启动候选、没有测试六个页面、没有生成截图。
- SSH 密钥准备另有警告：`SeSecurityPrivilege`。它没有阻止 root/候选构建，但会让本次不提供公钥，不能据此测试 SSH 登录。

本轮有临时部署文件，但没有切换原厂界面。摘要中的“恢复未确认”应理解为本轮没有进入需要恢复的试验阶段；这不替代对更早旧会话的检查。

## 仍缺少的信息

现有报告没有 `lstat/readlink` 输出，不能确认 `/mnt/data/p011-menu` 是符号链接、普通目录还是其他对象，也不知道目标路径。旧试验残留是候选解释，不是本轮已证明的根因。不执行 `rm -rf`、不覆盖未知路径。

## v0.4.3 修改范围

1. 路径检查先生成 `device/path-preflight.json`，记录类型、链接目标、临时根目录实际路径、启动标识和可识别的活跃会话。
2. 在原版哈希、原厂进程及父子关系正确后，只移除可验证的过期项目符号链接。允许 `/tmp` 及系统实际解析后的临时目录；清理前再次核对链接 inode、目标及进程。
3. 可处理的情况仅限：目标会话不存在；确定属于上一启动周期；或当前周期明确 `RESTORED` 且无相关活动进程。只 unlink 链接本身，不删除目标文件/页面/日志。
4. 普通目录、外来链接、活动会话、当前周期恢复未完成或证据不足，全部保留并停止。输出具体分类，不把它们视为自动清理对象。
5. 专用 SSH 私钥改用文件句柄上的 DACL-only 更新及读回检查。不请求审计 SACL、不变更所有者、不启用额外权限；实际密钥处理前先对临时假文件运行自检。不读取私钥内容，不将密钥写入日志。
6. 当明确 `start_attempted=false` 且无生命周期标记时，摘要显示 `NOT_REQUIRED_NO_TRIAL`，各页标记“未测试”。缺少该字段时仍显示未知，不默认成功。
7. v0.4.2 的压缩程序集加载修复保留。所有六页、菜单资源补丁、样片和业务后端都与 v0.4.2 相同。

## 使用

先结束其他试验，正常重启学习笔一次并回到原厂主页，保持 ADB 连接。重启是为了终止可能遗留的旧会话；本轮失败自身没有要求恢复原版程序。

将 P011-Tools-Test-v0.4.3.zip 完整解压到 `D:\project\P011`，更新 `P011-Tools-Test` 文件夹，双击 `START.cmd`。不要修改旧 packages、backups、keys、logs、results。

若是已确认的旧链接，显示 `STALE_ALIAS_REMOVED` 后继续；若显示 `PATH_CONFLICT`，保留原对象、自动生成含 path-preflight.json 的新结果包，不手动删除该路径。普通目录不会被这版自动腾挪。

正常时沿用 600 秒限时工具测试和自动日志/截图/结果收集。不要在试验运行过程中再重启、恢复出厂或升级。

结果：`D:\project\P011\results\P011-ToolsTest-Run-时间.zip`。

## 验证范围

已执行 25 项主机真实文件系统链接分类/保留/清理测试、33 项后端样例检查，以及 4 项 Linux 模拟应用进程测试（到时恢复、候选崩溃、手动停止、已存在目录保护）。运行时 Python 文件通过 Python 3.5 语法解析。

没有在 Windows 或 P011 上执行 v0.4.3。Windows ACL 原生调用尚未编译/实机验证；启动时会在你的电脑先做可删除的假文件自检。主机模拟不证明五类工具的实机功能已通过。

## 通用技术依据（不是 P011 路径现场证据）

- Python os.path.realpath：消除路径中的符号链接；lexists 包括悬空链接。https://docs.python.org/3/library/os.path.html
- Windows SetSecurityInfo 可以按 SecurityInfo 标志只修改 DACL，不必修改 SACL 或所有者。https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
- Windows DACL 与 SACL 要求的访问权限不同；SACL 操作涉及 ACCESS_SYSTEM_SECURITY。https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information
