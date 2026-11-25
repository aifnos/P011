# P011 MenuLab v0.1 — 原厂菜单研究与离线候选包

适用固件：`z031_v2.1.2-20221124_143128-user`。当前阶段：静态分析 + 离线验证；嵌入原厂菜单尚未实机运行。

## 工作目录

将 ZIP 解压到 `D:\project\P011`，应得到：

```text
D:\project\P011\MenuLab\
  README.md
  docs\菜单源码导航.html
  docs\原厂菜单与扩展方案.md
  source-original\...
  examples\device\...
  patch\...
  tools\...
  tests\...
```

直接打开 `docs\菜单源码导航.html`，可搜索全部恢复的 QML/项目脚本并查看行号。网页完全离线，不读取 USB，不执行 QML。

## 本轮得到的核心结果

原厂 `NaviPanel.qml` 的两套固定列表为答疑 7 项、查词 6 项。候选在各列表末尾追加“工具箱”，指向 `file:///mnt/data/p011-menu/ToolboxPage.qml`，不改变原项目次序和固定红点下标。4 个示例页是自写原型。

在精确原版 Z03 中，只改动一个压缩资源记录，文件长度保持不变，其他399个资源和全部可执行代码段一致。详见 `tests/offline-validation.json`。

## 可选：仅在电脑上生成候选副本

这一步**不安装、不运行、也不替换学习笔程序**。要先准备原版 Z03；之前保存的原版可以复制到新的备份目录，也可通过 ADB 只读拉取。下面脚本不会覆盖已有本地备份：

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $root = 'D:\project\P011'
    $file = Join-Path $root 'backups\Z03'
    New-Item -ItemType Directory -Path (Split-Path $file) -Force | Out-Null
    if (Test-Path -LiteralPath $file) {
        Write-Host "沿用本地文件，未覆盖：$file"
    } else {
        adb pull /usr/bin/Z03 $file
        if ($LASTEXITCODE -ne 0) { throw 'ADB 拉取失败。不要继续构建。' }
    }
    Get-FileHash -LiteralPath $file -Algorithm SHA256
}
```

预期 SHA-256：

```text
e6760ad70cc17b089fd3dded68e58feb545a6b77f3f653b90d7427104b626997
```

然后运行本地构建器：

```powershell
$pkg = 'D:\project\P011\MenuLab'
& ([scriptblock]::Create(
    (Get-Content -LiteralPath "$pkg\tools\Build-MenuCandidate.ps1" -Raw -Encoding UTF8)
)) -PackageDir $pkg `
   -OriginalPath 'D:\project\P011\backups\Z03' `
   -WorkRoot 'D:\project\P011'
```

结果保存到 `MenuLab\build\candidate-时间\`，包括 `Z03.menu-candidate`、示例device目录和校验清单。原版不同、资源块被改、嵌入源码与预编译块不符会停止。构建成功只代表副本校验成功，不代表 Qt 或 P011 运行测试通过。

**不要直接 adb push 覆盖 /usr/bin/Z03。** 下一阶段需要专门的受监控短时运行与自动回退，先识别原厂启动脚本的实际父子进程，避免两份 Z03 并行或自动循环重启。这个包不含上述设备部署器，也不执行 remount、killall、开机脚本修改等操作。

## 开发源码的关系

- `source-original/NaviPanel.qml`：精确恢复的原始文件。
- `patch/NaviPanel.readable.qml`、`.diff`：便于审查的改动版本。
- `patch/NaviPanel.embedded.qml`：实际压缩嵌入的精简文本，只有空白和完整单行注释被精简。
- `NaviPanel.resource-block.bin`：对应的固定资源块，1584字节。
- `tools/Build-MenuCandidate.ps1`：应用这个固定资源块，不会自动编译任意改动后的QML。

修改“可阅读版”不会自动改变已经生成的资源块。要自己再开发嵌入入口，可在开发电脑的 Python3 环境运行 `tools/rebuild_resource_block.py`，显式传入原版、QML和全新输出目录；超长会拒绝而不是破坏邻近资源。新生成版本需要重新做完整验证，不能沿用本包的候选哈希。

```text
python tools/rebuild_resource_block.py --original D:\project\P011\backups\Z03 --qml patch/NaviPanel.embedded.qml --out D:\project\P011\MenuLab\build\manual-candidate
```

不要在学习笔的精简 Python 中运行这个 PC 构建工具。

## 本机离线检查

开发电脑有 Python3 时可运行：

```text
python tests/validate_offline.py --original D:\project\P011\backups\Z03
```

该程序只校验数据结构/哈希与资源记录，创建临时电脑文件，不连接设备、不执行 ARM 程序。它不是 QML 编译器，不验证原厂 C++ 上下文和实际触摸。

## 实验页边界

工具箱 800×268 的内容区域来自原厂 main 父容器，自己不再 y=106 或旋转。计时器仅页面存活期间工作，离开即销毁；不是后台提醒服务。设备信息页只调用已在原厂 QML 使用的版本getter。样例使用设备现有字体名称，不附带字体文件。

未来要启动 Python/SDL，需要新增匹配 Qt5.10/ARM32 的白名单原生桥；不能把 .py 路径填进 Loader.source，不能假定原厂存在 devManager.runCommand。

## 已验证与未验证

已实际完成：原版和candidate哈希、400资源逐项比对、补丁范围外一致、ELF代码段一致、原菜单保序、Python构建器正反例、QML基本词法检查。

未实际完成：Qt5.10引擎编译与实例化、Windows PowerShell构建器运行、P011原厂菜单加载与自动回退测试。

本包面向用户自己的设备和已备份固件，不修改厂商账号、会员、服务端授权或设备标识。
