# Qt 6 GUI / Wayland / GLES 有限探针

`gui_trial.py` 仅用于真实 `bin/p011-browser-gui-probe`。它不依赖 Qt WebEngine helper，不测试 JavaScript、网页或网络。探针固定约 900ms 自动退出，外部独立设备 guardian 的启动/运行上限为 10 秒，之后最多两轮各 2 秒清理。运行后保留全部文件与证据，不接管旧目录或删除失败目录。

主控先按当前 `boot_id`、三个系统文件 SHA256、核心 PID/start time/exe 和父进程核对 `--expected-snapshot`，首次设备写入前及启动前再核对，guardian 和主控结束时分别核对。显式指定当前物理 ADB transport；没有设备自动选择逻辑。

设备写入仅限 `/mnt/data/p011-browser/gui/<manifest sha16>-<北京时间时间戳>`。父区域必须已经具有 root 0600 的 `.area-owner`，精确内容为 `p011.browser.area.v1\n`（末尾一个真实 LF）。每次路径全新，payload 与控制文件属于 root；仅 `app` 及其临时/缓存子目录属于低 UID/GID 65534 且为 0700。上传后逐文件核对大小和 SHA256，才公开只读 payload。

root guardian 先连接 `/run/user/0/wayland-0`，将已连接 FD 交给 GUI 子进程；子进程清空附加组、切换非 root GID/UID，在独立 session/process group 中运行。它不修改原 Wayland socket 权限、Z03、Weston、系统启动、亮度或保活配置。仅凭 PID/starttime/exe/UID 和已跟踪父子关系关闭本次自有进程；无法证明归属的残留进程保留并判失败。正常收尾与“发出停止信号”分开判断。

在项目根目录以 PowerShell 执行（替换 payload、snapshot 与当前 transport）：

```powershell
python .\working\BrowserP011-v0.1\host\gui_trial.py --transport 1 --payload E:\P011-browser-build\gui-probe --expected-snapshot .\working\BrowserP011-v0.1\state\selected-device.json
```

`--prepare-only` 只在 PC 上检查源文件、生成 manifest/config 与验证远端片段长度，不执行 ADB。HOST 检查：

```powershell
python .\working\BrowserP011-v0.1\host\test_gui_trial.py
```

ADB 中断后可以从原始日志目录恢复收集；不会重新启动探针：

```powershell
python .\working\BrowserP011-v0.1\host\gui_trial.py --transport 1 --collect D:\project\P011\logs\BrowserP011-GUI-<原时间戳>
```

若 USB 重连后 transport 改变，显式使用新的 transport；主控先要求 boot/hash/core/父进程仍与原记录一致，才读取原远端证据。原始 transport 另存为 `origin_transport`，不会自动寻找设备或接受重启后的身份。

Windows 旧 ADB 可能将上传文件设为 root 0666。上传阶段的父目录为 root 0700，校验门先绑定 host config/guardian 的大小和 SHA256，再核对完整 payload 文件集、各文件 owner/type/size/SHA256；全部通过才将控制文件改为 0600、payload 文件改为最终只读/可执行权限。其后另一个启动门才公开 payload 目录并启动一次。

若首次上传完整，但还停在权限校验阶段，可显式复用该次上传，避免重复占用设备空间：

```powershell
python .\working\BrowserP011-v0.1\host\gui_trial.py --transport 1 --payload E:\P011-browser-build\gui-probe --expected-snapshot <当前snapshot.json> --resume-upload D:\project\P011\logs\BrowserP011-GUI-<原上传时间戳>
```

此命令要求原 host manifest/config/guardian 与本地源字节绑定完全相同、当前设备仍匹配原 baseline，远端 control/payload 仍是 root 0700，且没有 app、launch marker、raw 或 COMPLETE 记录。不会重新 push，不会接管其他目录；新的结果写入新日志，保留 `origin_log`、`origin_transport`，旧 ZIP 不改写。已经进入校验完成或启动阶段的目录不能用此参数重复运行。

每次运行都生成新的私有日志目录与校验过 CRC 的 `.private.zip`、ZIP SHA256。保留每次 ADB 的原始 stdout/stderr、host/remote exit，另保留设备应用的原始双流、guardian 双流、实际子进程 exit/身份与清理状态。旧版 ADB 自身可能把远端 stderr 合进 shell stdout；应用原始双流通过设备独立文件保存。

通过条件要求真实 Qt 6.8.5、Wayland surface exposed、GLES context created/makeCurrent、GL error=0、swap_called、rendered，以及正常退出、自有进程清理和系统身份不变。`swapBuffers` 返回 void，`swap_called` 只代表调用过；结果不会宣称 swap 已被实体屏幕接收。应用 GL frame 与物理屏幕验收、Qt WebEngine/Chromium/网页验收分别标识。
