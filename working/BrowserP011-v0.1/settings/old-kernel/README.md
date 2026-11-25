# 原有浏览器内核：正式设置入口

按用户 2026-10-20 最新要求，沿用设备的 Qt 5.10.1 / QtWebEngine 1.4。新增设置“浏览器”，直接加载外置页面；不安装 Qt 6、controller、新服务或启动项。此前 Qt 6 候选与日志仅作历史保留。

当前只接受固件 `z031_v2.4.0-20251128_174826-user` 和当前带 Bili 的 Z03 SHA `3526b379c4083092c9c282d4d749d2e5c72d89e56730bf08c975e3222ed42896`。新的 Z03 SHA 为 `b7d3ae6d7696364970613f0a23f8eeabec39f90bdb6f807ccb6c59221b4e70d8`。只改 SetMainPage 一个 QRC 记录，其余 399 条资源、Bili 的用户反馈入口、ELF 代码和记录外字节保持。浏览器为第 17 项，原有顺序和红点下标保持。

界面和首页资源安装到 `/mnt/data/p011-browser/settings/legacy/`，由 root 持有。固定 source 是 `file:///mnt/data/p011-browser/settings/legacy/BrowserPage.qml`。页面继承原设置的 800×268 区域。

三个入口默认选择当前会话 ADB transport 1，也可把明确 transport 作为第一个参数：

- `检查浏览器安装状态.cmd`：只读设备身份和进程快照，不上传、不安装。
- `正式安装浏览器.cmd`：使用 `selected-package.txt` 指定的不可变包，先核身份和全部上传字节，备份当前 Bili Z03，再进行本次明确的正式安装。
- `恢复浏览器设置入口.cmd`：只按本安装 receipt 和当前身份恢复本次备份的 Bili Z03；保留页面、证据和备份，不递归删除管理目录。

主机直接调用示例：

```powershell
python -B .\host_legacy.py --action inspect --transport 1
python -B .\host_legacy.py --action install --transport 1 --expected-snapshot <本轮snapshot.json>
python -B .\host_legacy.py --action restore --transport 1
```

安装会只读确认正式 Bili listener、播放 lease 和工作线程均闲置，以避免打断账号或播放会话。它保留当前 UI 与 vendor 父循环的 PID/starttime/exe 绑定；必要时只向该 UI 发正常 TERM，由同一父循环重载。不会 killall、重启设备、修改 Bili 程序或其 receipt、账号/历史/媒体数据、vendor startup、系统库、无线/NV 或 USB 设置。

根分区原为只读时，仅显式 install/restore 动作会在原子替换 Z03 和定点缓存处理期间临时 remount rw，并在 finally 确认回到原挂载模式。只处理 SHA1(`:/ZybQmlFiles/ZybSet/SetMainPage.qml`) 对应的固定 `14289f774f2ede3ee177615be7dc93a12ba1fcdb.qmlc`；核对 qv4cdata 头、完整来源、root 普通文件、原始元数据和 SHA，备份后再核一致才移除。原厂 cache 为 0666 的特例只用于此固定文件，不放宽安装文件权限；不遍历或删除包含此依赖的其他缓存。用户数据不清理。未知身份、未知部分安装、缓存漂移或进程变化均停止并保留证据。

每轮输出到项目 `logs/BrowserP011-LegacySettings-*`，保留 ADB stdout、stderr、host/remote exit、前后快照、安装操作结果及自有元数据/原件备份，并自动生成 `.private.zip` 与 SHA-256。这里的 `installed` 只证明文件、进程和挂载事务完成；设置导航、网页实际显示、触摸和声音需分别记录，不自动改为通过。

重新制作包只在电脑进行，不连接设备：

```powershell
python -B .\build_package.py --page-dir ..\legacy-page-source
```

不可变包目录包含固定单 QRC Z03、5 个页面资源、Python 3.5 安装器及逐成员 SHA。设备 Python 不依赖缺失的 stdlib json，报告使用原有 output-only `p011_json.py`。本地 ZIP 是私有固件派生包，不作为公开仓库内容或完整救砖镜像。
