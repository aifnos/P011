# 设置中新增浏览器：定点安装计划

当前仅有电脑端候选构建；本目录不包含会自动替换设备 Z03 的测试入口。浏览器运行包未就绪或未验证时，不安装一个会误报可用的设置项。

入口追加在原设置网格第 17 项（索引 16），名称“浏览器”，复用原 WLAN 图标。前 16 项顺序、升级/蜂窝/会员红点下标保持。页面使用父内容区 800×268，不另加 y=106 或旋转。

候选输入必须是已安装 Bili 的 Z03，SHA-256 `3526b379c4083092c9c282d4d749d2e5c72d89e56730bf08c975e3222ed42896`。只改 `SetMainPage.qml` 现有压缩 QRC 记录，不能从原厂 cb8d…重新生成并抹去反馈页的 Bili 入口。现有反馈记录、其余 399 条资源和目标记录以外全部字节须相同。

电脑生成器 `build_settings_candidate.py` 不访问 ADB，输出新目录内的完整候选、解压设置页和逐项边界清单。压缩槽位为 offset `0x226120`、1763 字节；仅去掉行首尾空白及空行以适应原槽，保留原文字串和业务语句。

设备安装由当前主任务单独执行并记录原始双流及退出状态，不能执行旧 START：

1. 明确选择当前物理设备，冻结 boot_id、Z03/control_engine/vendor launcher 哈希、唯一 UI/Weston/控制进程 PID/starttime/exe 及父循环身份；核对现有正式 Bili 安装和最新修订，不触碰其账号或媒体数据。
2. 先在 `/mnt/data/p011-browser` 的 root 管理区部署并校验完整浏览器候选、独立 controller 和本目录固定 `BrowserEntry.qml`，确认只通过私有 HTTP 接口启动固定 argv，浏览器子进程为 UID 65534/GID 44。不能给网页暴露 shell 或 controller 凭据。
3. 用 root 私有新目录保存当前 `/usr/bin/Z03` 的完整原件、SHA、原权限和安装前身份；在备份读回匹配后记录本次明确的设置功能安装范围。备份为当前 Bili 版本，不能用更早原厂镜像替代。
4. 临时写入根分区和原子切换只能出现在显式设置安装动作中，遵循该挂载原状态；这不是自动浏览器测试的一部分。不得更改 vendor startup、系统库、WCN/NV 或其他系统分区。
5. 如必须重载 UI，只向已冻结且再次核验的 UI PID 发送正常 TERM，让同一 vendor 父循环启动新 UI；不能 killall，不能信任复用 PID，不能以请求停止代表已恢复。重载前先确认没有 Bili 播放或账号操作正在进行。
6. 安装后核对完整 Z03 候选 SHA、原文件备份、当前进程/父循环、其他两原厂文件及挂载原状态，保留单独设置安装 receipt。Bili 自己的历史安装 receipt 不应被伪造为包含此次浏览器修改，恢复工具需明确提示这条新身份链。
7. 只做一次必要的入口打开、独立进程退出和返回设置检查，保存日志 ZIP。页面图像或 UI 进程存在不等于物理触摸和长期使用通过。

恢复必须以本次设置安装 receipt 和当前候选 SHA 为门禁，只还原这次备份的 Bili Z03；出现未知文件或进程身份时停止。原 Bili 恢复程序可能会因新 Z03 SHA 拒绝，应先恢复本设置变更再使用 Bili 恢复入口。

启动桥接方案：独立 root controller 仅监听 `127.0.0.1` 动态端口，在固定 root 0600 文件 `/mnt/data/p011-browser/settings/endpoint.json` 发布 `schema=p011.browser.endpoint.v1`、`host=127.0.0.1`、整数 `port` 与 64 位十六进制 `token`。旧 Qt 原生设置页读取后，只发送空 body 的 `POST /open`、`POST /status`、`POST /close`，携带 `X-P011-Native-UI: browser-qml-runtime` 和 `X-P011-Browser-Token`；服务只接受精确 Host，拒绝 Origin、GET 或其他请求。

controller 只能从已校验 manifest 选择当前浏览器，不能接受任意可执行路径、shell、环境或命令参数。返回只含 `ok`、`state=ready|starting|running|stopped|error` 和可选固定 reason，不返回 URL 或用户内容。原生页返回时等待关闭状态，销毁时仅尝试固定 `/close`；controller 仍须独立检查 UI PID/starttime 和心跳失联，保证销毁通知丢失也不会留下浏览器进程。controller 和浏览器启动环境隔离，不能把 Qt 6 库加载入 Z03 的 Qt 5 进程。新独立服务开机持久化需使用自身安装项，不能追加或改写 vendor startup。
