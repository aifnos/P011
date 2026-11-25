# v0.4 实现边界与技术依据

菜单二进制补丁未变，只替换外置工具页。原 ELF 与候选 ELF 校验、父进程识别、PID/starttime 防复用、恢复循环沿用此前已在 P011 手动 Stop 验证的逻辑。本版新增服务监督和事件统计，不能把旧测试等同于新功能已通过。

后端只绑定 127.0.0.1 随机端口，客户端用每次会话生成的 header token。仅允许 GET /api/state、GET /api/media、POST /api/action，操作名称固定；限制 Host/Origin、头长、请求体大小、拒绝重复头/分块传输。不提供任意命令、文件下载或 CORS 接口。SSH 使用独立进程和公钥，不修改系统密码。

ADB 只变更已识别的一个 debug 字段，以字节快照和已写内容哈希记录恢复；遇到其他写入不覆盖。此版不热切换 USB。设备端 watchdog 使用 time.monotonic，不受设备错误日期影响。

Python 固件缺少 json；复用项目 p011_json 输出编码器，HTTP 操作体是固定 ASCII 名称，无需 json 解析器。D-Bus 为可选依赖，Linux sysfs 与只读外部命令有单次超时。未提供的遥测字段不会补成零；RSSI/RSRP/信号质量不混用。

浏览器宿主为原 Z03，QtWebEngine API 对照 Qt v5.10.1 头文件；未尝试禁用沙箱或证书验证，未声称已经低权限隔离。视频用 QtMultimedia，不直接调用原厂联网课件业务。所有媒体由用户选择后才播放。

外部说明来源（设备实测仍以本机日志为准）：
- https://docs.kernel.org/power/power_supply_class.html
- https://man.openbsd.org/sshd_config
- https://github.com/qt/qtwebengine/blob/v5.10.1/src/webengine/api/qquickwebengineview_p.h
- https://github.com/qt/qtwebengine/blob/v5.10.1/src/webengine/api/qquickwebenginecertificateerror_p.h

测试方法：Python 3.5 语法检查、临时 sysfs/配置文件与协议解析器夹具、原厂/候选模拟进程恢复，文件完整性和 ZIP CRC。主机测试不测试真实驱动和音频，不测试 Windows 终端/驱动，不替代 Qt 5.10.1 组件实例化。
