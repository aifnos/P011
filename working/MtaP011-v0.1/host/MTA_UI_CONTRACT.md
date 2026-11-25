# 手机互传 QML 页面接入

`device/MtaPage.qml` 使用宿主提供的 **800 × 268 内容区域**，无额外纵向偏移、旋转或原厂生命周期挂钩。组件配色复用现有工具箱，未携带字体。

## 服务与能力

宿主设置 `serviceUrl = "http://127.0.0.1:端口"`、`token`。仅使用 `X-P011-MTA-Token` 请求头；服务不接受 query token，页面也不提供该兼容开关。非回环地址、空 token、断线、格式异常、能力缺失均禁用无线动作。修改地址或 token 会使旧请求失效，避免迟到响应重新启用控件。宿主文件中心与 bootstrap 请求也使用 epoch / abort，服务切换清空旧目录和文件选择。

- `GET /v1/status`：生产服务返回状态对象本身（bare object）。页面同时可解析显式 HOST fixture 的 `{ok:true,data:状态对象}` 包装；这不是生产响应要求。
- `GET /v1/files`：返回 `{files:[{id,name,size}]}`。ID 仅在相对路径及完整文件身份不变时复用；刷新后发生变化的旧 ID 必须重新选择。
- `POST /v1/action`：JSON 请求体，仅页面枚举动作，不含任意命令或文件路径。
- 成功动作可直接返回新状态，也可返回确认，随后页面重新查询状态。
- 状态中的能力应由后端当前探测决定，不因显示页面而开启蓝牙或广播。

状态字段为 `state,nickname,devices,request,transfer,received,capabilities,reason,restorePending`；`discoverable,scanning` 明确表示活动。能力 `receive,send,scan,rename` 可为布尔，或 `{available:布尔,reason:原因}`；缺失不推断为支持。

`devices` 元素 `{id,name,available}` 仅表示本轮发现状态。`available !== true` 禁止发送；可发现也不等于 `capabilities.send.available=true`。选中设备消失或离线会清除选择，断线不显示旧列表。`request` 为 `{id,name,fileCount,totalBytes}`。`transfer` 为 `{bytes,totalBytes,filesDone,totalFiles}`，可含 `archiveBytes`（ZIP 网络字节）、`localCommitVerified`（文件已校验并落盘）、`peerAckVerified`（对端完成 ACK 已收到）。这三个事实不能相互替代。`received` 元素为 `{id,name,size}`，来自实际落盘目录中的记录。

“开始接收”先准备 / 持有原网络快照，之后注册可发现。手机发送时可能临时切换 Wi-Fi，WSS 文件确认发生在网络连接之后；拒绝文件可以阻止下载与落盘，但仍需恢复已经取得的网络租约。临时联网授权与文件接收授权是两个阶段。

界面识别 `idle,advertising,discoverable,scanning,waiting,connecting,transferring,restoring,complete,completed,error,failed,awaiting_confirmation`。未知状态显示“待核实”，不会显示成功。恢复中禁用再次收发，完成应由后端明确报告。

## 动作与宿主信号

| 动作 | 参数 |
| --- | --- |
| `discover_start` / `discover_stop` | 无 |
| `scan` / `scan_stop` | 无 |
| `accept` / `reject` | `requestId` |
| `cancel` | 无 |
| `recover` | 无；只核验/恢复已有归属的租约，不清理未知配置 |
| `send` | `deviceId,fileIds` |
| `rename` | `nickname` |

- `fileCenterRequested("select")`：宿主打开受限用户文件中心；返回后设 `selectedFiles=[{id,name,size}]`，其中 `id` 为后端发行的不透明 ID。页面拒绝没有 ID 的选择，不把任意路径发往服务。
- `fileCenterRequested("received")`：宿主打开接收目录。页面内“已收到”仅展示服务提供的记录。
- `nicknameEditRequested(currentName)`：宿主调用已验证的键盘组件，编辑完成调用 `applyNickname(name)`。仅接好键盘后设 `nicknameEditorAvailable=true`；页面不调用未经证明的原厂私有 ABI。
- `exitRequested()`：宿主决定退出与安全恢复流程。`prepareLeave()` 仅终止本页 HTTP 请求，不代表无线或原厂恢复完成。

## PC 界面验证

在此候选目录执行：

```powershell
python tests/test_mta_ui_contract.py
python host/preview_mta_ui.py --screenshots results/ui-host
python host/verify_mta_host_lifecycle.py --output results/ui-host-lifecycle
```

`--interactive` 打开 PC 预览。所有模拟数据只在显式 HOST fixture 预览服务中存在；生产页面不内置假手机、假文件或假进度。截图与结果 JSON 标为 `HOST_QML_QA_ONLY`，**不证明 P011 运行、蓝牙广播、手机发现、Wi-Fi 切换或互传成功**。PC Qt 版本为结果中实际记录值，目标 Qt 5.10.1 仍需独立验证。

`verify_mta_host_lifecycle.py` 使用真实 `MtaHost.qml` + 延迟回环 HTTP fixture，核验旧 endpoint / token / bootstrap 回复不能复活目录、选择或旧 token，以及键盘取消 / 完成后不会覆盖文件页面。该报告及截图标为 `HOST_ONLY_QML_LIFECYCLE` / `HOST_ONLY-*`，不包含 fixture token、不访问 P011，也不证明无线恢复或手机兼容。
