# 发送链路 v76：实际 Linux TCP/TLS 专项与正式接线边界

2026-10-03。验收手机为用户指定的小米 15 Ultra；HyperOS 和原厂互传版本尚未确认。本阶段没有访问、部署、重启或操作 P011，也没有操作手机。

## 当前结果

ROOT `9839fc` 首次执行 R5 的唯一新方法 `GoSendTransport76Test.test_native_linux_owner_and_tls`：HOST 0、child 0、无超时，child 只调用一次；checker elapsed 0.469 秒，unittest `Ran 1 test in 0.289s / OK`。没有重跑已经通过的 SenderPump 六场景或旧测试方法。

本专项实际完成 Linux `lo` 上的 TCP 绑定／预监听／非阻塞 accept／TLS 包装与原 FD 移交，同一个原发送 worker 内的两条 TLS 连接、WebSocket 控制与完整 ZIP 下载、CRC／字节／哈希比对、对端终末确认与 ACK 发出，再核实际 once-close／EBADF。手机协议端是一个模拟线程，不是小米原厂互传。

GO 所有权、Journal、旧 IP／DHCP setup／ACK、WPA STA 原始回复均为明确标注的祖先模型。只测试新 Native76 的 TCP/TLS 资源层，不据此签实际建组、地址安装、DHCP 发包或手机关联。完整 Parent/F/State 也没有在本专项执行。

ROOT `b161f3` 核对 31 份私有输入快照与当前源的大小／SHA，无不一致；26 份目标源码在 checker 中通过 Python 3.5 语法检查，实际运行仍是 WSL Python 3.13.12，不是 P011 Python 3.5。独立审查另读全部 31 原件与 28-row plan／20-definition map，完整解压并逐字节、手工 CRC 校核公开 ZIP，严格 marker／Ran1／OK 与前后来源及工具身份一致；未重跑测试或导入目标源码。

## 失败原件与原因分开保留

| 版本／结果目录 | 实际结果 | 后续处理 |
| --- | --- | --- |
| `go-send-transport-v76-host-20261003-053643-2bc8016c` | FAIL，cleanup 的 `native_close_pending` 掩盖主因 | R2 仅补独立清理及原异常保留，不回填旧结果 |
| `go-send-transport-v76-r2-host-20261003-054638-2fb095ca` | FAIL，HOST UDP 67 已占用 | R3 让明确属于旧 DHCP 模型的夹具使用实际空闲 UDP 端口，不停服务、不改网络 |
| `go-send-transport-v76-r3-host-20261003-055046-7bc44c0d` | FAIL，在原 25 秒绝对期限拒绝，缺少连接阶段归因 | R4 仅增有限私有阶段投影与对端原异常，不能把超时称作性能不足 |
| `go-send-transport-v76-r4-host-20261003-060130-0a109549` | FAIL，模拟手机首次 TCP connect 得到 errno 111，尚未进入 TLS | 原端口链一致；随后只读实际路由查明 WSL localhost 默认走 `loopback0`／table 127，而 listener 绑定 `lo` |
| `go-send-transport-v76-r5-host-20261003-061115-99a54375` | PASS，仅新 Linux TCP/TLS 专项 | 模拟手机 socket 也实际绑定 `lo`，源／目标／设备绑定回读，仍只 connect 一次；生产 Native/Pump 和原 25 秒期限不变 |

ROOT 的实际只读 `ip route get 127.0.0.1 from 127.0.0.2` 返回 `via 169.254.73.152 dev loopback0 table 127`；加 `oif lo` 返回本地 `dev lo table local`。`ip rule` 和 table 127 与此一致。没有修改系统路由、接口、地址或防火墙。这个诊断解释 HOST 夹具的连接差异，不能当作 P011 故障原因；R3 未记录的主因也不逆推补签。

## 固定来源与公开结果

| 新来源 | 字节 | SHA-256 |
| --- | ---: | --- |
| `candidate/go-send-transport-v76/runtime/mta_go_native.py` | 200317 | ee46d8313fe31cbc5a0d16d0d14aff7ce2b3fb507f3cdac572e59bc5f16dfa9f |
| `candidate/go-send-transport-v76/runtime/mta_go_dhcp.py` | 21997 | 3f7dbab30c8925cf0ea288a1e011787d436c07d3a8178a8a45934db3597f9312 |
| `candidate/go-send-transport-v76/runtime/mta_go_bootstrap.py` | 30951 | 25247dcb905b53cab1e1df1d0949e8c9296b91caf36d94d4c1171763cbc46568 |
| `tests/test_go_send_transport_v76_r5.py` | 61376 | 59b1b484725ce72cdca367eb4ae7d97e37d04b959fdc23288953ca4002165359 |
| `host/go_send_transport_v76_definition_manifest.json` | 4556 | 045d28f552e572182b7d2653863eccb6ced9b26a7f3aee093fae69ea0fba9eac |
| `host/go_send_transport_v76_r5_source_manifest.json` | 6055 | 518a7366dcf8b5e7745187f184c2e3f89e01d7f7f2d5b8d34cb0d67c4ee8d350 |

一键入口 `HOST_MTA_GO_SEND_TRANSPORT_V76_R5_CHECK.cmd` 仅 PC／已有 WSL 测试，无 ADB／射频／系统网络配置。CMD 本身未点击；实际执行的是同一个固定 checker。26 runtime 图有旧 F60 和 Loader72 定义，仅供该专项原祖先身份；不是下面新 Parent/F24 图的运行证据。

公开结果：[public-result.zip](results/go-send-transport-v76-r5-host-20261003-061115-99a54375/public-result.zip)，3628 B，SHA-256 `67684c4cbcc5ef6c4b8002390875c935f750ed1e2b0659dff04e913d6a11a254`。四成员仅 `result.json`、`README.txt`、严格安全 `stdout.raw`／`stderr.raw`；失败私有诊断、证书、私钥、归档内容和手机标识不在公开包。

## 已制作但仍未运行的 Parent/F 来源

v76 新 F／Loader、普通父进程 `runtime/mta_go_send_bridge.py` 和 `mta_go_send_publication.py` 已制作并通过目标语法静态检查，但不算 Parent/F 运行或部署通过。它们保留原文件句柄／归档和继承 FD、真实父子进程、原 task/epoch/绝对期限、窄私有 START/LISTENING/SELECTED/RESULT IPC，以及同一个 GO worker 的 DHCP／STA／TCP／恢复顺序。原 service20 默认不变；只有实际原 F `GoSendLaunch` 可以选择同一个原任务期限，不允许 caller TTL 或 poll 续期。

Publisher 的固定 bundle seal 仍未设置，会拒绝发布；不是可运行的正式安装包。当前发送 IPC 只有 LISTENING／RESULT，没有实时进度。下一 v77 正在制作有界实际字节进度；正式 State／Boot／文件中心同源接线和真实准入仍待完成，不能直接置 `send_available=True`。

## 不变的设备与目标边界

旧 P011 pending 与完整网络恢复未证的历史结论不改；未自动处理记录，也未自行正常重启。实际 CLIENT 接收准入、完整发送流程、P011 运行、原网络恢复及小米原厂双向收发仍待验证。`send_available`／`receive_available`、设备／手机／物理恢复没有晋升；目标 active，尚不是只剩人工手机验收。
