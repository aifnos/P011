# 发送进度、原服务期限与 State 接线

2026-10-03。本阶段没有访问 P011、启动无线、重启、清除旧 pending 或操作小米手机。对端记录为小米 15 Ultra；系统／原厂互传版本仍未知。目标仍 active，生产收发未开放，尚非只剩人工测试。

## 本次新增的证据

ROOT `0bcb0f` 唯一首次执行 HOST77：child 0、无超时、0.531 秒；唯一新方法／18 个独立夹具，旧测试方法 0，unittest `Ran 1 test in 0.352s / OK`。27 个目标定义做了 Python 3.5 语法检查。真正执行的是 Linux 私有 pipe 的 fstat、nonblocking、PC_PIPE_BUF、select、read/write、close/EBADF，以及固定77的进度输出／父端消费算法。

原 State／Operation／Process／GoEntry／Launch／Native owner／Pump 与 accepted GATT-write 祖先是明确的 HOST 模型，不是这些 producer 或 F 入口的执行证据。零字节 EAGAIN 是显式故障注入；短写 instrumentation 实际调用原 os.write 写一个严格前缀。没有 GO、DHCP、真实 GATT 写入、TLS 文件传输、真实 child reap、准入或网络恢复证明。

ROOT `d2984a` 与测试作者的只读 artifactcheck 已核32份当前来源／private snapshot逐字节、大小、SHA一致。作者核验不称独立测试设计；没有重跑方法或 AST。[四成员公开结果ZIP](results/go-send-progress-v77-host-20261003-065638-731f7b84/public-result.zip)：3770 B，SHA-256 `9656cb69339fa2bed6f373f27205216421a43bd60690caaf2f0961d7edaa016d`。stdout116 B固定安全marker，stderr96 B严格摘要；ZIP所有成员读回与CRC一致，不含密钥、凭据和private inputs。

[电脑一键入口](HOST_MTA_GO_SEND_PROGRESS_V77_CHECK.cmd)只核主机。实际运行的是固定 Python 的 checker，不冒充CMD已由人工双击或P011通过。此专项已通过，不为新接线重复执行旧18夹具。

## 冻结来源

| 来源 | 大小 | SHA-256 |
| --- | ---: | --- |
| Bridge77 `candidate/go-send-progress-v77/runtime/mta_go_send_bridge.py` | 55247 | `b5f723c7cd259e06d3aa07322909b4d96e48ad97529cd31f7166afe1a3b0f72c` |
| F77 `candidate/go-send-progress-v77/runtime/mta_go_executor.py` | 36974 | `c6bbf1b483c1ceea8f4d4cd4a6ada5ba843a07e8a10cc490fecef34acb950c0b` |
| 固定24图 `host/go_send_progress_v77_definition_manifest.json` | 5372 | `802a8cf5abb1f360f3c637c1eac312e8edec00fd3a41ac065654b76552bffb6c` |
| HOST77 test | 32960 | `9847bdbe440c7bf9fec2b390399d7f5391253d7e7b8952bed61a7a33b97f5789` |
| HOST77 29行plan `host/go_send_progress_v77_source_manifest.json` | 6275 | `8f31079ac4eb3d15eba36d00e4437af0c0633d90121d20f358e6dedae75865e9` |
| Session78 `candidate/go-send-state-v78/runtime/mta_transfer_session.py` | 20633 | `e7321ad446318f96bf84b1a94f0e5e3c76b1e973e28826f1c2514527b6967859` |
| State78 `candidate/go-send-state-v78/runtime/mta_service.py` | 84637 | `b7729b6d0272b83a9c2af9e7b3003b97f68bc0fa15038c214ec8e04b7bb41998` |

State78 对真正基线 `candidate/client-state-integration-v32/runtime/mta_service.py`（57929 B／`c27a6978fb91fd414da96c57577e7030e059583bc10aad40b26dd0924505a2ab`）完整diff已由ROOT与另一个SOURCE审阅者读完。普通 `runtime/mta_service.py` 是51946 B legacy，不是这个基线；旧两件均未改。State78本身只有源码审阅，没有执行、AST或部署证据。

## 进度与期限语义

进度是固定十字段的被动观察，同状态至少间隔0.5秒、状态变化立即发，最高640个PROGRESS／642个总帧／512 KiB stdout，保留终末帧空间。EAGAIN不推进序列；短写保持未知，不补写。父端核任务绑定、序列、字节单调与阶段，保留首二末二及latest。进度满额或peer_completed数据不能代替原RESULT、真实reap、资源关闭或网络恢复。

两个已知 GATT 生命周期事件只在原accepted write已消费、helper／intent／epochs／事件原件仍绑定后分类；不吞未知cleanup/error，不清用户取消。State自身关闭helper时另有原worker关闭票据，但该事件仍不当作闭合证据。

Session78只收窄期限：GO任务取原服务绝对期限与原task timeout的较早值；重新点击不会延长服务。ROOT `21ecd4` 的五个constructor/start边界模型通过，6份原件／四成员ZIP由ROOT和该测试作者核验一致。[Session78公开结果](results/session-absolute-v78-host-20261003-063246-3caa0a6d/public-result.zip)：1856 B，SHA `22cdccfd6545baf3a015b82da3e1fa493181962b5df5400984eedcb67d10054d`。Thread.start与clock被截获；没有真实worker／finalizer／生命周期／准入执行。

## State接线与具体缺口

State78加入 `send_prepare`：原文件IDs→同worker打开Selection→真实归档PreparedSend→固定Publication→Bridge启动F/listener→扫描／选择／ECDH→传输。Selection、prepared、publication、bridge、helper保留强原件；资源关闭留在原worker，外部finalizer只读取保存事实。原服务cap必须由后续正式Owner传入。

目前 `_go_send_admitted` 仍明确拒绝，Publisher76 bundle seal仍None，旧Boot69-r3没有三个发送父模块；不能把这些源码存在写成正式可用。F被调用后，State78仍要求独立Native恢复事实，当前始终保持pending，不据RESULT.restored开下一轮。

SOURCE联合审阅发现一个确定闭合缺口：Bridge77捕获key.close异常却可能仍返回closed=True；原KeyPair又在native free前设closed=True。因此不能只查key.closed。正制作独立79窄修复，保存原key生成／关闭调用返回和异常事实、纳入closed；77及已通过结果不覆盖、不回填。新正式发送页面也在独立候选接线，尚无测试／部署结论。

仍需完成固定Boot／asset seal／正式服务与QML接线，实际只读启动准入，以及独立网络恢复producer／consumer，再做P011当前基线和端到端测试。准入不是要求同次GO先成功的循环门：实际RF仍由单线程F的原Store/Native事务逐步验证。设备旧pending／完整恢复未证保持，正常重启许可尚未回复，不自动删除记录或重试RF。历史日志和早期失败原件不改。
