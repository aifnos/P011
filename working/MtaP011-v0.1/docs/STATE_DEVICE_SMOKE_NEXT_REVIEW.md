# 最新 State 无 RF P011 smoke：下一步只读评审

仅方案，未执行 ADB/设备、测试、OS 子进程或读取真实用户文件。冻结 8 文件 SHA 已逐项读回，与交接一致；不升级旧 UI/TTY/TLS PASS。

## 现有入口是否确实取最新 State

- `host/device_ui.py:snapshot` 和 `host/device_toolbox.py:snapshot` 都复制当前 `BASE/runtime/*.py`，所以重新 snapshot 会包含最新 State、WiFi、Session、两个 UI entry；不是固定调用旧归档。
- launch 在 fresh Python 将新 candidate/runtime 置前，再 import 当前 entry；standalone 的 `State` 与 toolbox 的 `MtaState` 都来自根 `mta_service`。copied runtime 的 `mta_toolbox_*` 是独立命名空间，不替换 MTA State。
- 但现有 snapshot 没有预先固定 8 个 SHA/完整 import closure，glob 会无声收入后来新增模块；旧 host checker 不能仅凭运行成功证明跑的是 reviewed 当前组合。
- 现有两入口会对复用 candidate native 直接 chmod700，没有 exact FD 全员验证/旧目录不改门槛。不能直接照旧入口作新的严谨 freeze；需新版本 checker，不改旧档。
- `verify_mta_host_lifecycle.py` 用合成 HTTP fixtures 测根 QML 的 epoch/键盘/文件页；不实例化生产 State/新 Session，不是 P011 后端接线证明。

## 最小方案：先后分层，不以页面代替线程证据

1. ROOT 冻结/审查新独立 checker 与 HOST 故障测试，创建 fresh versioned candidate/session，仅 synthetic test-user；旧 candidate、源/日志、用户 AREA/user 不触碰。
2. 首轮优先 standalone 5 图（有限 main 35 秒、alarm60、外部更长等待），减少变量；随后同组合 toolbox 8 图验证两 server/返回 fresh cancel→status。二者证据独立，不互相替代。
3. launch 必须是已预算的短 inline argv 或 exact staged pinned runner；不要重新使用长源码 stdin canonical 输入。核验 candidate/manifest full SHA，以及实际导入模块 canonical `__file__` 属于新 candidate、entry.State/MtaState 指向同 exact 根 State。
4. 全部新文件 fd 校验 owner/type/nlink/metadata/size/full hash 后才规范新文件权限，再完整读回并尝试关闭所有 fd；不 chmod 旧 candidate，不仅校验 basename/path。
5. 实际只允许只读 `--capabilities` probes、loopback HTTP、合成目录/QML 截图、cancel/rename/本地导航；禁止 discover_start/scan/receive/connect/recover、LAN/audio/用户文件与任意命令。
6. `scan_available` 可能真实为 True，不能靠 receive=false 误以为所有 RF 都禁用；checker/QML 自动流程须有严格 action 白名单与事后 native/helper/lease/event 观测，意外 RF 请求立即判 FAIL，不自动重启/恢复/重试。
7. 核验实际 native network capability receive/send=False、源码 define0 与 binary full SHA；只读取事实，不把 fake capability 或测试改开关代替平台 gate。

## 必须新增的 closure 观测

- 现有 entry 仅给 resources_closed/occupancy_released 布尔，不公开 exact worker/finalizer/probe actor counts。新 observer 应强引用实际创建的 State/servers/serve threads/Qt child，输出固定 bool/counts；private refs/PID/token/path不公开。
- 若沿用 entry.main，可经 ROOT 审查的 capture-only constructor wrapper 保留真正 State 实例（不换类、不改 capability/task/restore）；或新 pinned target runner 显式持有相同对象。无此观察不能宣称 full lifecycle counts 已实测。
- worker/session alias exact 相同；所有历史 finalizer actual is_alive=False，unknown starts/actors/pending=0；State.close is True、closed is True、passive session status.closed=True，不能用 doneEvent/线程字段清空替代。
- 每个 readonly Popen 实际 poll exited、原 stdout/stderr exact 身份及 closed=True；spawn_pending/unknown=False；不凭 capability JSON 正常或进程名不存在判闭合。
- 普通 UI cancel 创建的是 cleanup Session，worker 可能 skipped，不能声称真正接收 worker 或 transfer/socket close 已验证。可另加明确 SYNTHETIC 的 private cleanup operation.start→saved worker actual exit→external finalizer→State.close；不启动 radio/lease/transport。
- HTTP 保留 exact serve/request refs，join 锁外，真实 threads exited、raw loopback listeners closed；2-server 版还观测 sampler worker exited、LAN never started。现有 minhttp 无完整历史 ledger，需 capture-only thread registration observer或另列此限制，不能由 workers map 为空推出所有历史线程已退出。
- 当前 exact lock directory/两文件按 inode/UID/mode/nlink/PID-start 内容核验后移除；确认占用实际不存在、session owner 进程 actual exited。若任一 unknown/live/pending，保留 lock/journal，不进入下一轮，不按同名文件删除。

## 原厂与网络的独立检查

- before/after 不经被测 State 自报：固定原厂文件 hashes、Z03/control_engine/weston exact PID/start/exe/parent 一致；保持原厂始终运行，没有“重启恢复”隐含步骤。
- 额外只读原 Wi-Fi COMPLETED/frequency/interface identities、网络 processes、完整 IPv4 地址/路由/rules 与 IPv6 地址/路由、same boot、project private actors/interfaces/locks/journal 事实；旧 stock_snapshot 仅 hashes/processes 不足以独立证明无线没变化。
- 超时/无 RESULT/OK/REMOTE_EXIT 分开记 host/remote 状态，失败的旧结果不改写；只 pull 当前 owned session 固定结果与合成图片，raw/owner/token/source/proc身份留 private。
- 图片逐张审阅 800×268、无重复 y106/rotation/键盘残留；保留页面断言、日志、Qt capture/光学/真实触摸层区别。最新 smoke 不证明手机互传、P2P/DHCP、用户文件、安全故障或所有 transport 闭合。

## 最小新 checker 必须钉住的输入

- reviewed host checker、其 HOST tests、target observer/runner 与 manifest full SHA；交接 8 文件固定 SHA（4 runtime 实际入包，3 tests/doc 作为 HOST 参考不部署）。
- runtime import closure：mta_service、mta_wifi、mta_transfer_session、mta_transport、mta_crypto、mta_files、mta_storage、mta_protocol、p011_json、minhttp、mta_safety、qt_quicktest_runner，以及实际选择的 ui/toolbox session。
- MtaTrial/MtaToolboxTrial、根 device QML/JS、exact 两个 native binary full SHA/owner；toolbox 轮另钉 copied runtime/device/web 与 verify_integration/source pins，不用动态 glob 替代清单。
- 独立 baseline reader、短 argv budget parser/remote status validator、fixed public schema、结果 ZIP CRC/逐成员 SHA与私有排除。未用的 DHCP/P2P/private candidate 不因 glob 顺带部署执行。

本轮只新增此文档；ROOT 决定具体新 checker 文件与观察方式后，先 HOST 假环境门槛，再唯一无 RF actual。旧 af24 UI PASS、最新 TTY actor0、此前 TLS 回环分别保留原证据范围。
