# 互传服务独立安全 review

审查范围：`runtime/mta_service.py`、`mta_transport.py`、`mta_files.py` 与 `device/MtaHost.qml` / `MtaPage.qml` 的接入契约。审查者只新增本文件及 `tests/test_service_integration.py`；生产修正由这些模块的 owner 完成。

## 证据与验收边界

- 新增测试只属于 **HOST**。无线 / ConnMan helper 为明确的无副作用 fixture，没有操作 ADB、蓝牙、Wi-Fi、系统服务或学习笔文件。
- post-commit 测试使用真实 HOST TLS、WSS、发送 ZIP、下载 ZIP、`SafeZipReceiver` 校验和原子落盘；仅在落盘后的完成通知写入处注入确定性的故障。它证明本地结果处理，不证明手机协议兼容。
- 当前 P011 密码原语 / 文件落盘 smoke 与 native 只读 capability 证据由主线程另行记录；不得从本套测试推导 P011 的广播、手机发现、网络切换 / 恢复、手机完成提示。
- `send.available=false` 是正确的未验证能力门控，**不是“完整双向互传已完成”**。发送端 P2P/AP 网络所有权、恢复和真实手机收发仍是目标中的未完成部分。

运行命令（候选目录）：

```powershell
python -m unittest discover -s tests -p 'test_service_integration.py' -v
```

首轮 19 项为 9 FAIL + 1 ERROR；失败断言没有用 `expectedFailure`、跳过或改测试预期隐藏。生产 owner 根据可复现因果链完成修正；新增 prepare / helper close 回归后，最终 **26/26 HOST PASS，0 SKIP**，测试文件 Python 3.5 语法检查 PASS。缺 HOST OpenSSL 时，只有真实 TLS 测试明确 SKIP，绝不转为 PASS。

真实 QML 宿主生命周期验收另外执行：

```powershell
python host/verify_mta_host_lifecycle.py --output results/ui-host-lifecycle
```

结果为 **6 checks PASS / 8 screenshots / 0 QML warnings**，实际 HOST Qt 5.15.2、800×268。报告 `results/ui-host-lifecycle/HOST_ONLY-result.json`，截图均为 `HOST_ONLY-*`。已查看新服务文件列表、键盘及取消 / 完成后的文件页截图；没有键盘或旧页面叠层。此层仍不是目标 Qt 5.10.1 的实机验收。

## 发现、因果链与回归入口

### P0：恢复失败丢失 Wi-Fi 租约所有权

旧 `State.receive()` 每次建立新的 `WifiBackend`，并直接执行 `self.lease = backend.receive(...)`。真实 backend 可以在已启动 mutation helper 后，因为连接 / 恢复失败抛出异常，此时赋值未完成，`self.lease` 仍为 `None`。旧 finally 把 `lease=None` 当作恢复成功；新的 backend 又绕过旧实例的 `_restore_failed` / `_active_lease`，允许叠加网络操作。

另一条路径是 `lease.close()` 返回 False 后仍清空 `self.lease`。随后的 `State.close()` 只检查蓝牙，没有 Wi-Fi 所有权，可能返回 True。

回归入口：

- `test_failure_before_lease_assignment_blocks_retry_and_close_success`
- `test_failed_connect_retry_keeps_one_backend_ownership_domain`
- `test_false_lease_close_is_not_discarded_or_reported_restored`
- `test_pending_wifi_restoration_can_only_clear_on_real_fixture_recheck`

生产 owner 已引入持久 `wifi_backend`、保留 active lease、`wifi_restore_pending` 与 `restore_active()` 重试；以上 HOST 回归已由失败转为通过。这个 HOST 修正结果不代替真实 Wi-Fi 恢复核验。

额外 prepare 回归验证原网络快照先于 helper / listen，prepare 自身失败或后续 crypto 失败均恢复已归属的快照，不注册发现。停止非 worker 会话先核验网络恢复，再释放无线 helper：`test_prepare_snapshot_precedes_discovery_and_stop_restores_ownership`、`test_failed_prepare_never_starts_discovery_and_closes_owned_snapshot`、`test_crypto_failure_after_prepare_restores_snapshot_without_discovery`。

### P0：失败的蓝牙恢复检查被第二次 Stop 误清除

旧 `stop_radio()` 在 helper / key 已清理后，无条件把下一次调用当作“本生命周期未修改无线状态”，返回 True，即使先前独立 capability 检查已经失败。

回归入口：`test_failed_radio_check_is_not_erased_by_second_stop`。生产 owner 已加入跨 Stop 保留的 `radio_restore_pending`；HOST 回归通过。

### P1：异步 helper 事件及 watchdog 不属于原会话

旧 helper callback 没有 session / epoch，停止后迟到的 `advert ready` 可再次设置 `discoverable=true`；旧 helper 的 `cached=false` 发现事件也能混入新一轮扫描。仅依赖 native 的 `cached` 字段不足以判定事件属于当前页面会话。

旧 reader 在 `PrivateHelper.__init__()` 就启动，可能先于 `State.helper` 赋值发回 `listen ready`。旧 watchdog 也没有 epoch，可能在旧取消唤醒后误停新 helper。

回归入口：

- `test_delayed_advert_ready_cannot_resurrect_stopped_session`
- `test_old_helper_callback_cannot_insert_rows_into_new_scan`
- `test_discovery_never_promotes_native_cached_rows`

生产 owner 已将 reader start 显式放到 State 取得 helper 所有权之后，并加入 helper / watchdog epoch。测试使用生产分配给 FakeHelper 的真实 callback，不绕过 epoch。

原实现另一个可独立复现的问题是 `closed` / `stop` 事件没有使当前扫描失活。native helper 提前退出后，短时间内设备仍可显示“本轮发现 / 在线”。回归：`test_native_closed_event_invalidates_live_discovery`。生产 owner 已使 live flags 失活并保持错误 / 恢复状态；HOST 回归通过。

### P1：启动 IPC 失败后 helper 无清理路径

创建 helper 后，`send(listen)` 或 `send(scan)` 抛异常。此时 watchdog 还未建立，旧 scan 路径没有 try/finally，helper 被留下；旧 receive 启动异常也只释放 key。

回归：`test_listen_command_failure_closes_created_helper`、`test_scan_command_failure_closes_created_helper`。必须清理 **本服务自己的** helper handle 并独立检查恢复；不能以全局进程名终止。

还补充 `test_helper_close_error_preserves_ownership_and_pending_failure`：helper.close 抛异常时保留同一 helper 的归属，标记 restorePending，后续 close 不能报 True；只有真实 fixture 的后续退出 / 独立核验通过才能释放。以上 HOST 回归通过。

### P1：已原子落盘后的通知失败丢失本地完成结果

`ReceiverTransport.run()` 在 `SafeZipReceiver.receive()` 返回完整实际文件结果后，发送 type 1 完成通知。原实现只容忍随后“等待 ACK”失败，没有容忍 **通知本身发送失败**；该写入异常逃出 `run()`，服务收到 `result=None`，无法再区分“文件从未保存”与“已经保存但手机未收到完成通知”。真实落盘文件仍在，不应重复下载来消除这个状态。

回归：`test_tls_postcommit_status_write_failure_preserves_local_result`。测试确认原子落盘且读取字节完全一致，再注入 completion-write fault。合理结果应保留真实本地文件、`peer_ack_verified=false`；Sender 也不得虚构完成。恢复是否成功另行决定 service 是否允许退出 / 下一次传输。

本地 commit、对端 ACK 与网络恢复应是三个独立事实。整体“传输完成”不能替代后两项，也不能因通知失败否认已经保存的文件。

生产 owner 已在 completion-write / ACK 的有限失败范围内保留 commit 结果，并明确 `peer_ack_verified=false`；真实 HOST TLS 故障注入回归通过。

### P1：post-commit 目录刷新异常逃出 worker

原 `State.receive()` 的 finally 在释放租约、停止 helper 后直接调用 `registry.list_files()`；目录暂时不可读抛出的 `OSError` 不在接收 try 范围内，因此可以逃出 worker，状态已改为 completed 但 `received` 未刷新。需要容忍目录展示失败并保留已验证的 commit 元数据 / 恢复结果，不把刷新异常当作未曾保存。

回归：`test_postcommit_catalog_error_does_not_escape_worker_cleanup`。该用例的文件确实经过 `SafeZipReceiver` 写入，而非假造成功数据。

生产 owner 已保留 `localCommitVerified` / `peerAckVerified`，目录刷新异常作为单独展示错误处理，HOST 回归通过。文件保存但恢复失败仍报 error / restorePending，不能开始新试验。

### P1：刷新 catalog 后旧 fileId 对应新内容

旧 `FileRegistry.list_files()` 仅按相对路径复用 opaque ID，同时更新 signature。用户选文件后同名文件发生变化，再刷新目录，旧 ID 会静默映射到新内容。`open_selection()` 的身份检查此时通过，因为它检查的已经是新 signature。

回归：`test_rescan_does_not_reauthorize_an_old_id_for_modified_content`，用不同实际大小消除时间戳粒度的不确定性。生产 owner 已改为 `(relative, signature)` 同时匹配才复用 ID；HOST 回归通过。

### P2：bool 设备 handle 与接入文档不一致

`isinstance(True,int)` 为 True，旧 discovered 处理把 `peer=true` 变成 ID `"True"`。回归：`test_bool_peer_id_is_not_an_integer_device_handle`。应拒绝 bool 与不在 native handle 范围内的值。

真实 HOST HTTP 用例 `test_default_header_contract_works_but_query_tokens_are_not_accepted` 确认默认 token header 请求返回 200、仅 query token 返回 403，且 status 为 bare object。此前 `MTA_UI_CONTRACT.md` 声称支持 `tokenInQuery=true` 及必返 `{ok,data}` 与实际服务不一致。安全默认没有放宽：生产 owner 已移除页面 query token 开关，本 review 已把文档改为 header-only / bare status。QML 默认 header 路径能够解析 bare status。bool peer 回归也已通过。

## UI 静态发现与独立 HOST 动态复验

- 旧 `MtaHost.fetchFiles/bootstrap` 缺少 `MtaPage` 已具备的 epoch / abort，迟到响应可能改旧文件列表或 accessToken。生产 owner 已统一宿主有 epoch 的请求组件；延迟 endpoint catalog、同 endpoint 旧 token catalog、旧 endpoint bootstrap 三种真实 HOST HTTP 场景动态复验通过。
- 旧目录 / picked 在宿主服务切换时没有清空。生产 owner 已在 resetHost 清空 fileRows、picked 与 page.selectedFiles；新的目录按 opaque ID 校正选择。HOST 动态复验通过。
- 旧设备文案无视 send capability；生产 owner 已改为“本轮发现 · 发送尚未就绪”。能力门控未放宽。
- 键盘 open() 会自行赋 visible，若宿主直接给这个属性 stage binding，容易破坏绑定。生产 owner 已用父 Item 进行 stage gating；真实键盘 open → 指针点击取消 / finish → 文件页两种场景动态复验并截图通过。
- nickname capability 永远 True，但服务禁止 helper 活跃时 rename；页面 radioBusy 没有包含 scanning / advertising，因而改名按钮可能可点但后端拒绝。前后端忙碌定义应一致。
- `prepareLeave()` 只终止页面请求，本身不代表无线资源或原厂界面恢复。宿主必须调用 service close 并检查独立结果；不能因点了“返回”就记恢复 PASS。

## 网络同意与文件同意是不同阶段

`test_network_consent_precedes_file_prompt_explicit_ordering` 记录的事实是：当前协议先依据 BLE 交换凭据连接手机临时网络，然后经 WSS 取得发送文件数 / 大小，之后才显示文件确认。文件确认可以阻止下载与落盘，但不能倒推为“此前网络未切换”。

因此 `discover_start` 的用户授权必须明确覆盖临时网络连接 / 快照准备 / 有限租约与恢复；不能只写“让手机发现本机”。原网络快照应在注册可发现 / 广播之前准备并归属本次 session。用户拒绝文件时仍须恢复已经取得的网络租约。若产品要求连接前二次同意，需新增独立的网络同意阶段，不能伪造 file manifest 来提前展示。

## 未完成与下一层验收

- 真实 P011：准备原网络快照 → 注册接收 → 手机 BLE 握手 → 临时网络连接 → 用户确认 / 拒绝 → 有界下载 → 文件真实落盘 → 网络和蓝牙恢复，需要贯通日志与独立 readback。
- 真实手机：原厂互传发现 P011、确认名称 / 文件数 / 大小、实际字节相同、手机完成提示，未由 HOST 的 sender / receiver 自互通替代。
- 完整双向：P011 发送仍需实际 P2P/AP backend、文件中心选择、当前发现设备身份 / 连接绑定、取消 / 失败恢复以及手机接收验证。不能为满足界面而把能力硬改为 True。
- 任何恢复失败应保留所有权和 pending 标记、禁止叠加新操作、明确告知待核验；不得丢资源对象后把第二次 Stop 当作恢复证明。
