# CLIENT caps：固定只读设备检查入口

2026-10-01。作者只维护 `host/device_client_caps_readonly.py`、`tests/test_device_client_caps_readonly.py`、本文，未执行 ADB、设备 checker、native、socket、RF、网络写、Docker、编译、冻结或真实结果 ZIP；ROOT 首轮只读设备结果及后续窄修分别记录于下文。HOST 假 ADB 不等于设备验收。

## 执行与固定来源

默认／`--source-check-only` 只在电脑核源 pin、Python3.5 AST、生成源码边界，不初始化 Adb、不创建日志目录或 ZIP。
唯一设备入口须同时给 `--execute-reviewed` 和 `--expected-checker-sha256=<当前本文件完整SHA256>`；缺参数、错 pin、未知 CLI（包括 interface/IP/port/TTL）拒绝。ROOT 全文审查后才执行；本轮作者不执行。
先核所有 host source/依赖 pin 再构造 target。`device_probe.py` SHA `e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348`；原 `select_target/Adb` 不改、不代理，仍仅选择恰一个 product:sprdtrum/model:sprdisk 的 P011 transport，绝不选默认 emulator。
已审 decoder SHA `c1792c2294fed5da16ec4a676423fbcbe53d44e9bc4ddadc1bc26fd45afe046c`；transport 最终审定 SHA `df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420`。
旧 transport `676f1780a4b10bcbf296153ecb4d9a490ee7b7c1a2f2e5413e7b85cc92c1521c` 仅为起草时历史 pin，未用它运行设备；ROOT 已审 CPython3.5.5 timeout 纳秒量化窄修后，唯一来源更新为 df6b。不是放宽到任意未来源码。
两模块 bytes 原样 base64 携入，目标内存重新核 hash，再 `ModuleType/exec`；`mta_client_caps_transport` 只导入这次已注册的 pinned decoder。无 sys.path 项目加载、device staging/chmod、目标文件／pycache 写；目标不需要 stdlib json。

## 只读目标请求与资源边界

从固定 `/sys/class/ieee80211` 列表要求恰一个 canonical phyN，且固定 index 文件数值等于名称下标；0项、多项、前导零、越界、形状不明均 FAIL，不猜 phy0。
唯一 `ClientCapsReader(index, timeout=5.0).read()`：同一个 socket／共享5秒 reader deadline，固定 CTRL_GETFAMILY → GET_PROTOCOL_FEATURES → split GET_WIPHY 三请求；没有 retry/scan/CLIENT创建/控制服务或任意命令。只读 NETLINK，不发 WLAN RF 操作。
请求/peer/headerseq/socketport/DONE/flags/长度/属性及 finally 单次 close+fileno=-1 使用已审 transport；unknown factory/close/read/pin/解析不足全部 FAIL。reader PASS 只表示 declaration 读取和自身 socket 关闭，不授权 CLIENT 或关联。
模块导入、唯一 phy 读取另有固定5秒准入预算；HOST 总25秒准入／等待预算。OS 文件读取、ADB enumeration和Python调度不是可抢占硬实时上限。原 selector 最多15秒可能耗尽余量，此时不开 caps 或报告未知，不自动重试；after 仍独立尝试但预算不足不能假报成功。
源码每行≤2048B、总≤256KiB；压缩命令≤3500则单 shell，否则精确有界 stdin。派生解析只可剥离**完全匹配本次完整源码的 echo 前缀**，CRCRLF/CRLF只在派生副本归一化；尾部严格 RESULT/OK/exit0 三行，未知／截断／改动 echo、多 marker/free output 拒绝。

## 独立有限 baseline，不是全网恢复

before/after 各独立读取 boot、固定三原厂 SHA、Z03/control_engine/weston（以及观察到的固定原网络服务）PID/start/exe/完整 argv、完整 task ID/start 集合；task 名单和主进程身份在采样末尾重新核对，Z/X/不可读已识别 actor 失败关闭。两边独立核固定 stock pins/必要 actor，再比较有限快照。
sysfs net 名称/ifindex/iflink/type/flags/operstate/address/原 symlink identity，与 `/proc/net/route`、`if_inet6`、`ipv6_route` 原始 bytes 仅留 private。忽略任务瞬时 R/S 状态作身份比较，不忽略 task 集合/start；采样不是原子系统快照。
没有 wpa_cli/Popen，不操作原 wlan0，不假设 ConnMan/Android 服务拥有接口。wlan0 缺席可以作为同一有限快照读回事实，只报告 presence，绝不声称 P2P 修复／原 STA 已连接。
没有读 IPv4 全地址／全部 tables/routes/rules：公开 `all_ipv4_tables_rules=NOT_EVALUATED`、`p2p_restoration=NOT_EVALUATED`。即使 checker PASS，也不能替代 full baseline recovery、原驱动状态或 GUI／手机验收。
成功还要求 reader 完成且自身 socket 已关闭、完整 raw 已保留、两套 pins/必要 actors 通过、有限 before==after、无任何 host/after/schema 错误。任何层失败原样区分，不把 cleanup/一致性当互传成功。

## 私有原文与公开白名单

原 Adb.run 实际保留每个 command stdout/stderr/host-exit，派生单独记录 remote-exit；host exit 非0仍读它已保存的 raw marker，不把 host9+remote0当成功。超时/缺 marker记录未知而非0。
**明确缺口**：原 approved selector 的 `devices -l` 枚举 raw 未独立捕获，公开 `selector_raw_captured=false`；本轮不猴补代理。目标选择仍使用原精确算法。以后若补须独立审选择器。
目标 private RESULT 保留完整 datagrams（peer/ancillary/flags/seq）、requests、wiphy messages、已收 unassessed attributes 和 rich decoded primitives；未知属性拒绝前的完整消息仍在 raw。异常完整 traceback 只写 `private.traceback`，不向 target stderr 打印；没有异常为 None。HOST 严格要求 exact None/str 且UTF-8≤65536字节（包括拒绝非法surrogate），缺失／额外字段及超限拒绝，原raw仍保留不截断。`_caps_result` 完全剔除private，公开JSON/README/ZIP永不投影traceback；target文件没有保存凭据。
公开只固定 checker/source pins、stage/class/reason、counts/presence、iftype number集合及 false/NOT_EVALUATED/NOT_TESTED。无 phy名称/index、MAC/SSID/IP/PID/boot/argv/user identifier/raw字节或自由异常文本。
`caps_read_requested` 与 `caps_read_invoked` 分开：只有已严格解析 reader.status.attempted 才报告调用事实；命令/解析失败则 NOT_RECORDED，不从发送请求推断 target 已执行或没执行。
本地 ZIP 仅固定 `result.json` 与 `README.txt`，不含 raw、source、journal、候选、设备标识。测试的 mock ZIP 只在临时目录，不是可分发的 P011 成功结果。
receive/send始终false；CLIENT初始化/关联/手机 NOT_TESTED。首轮在phy阶段失败，没有reader状态/driver split dump成功或socket关闭证据；完整原网层仍未评估，不升级功能或恢复证明。

## 历史 HOST 首批专项（保持原证据）

2026-10-01 唯一一次该文件专项（工具输出 `10598b`），目录 `working/MtaP011-v0.1`：
`python -B -m unittest discover -s tests -p test_device_client_caps_readonly.py -v`。
实际输出 `Ran 17 tests in 0.329s`、`OK`，host exit `0`（工具 wall 0.740s）；不是全项目套测，也未为人工累计再次运行已通过项。
17项覆盖默认不初始化ADB、checker/依赖pins、Python3.5 AST、固定只读源码/行长/bytes、原精确P011选择、unique phy失败关闭、严格echo/marker/public schema、host与remote exit分离、socket关闭未知拒绝、before pins失败仍独立after、actor/task/interface变化、wlan缺席不冒充恢复，以及临时公开ZIP固定双文件。
FakeADB测试全程阻断真实 `socket.socket` 与 `subprocess.run`；selector仅在HOST测试中mock原helper的枚举返回，没有生产代理。生成的mock目录/ZIP仅限TemporaryDirectory并由测试清理，没有运行真实设备checker、实际NETLINK/socket、ADB、RF或真实结果打包。
首批harness：393行/26955B，历史SHA `9146f9fbe2a8665fc31fd348e775027982beebe04560472e9b96a9fc8033ee6e`。
首批tests：201行/12666B，历史SHA `56a4d21f82b0e9911f54cfc08dcf465e54bd5a8f886062d050e42fe6cce496c4`；本文当前SHA随交付单独记录，不自引用。
这批证据只证明HOST/source/mock边界，真实Python3.5导入、sysfs/driver caps、实际socket关闭及独立有限baseline仍未由作者执行；CLIENT/RF-init/关联/手机和完整互传不升级为PASS。

## ROOT 首轮 FAIL 与 PTY 窄修

ROOT 唯一首轮设备结果 `logs/MtaP011-ClientCapsReadOnly-20261001-112454-67ff5518` 原FAIL保留不重判：before/after三原厂SHA和有限baseline相同、wlan0均缺，三个HOST/remote exit均0。ROOT离线 `d056c5` 核本次完整source echo完全匹配；private RESULT实际为failure.stage=phy/class=value_error、status=None，旧 `_caps_result` 可验形状，但 `_parse` 拒绝 remote_frame。
原因层级：旧target `traceback.print_exc(stderr)` 经ADB PTY合并到stdout，破坏严格三行frame；**同时phy阶段实际失败仍未解决**，不能把传输修正当caps读取成功或硬件恢复。原raw及原result不改。
本轮仅将异常完整字符串放入固定private字段，以repr保持单行RESULT，再保留OK/EXIT；不会忽略自由输出、损坏echo或额外marker。依赖两模块/helper pin、reader请求、唯一phy和所有原门槛未变；作者不实际重试。
本轮唯一新增／必要受影响命名HOST批（工具 `8d8be9`），目录 `working/MtaP011-v0.1/tests`，使用 `python -B -m unittest -v test_device_client_caps_readonly.CheckerTests.<以下固定命名方法>`：
新增4项：`test_target_phy_failure_traceback_only_private_one_result_line`、`test_phy_failure_complete_pty_frame_strict_private_result`、`test_phy_failure_traceback_private_raw_not_public_or_zip`、`test_private_traceback_schema_required_and_utf8_byte_bound`。
必要受影响7项：`test_pinned_memory_modules_python35_no_device_writes`、`test_transport_line_and_bytes_bounded_shell_fixed`、`test_fake_success_is_readonly_limited_and_raw_private_zip_pair`、`test_unknown_close_retains_failure_no_false_success`、`test_host_exit_failure_keeps_raw_and_remote_exit_separate`、`test_public_schema_bool_count_unknown_reason_and_types_reject`、`test_echo_exact_crcrlf_and_strict_marker_envelope`。
实际完整输出11项各 `ok`，`Ran 11 tests in 0.225s`、`OK`、host exit `0`（工具wall0.630s）。没有重跑历史17整批，没有运行当前全部21项或全项目套测；不将17+11人工相加成独立测试数量。
目标BODY仅在HOST fakeOS／空PINNED_MODULES下触发synthetic phy_selection失败，证明唯一RESULT/no stderr及private完整traceback形状，不是P011实际sysfs验证；FakeADB全程仍阻断真实socket/subprocess。四项新测试分别覆盖实际报告的phy/statusNone形状、完整源CRCRLF echo、损坏echo/free output/extra marker拒绝、private raw留存和公开JSON/README/临时ZIP不泄漏、None/exactstr/UTF-8字节界／无效类型／missing／extra字段。受影响批包括Python3.5 AST，所有旧source/依赖pins不改。
当前harness：395行/27264B，SHA `948a6c8dfdbb134fcd2f060ff30447c96e4111e1af135f89174ec1f3e3c00a21`；tests：258行/16939B，SHA `a78c8d433f0f3d89a50cc16c65b556a87917d5687675ea1ff957066c992a75c5`。本文SHA单独交付；作者本轮没有实际重试，原112454 FAIL不改，phy根因与真实CLIENT/互传仍未证明。
