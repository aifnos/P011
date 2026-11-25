# 互传制作当前状态

## 2026年10月6日 21时45分 新版文件中心实际服务创建关闭通过

新服务入口已完成并绑定 mutex 实际包，默认 PC-only SOURCE 沿用原 `local` 模式标签；首次通过 171 份来源/快照与 14 件实际包闭合。目标为 62,148 字节/SHA-256 `1f8dd830d85b160365428aaa4266efbe59e9f7f46d0f49a9dfd03800892743cc`，包含实际 Outer 与 FC9 共 10 份内存源、125,742 字节。旧 v3 入口、原 60+60 秒、alarm180/HOST210、身份/IO/关闭门和目录策略保留。

随后唯一 P011 DEVICE 通过：实际 Parent/Boot/Owner/State 启动，创建新版 FC9（101,682 字节）后立即关闭；目录 11/11、普通源 32/32、Outer 2/2、Owner 71/71 个文件描述符关闭，两个能力子进程均关闭，本地 HTTP 线程曾创建 1、业务请求 0，服务关闭确认通过，pending=false。五条 shell 的 HOST/remote0、stderr0；两次 push 的 HOST0、stderr205/196为进度，remote raw记为UNKNOWN/报告null，不能签为远端0。carrier 两文件稳定且资源关闭，原厂/Wi-Fi 前后保持；21:44:56 独立后置只读原厂核对再次通过。

- [默认 PC-only 一键](HOST_MTA_FORMAL_SEND_FC_MUTEX_SERVICE_V1_CHECK.cmd)与[显式笔端一键](TEST_MTA_FORMAL_SEND_FC_MUTEX_SERVICE_V1.cmd)。入口10,584字节/SHA-256 `b49cd447d43fcc07251e68126fb10771d84fe35cd544f4da22a0a59d331853d6`。
- [PC SOURCE ZIP](results/formal-send-fc-mutex-service-v1-20261006-214310-a4babcb0/RESULTS.zip)：2,173字节，SHA-256 `f60b5e6f924952bd7f29e6e801666483e22cda2d6c6ca22c2e4c46a3f1f45dcb`。
- [P011 服务 ZIP](results/formal-send-fc-mutex-service-v1-20261006-214332-9706156c/RESULTS.zip)：2,990字节，SHA-256 `7b9672946fc30e9ebe05dc1426c0bbf4583e25a39479d895d58134fac7dfe0a6`。

本轮只补实际构造与关闭，不调用业务 HTTP、媒体、凭据、UI、CONTROL 或 RF，也不读写传输文件；正常构造允许创建固定用户目录，未替换原厂文件。实际锁争用、短音频回调期限、阻塞文件 IO 抢占、完整父期限、手机 CONNECT/TLS、双向互通及完整网络恢复仍未验收。小米点击连接 FAIL 保留，terminal-only 手机入口只签 SOURCE，peer15 改最多60授权及新手机就绪/现场核对/真实 READY 仍待；目标 active。服务 SOURCE/DEVICE 的独立只读回读均通过：171 来源与快照保持、PC 十源 DATA 解码匹配实际源、DEVICE 原 SERVICE_RESULT 的49字段与报告一致、公开两成员 ZIP 原字节及CRC匹配；Root补核DEVICE封存bootstrap与SOURCE完全相同、wire同针，无重跑。三入口 SOURCE 及此前 Startup/Stage 独立回读同样通过。以下21:24及更早为历史检查点。

## 2026年10月6日 21时24分 新包入口和笔端启动暂存通过

双侧媒体锁包已接入三个独立入口：接收启动、发送暂存、terminal-only 手机观察。首次默认 SOURCE 分别通过 334、179、353 份来源及快照核对；来源、有效包绑定和预算已更新，不再使用旧包根。三份 SOURCE 的独立只读回读均通过，手机 target 解码出的 terminal、phone 与新 Runner 逐字节匹配；原 peer15、无 trace 安装及未观测标识保持。未重跑已通过且未受影响的业务专项，旧候选与失败记录保留。

新版接收入口随后唯一执行不触无线的 P011 Startup，HOST/remote 均为 0，stderr 为 0，严格关闭策略通过。实际暂存 74 文件和 4 目录，Owner 启动状态采集通过，3 个 Proc reader、2 次 STATUS 及 2327 个文件描述符均已关闭，pending 为 false，前后原厂和有限网络基线保持。缓存时刻显示准备阶段约 10.292 秒，低于保留的 20 秒上限；这是本轮观察，不是稳定性或性能 A/B 结论。FileCenter 未创建、Trial 未申请、RF 和手机窗口未开启。

新版发送入口唯一执行 files-only Stage，实际创建 37 文件和 3 目录，342/342 个文件描述符关闭，carrier 资源关闭；原厂与 Wi-Fi 前后保持。所有 shell 命令的 HOST/remote 均为 0；两次 ADB push 的 HOST 为 0，无远端命令退出语义，raw 记为 UNKNOWN、报告为 null/known=false，stderr 208/205 字节为传输进度，不能统称所有 stderr 为 0。发送 Parent、Owner、FC9 和 GUI19 未启动。21:23:52 独立后置只读检查再次确认原厂三文件、进程身份、Wi-Fi 与临时菜单缺席正常。

| 验证范围 | 实际结果与脱敏 ZIP |
| --- | --- |
| 接收 SOURCE，未运行设备 | [结果](results/receive-fc-mutex-v1-startup-source-20261006-203717-ca877bbd/public-result.zip)，20,111 字节，SHA-256 `fbf908240c37f87639629856158ff8aee36b3c8254d64613b7e7264a2bd5e79c` |
| 发送 SOURCE，未运行设备 | [结果](results/formal-send-fc-mutex-stage-v1-source-20261006-211823-c79cfbb6/RESULTS.zip)，2,698 字节，SHA-256 `7da00df570ace6aac1376b5bca06f1adacf6442ac49d74ad9499911a589d5107` |
| 手机观察 SOURCE，未开窗口 | [结果](results/phone-fc-mutex-terminal-v1-source-20261006-211845-c462ed50/public-result.zip)，22,043 字节，SHA-256 `d26f2a8a0f1e99ed903f358dce0ec016820b8769267b3d2261d4439511e853ca` |
| P011 接收 Startup，不触无线 | [结果](results/receive-fc-mutex-v1-startup-device-20261006-212104-0f645d47/public-result.zip)，20,888 字节，SHA-256 `18fe9ef0bf000e902a91ef350d0161d3b9d0d23e9bc4389aef9ca0a799988318` |
| P011 发送 files-only Stage | [结果](results/formal-send-fc-mutex-stage-v1-stage-20261006-212235-38c7947a/RESULTS.zip)，3,435 字节，SHA-256 `487d4b0e75d19ec02b2f498683a65492d4d9ad88b281bd6344b5e7549c4a42d0` |

新的默认 PC-only 一键入口为 [接收 SOURCE](HOST_MTA_RECEIVE_FC_MUTEX_V1_STARTUP_CHECK.cmd)、[发送 SOURCE](HOST_MTA_FORMAL_SEND_FC_MUTEX_STAGE_V1_CHECK.cmd) 和 [手机观察 SOURCE](HOST_MTA_PHONE_FC_MUTEX_TERMINAL_V1_CHECK.cmd)。对应 TEST 仍需显式选择设备模式；手机 TEST 会申请无线窗口，不能当只读检查自动运行。原始双流、独立 HOST/remote 退出、私有源及快照保留本地，不进入公开 ZIP。

小米点击“连接失败”的判定不变，不能归因于媒体锁或签为已修复。新的 terminal-only 手机入口尚未实机开窗；原 peer 观察上限仍为 15 秒，之前询问的最多 60 秒独立诊断调整尚待答复，之后仍需新的手机就绪、现场核对和本轮真实 native READY。正式 FileCenter 运行、完整父期限及阻塞文件 IO 抢占、CONNECT/TLS、真实文件双向互通和完整网络恢复均未验收，目标保持 active，10 月 4 日边开发边实测范围不缩小。以下 20:20 及更早条目是历史检查点。

## 2026年10月6日 20时20分 双侧媒体锁包实际装配通过 尚未接笔端入口

Root首次且唯一执行新电脑 `--assemble`，整体退出0。两包纯派生、逆差和绑定检查先完成，再各调用一次固定新writer；发送与接收child均退出0、stderr0、未超60秒。发送14件、接收11件共25件实际产物逐件字节/pin一致，431份来源、保存快照及当前源保持。没有重跑旧HTTP、音频、TLS或其它专项，也未覆盖旧包。

实际发送FC9为101,682/131,072字节，普通37件1,368,142字节及GUI19件4,185,296字节保持，Owner/Boot/Outer/Worker与Stage库存的源码绑定通过。实际接收FC9单独为115,400/131,072；75角色仍4,193,768/4,194,304，余536字节，69角色保持、仅六个机械接装闭包。新defs为574,969字节/SHA-256 `4fce39627676c7f359dfd031ce8edb19e232c1a5981806895014829a4fbb8dfd`，实际319来源闭合；原prepare20业务闭包1与新mutex业务闭包1分开验证，准备20/collector10保持。

- [实际装配结果ZIP](results/filecenter-mutex-package-v1-assemble-20261006-201237-21471b0e/public-result.zip)：3,191字节，SHA-256 `62f7c85d8f0e2611ccfc6ad1236df63059d0c256dd4ed08b16a2796df0d69846`。
- [电脑一键SOURCE检查](HOST_MTA_FILECENTER_MUTEX_PACKAGE_V1_CHECK.cmd)默认仅核已发布实际产物与源码，不发布运行包、不调用ADB。checker为24,842字节/SHA-256 `4cd5961ecf3459d5793e7e3781d8f665f6eb957265364dcc633789d06b58d966`；完整原stdout/stderr/退出/timeout、facts与输入快照留在本地private。

独立PowerShell/.NET读回通过：431快照/当前源逐字一致，25产物与两个child stdout pins匹配；公开ZIP仅result.json 8,121字节与README 898字节，CRC、完整成员字节及私有封存ZIP一致，无private成员。SOURCE装配不是运行验收；新设备根存在性、正式Owner、完整FileCenter期限、阻塞文件IO抢占和完整恢复仍未验证。

下一机械适配Startup、terminal-only手机和发送Stage薄入口：同步实际pin/root/319来源与FC9硬门后首次SOURCE，保原IO、期限和严格关闭。现在这些实机入口仍绑定旧包，不能直接拿旧入口签新包通过。本轮无ADB、Stage、UI、RF、手机或用户文件动作。原手机点击连接FAIL保持且不归因mutex；peer15改最多60秒仍待此前授权，下一窗口仍需新就绪/现时核对/真实READY。CONNECT/TLS、真实双向文件与完整网络恢复未验，完整目标active。以下19:50及19:03为历史检查点。

## 2026年10月6日 19时50分 双侧媒体锁接装生成器源码冻结 尚未执行装配

独立发送与接收生成器已完成全文静态审阅，接收另经独立只读审阅，未发现明确缺陷。当前目录仍只有生成器源码，没有新 runtime、manifest、generation 或 definitions 产物，不能据此标为实际包闭合、SOURCE 通过或可上机。

- [发送生成器](candidate/formal-send-fc-mutex-v1/generate_package.py)：38,185字节，SHA-256 `69ce44c85b11c89e491c8877b839a0eed9322c22ff51f8c6a819589a4d50742a`。纯 `prepare()` 计划14件产物；仅显式 `--write` 发布。新根 `p011-mta-formal-send-filecenter-mutex1-v1`，FC9预算预计101,682字节，普通37件仍应为1,368,142字节；实际数量、字节与pin待首次装配确认。
- [接收生成器](candidate/receive-fc-mutex-graph-v1/generate_graph.py)：43,011字节，SHA-256 `98ad07f8dabe99fdfdca601da63138dc6bbd62fcf7dcbc277c65a648162534c8`。由当前prepare20图派生11件产物，原prepare20业务闭包与新mutex闭包分别验证；新根 `p011-mta-rx-mlock1-v001`。原75角色4,193,768字节/余536与独立FC9预计115,400字节/128KiB上限均有派生断言，实际产物与新defs来源数尚待。

下一由Root唯一执行电脑装配：先派生、预检两包，再各调用一次固定writer并保留原双流/退出，逐件核实际文件与源保持。若发送成功而接收失败，仅继续未完成的接收发布，不覆盖或清理旧包/部分产物。原HOST媒体锁证据复用，不重跑旧HTTP、音频或TLS专项。

现有Startup、terminal-only手机及发送Stage薄入口仍绑定旧包；新包生成后还须同步实际pin/root/来源数/FC9预算门，不能只换外层描述。原prepare20、collector10、peer15及业务/关闭策略保持。本轮未执行Python、生成器、测试或ADB，没有设备/RF/UI/手机/用户文件动作。旧点击连接FAIL不改判，mutex不是其已确认原因；peer15改最多60秒仍待此前授权，新窗口仍需新就绪、现时核对与真实READY。双向文件、CONNECT/TLS和完整网络恢复未验，完整目标active。

## 2026年10月6日 19时03分 媒体锁争用修补通过HOST专项 尚未接装上机

两套FileCenter Companion已生成独立媒体锁候选，各增加1,568字节：发送27,656/SHA-256 `57531992acaf8b3519e090f8e1cf61a2ac97dc18e14bee15662573dbb9ca5bfd`，接收35,198/`44c14589ef7b6a0af98c6a3446b3bd7539640f5b7fccc23c5c9677c705ae02ca`。八处限定替换及完整字节/AST逆差保持原create/check/close/closed、身份、存储和HTTP业务；每次争锁等待至多50毫秒，继承原父期限，HTTP请求只能裁短，取得锁后拒绝会释放自有锁，不释放其他线程持有的锁。

唯一新HOST专项通过：21输入和快照保持，child0/stderr0，实际Linux存储/HTTP/socket/thread，两套各七场景、共42条连接。旧母源在1.25秒父期限后0.20秒仍争锁；候选父期限场景总耗时约1.251秒，0.50秒短请求场景约0.505秒，关闭场景约0.206秒。错误Range后正常Range及取得锁后guard拒绝的释放检查通过，原资源关闭与隔离目录清理通过。这些是显式私有Companion/root/guard夹具，不是正式Owner准入、P011或手机验收；audio_source_fd仅继承父期限，尚未绑定更短音频回调期限，阻塞文件IO可抢占和完整FileCenter期限仍未签。

- [媒体锁HOST结果ZIP](results/filecenter-media-lock-deadline-v1-host-20261006-190254-3d1529d7/public-result.zip)：1,719字节，SHA-256 `d6d53d0e00f7afafc2e6b7b27361ec7cadbf615a0583f06550c35fcda2591f38`；[电脑一键](HOST_MTA_FILECENTER_MEDIA_LOCK_DEADLINE_V1_CHECK.cmd)。没有重跑旧18个HTTP场景、音频或TLS专项。
- [发送HTTP-cap暂存入口SOURCE结果ZIP](results/formal-send-fc-http-cap-stage-v1-source-20261006-184021-d571a810/RESULTS.zip)：2,413字节，SHA-256 `8853521ff66ab165df9bad259c79c7b43400051b3b0583639836bd45e847fd5e`。默认SOURCE唯一通过160输入/快照；普通37件1,368,142字节及原120/180秒保护保持，sender27/observer41仅只读先决库存，未启动Parent/Owner/UI/RF、未实际Stage。此入口仍绑定先前HTTP-cap包，不冒充新mutex接装。

下一将新mutex机械接入发送包和当前receive-startup-20s图，不能回退至旧10秒图或保留旧FC9未变声明。预计发送/接收FC9分别101,682/115,400字节，实际新库存与闭包尚待；75载荷仍以当前4,193,768字节/余536为准，不扩大cap。本轮没有ADB、设备、无线或手机动作。用户点击“连接失败”保持，媒体锁不是其已确认原因；peer15改最多60秒仍待授权，新窗口需新就绪/现时核对/真实READY。双向文件、CONNECT/TLS及完整网络恢复未签，完整目标active。

独立只读审查及封存读回完成：21快照匹配冻结来源，单一原始marker与结果投影逐类型一致，child0/stderr0；公开ZIP的两成员、CRC及私有封存原字节一致。上列耗时是整个phase，不是纯锁等待延迟。[集成计划配方](candidate/filecenter-media-lock-package-v1/recipe_plan.py)已作者并全文审查，15,390字节/SHA-256 `f439adf081a2edbda86029113d82a2941e3a2224352c5f85bdd461f48331aa20`，尚未执行。它只返回空输出计划并拒绝--write，不是可用包生成器；当前304来源/11产物的继承闭合、旧FC9恒等门替换及实际Owner/Worker/Runner/defs传播仍需完成。

## 2026年10月6日 18时23分 低干扰终态候选与手机薄入口检查通过，尚未上机

已独立生成terminal-only运行源15,049字节/SHA-256 `c77db43cb42d60f624b96bacb92e5a8c03b943faf82921059ab4d04b15085c97`。只将原`trace.install()`改为原existing-hook拒绝门、不安装线程钩子；public新增`exception_events_observed=False`及新schema。完整字节/AST逆差保留原finally、源/模块/类型/状态身份、锁、actor/radio终态投影，实际installed/restored标志均false，不伪造旧true。空events表示中途异常未观测，不是无异常；terminal=None也不是安全关闭回执。

新HOST合同唯一执行PASS，6输入/快照保持、实际child0/stderr0、九类普通fixture覆盖返回/异常同对象、异常状态/占锁/模块变更、两个外来钩子拒绝保持、radio有限错误和缺component。不是P011、真实Trial/Owner、射频或手机验收，不签实际链路提速。

同prepare20图的新手机薄入口首次默认SOURCE因嵌套schema anchor少一层转义，在prepare早期报`terminal_exact_forward`/host1；尚未进入结果写入器且未调用ADB。原作者源14,657字节/97e267…原样备份及衍生失败说明保留。Root只补该before/after转义，修后入口14,665字节/SHA-256 `008d8abbdd54b4a8caad36c5511395e465934f996e3420c3758884543c5d7e4a`；唯一修后SOURCE PASS，337来源/快照保持，target2,015,946字节/最大行137。严格新九字段parser与有效main均要求异常未观测、实际installed/restored=false；不翻译旧schema、不假造True。

原75图/载荷4,193,768字节/余536、flat304、FC9/113,832、prepare20/collector10、Publication120、真实READY15、phone120、peer15、observe135、Owner600+cleanup60、alarm780/HOST790及业务IO/Trial/关闭条件保持。仅诊断源码/编码、parser和诊断coverage门改变，未Stage/DEVICE/RF/UI/手机，也未处理pending或用户文件。

- [新HOST合同ZIP](results/receive-handoff-terminal-v1-host-20261006-181915-dde364b7/public-result.zip)：SHA-256 `3caea90a257d1e7b1c946f21b339f8d79497162e4edcaddc275aaa0d17a48ee0`；[电脑一键](HOST_MTA_RECEIVE_HANDOFF_TERMINAL_V1_CHECK.cmd)。
- [首次SOURCE早期失败说明](results/phone-terminal-20s-v1-source-early-failure-20261006-182033/failure-note.md)：衍生记录，不冒充原始双流或把首次FAIL改签。
- [修后手机入口SOURCE ZIP](results/phone-terminal-20s-v1-source-20261006-182057-e199f11b/public-result.zip)：SHA-256 `28e165ae55a41910a36322f826a3624eb86757dfab33a291f25db0ea9bc42f0f`；[默认SOURCE一键](HOST_MTA_PHONE_TERMINAL_20S_V1_CHECK.cmd)。显式TEST文件存在不等于允许自动开新窗口。

下一仍需新的手机就绪/临窗口笔端核对/本轮真实READY。独立peer15→最多60秒授权尚待，不自行修改期限；旧手机连接FAIL、CONNECT/TLS、双向、安全落盘及完整用网恢复未签，完整目标active。以下17:58和更早记录保持为历史事实。

## 2026年10月6日 17时58分 笔端原钩子模型开销确认，原汇总FAIL保留

新载体唯一SOURCE通过，随后唯一P011纯模型实际执行。三个命令HOST/remote均0、stderr均0，前后原厂文件/进程及有限Wi-Fi状态相同；实际模型1.763秒完成16新线程/四ABBA/64次2000条库存夹具调用，返回值一致，线程join、钩子撤销、五模块别名恢复和自建命名空间清空均true。没有RF/UI/Stage/手机/文件传输或业务图改写。

原DEVICE父汇总因ADB回显完整输入源码而报`ValueError:model_envelope`，原FAIL与ZIP保持。仅修电脑解析：只允许与发送target逐字一致的完整前缀，随后仍要求唯一有限模型repr和独立远端退出；不丢任意额外输出、不重跑模型。新PC-only retained读回严格核七原输入/旧父pin、解析代码逆差、同target、原before/model/after双流及有限基线，派生检查PASS；不是给原DEVICE改签整体PASS。修正载体的新SOURCE也通过。

原始P011模型每次墙钟none10.69～10.96毫秒、原trace42.41～42.60毫秒；进程CPU none10.71～10.97毫秒、原trace42.41～42.60毫秒，四组CPU倍率3.88～3.97。thread CPU未采集、未伪造。这说明实际P011解释器上该夹具的诊断开销明显，不是实际Handoff/Trial/Owner、现场IO或完整Publication性能测量，不能按倍率预测接收提速或宣称连接修复。

- [初次SOURCE ZIP](results/receive-trace-overhead-v1-source-20261006-175403-7920785b/public-result.zip)：SHA-256 `877cebcc9aabecf27ccf1ca911b3f5d3dbf8729be73471c14aee2a16a7250c55`。
- [原DEVICE父FAIL ZIP](results/receive-trace-overhead-v1-device-model-20261006-175454-814f0725/public-result.zip)：SHA-256 `560c348fa9c3fc0db92558b693306be69e0dbe4fae3dec757573dcaafd8d169d`。
- [已有笔端raw派生读回ZIP](results/receive-trace-overhead-v1-retained-readback-20261006-175815-21f50f8d/public-result.zip)：SHA-256 `a6d40a05da272ebceb234d2ad0c7429efffb7d98797d0c61ce3746422a13419c`；[读回脚本](host/receive_trace_overhead_retained_v1_check.py)不访问ADB或重放旧测试。
- [仅解析修正SOURCE ZIP](results/receive-trace-overhead-v1-source-20261006-175825-b9b6afbe/public-result.zip)：SHA-256 `57116a366fa55e780d3a18a056bfbd38aa838d569374b9ec5a75629adb59bc92`。

下一最小可逆诊断方向为不安装线程trace、保原终态投影；尚未制作/部署。需明确异常事件未观测，不能将空events当无异常；业务身份/IO、接收确认、原peer15与其它期限均保留。独立peer15→最多60秒仍待授权，下一手机试验仍需新就绪与真实READY。旧手机FAIL、CONNECT/TLS、双向与完整用网恢复未签，目标active。

## 2026年10月6日 17时40分 跟踪钩子电脑对照通过，笔端开销尚待测量

新增纯HOST模型唯一执行PASS：实际冻结TraceOwner/dispatch/original_modules/close_trace未改，四ABBA、16个新线程、每块4次，共64次2000条库存夹具调用；全部返回值/校验和一致，线程、钩子及五个模块位置恢复，3输入/快照保持，实际child0/stderr0。它使用普通selected三行`_check`及非selected Trial样式生成器，不是真实Handoff/Trial/Owner生命周期或Publication读取。

四组墙钟每次调用开启原钩子约为无钩子的4.62～5.26倍；平均约0.305毫秒与1.524毫秒。Windows进程/线程CPU计时在无钩子侧均为0、钩子侧粒度为1.953125毫秒/次，不能据此精确归因CPU、推定P011速度或宣布连接问题已修复。原15秒观察取消与手机FAIL保持。

- [HOST模型ZIP](results/receive-trace-overhead-v1-host-20261006-174005-de7d2f3d/public-result.zip)：SHA-256 `dce5a1e10442bb9f348566e664cca6232535e94a669393d8a74392f1c4e889da`。
- [电脑一键](HOST_MTA_RECEIVE_TRACE_OVERHEAD_V1_CHECK.cmd)只测隔离夹具，不访问ADB；原始双流/退出及完整输入快照私有保留。公开ZIP仅result.json与README.txt。

下一制作同夹具P0113.5.5独立进程对照，使用进程CPU/墙钟、不伪造缺失的thread_time；无互传业务、RF、UI、Stage或手机窗口。peer15→最多60秒授权仍待，业务/观察期限均未修改；完整双向、CONNECT/TLS和完整网络恢复未签，目标active。

## 2026年10月6日 17时24分 真实点击已捕获，15秒诊断观察主动取消

独立prepare20手机入口实际执行两轮，332输入/快照保持，均没有覆盖原图或系统文件。17:05轮实际READY后机会116.402999秒、无peer/Factory启动，原checker保留`PHONE_DISCOVERY_OPPORTUNITY_FAIL`/`native_operation_failed`；用户明确反馈未赶上或未点击，不能据此判手机连接失败。服务的native120从listen后起算，而observer从实际advertising起算，窗口起点不一致；该轮error计数0，stop/closed使cancelled进入合并failure判断，不能仅凭标签认定原生异常或唯一到期原因。旧原始结果不改签。

用户重新就绪后，17:15轮先完成三项新的只读前置核对，再仅执行一次手机DEVICE。实际typed READY已转发，用户点击后手机显示连接失败。原始HOST0/remote1/stderr0，结果为`HANDOFF_CAPTURED_CANCELLED`、reason=`peer_activity_cancelled`、握手outcome=`phase_deadline`，仍FAIL，不是完整收发通过。

这轮真实P2P和handoff received/decrypt_attempted/bridge_started为true，plain_present及Factory started已观察；frame claim/F进程/部署、CONNECT/TLS和文件传输未完成。相对discover_start返回，peer首次36.390110281秒、Factory首次43.023270930秒，随后start→io→sources；最后51.097375078秒仍在new相位、sources_done=0、未返回/结束。observer在peer后15.005698028秒主动cancel，Factory原prepare120未到期；仅约8.074秒的已观察Factory跨度，不能推断放行后必然成功，也不能将首个源码读取中断当作已证源码读取失败。

退出记录显示2333个登记FD全部关闭，Owner/Startup/三个能力actor/helper关闭回收，resource_pending/staging_pending及Wi-Fi/radio pending=false；新建文件/目录0/0，暂存资产核验复用。17:19独立只读后置核对通过：两轮0连接/0活动广告实例、pending不存在且未处理，原厂文件/进程及有限网络基线保持。完整网络恢复、手机互通及双向安全落盘仍未验证。

- [未点击轮原FAIL ZIP](results/phone-startup-20s-v1-device-20261006-170510-ef95cb33/public-result.zip)：SHA-256 `9667fc4fee28d69bb79fe8a895b068458ebe8838495af677754e99ec31781330`。
- [实际点击握手ZIP](results/phone-startup-20s-v1-device-20261006-171551-9d69794b/public-result.zip)：SHA-256 `b3f8b61db7ae5096eda684120153368ba8c6bedb463e21badb240528f2fbf0b8`。
- [本轮前置条件](results/receive-prerequisite-readonly-20261006-171531-eab85114/public-result.zip)、[六层目录](results/receive-directory-readonly-20261006-171532-a8c74fa3/public-result.zip)、[原生无线基线](results/receive-radio-baseline-device-20261006-171536-616537e9/public-result.zip)均只读通过，不代签接收准入。
- [后置无线ZIP](results/receive-radio-baseline-device-20261006-171925-04cafea1/public-result.zip)：SHA-256 `4a582c188c6cb93a3dea57ac966fd842ff20a22628f8a129dc2182ffdf1dd4f1`；[后置条件ZIP](results/receive-prerequisite-readonly-20261006-171929-c1e254f8/public-result.zip)：SHA-256 `711386e204605353489a8c1474914e015087f3fa8dde32e40c52502c51ae878d`。

下一先厘清诊断观察合同与接收准备耗时，已询问能否仅在独立候选把peer观察15改最多60秒，仍受原手机窗口/父期限限制，native TTL、业务prepare120及Owner期限不变；尚未收到授权，不修改或自动开下一窗口。同步只读分析Publication现场检查开销，不减少身份/IO保护。完整目标active，边开发边实测范围保持；不重已过Startup/Stage或未变专项。启动前两次PC调用缺必需参数被argparse拒绝、工具shell退出1，未进入设备；补显式参数后实际前置各只执行一次，工具观察保留，未冒称有单独原始退出封包。

## 2026年10月6日 17时00分 同图手机入口SOURCE通过，等待新的手机就绪

独立手机薄入口已接16:51实际prepare20图，未覆盖旧FCCAP手机入口。默认SOURCE唯一执行PASS，332输入及快照保持；target2,015,926字节/最大行137，75载荷4,193,768/余536、flat304、FC9/113,832和单常量闭包1保持，继承profile/Owner/Scope/HTTP和全部机械来源独立核对。载体完整字节/AST逆差及原IO门成立。

报告明确准备20与collector10，Publication120、真实广播READY15、手机机会120、peer15、观察135、Owner600+cleanup60及alarm780/HOST790未改。PHONE28,352、trace14,820、严格schema和五项缓存投影保持；只转发本轮实际typed READY，不伪造手机确认。仍为receive-only握手/取消观察器，accept/send=false；捕获后取消不是CONNECT/TLS、文件收发或手机兼容PASS。

- [手机入口SOURCE ZIP](results/phone-startup-20s-v1-source-20261006-165907-3d5d8e90/public-result.zip)：SHA-256 `6e824b3096af53b038cb1cccea4832a7122c546f80063185b9123527314c5ca6`。
- 一键：[默认SOURCE](HOST_MTA_PHONE_STARTUP_20S_V1_CHECK.cmd)、[明确手机DEVICE](TEST_MTA_PHONE_STARTUP_20S_V1.cmd)。仅SOURCE已执行；DEVICE不可因文件存在而自动运行，需新的手机就绪、临窗口笔端基线/资产/Received/pending/actor核对和本轮真实native READY。

已询问新的小米15 Ultra就绪，尚未收到本轮确认，未开RF/手机窗口。复用下述已经通过的启动与暂存，不重复未变专项；旧连接FAIL及完整双向/安全落盘/FileCenter/用网恢复仍待，完整目标active、边开发边实测范围保持。

## 2026年10月6日 16时51分 独立20秒准备候选首次启动退出通过

按用户明确授权，仅把独立Factory的`STARTUP_READ_SECONDS`从10.0改20.0，字节数和全部函数/类的源码及位置AST保持；旧10秒源、旧图和FAIL未改。准备期限仍取原Owner绝对期限与初始化时刻+20的较早值，每次身份/目录/IO检查保持。准备完成后进入`read_closed`，采集器保持独立10秒、STATUS3及原父期限，不续Owner；60+60、alarm240/HOST250和严格COMPONENT/Trial/关闭门未变。本轮没有接入42字节proc优化，也没有安装分析器。

实际唯一生成11件新产物，root=`p011-mta-rx-prep20-v001`，flat304；75角色4,193,768字节/余536，69角色与FC9/113,832字节保持。六机械闭包及单常量闭包、继承Owner/Scope/HTTP/profile来源均核对；没有覆盖旧volatile根或系统文件。SOURCE318输入及快照保持，目标2,015,647字节/最大行129；独立ZIP两成员CRC和原始字节读回通过。

唯一无RF DEVICE整体PASS：HOST0/remote0、stderr0，Owner启动、实际基线采集、ProcReader3、STATUS2和严格closed policy通过；2340个已打开FD及Owner/Startup/actor/socket关闭，resource_pending/staging_pending=false，原厂文件/进程和有限网络基线保持。74文件/4目录在新根完整暂存，保留供后续核验复用；不重旧Stage/CONTROL/锁或未变专项。

既有V2缓存显示准备init→postimport为8.819319917秒，距20秒余11.180680083秒；postimport→后续last跨度5.922437688秒，原Owner当时还余40.833141898秒。跨度只来自原缓存，不是新增时钟、精准函数耗时或同条件A/B；本次准备也低于10秒，因此不能把时长下降归因期限调整，更不能凭单次PASS宣称稳定性。

- [SOURCE ZIP](results/receive-startup-20s-v1-source-20261006-165009-ad0959a1/public-result.zip)：SHA-256 `0761b90102560c53ea65761607541fa8db768e32d1dc63e196faa8d9f3a63eab`。
- [笔端启动退出ZIP](results/receive-startup-20s-v1-device-20261006-165041-07562d6b/public-result.zip)：SHA-256 `0d6ff3c253cf81b22e9edf469804f639b117f71a672f59a4213244909692d097`。
- 一键：[默认SOURCE](HOST_MTA_RECEIVE_STARTUP_20S_V1_CHECK.cmd)、[明确DEVICE](TEST_MTA_RECEIVE_STARTUP_20S_V1.cmd)。本轮已执行，不自动重复。

本轮无BLE广播/扫描、Wi-Fi互传、UI、HTTP请求、手机或用户文件动作，不签完整网络恢复、手机READY/CONNECT/TLS或双向互通。下一接独立手机薄入口并先做SOURCE；新的小米就绪和本轮真实native READY后才允许通知点击，不自动开窗口。完整目标active、边开发边实测范围保持；下述16:34及旧FAIL为历史事实。

## 2026年10月6日 16时34分 派发优化收益有限且设备缺原生分析器

新proc派发候选已实际生成：Factory为99,717字节，相比当前缓存图只增42字节，仅把`_live_profile`的Startup六项`any(generator)`改为同顺序`for`。完整字节和位置AST逆差成立，前缀短路、fresh tuple、type/is/code、原失败、clock/IO和期限保持。预计接完整图后为4,193,810字节、余494；这只是投影，未装配新图或部署该优化。

新HOST唯一执行通过：三个方法、13个完整流程场景，两个合成root PID实际覆盖第二轮变更分支；比较真实`_stat_data/_live_profile`的原新轨迹、时钟、缓存、返回及首失败。共28次完整方法夹具调用，含26次病例对照及CPU合同初始化两次。8输入及快照保持，child/checker均0，原stderr621字节、三项均ok。它只证明显式内存IO/Owner夹具合同，不是native准入、真实FD关闭或设备性能；未重旧缓存测试。

独立SOURCE通过13输入及快照。唯一P011内层guard模型也通过，Python3.5.5、四组ABBA、16块各8192次，共131072次及两侧各128预热。真实process CPU平均由34.974979599降至28.354031311微秒/次，差6.620948288微秒、下降18.930527948%；四组CPU和elapsed方向一致。模型仅执行实际Startup内层AST，两个独立普通类型realm不调用真实Scope/Owner生命周期、IO或clock。实际target17,611字节、最大行134，原30秒alarm/45秒HOST和48,000/256/65,536预算保持。

该处成功调用数为`len(names)-1`、源码上限4095，当前实机数未知。假设196次或4095次，模型差值投影仅1.297705864或27.112783239毫秒，不能当真实proc收益；也不足以据此填平此前0.505079185秒准备缺口。因此本轮不为这一处重复完整图、Stage或Startup，不改变原10秒期限或旧FAIL。

实际调用链的更大疑点是目录身份检查：每次Scope full guard会调用Received `DirectoryBinding.check()`；六层绑定的一次检查有6次fstat、6次stat及两次原Directory时钟。成功短comm读取若实际os.read次数含EOF为L，则`_Files.read`内部有`9+2L`次full及4次alias；通常L=2时，含外层PID stat和分类约15次full、5次alias，即180次目录身份系统调用、约41次Owner._context。以上是源码结构计数，不是本次调用/耗时测量；现场检查不能跨读缓存或删除。comm没有expected，SHA分支不执行，不将另一Native链的摘要去重误套于此。

16:34的新依赖SOURCE及唯一只读DEVICE查询通过，各6输入与快照保持、target1130字节。P011的`_lsprof`和`cProfile`均ImportError；原生Profiler与包装Profile分别不可构造，未enable/run/getstats，不代表实际profile通过。没有安装依赖、启动运行候选、创建图/Stage或RF/UI/手机动作。两次DEVICE的前后原厂有限身份、进程及Wi-Fi保持；原始三组HOST/remote退出均0、stderr空。下一先确认可用的私有分析工具/编译路径，再对当前实际启动做有界调用归因，不堆更多分段或微基准来代替互传修复。

- [新语义HOST ZIP](results/receive-profile-proc-dispatch-v1-host-20261006-144546-33f338dd/public-result.zip)：SHA-256 `1b4cfa799911448374703406d8c2daa70fc0a9b97111c5269dfee596474c3fa9`。
- [模型SOURCE ZIP](results/receive-profile-proc-dispatch-bench-v1-source-20261006-144405-9a1005e0/public-result.zip)：SHA-256 `20d6445de17cb1b4a7cfbebdbbf679e97eaca4003319f272a8f73eae976a75a7`。
- [笔端模型ZIP](results/receive-profile-proc-dispatch-bench-v1-device-model-20261006-144554-bb6a5380/public-result.zip)：SHA-256 `40decd6776306056e563c720ef09e3fcda5c689ca98ba264778418028240a2d6`。
- [分析器依赖SOURCE ZIP](results/cprofile-environment-v1-source-20261006-163415-319436f6/public-result.zip)：SHA-256 `0e945b3500559e61d381088633258bb880e42ff83f174018dc83a6efb84fea62`。
- [笔端依赖查询ZIP](results/cprofile-environment-v1-device-20261006-163420-75134d43/public-result.zip)：SHA-256 `fa710f2f328f08d94ce984faa2d8df8d25a872f9a34c4f32e59fc869f2c052c6`。
- 一键：[新HOST](HOST_MTA_RECEIVE_PROFILE_PROC_DISPATCH_V1_CHECK.cmd)、[模型SOURCE](HOST_MTA_RECEIVE_PROFILE_PROC_DISPATCH_BENCH_V1_CHECK.cmd)、[明确笔端模型](TEST_MTA_RECEIVE_PROFILE_PROC_DISPATCH_BENCH_V1.cmd)、[依赖SOURCE](HOST_MTA_CPROFILE_ENVIRONMENT_V1_CHECK.cmd)、[明确只读依赖](TEST_MTA_CPROFILE_ENVIRONMENT_V1.cmd)。已经执行的入口不自动重复；公开ZIP只含结果与说明，原始双流/退出/快照私有保留。

完整目标active、边开发边实测范围保持。用户已明确授权仅在独立候选把纯只读准备上限改为20秒，保每次身份检查、原厂、外层绝对期限及恢复保护；正在生成该候选，尚未取得新Startup实机结果，旧10秒候选和失败不改，不自动打开手机窗口。新的手机就绪和真实native READY、旧手机连接FAIL、双向TLS/安全收发及完整FileCenter/Owner期限与用网恢复仍待；本轮模型及有限原厂保持不代签它们。下述14:32及更早记录保持原判。

## 2026年10月6日 14时32分 准备超时已定位到进程枚举区间

本轮最新只读核对通过：P011正常连接，原厂身份和前后状态保持，Wi-Fi已连接，BlueZ与ConnMan有服务归属，临时菜单不存在。该核对不等于互传准入或完整网络恢复。

新增独立profile缓存候选，仅在真实Factory的`_live_profile`中增加空tuple及六次已有`attempt.last`的DATA拷贝，净增304字节。没有新增时钟/IO、权限缓存、分支、返回或期限；完整字节与位置AST逆差成立。实际11件新图产物闭合，289项来源、六机械闭包，69角色与FC9/113,832字节原样；75角色4,193,768字节，保原4MiB上限，余536字节。首次电脑装配因纯helper漏注入`literal_assignment`而FAIL，发生在write_outputs之前；只补66字节命名空间依赖后创建全部缺失输出，旧FAIL保持。

Startup SOURCE通过302输入与快照，新增Scope母recipe也进入来源保持核对。三个新HOST test实际均ok、child退出0：完整真实方法的九个合成IO/Owner场景、18次旧新调用轨迹对照，真实V2/profile注入逆差和被动reader/严格parser合同。外checker因Windows CRLF末尾断言误拒，原整体FAIL和双流保留；只在派生stderr上归一换行，未重跑三个已通过测试，不补签旧结果。

唯一新Startup DEVICE仍FAIL，但六项实际缓存已读到。原10秒准备窗口的init→postimport为10.505079185秒，超0.505079185秒；原始首个trace为Factory startup_readonly1392→check_active519→_fail99，raw code为unclassified，冻结源码519映射到startup_expired。Owner和collector尚未启动，Trial=None；HOST0、stderr0、remote1。PC后续result_fields来自严格Trial解析，不是首因。

profile缓存总区间为6.096374535秒，其中proc区间5.661049150秒，约占92.86%。下表是既有采样边界的跨度，包含相邻边界残余工作，不是精准函数wall time，也不是同条件性能A/B。

|缓存区间|跨度秒|
|---|---:|
|Python读取与hash至首个边界|0.028559231|
|进程目录枚举、身份校验及comm读取|5.661049150|
|选中daemon的身份与映像|0.210724538|
|namespace及配置|0.034474462|
|endpoint及FD引用|0.090637461|
|最终连续性核对|0.070929693|

私有源/WPA/profile尾部与导入校验分别为2.705516344/0.147297961/1.555890345秒。当前proc跨度同时包含系统读取和重复guard，尚不能认定纯派发是全部首因。下一单变量候选只拟将`_live_profile` Startup分支的六项any(generator)改为同顺序直接for，保留全部type/is/code、短路、现场tuple和原clock；预计增42字节，最终预算待实际生成。未生成新运行源、未做该优化HOST/笔端测试，不签收益。

本次新volatile根`/var/volatile/tmp/p011-mta-rx-pfcache-v01`完整暂存74文件4目录；2315个登记FD全部关闭，Owner/Startup/actor/client socket关闭，resource_pending及staging_pending=false。原厂文件/进程和前后有限网络基线保持；complete、startup_verified、closed_policy仍false，不签完整启动、用网恢复或手机连接修复。新接收资产保留核验复用；无RF/UI/手机/用户文件传输、凭据/FileCenter创建或系统替换。

- [最新只读ZIP](../../logs/MtaP011-Readonly-20261006-141143-874984.sanitized.zip)：SHA-256 `f10fd5bde7bec21db7dec171affb710a94315437e742d008c80a6e0d5113fba5`。
- [Startup SOURCE ZIP](results/receive-profile-cache-v1-startup-source-20261006-142128-ebc81f06/public-result.zip)：SHA-256 `fd53b39602de4269a89cbeece58f1f46c5b5f5baa2481464dc382533fca50233`。
- [笔端缓存诊断FAIL ZIP](results/receive-profile-cache-v1-startup-device-20261006-142650-be5f94cc/public-result.zip)：SHA-256 `9a3a82578e2ac0bd6c71c6ae3ab18e2905003c83f7f283687fadc6c5451ee8a0`。
- [三个HOST test实际通过但checker误拒的原ZIP](results/receive-profile-cache-v1-host-20261006-142549-55c1d0c4/public-result.zip)：SHA-256 `bab57693bd9194f5f6b63bd690b0928b5e4c73209d85bcac811f116eeaad5a6d`。11旧快照保持；当前只有checker的98字节EOL派生修订，其余10源保持。
- [首次装配工具观察FAIL ZIP](results/receive-profile-cache-graph-v1-assembly-fail-20261006-142054/public-result.zip)：SHA-256 `05e44e00a27493eea4d6f253791cf8b441389d83d81ccc49fff2ee5e7f060387`。此项未单独捕获原始双流，失败源为有限补丁逆转后与预运行hash相同的重建件，不能称原raw快照。
- 新电脑入口：[缓存HOST检查](HOST_MTA_RECEIVE_PROFILE_CACHE_V1_CHECK.cmd)、[Startup SOURCE](HOST_MTA_RECEIVE_PROFILE_CACHE_V1_STARTUP_CHECK.cmd)；[明确笔端诊断入口](TEST_MTA_RECEIVE_PROFILE_CACHE_V1_STARTUP.cmd)不自动重复。本轮全部ZIP均独立.NET逐成员读回，不包含私人原始日志。

完整目标active、边开发边实测范围保持。手机需新的就绪及真实native READY，旧连接FAIL、双向互通、完整FileCenter/Owner父期限与用网恢复仍待。不重已过专项、Stage、CONTROL或锁初始化；不把本轮原厂保持或合成HOST模型代签完整验收。

## 2026年10月6日 14时06分 新入口接装完成但笔端准备超时

P011重连后，两次最新只读采集通过：原厂文件哈希及进程身份保持，Wi-Fi已连接，BlueZ与ConnMan有服务归属，临时菜单不存在。原始双流、HOST和remote退出均0，stderr空；公开ZIP不含私人设备标识。这是有限原厂与能力核对，不是互传准入或完整恢复。

新接收Startup、手机和发送HOST入口已绑定13:48的实际独立包，默认SOURCE分别通过285、301、154份输入及快照。Startup保留原10秒准备、60+60秒和240/250秒外层保护；手机保留PHONE、schema、trace、READY、Trial、期限和关闭策略。手机来源检查已精确改为两份FC HTTP来源，FC9为113,832字节；未执行手机DEVICE或开启广播窗口。

唯一新Startup DEVICE整体FAIL。新volatile接收根`/var/volatile/tmp/p011-mta-rx-fccap-v0001`完整暂存74文件、4目录，stage_verified=true；随后Factory在私有导入后的check_active触发原startup_expired，准备10.622360秒、超原10秒0.622360秒，Owner尚未启动，collector未开始，Trial=None。HOST解析Trial的result_fields是后续检查错误，不是首因；HOST退出0、stderr空、remote退出1均保留。

四个缓存分段分别为私有源2.725573秒、WPA0.141966秒、环境profile6.199677秒、profile尾部与导入校验1.555144秒。12:02旧Scope通过运行的profile为5.023876秒，累计9.410639秒；两次累计差1.211721秒，其中约97%位于profile段。实际两份Factory的64个函数/类源码及AST相同，本轮FC对象没有创建，不能把时间差归因HTTP修补，也不能作为同条件性能A/B。下一只在现有时钟缓存上细分profile的读取阶段，不加时钟/IO或权限缓存，不放宽期限，不盲重本次Startup。

失败后的Owner、Startup、能力actor、client socket及2315个登记FD均已关闭，resource_pending=false、staging_pending=false，原厂文件、进程、路由及网络接口有限基线保持。完整closed_policy仍为false，不能把关闭事实改签启动通过或完整用网恢复。新接收资产保留于volatile目录，后续核验复用，不重复暂存；未退出原厂UI、创建凭据/FileCenter、处理旧记录、操作手机、传用户文件或执行无线动作。

新发送入口仅SOURCE：实际14件包、Owner/Boot/Outer/Worker/Guardian、FC9/100,114字节及普通37件/1,368,142字节库存闭合，GUI19原样。生成89,989字节bootstrap、34字节wire和三阶段载体源码，未执行它们；原17字段及600+60/800/810秒源码合同保持。Stage、CONTROL、DEVICE参数明确拒绝，新发送设备根尚未暂存或核实运行，不提供可误启动的设备CMD。

- [重连只读ZIP](../../logs/MtaP011-Readonly-20261006-135259-082575.sanitized.zip)：SHA-256 `00af40e2d192f3548dd50d02fb4e35537554f84be1049d767ec7345124e487ef`。
- [Startup SOURCE ZIP](results/receive-fc-http-cap-v1-startup-source-20261006-135557-cd8f55ff/public-result.zip)：SHA-256 `e8eec50b0e227a35bf6cbc258b39fd2ce0a3b8f1d67637692114eac364ca3663`。
- [笔端Startup FAIL ZIP](results/receive-fc-http-cap-v1-startup-device-20261006-135639-eb79c456/public-result.zip)：SHA-256 `3965f666fae8d5769f98a7d3b0b1c59be288398cfc67047865155ff1a8a680cf`。
- [手机SOURCE ZIP](results/phone-fc-http-cap-v1-source-20261006-135951-401ad0be/public-result.zip)：SHA-256 `98321ec7d38f60d07d67fc24382abb009d5a292a62deba3a39f3b47eca0734fd`。
- [发送SOURCE ZIP](results/formal-send-fc-http-cap-v1-source-20261006-140343-b86d53e4/public-result.zip)：SHA-256 `86895522ec4aa75243dffd1847ab972f51d121ba219868d88d9fc21cb6c46ee2`。
- 一键电脑入口：[接收Startup](HOST_MTA_RECEIVE_FC_HTTP_CAP_V1_STARTUP_CHECK.cmd)、[手机源码](HOST_MTA_PHONE_FC_HTTP_CAP_V1_CHECK.cmd)、[发送源码](HOST_MTA_FORMAL_SEND_FC_HTTP_CAP_V1_SOURCE_CHECK.cmd)。本轮已执行，不自动重复；手机实际窗口仍需新的就绪及真实native READY。

完整目标active、边开发边实测范围保持。旧连接FAIL、真实手机双向互通、完整FileCenter/Owner父期限及用网恢复仍待；已通过且未变的HTTP、TLS、音频专项与旧GUI证据继续复用，不重旧suite、CONTROL或锁初始化。

## 2026年10月6日 13时48分 文件中心修补已接入独立发送和接收包

13:26已验证的HTTP父期限修补已机械接入实际发送、接收来源链，共生成25件独立电脑产物。旧包、旧图和19件GUI保持，不覆盖原厂程序或系统文件；本轮没有调用ADB、运行候选、无线广播、手机操作或用户文件传输。

发送包位于`candidate/formal-send-fc-http-cap-v1/`，从实际deploy-v7 Owner和status-package-v3 Worker派生，14件产物包括10件runtime、两份来源清单和两份差异/来源报告。Owner、Boot、Outer、Stage与Worker/Guardian常量同步；文件中心九源仅更新send Companion与共享HTTP，其余七源保持，合计100,114字节。普通32源、37件库存和1,368,142字节总量不变，GUI及资源校验器复用。两处方法内常量仅为Owner隔离根、Worker文件中心总量，业务和原10秒/600秒/60秒保护不变。

接收包位于`candidate/receive-fc-http-cap-graph-v1/`，共11件产物。新definitions169,842字节，SHA-256为`c43f342a7c7ccafe5e2780de7f4068bdfe84195579b5f1c6e970d78ad19abfc2`。274项来源、六个机械闭包的实际校验通过；75角色仍为4,193,464字节，4MiB余量840字节，69角色与State/协议/Proc/native/WPA/monitor原样。独立文件中心九源113,832字节，未混入75角色预算；仅换receive Companion和同一共享HTTP，余七源保持。

默认SOURCE及最终接收装配检查均通过，369份输入与快照保持，25件实际文件逐项读回；两套完整九源路径、长度和SHA-256与实际Owner/Worker/接收definitions一致。发送writer只执行一次、退出0且stderr空；最终仅执行尚未执行的接收writer，退出0且stderr空，SOURCE不启动子进程。此前HTTP主机对照证据复用，没有重测旧专项、Startup、Stage、CONTROL或锁初始化。

三份本轮FAIL保留：首次checker布尔合同表达式错误、发送写完后的checker ASCII解析错误、接收装配器对含中文HTTP源码的ASCII解析错误。修正仅涉及检查/装配代码的布尔与UTF-8解析，三份运行修补源未变。旧装配器字节与双流保留在失败快照中；最终通过不改写旧FAIL，也没有重复生成已完成的发送包。五个公开ZIP均仅result.json和README.txt，封存读回与独立.NET逐成员大小/SHA核对通过。

- [实际装配及两包读回ZIP](results/filecenter-http-cap-package-v1-assembly-receive-20261006-134659-093d8aa4/public-result.zip)：SHA-256 `8a874d18967a16780f110faaacd7b4bd54fa4072d155934b7c47424b4d22d154`。
- [默认SOURCE ZIP](results/filecenter-http-cap-package-v1-source-20261006-134728-e8a6d25f/public-result.zip)：SHA-256 `b1a712fe9f06ec7f7d676a6bf5934b12964e95f9611b753d9d4a931b66bd5fed`。
- [首次合同FAIL](results/filecenter-http-cap-package-v1-assembly-20261006-134243-851486f3/public-result.zip)、[checker解析FAIL](results/filecenter-http-cap-package-v1-assembly-20261006-134340-f43e29e8/public-result.zip)、[接收装配解析FAIL](results/filecenter-http-cap-package-v1-assembly-receive-20261006-134429-8bc5893b/public-result.zip)：原记录与私有输入保留。
- [默认电脑检查入口](HOST_MTA_FILECENTER_HTTP_CAP_PACKAGE_V1_CHECK.cmd)、[显式电脑装配入口](BUILD_MTA_FILECENTER_HTTP_CAP_PACKAGE_V1.cmd)：无设备分支，后者只独占创建缺失文件或核验已存在文件完全一致；不自动重跑。

新隔离根仅在电脑端定义，未核实设备存在性、未Stage或接笔端薄入口。完整FileCenter/Owner期限、媒体锁/阻塞文件IO及历史Worker verified=false保持；本次SOURCE不证明P011新版本运行或小米连接恢复。下一独立传播Startup/phone/发送HOST入口的新definitions、根、274来源和FC9精确总量，保留原IO/READY/时限/关闭门，再选择受影响的有限笔端验证。手机仍需新的就绪确认和本轮真实native READY；旧连接FAIL、双向互通及实际用网恢复待，完整目标active，边开发边实测策略不缩小。

## 2026年10月6日 13时26分 文件中心HTTP父期限修复通过主机对照

发现发送与接收两套实际文件中心HTTP请求均遗漏父活动期限：原解析器使用180秒请求期限、4秒请求头期限，慢POST或媒体sendall仍可能越过会话截止。新版本只为两份Companion添加Handler.setup继承父期限，共用HTTP只把请求头期限裁到同一上限；原180秒上限、权限、路由、BodyStream、发送和关闭方法不变。

三件运行候选为`candidate/filecenter-http-parent-cap-v1/`下send、receive、shared源。两个Companion各增加122字节，HTTP增加20字节；完整字节逆核通过，旧源未修改。首次SOURCE19输入及快照保持通过。首次HOST因测试端误调用精简JSON编码器不存在的loads而FAIL，发生在发送母源媒体响应解析；此前两个发送母源慢请求已执行，原整体FAIL和原始双流保留，不补签完整通过。

仅改测试端为HOST标准库解析实际HTTP回复，继续剩余12场景，未重前两个场景或旧方法。唯一HOST方法15.484秒通过，18条真实HTTP连接；两套实际FC9各九模块，14源加入口等共19输入保持。四个剩余母源反例在1.25秒父期限后0.20秒仍阻塞于原recv/sendall；六个候选慢请求在父期限后最多0.35秒的调度余量内退出。两套候选正常文件列表和页面事件请求通过，真实时钟/socket/线程/文件系统未替换。

原Companion关闭及实际actor线程、服务线程、请求FD、客户端、媒体和存储句柄核验通过，12个新合成目录核验身份后已清理，加载命名空间恢复。50秒alarm先于测试入口，HOST60秒上限，子进程退出0；raw双流、源码和快照留私有目录。此次未调用ADB或学习笔，无RF/UI/手机、播放子进程、graph生成或Stage。

私有Companion的root/guard是明确构造夹具，不签正式Owner准入或完整FileCenter/Owner父期限。媒体锁等待与阻塞文件IO仍未验证。候选尚未接装发送普通图、接收Scope75图或设备包，历史Worker的wired=true/verified=false不改；此前笔端TLS回环证据继续有效，但不能代签本次修补的笔端行为。

- [剩余场景通过ZIP](results/filecenter-http-parent-cap-v1-host-20261006-132547-293bbd4e/public-result.zip)：SHA-256 `823c58eae2fe2b5b07b052091a448a957c2f090fabfaf1816c2721a82cdedb6c`。
- [首次HOST失败ZIP](results/filecenter-http-parent-cap-v1-host-20261006-132413-1f8613b5/public-result.zip)、[首版SOURCE ZIP](results/filecenter-http-parent-cap-v1-source-20261006-132401-757a7936/public-result.zip)：三个公开包均仅result.json和README.txt，封存CRC/读回及独立.NET逐成员SHA核对通过。
- [默认电脑源码检查](HOST_MTA_FILECENTER_HTTP_PARENT_CAP_V1_SOURCE_ONLY.cmd)、[显式主机真实HTTP检查](HOST_MTA_FILECENTER_HTTP_PARENT_CAP_V1_CHECK.cmd)：已执行，不自动重测；两个入口均无设备分支。

下一将两件FC9来源及Owner常量机械接入独立发送/接收包，不覆盖已验证图或旧目录，不更改业务门、期限或关闭判据。接收新增方法属于独立FC9，不计入75角色payload；需同步精确总量及实际pin链，不能仅改源码便称已部署。新的手机就绪与真实native READY仍待，原连接FAIL及双向互通/实际网络恢复未验收，完整目标active。

## 2026年10月6日 13时07分 P011真实TLS与落盘故障验证通过

当前接收与传输源码已在P011本机回环完成两个真实TCP/TLS/HTTP与文件落盘故障场景，首次笔端运行通过。这是笔端数据通路证据，不是小米原厂互传或完整双向验收。旧手机连接FAIL及此前HOST测试预期路径FAIL均保留。

先做的只读依赖检查确认Python3.5.5、TLS核心模块及OpenSSL1.0.2p可用；笔端缺少pathlib与unittest，文件系统默认编码为ASCII。新目标仅适配测试框架与显式UTF-8路径操作，七份原业务模块197,023字节保持原样，不向系统安装依赖。实际OpenSSL文件的只读句柄、SHA-256及关闭也通过核验。

- 落盘后迟到取消：两件文件、274,144字节，原Storage仍抛出原TransferCancelled，同一持久化结果与文件保留，不改判接收成功；耗时2.663秒。
- 终结确认发出前断线：两件文件、274,144字节，原SenderPump在ACK未发送时关闭真实控制连接，原Receiver的Stream/WebSocket收到真实EOF；文件保持，对端确认与发送完成仍为false；耗时2.041秒。
- 每场景两条TLS连接，共四条；文件路径、大小、完整内容及SHA-256核对通过。线程与调用者退出，原下载句柄、归档、证书准备和socket关闭，观察器与构造投影恢复。

默认SOURCE和唯一DEVICE均保持18份输入与快照，当前Scope清单选用的Transport/Storage逐项匹配；目标87,978字节、最长行136字节。笔端原厂前检查、故障测试及原厂后检查三条命令的HOST/remote均0、stderr均空。每场景原30秒运行与5秒清理不变，外层80秒alarm在读取stdin前生效，HOST等待上限95秒，不续期。

本轮仅在固定volatile区域创建两个新合成测试目录、测试证书和回环socket，目录身份核对后均已清理；未访问用户文件，未暂存运行候选或重建图，无RF、UI、配对、扫描、网络切换或原厂/启动项/分区修改。原厂文件、进程与Wi-Fi连接状态前后保持。构造回环准入及socket owner仍为显式夹具，不签原生接口准入、完整Executor/Bridge或完整用网恢复。

- [笔端真实故障ZIP](results/p011-durable-network-v1-device-20261006-130625-e0485d62/public-result.zip)：SHA-256 `5d5b4eea09d251ccd5ae4364aefd3a490e8bde1326c7ef09a365ec8530664a67`。
- [对应SOURCE ZIP](results/p011-durable-network-v1-source-20261006-130541-f6c62004/public-result.zip)、[笔端只读依赖ZIP](results/tls-environment-v1-device-20261006-125447-69a80f08/public-result.zip)：与笔端ZIP均仅result.json、README.txt，封存CRC和读回通过，另经独立.NET逐成员SHA核对；原始双流、退出、目标与输入快照留本地。
- [默认电脑源码检查](HOST_MTA_P011_DURABLE_NETWORK_V1_CHECK.cmd)、[显式笔端回环试验](TEST_MTA_P011_DURABLE_NETWORK_V1.cmd)：本次已执行，不自动重测。

完整目标保持active。下一真实手机连接分类仍需新的小米就绪确认、临窗口完整核对与本轮真实native READY；重连P011不等于手机就绪，不重复询问或自行开启窗口。接收/发送原厂链路、完整FileCenter/Owner子任务期限与实际网络恢复尚待；此前音频锁等待证据复用，不重已过专项、Startup、Stage、CONTROL或锁初始化。

## 2026年10月6日 12时49分 重连核对与真实接收故障验证通过

P011重新连接后，显式选择唯一学习笔而非模拟器，两次只读采集通过：新版原厂三文件哈希与进程身份保持，Wi-Fi已连接，BlueZ和ConnMan均有服务归属，临时菜单不存在。本次没有设备写入、扫描、广播、配对、网络切换或原厂界面操作。这是能力与有限原厂核对，不是接收准入或完整用网恢复。

新增当前源码专项默认SOURCE通过15份输入与快照回读，未启动子进程；随后唯一HOST Linux方法通过两个独立真实loopback TCP/TLS/HTTP与落盘故障场景。每场景两件文件、274,144字节，共四条真实TLS连接；当前Scope清单选用的Transport、Storage哈希逐项匹配，原业务模块未修改，未重建图或暂存设备。

- 落盘后迟到取消：原Storage抛出原`TransferCancelled`，保留同一持久化结果及文件，接收不改判成功。
- 终结确认发出前断线：原SenderPump在ACK仍未发送时关闭实际控制连接，原Receiver的Stream和WebSocket收到真实EOF；文件保持，但对端确认与发送完成仍为false。
- 两场景耗时分别60.748和97.039毫秒。接收线程退出后，原下载句柄、目录、归档/证书准备及socket生命周期关闭验收通过；完整文件路径、大小、SHA-256和内容字节核对通过，观察器与构造准入投影恢复。

首次HOST运行因测试遗漏原归档的序号前缀而FAIL，原记录保留。仅修正测试的精确`序号/原路径`映射与受限失败文案，原故障、EOF、期限和关闭判据未变；修正后仅重受影响方法，未重旧正常测试。构造loopback准入与HOST socket owner仍是明确夹具，不签原生接口准入、完整Bridge、P011传输、手机互通或系统恢复。

- [当前SOURCE ZIP](results/receive-durable-network-v1-source-20261006-124822-bd676bb7/public-result.zip)、[真实故障HOST ZIP](results/receive-durable-network-v1-host-20261006-124852-4a3eb732/public-result.zip)、[首次FAIL ZIP](results/receive-durable-network-v1-host-20261006-124345-bcc16ad0/public-result.zip)：仅result.json和README.txt，封存CRC与读回通过，另经独立.NET逐成员SHA核对。原始双流、退出和输入快照留本地。
- [重连只读ZIP](../../logs/MtaP011-Readonly-20261006-124345-471863.sanitized.zip)：仅两成员，独立成员SHA核对通过。
- [默认电脑源码检查](HOST_MTA_RECEIVE_DURABLE_NETWORK_V1_SOURCE_ONLY.cmd)、[显式HOST真实故障检查](HOST_MTA_RECEIVE_DURABLE_NETWORK_V1_CHECK.cmd)：已执行，不自动重测。

手机仍待新的小米就绪确认、临窗口完整核对和真实native READY后再通知点击；这次重连不是手机就绪。旧连接FAIL及双向互通、实际落盘与网络恢复验收保持待验证，目标active。继续边开发边有限实测，不重复已过专项、Startup、Stage、CONTROL或锁初始化。

## 2026年10月6日 12时27分 音频锁等待期限实机通过

P011已重新识别，显式选择唯一学习笔而非模拟器。新增入口默认只做电脑源码检查；8份输入快照与回读、完整原音频模块、17,705字节目标及Python3.5语法检查通过。随后唯一笔端测试通过，HOST、remote和checker均0，三条命令的stderr均为空。实际源码未修改，也没有重新暂存或重复已过的启动、CONTROL、共享锁和无线测试。

本次在P011上完整加载两个现有音频模块，调用原构造、停止、快照和被动关闭方法，用真实线程持有原RLock。原方法在传入的0.12秒绝对cleanup期限后返回原`audio_state_lock_pending`；快照、被动查询和给出更长期限的重试没有等待续期。释放夹具锁后，原stop完成，线程退出、空音频actor关闭、pending=false、tickets=0，未调用事件或文件源回调。

| 实际笔端操作 | 耗时 毫秒 |
| --- | ---: |
| 首次停止等待 | 120.417 |
| pending快照 | 0.126 |
| 被动关闭查询 | 0.021 |
| 更长期限重试 | 0.099 |
| 释放后原stop | 0.249 |

只签调用者cleanup cap的锁等待与不续期行为；父cap引用保持不是父期限行为验收。未运行实际播放、子进程、HTTP、Companion、Owner、UI或RF，完整FileCenter子任务deadline仍未验证，历史Worker `verified=false`不改。前后原厂三文件哈希、进程身份及Wi-Fi连接状态保持，BlueZ和ConnMan总线有归属；这不是蓝牙新扫描结果或完整网络恢复证明。

- [SOURCE ZIP](results/filecenter-audio-deadline-v1-source-20261006-122527-2d088cc5/public-result.zip)、[笔端ZIP](results/filecenter-audio-deadline-v1-device-20261006-122547-7f214d82/public-result.zip)：各仅result.json和README.txt，CRC及成员读回通过，另经独立.NET逐成员SHA核对。原始双流、退出码、源码及输入快照留本地。
- [默认电脑检查](HOST_MTA_FILECENTER_AUDIO_DEADLINE_V1_CHECK.cmd)、[显式笔端检查](TEST_MTA_FILECENTER_AUDIO_DEADLINE_V1.cmd)：本次已执行，不自动重测。

手机握手仍等新的小米就绪确认，原连接FAIL不改判。下一无手机可推进项是当前版本真实TLS/HTTP与耐久落盘连接后的迟到取消、真实peer断开故障；已有旧版真实TLS和新版模拟网络不能拼成当前实测通过。只读路线已核清，尚未编写或执行该新测试，不需要重建75图或暂存。完整双向互通和实际恢复仍待，目标active。

## 2026年10月6日 12时08分 Scope启动通过 手机入口已接新图

P011重新连接后，11:57只读基线通过。Factory `_StartupReadScope._originals` 两组generator改为同序for，唯一方法增加114字节；67情形／134次原新方法调用HOST通过，8输入保持。专项只执行首段检查到固定边界，不签后续真实IO。首次seed生成器在写后元数据核验退出1，两件产物保留，原失败和双流未单独保存的缺口不改判；新HOST以完整字节／AST逆及实际输入独立核对保留产物，没有重复写入。

独立Scope图的PLAN及唯一EXCL写入通过，11件产物、260项来源、75角色4,193,464字节／余840字节；6项变化、69项原样，之前已测Owner改动保留。新Startup SOURCE和唯一无RF实机均通过，270输入前后保持，HOST／remote／checker均0。首次暂存74文件／4目录；Owner启动、实际基线采集、ProcReader3和STATUS2通过，2321次FD打开均关闭，Owner／启动资源／观察器关闭，原厂哈希、进程及前后基线保持，pending=false。

| 原缓存边界段 | 本次秒数 |
| --- | ---: |
| 35源读取 | 2.690360 |
| WPA读取 | 0.143564 |
| live profile | 5.023876 |
| 导入及后置核验 | 1.552839 |
| 准备合计 | 9.410639 |

原10秒准备期限未改，本次余0.589361秒。这里只证明一次真实启动成功，不是稳定性或同条件性能A/B，不能把历史差值全归因此循环改动。12:03后置只读两次一致、0连接／0活动广播、pending不存在且未处理，有限原厂保持；本轮没有RF、UI、手机或文件传输，也没有系统、启动、WCN/NV修改。完整用网恢复仍待。

手机诊断入口已机械接到同一实际Scope图，唯一默认SOURCE通过：286输入保持、载体2,015,870字节／最长行137字节，device=NOT_RUN。原phone28352、严格schema5907、trace14820和READY／期限／关闭门保持，没有重建运行图或再次暂存。下一步回到真实手机连接分类：需要新小米就绪、临窗口当前资产／Received／pending／actor／原厂基线核对，并收到本轮真实native READY后才通知点击。原手机连接FAIL、CONNECT／TLS、双向安全落盘、取消及实际恢复仍待，完整目标active。

- [67情形HOST ZIP](results/receive-scope-dispatch-v1-host-20261006-115853-89f75b74/public-result.zip)、[Startup SOURCE ZIP](results/receive-scope-dispatch-v1-startup-source-20261006-120152-2474f0f8/public-result.zip)、[笔端Startup ZIP](results/receive-scope-dispatch-v1-startup-device-20261006-120251-2a141a3f/public-result.zip)、[后置只读ZIP](results/receive-radio-baseline-device-20261006-120359-1c4ee2c4/public-result.zip)、[手机入口SOURCE ZIP](results/phone-scope-dispatch-v1-source-20261006-120806-19e4f327/public-result.zip)。这些公开包及新图PLAN／WRITE包均独立逐成员SHA读回，仅两成员；原始数据和输入快照留本地。
- [新手机默认SOURCE一键](HOST_MTA_PHONE_SCOPE_DISPATCH_V1_SOURCE_ONLY.cmd)。本次Startup DEVICE已完成，不自动重复；手机TEST须协调新就绪，不能自动运行或以SOURCE代签互通。历史资产、失败和日志保持。

## 2026年10月6日 11时40分 笔端模型测速确认派发改动有局部收益

P011 重连后的只读基线通过：两次观察一致、0连接、0活动广播，pending不存在且未处理，有限原厂身份保持。随后新增微基准的SOURCE及唯一笔端运行均通过，10份实际输入和目标源码前后保持；目标18,069字节、最长行134字节，HOST及remote均0、stderr为空。设备前先保存输入快照，固定stdin读取前设置30秒闹钟，HOST上限45秒；没有续期、回退或重试。

微基准只调用真实原版／候选 `_context` 的未改AST方法，使用独立namespace和普通类型字段模型，pid=None。四组ABBA、每块8192次，共131072次测量调用；两侧各128次预热、模型构造和编译均不计时。下表是包含调用循环开销的热模型结果，不是实际启动耗时。

| 模型 | 测量调用次数 | 经过时间合计 秒 | 进程CPU合计 秒 | 每次平均CPU 微秒 |
| --- | ---: | ---: | ---: | ---: |
| 原版generator | 65536 | 4.996788 | 4.991793 | 76.169 |
| 候选同序for | 65536 | 4.293615 | 4.289182 | 65.448 |

本轮模型CPU耗时降低14.075%，四组方向一致。因此保留这项候选继续研究，但不把局部收益换算成完整启动加速或稳定性。上轮实际Startup超时FAIL保持；模型没有调用真实Owner构造、start、其他九方法、IO、UI或无线业务，不能证明10秒准备已稳定或手机连接已修复。测试前后原厂哈希／进程一致，Wi-Fi均处于已连接状态；没有Stage、CONTROL或共享锁初始化，没有原厂／启动／WCN/NV／系统分区修改。

源码进一步定位到live profile逐进程读取周围的高频身份检查。下一只优化 `_StartupReadScope._originals` 两段generator的派发，保持同序短路、所有当前身份／IO／Directory／时限与关闭检查，不缓存授权、不删除daemon双读。新Factory优化尚未制作或部署；之后按受影响范围做有限无RF实测，复用未变资产。CONNECT／TLS、双向安全落盘、取消及实际用网恢复仍待，目标active；当前不需要操作小米手机。

- [笔端模型结果ZIP](results/receive-owner-dispatch-bench-v1-device-model-20261006-113639-d76199ff/public-result.zip)、[SOURCE结果ZIP](results/receive-owner-dispatch-bench-v1-source-20261006-113631-0007badb/public-result.zip)、[重连后只读ZIP](results/receive-radio-baseline-device-20261006-113010-59378e2f/public-result.zip)。三包均独立核对两成员SHA一致；原始双流、退出码和输入快照留本地。
- [默认SOURCE入口](HOST_MTA_RECEIVE_OWNER_DISPATCH_BENCH_V1_CHECK.cmd)、[模型说明](candidate/receive-owner-dispatch-bench-v1/README.md)。本轮DEVICE已完成，不自动重复；完整接收Startup与手机试验仍分别验收。

## 2026年10月6日 11时20分 Owner派发候选未取得启动改善

唯一业务改动为Owner `_context` 九项方法校验从 `any(generator)` 改成同序显式 `for`，增加78字节。实际语义专项通过：一个方法、70个情形、140次原／候选调用，8份输入保持；包含正常、九项逐字段拒绝、前缀／ticket／后续Owner检查、原非门异常及callback原对象身份。夹具曾错误选择母源不存在的 `_CODES`，在执行前独审发现并窄修，业务源没有因此改变；没有把未执行的审查缺口称为运行FAIL。

独立新根 `p011-mta-rx-dispatch-v1` 的11件电脑产物已生成，75个角色4,193,350字节／余954字节；5个ordinary角色及private Executor因根／pin传播变化，共6变69原样，其他private34、Proc、原生组件和文件中心9源原样。Startup SOURCE通过255输入保持，245项平铺来源、载体2011509字节／最大行129字节。原10秒、60+60、alarm240／HOST250、严格Trial及资源关闭／PASS门未改；旧源和资产未覆盖。

11:16唯一新无无线笔端试验为FAIL：HOST0／remote1／checker1。新根首次暂存74文件／4目录并核对通过，2307次打开的FD均关闭；Owner、启动资源、能力观察器关闭，原厂哈希、进程和前后基线保持，pending=false。Owner未启动、collect未执行、Trial均None；HOST随后严格拒绝None字段，不是远端失败的首因。Factory在导入后 `check_active:514` 拒绝，原缓存显示准备末点已超过原prepare_until约0.867110秒。

| 原缓存阶段 | 10:53 progress候选（秒） | 11:16 dispatch候选（秒） |
| --- | ---: | ---: |
| 35源读取 | 2.772999 | 2.745849 |
| WPA读取 | 0.149698 | 0.147153 |
| live profile | 5.513860 | 6.235303 |
| 导入及后置核验 | 1.550568 | 1.738805 |
| 准备合计 | 9.987125 | 10.867110 |

本次没有观察到改善，不采用“已经优化成功”的结论。两次分别为旧根资产复用与新根首次暂存，环境条件未对齐，不能据单次差值认定循环改动导致倒退，也不把profile全部耗时归于纯派发。下一先在P011 Python3.5上用不调用真实Owner构造／IO的有界模型微基准，对照原／新 `_context` 的纯派发成本；若仍有价值，再按同样预热条件验证实际启动。微基准尚未制作或执行，模型CPU结果也不能代签实际启动或手机互通。不立即重复本次TEST，不重Stage、CONTROL或锁初始化；新失败和raw保留。

11:18后置原生只读通过：两次观察一致、0连接／0活动广播、pending不存在且未处理、观察器关闭、有限原厂保持。这不是实际用网后的完整恢复。本轮没有RF、UI、手机、文件传输、原厂系统／启动／WCN/NV修改。目标active，旧手机连接FAIL和CONNECT／TLS、双向安全落盘、取消与实际恢复仍待；当前不需要用户操作小米手机。

- [70情形HOST ZIP](results/receive-owner-dispatch-v1-host-20261006-111546-41d0353c/public-result.zip)、[新Startup SOURCE ZIP](results/receive-owner-dispatch-v1-startup-source-20261006-111438-82bade63/public-result.zip)
- [本轮笔端FAIL ZIP](results/receive-owner-dispatch-v1-startup-device-20261006-111604-78707ef3/public-result.zip)、[后置只读ZIP](results/receive-radio-baseline-device-20261006-111855-82c88e98/public-result.zip)。四份公开ZIP仅含result.json和README.txt，独立逐成员SHA读回一致。
- [主机专项一键](HOST_MTA_RECEIVE_OWNER_DISPATCH_V1_CONTRACT.cmd)、[新Startup SOURCE一键](HOST_MTA_RECEIVE_OWNER_DISPATCH_V1_STARTUP_CHECK.cmd)、[新根生成器](candidate/receive-owner-dispatch-graph-v1/generate_graph.py)。11件产物已生成，不再次--write；笔端TEST已执行，不自动重复。

## 2026年10月6日 10时55分 无无线启动通过，准备时间余量仍不足

P011 重连后的新只读检查通过。本轮没有开启扫描、广播、手机连接窗口或文件传输；没有改原厂 Z03、启动项、无线固件/NV、系统分区，也没有重复 Stage、CONTROL 或共享锁初始化。

新增 retained-v2 只在运行结束后读取已有缓存及原异常帧，不增加笔端 clock／IO 调用，不改变实际75角色、10秒准备期限、资源关闭或成功判据。主机专项一个实际方法的22个情形、11份输入保持通过；SOURCE核对240份输入保持，实际载体2011533字节，单行最多129字节。75角色仍为4,193,272字节，余1032字节。

10:53 的唯一新笔端试验整体 PASS：HOST／remote／checker均0，Owner启动、基线采集、3次ProcReader和2次STATUS核对通过；2319次打开的FD均关闭，Owner、启动资源和能力观察器关闭，原厂哈希、进程及前后基线保持，pending=false。资产原样复用，新建文件和目录均为0。Trial只证明未请求无线接收及退出撤销，phone_verified和restoration_verified仍为false。

从原缓存时钟取得的准备推进量如下。它们包含各阶段的校验与IO，不是纯CPU或独占导入耗时；本轮不是同条件性能A/B，也不是稳定性验收。

| 缓存边界段 | 秒 |
| --- | ---: |
| 初始化至35源读取完成 | 2.772999 |
| WPA读取 | 0.149698 |
| live profile构建 | 5.513860 |
| 导入及后置核验 | 1.550568 |
| 合计 | 9.987125 |

距原10秒准备期限仅余0.012875秒，不能认为启动已稳定。下一只优化高频Owner方法身份检查的纯派发开销：九项检查保持原顺序、短路和全部身份／IO／期限边界，不缓存授权结果。候选尚未生成、测试或部署；收益待同设备验证。早先10:06准备超时FAIL及10:32在Baseline.collect的io_error FAIL保留，不能由本次PASS改判；后者当时没有取得内部原因，不能猜作actor_unknown。

10:55后置原生只读再次通过：两次观察一致、0连接／0活动广播、pending不存在且未处理、观察器关闭、有限原厂保持。这不是实际用网后的完整恢复或物理界面验收。手机仍需新的就绪及真实native READY，当前不执行手机TEST；CONNECT／TLS、双向安全落盘、取消和实际网络恢复未完成，目标active。

- [主机专项ZIP](results/receive-startup-retained-v2-host-20261006-105337-d1ef9d3b/public-result.zip)、[SOURCE ZIP](results/receive-startup-retained-v2-source-20261006-105338-8199d31f/public-result.zip)
- [本轮笔端PASS ZIP](results/receive-startup-retained-v2-device-20261006-105358-0f3ee5e8/public-result.zip)、[后置只读ZIP](results/receive-radio-baseline-device-20261006-105505-f3da63b7/public-result.zip)。四份公开ZIP均仅含result.json和README.txt，独立逐成员SHA读回一致。
- [SOURCE一键入口](HOST_MTA_RECEIVE_STARTUP_RETAINED_V2_CHECK.cmd)、[专项主机入口](HOST_MTA_RECEIVE_STARTUP_RETAINED_V2_CONTRACT.cmd)。已完成的笔端测试不重复运行。

## 2026年10月6日 10时12分 新接收候选实机启动超时

接收准备诊断已接入独立的 `p011-mta-rx-progress-v1` 候选。实际生成11件产物，75个角色共4,193,272字节，仍在原4 MiB上限内，余1032字节；6个角色更新，其余69个保持原样。Proc、原生无线组件、WPA、monitor和文件中心9源未变，旧候选未覆盖。装配器前两次因固定接口来源缺失而在写入前失败，补齐明确封pin的来源后完成生成，没有执行历史测试或旧入口。

新无无线启动入口的SOURCE检查通过，238份输入保持；新手机入口的SOURCE检查通过，255份输入保持。严格五字段解析专项实际通过16个合法情形、35个非法literal和4个非有限数值检查，原完整parse_smoke、Trial、remote、terminal和成功判据保留。首次专项的字段静态识别错误及其失败快照保留，修正后才执行夹具。这些结果不代表笔端握手或手机互通通过。

唯一笔端无无线启动仍为FAIL。候选暂存和验证通过，创建74个文件、4个目录，2315次打开的FD均关闭；Owner、启动资源和能力观察器关闭，原厂哈希、进程及前后基线相同。但Factory在私有模块导入及形状核验后、collect前的check_active触发startup_expired，Owner未启动，TRIAL_START／END均为None。原10秒准备期限没有放宽，原FAIL不改判。该期限包含读取、准备与导入，现有日志没有分段数字，不能认定导入本身独占超过10秒。

10:08后置原生只读检查通过：两次观察一致、0连接／0活动广播、pending不存在且未处理、观察器关闭、有限原厂状态保持。没有扫描、广播、配对、Wi-Fi修改、手机窗口或文件传输；这不是完整用网恢复或物理界面验收。已完整暂存的新候选不重复Stage，不删除旧资产或重建CONTROL／共享锁。

下一步只在新的私有诊断中投影已缓存的准备边界和deadline，区分源读取、profile与导入耗时，不增加clock／IO调用，不改75角色或10秒门。当前手机TEST入口不执行；启动问题定位后，仍须新手机就绪和真实native READY才能通知点击。CONNECT／TLS、双向安全落盘、取消和实际恢复仍待，目标active。

- [严格解析专项ZIP](results/phone-publication-progress-v1-host-20261006-095850-e4bb7aec/public-result.zip)、[启动SOURCE ZIP](results/receive-publication-progress-v1-startup-source-20261006-100600-42636e7d/public-result.zip)、[手机入口SOURCE ZIP](results/phone-publication-progress-v1-source-20261006-101017-d2c938bd/public-result.zip)
- [本轮笔端FAIL ZIP](results/receive-publication-progress-v1-startup-device-20261006-100622-ef468961/public-result.zip)、[后置只读ZIP](results/receive-radio-baseline-device-20261006-100819-dacc9906/public-result.zip)。五份公开ZIP均仅含result.json和README.txt，独立逐成员SHA读回一致。
- [无无线启动SOURCE入口](HOST_MTA_RECEIVE_PUBLICATION_PROGRESS_V1_STARTUP_CHECK.cmd)、[手机入口SOURCE](HOST_MTA_PHONE_PUBLICATION_PROGRESS_V1_SOURCE_ONLY.cmd)、[手机接装边界](docs/PHONE_HANDOFF_CLASSIFICATION_V1.md)。SOURCE不操作设备，暂不重复本轮笔端TEST。

## 2026年10月6日 9时44分 接收准备诊断候选主机检查通过

接收准备诊断两源候选已生成并通过主机专项：实际两个方法、53个成功／故障流程和27个投影情形，9份输入与快照保持。Factory只增加12个缓存元组赋值，原业务调用顺序、异常对象和finally保持；phone只改阶段投影，坏诊断或快照变化不抹掉原阶段事实。Factory增加1498 B，在当前2538 B业务增量余量内，但完整新图及机械绑定后的最终预算尚未核定。

可区分读取35源、WPA、JSON pin、live profile、Received、目录身份、manifest和写入／加载。时间是原start返回后已有成功时钟样本的推进量，不是整个准备过程或实时耗时。两源候选尚未封装完整75图、未部署；旧手机parser会拒新字段，须新严格schema和独立接收根接装，不能直接运行旧手机入口。

旧手机窗口在peer后15.010秒主动cancel，六次采样为解密后Factory=new；不是Factory120秒准备到期，也不能认定手机先报失败的唯一原因。旧FAIL保持。下一接装不可变接收图和严格手机投影，再按新手机就绪及真实native READY观察具体步骤；CONNECT／TLS、双向安全落盘、取消及实际用网恢复仍待，目标active。

09:34新原生只读实机两观察一致，0连接／0活动广播、pending不存在且未处理、观察器闭合、有限原厂保持；无无线修改或文件传输，不签完整恢复。两个公开ZIP均只有result.json＋README.txt，独立逐成员SHA读回一致。

- [两个实际方法主机结果](results/publication-progress-v1-host-20261006-094408-1d8e2613/public-result.zip)
- [主机一键入口](HOST_MTA_PUBLICATION_PROGRESS_V1_CHECK.cmd)；[两源生成工具](candidate/receive-publication-progress-v1/generate.py)默认只计划，四个产物已生成，不重复--write。
- [本轮无线只读实机结果](results/receive-radio-baseline-device-20261006-093417-f7feff90/public-result.zip)；[下一手机接装边界](docs/PHONE_HANDOFF_CLASSIFICATION_V1.md)。未变UI／Stage及旧专项证据复用，没有重测。

## 2026年10月6日 9时27分 新发送页面接装与原厂恢复通过

呈现栅栏候选已进入新的实际运行包。电脑生成核对48项输入、27项产物；待暂存19文件共4,185,296 B，18项内容中4项变化、14项原样，加清单后5项暂存文件变化。相对上一候选，ELF原QRC槽内只更新加载路径；相对原厂，其他399资源及槽外字节保持，槽内仍是候选嵌入页。未替换原厂Z03、启动项或系统分区。

新暂存入口42输入SOURCE及唯一P011 Stage通过：19文件／3目录创建、74个原FD与27个验证器FD关闭、38次读回通过，原厂前后保持、Wi-Fi连接。新界面入口56输入SOURCE后，唯一新CONTROL的原20秒smoke整体通过，HOST／remote／checker均0；ui_ready、原厂退出与恢复、Owner／Guardian／候选／凭据／worker FD关闭均true，pending=false。文件中心对象创建关闭通过，其子任务deadline仍wired=true／verified=false。本轮没有截图、物理触摸、竞态真实XHR或手机验收，不能用启动通过代签这些层。

09:26后置原生只读通过：两次观察一致、0蓝牙连接／0活动广播实例、恢复记录不存在未处理、观察器关闭、有限原厂保持、Wi-Fi连接。未进行无线修改或收发文件，不是实际用网后的完整恢复。旧手机连接FAIL仍待新的手机就绪和真实native READY复测；下一观察接收Factory的new→write准备边界，再判断CONNECT／TLS。目标active，继续边开发边实测。

- [新资源SOURCE](results/formal-send-status-ui-assets-v1-source-20261006-091920-019af664/RESULTS.zip)、[唯一资源实机暂存](results/formal-send-status-ui-assets-v1-stage-20261006-092004-aa5b136c/RESULTS.zip)
- [新界面SOURCE](results/formal-send-status-ui-v1-source-20261006-092351-7764d659/RESULTS.zip)、[唯一启动退出实机结果](results/formal-send-status-ui-v1-ui-smoke-20261006-092441-147c3671/RESULTS.zip)、[后置无线只读](results/receive-radio-baseline-device-20261006-092603-212612bf/public-result.zip)
- [资源默认SOURCE入口](HOST_MTA_FORMAL_SEND_STATUS_UI_ASSETS_V1_SOURCE_CHECK.cmd)、[界面默认SOURCE入口](HOST_MTA_FORMAL_SEND_STATUS_UI_V1_SOURCE_CHECK.cmd)。显式TEST分别只做新UI19暂存／受保护20秒smoke；已完成Stage和该CONTROL不可重复执行，不是手机窗口。
- 五ZIP均只含result.json＋README.txt，Root独立.NET逐成员SHA读回匹配；[来源与边界](docs/TRANSFER_RESULT_REPAIRS_V1.md)。历史FAIL保留，两次包装写前拒绝仅为电脑文件读取差异，v3窄适配后生成，不重Qt九场景或旧业务图。

## 2026年10月6日 8时46分 接收路径只读核对与界面响应顺序专项通过

| 本轮增量 | 已验证 | 仍未验证 |
|---|---|---|
| Received 接收目录 | 08:35，六级目录身份、权限及目录 FD 能力通过；六个原 FD 均已关闭，无文件增删改 | 接收准入、真实落盘与传输 |
| 当前接收包固定路径 | 08:45，六目录＋一个辅助文件的14次 lstat 均稳定、元数据合适；原厂文件／进程前后保持，Wi-Fi 连接 | 辅助包正文／SHA、完整库存、pending 和接收 actor 门 |
| 发送页面响应顺序候选 | 13输入 SOURCE 和一个实际 HOST QML 方法／九类延迟回调场景通过；旧 GET 覆盖新 POST 的两类反例已复现，新候选拒绝旧回调 | 真实 XHR、笔端接装、手机连接与传输 |

QML 只增加呈现对象栅栏：动作期间暂停竞争查询，旧回调不能覆盖新状态或释放新 pending；换 token、重置和退出均废弃旧呈现。原 request、applyStatus、布局、按钮动作、计时器与后端准入未改。它不是后端取消完成的凭据，也尚未进入实际 out／设备包。

新固定路径入口默认只做电脑 SOURCE，只有显式 `--check-device` 才采样。观察 PASS 与 `prerequisites_metadata_suitable` 分开；本次两者均 true，但不能据元数据签文件 pin、接收准入或完整网络恢复。原厂 baseline 实际读取文件哈希和进程，固定七路径 sampler 不读取辅助包正文。三段原 HOST／remote 均0、stderr0，五输入保持。Received 工具首次用 `-I` 在电脑导入失败、未接触设备；随后按其支持的 `-E -s -B` 调用通过，旧工具未修改。

本轮没有 Stage／Owner／新界面／RF／手机或用户文件动作。既有08:21发送UI启动／退出证据复用，不重复 CONTROL、资产暂存或空锁初始化。新的手机就绪仍待；临窗口再核完整 pin、pending、actor 和当时基线，真实 native READY 后才通知点击。旧手机“连接失败”、CONNECT／TLS、双向安全落盘和实际用网恢复仍未验收，目标 active。

- [Received 只读实机结果](results/receive-directory-readonly-20261006-083516-99ac005d/public-result.zip)
- [固定路径一键入口](HOST_MTA_RECEIVE_CURRENT_ROOTS_V1.cmd)：默认 SOURCE；[五输入 SOURCE](results/receive-current-roots-v1-source-20261006-084535-263dfe12/RESULTS.zip)、[14次采样实机结果](results/receive-current-roots-v1-device-readonly-20261006-084552-eb5c60a1/RESULTS.zip)
- [界面候选 SOURCE 入口](HOST_MTA_FORMAL_SEND_STATUS_PRESENTATION_V1_SOURCE_CHECK.cmd)、[电脑专项入口](TEST_MTA_FORMAL_SEND_STATUS_PRESENTATION_V1.cmd)：不启动设备；[13输入 SOURCE](results/formal-send-status-presentation-v1-source-20261006-084535-b48bf285/public-result.zip)、[九类实际 QML 场景结果](results/formal-send-status-presentation-v1-host-20261006-084552-973b4819/public-result.zip)
- [来源与证据边界](docs/TRANSFER_RESULT_REPAIRS_V1.md)。五个新 ZIP 均只有 result.json＋README.txt，独立逐成员 SHA 读回匹配；原始日志及输入留私有目录。

## 2026年10月6日 8时24分 新发送界面启动、20秒退出与原厂恢复实机通过

新UI入口的58输入SOURCE通过，随后新CONTROL的唯一20秒笔端smoke整体PASS（HOST／remote／checker0）。原17字段记录ui_ready／original_ui_exited／owner_closed／guardian_exited／candidate_exited／credentials_removed／worker_fds_closed／stock_restored均true、resource_pending=false；五份私有日志、carrier后验、有限stock前后及58输入保持通过。原600＋60、800／810秒保护及原判据未放宽，19UI资源未重建或重下发。这是新正常路径的实际启动／退出，不追签旧UI FAIL，也不证明新增失败目录释放分支的实机覆盖。

文件中心服务对象本轮确已创建并关闭；其start_returned／server_complete／state_complete／close_complete有实际诊断。parent_deadline_wired=true而verified=false保持，表示没有触发或验证文件中心子任务deadline，不能笼统称文件中心未启动，也不能宣称该子任务验收。没有截图、物理屏幕／触摸或手机操作，本轮未自动搜索、接收或发送文件。

候选日志保留一条厂商数据库重复列提示，READY正常、未阻断本轮；没有据此定位或修改数据库，也不签全部界面细节无异常。

08:22:45退出后新原生只读PASS：两次观察一致、0连接／0活动广播实例，pending不存在未处理、观察器关闭和有限原厂保持；不是实际用网后的完整网络恢复。此前手机新就绪仍未回复，下一先核当前手机握手入口的实际依赖，再在新就绪和真实native READY后复测旧连接失败。目标active，真实双向／CONNECT／TLS／安全落盘和实际网络恢复仍待。

后续电脑源码依赖复核已完成：当前手机入口为独立receive-only的rx-freezer-v1图，不运行发送ReadonlyDataParent，不依赖旧state-v69/native的GO发送分支；不需要把本轮sender v7或新UI塞入手机接收入口。现有232输入SOURCE及未变源码保持的证据复用，不重跑。窗口前仍须Root核当时接收根／runtime／native／辅助资产／Received／pending及actor；没有据电脑源码认定这些设备路径当前存在或pin相同。待新手机就绪才做现时核对与真实READY窗口，详见[手机入口与边界](docs/PHONE_HANDOFF_CLASSIFICATION_V1.md)。

- [新UI58输入SOURCE](results/formal-send-preflight-ui-v1-source-20261006-082104-37e877ae/RESULTS.zip)
- [唯一20秒启动与退出实机结果](results/formal-send-preflight-ui-v1-ui-smoke-20261006-082146-9752ec39/RESULTS.zip)
- [08:22:45后置无线只读结果](results/receive-radio-baseline-device-20261006-082245-5921dd4d/public-result.zip)
- [详细来源与验证边界](docs/TRANSFER_RESULT_REPAIRS_V1.md)。已完成的新CONTROL不可重复执行；不是新的手机窗口。

## 2026年10月6日 8时18分 新发送运行图暂存通过，界面接装进行中

失败预检目录释放专项在08:06通过电脑检查：8项实际输入保持，一个方法、40个模型子例。正例中的11个目录FD关闭及EBADF检查、两目录关闭与幂等通过；38个反例保持拒绝。使用实际选定Owner方法，但Parent、目录和系统调用为明确模型；不是笔端资源关闭证明。原异常、unknown及总关闭／pending门保持，旧UI FAIL不追签。

新正式发送图在08:07通过126输入SOURCE，12个实际电脑产物逐字读回；接装fresh Parent，普通32角色、37文件／1,368,142 B，observer41／1,548,495 B及sender27复用。08:14独立ordinary入口55输入SOURCE通过；08:15唯一笔端暂存PASS，创建37文件／3目录，342个原FD全部关闭，载体读回和有限原厂前后核对通过、Wi-Fi仍连接。没有重新暂存sender、observer或native，也未启动Parent、Owner、界面或无线。

新界面Guardian仅1常量、Worker仅5常量的4项产物已唯一在电脑生成，完整字节／AST逆及全部定义字节、行号保持；沿用19项UI、SESSION、validator、ELF和QRC，不重新构建。新HOST仍在准备，尚未运行SOURCE或20秒笔端启动／退出。因此当前证据是普通图暂存，不是新界面或手机连接修复。共享空锁不重复初始化；目标active。手机新就绪／真实READY、旧连接FAIL复测、双向／TLS／安全落盘和实际网络恢复仍待。

- [目录释放专项电脑结果](results/send-failed-preflight-cleanup-v1-host-20261006-080619-7150b630/public-result.zip)
- [正式发送图126输入SOURCE](results/formal-send-preflight-native-graph-v1-source-20261006-080733-be7bf806/RESULTS.zip)
- [普通图SOURCE一键入口](HOST_MTA_FORMAL_SEND_COLDSTART_ORDINARY_V1_SOURCE_CHECK.cmd)，[55输入SOURCE结果](results/formal-send-coldstart-ordinary-v1-source-20261006-081438-b8f8ecc2/RESULTS.zip)
- [普通图唯一实际暂存结果，不重复执行已完成Stage](results/formal-send-coldstart-ordinary-v1-stage-20261006-081527-2d9ed7bd/RESULTS.zip)，[详细边界](docs/TRANSFER_RESULT_REPAIRS_V1.md)

## 2026年10月6日 7时50分 空共享锁初始化与新只读预检实机通过

07:24 固定 lock／pending 元数据的6输入SOURCE及唯一设备观察通过：四次lstat均稳定，锁为类型化ENOENT、pending不存在。原厂前后有限核对保持、Wi-Fi连接；没有创建或打开锁。原正常GO／CLIENT在后续业务阶段才创建共享锁，不能直接调用其reserve／acquire来补前置，因为还会创建pending／journal。

独立初始化入口V3的14输入SOURCE通过；07:47唯一设备初始化也通过。两轮各196进程、497 FD链接的快照相同，未见可识别旧项目actor或旧锁FD；只创建一次固定空锁，root:root／0600／nlink1／size0，非阻塞flock、文件及父目录fsync、保留条目后验均通过。1,573次原open的本次库存全部关闭，四目录及锁原FD均close并取得typed EBADF。HOST／remote0、stderr0，原厂文件与进程保持、Wi-Fi仍连接。新锁条目保留，不重复初始化，不创建传输记录或调用Parent／Owner／Stage／RF。闹钟字段不保证已消费一次性闹钟的失败清理仍有剩余计时；硬清理保证仍为false。

初始化后的唯一新只读Parent在07:48通过：原collect返回、child0、原wait／reap、两EOF、9 FD及timer闭合，resource_pending=false，有限原厂保持。之前固定锁open的ENOENT缺口已越过；未修改原业务／失败／关闭／期限门，也没有重新暂存已通过资产。07:48:53新原生只读观察PASS：0连接／0广播、pending不存在未处理、观察器关闭及有限原厂保持。上述通过不是业务准入、完整网络恢复，也不改签旧UI Owner11目录FD未显式关闭及整体FAIL。

两个初始化电脑失败保持：V1通用源码锚误计数而source_contract FAIL，5输入保留；V2按ASCII解析含中文的UTF-8 transport而unexpected FAIL，11输入保留；两轮均未调用设备。V3仅窄修完整锁校验锚与PC AST解码，实际TARGET／transport字节改动、EXCL、进程、时限、FD及36字段判据不变，六项旧源码／CMD私有保留。公开ZIP只有result.json＋README.txt，已独立逐成员SHA读回。

下一接入fresh Parent的完整正式发送图，并仅修失败冷启动时的目录释放：保留unknown、原异常与原总关闭／17字段PASS判据。该Owner候选和接装图正在开发，尚未测试或部署；当前正式发送界面仍绑定旧libc Parent。新手机就绪／真实READY、旧手机连接FAIL复测、真实双向／TLS／安全落盘和实际网络恢复仍待，目标active。本轮没有Owner／新界面／RF／手机或用户文件操作。

- [固定锁元数据结果](results/go-device-lock-v1-device-readonly-20261006-072435-c2aa54c3/RESULTS.zip)
- [初始化SOURCE一键入口](HOST_MTA_GO_DEVICE_LOCK_INIT_V3_SOURCE_CHECK.cmd)，[14输入SOURCE结果](results/go-device-lock-init-v3-source-20261006-074737-49e9e20a/RESULTS.zip)
- [仅缺失时空锁初始化入口，不要重复执行](INIT_MTA_GO_DEVICE_LOCK_V3.cmd)，[唯一实际初始化结果](results/go-device-lock-init-v3-initialize-20261006-074753-c4202278/RESULTS.zip)
- [初始化后只读Parent通过](results/go-observer-native-v3-parent-20261006-074817-1bd3d65d/RESULTS.zip)，[07:48:53后置无线只读结果](results/receive-radio-baseline-device-20261006-074853-8518f74c/public-result.zip)
- [V1电脑失败](results/go-device-lock-init-v1-source-20261006-073435-5133d225/RESULTS.zip)，[V2电脑失败](results/go-device-lock-init-v2-source-20261006-074112-caaeffe8/RESULTS.zip)，[详细验证边界](docs/TRANSFER_RESULT_REPAIRS_V1.md)

## 2026年10月6日 7时14分 新隔离依赖已暂存，冷启动锁文件前置缺口已定位

新隔离 native 的18输入SOURCE及唯一设备暂存PASS：两个原helper共113,296 B，创建2目录／2文件，14个原FD全部关闭。fresh observer的69输入SOURCE及唯一Stage也PASS：41文件／1,548,495 B，4资产仅改必要路径与实际pin、37资产原样，inline Parent另计，创建2目录、131FD全部关闭；原Leaf manifest38、Proc、业务、失败、关闭和期限门保持。两个Stage均逐pin读回、源保持、有限原厂前后核对通过，Wi-Fi仍连接，没有Owner／界面／RF／手机或用户文件动作，不重复已暂存资产。

随后唯一只读Parent仍按原判据FAIL（HOST0／remote1／checker1）。98 B私有诊断已从旧 `_anchors182→stat107` 推进到 Body.collect413→_open213→open109：FileNotFoundError／errno2，直接对应固定DEVICE_LOCK的只读open；原目录anchors已经越过。命名空间名称／行号投影不是函数/code身份认证。原代码先要求全局互斥锁存在，正常GO／CLIENT创建路径却在后续业务入口，因此存在冷启动前置顺序缺口；不能直接调用这些入口补锁，它们还会创建pending／journal。下一只做固定lock和pending双轮类型化元数据，再依据当前占用与原EXCL／dirfd合同补最小初始化，不跳锁保护或启动旧Runner。

本次Parent child已wait／reap、两EOF、9库存FD及timer闭合，pending=false不覆盖旧UI Owner11目录FD未显式关闭及原FAIL。07:14新的原生只读PASS：0连接／0广播、恢复记录不存在未处理、观察器关闭／有限原厂保持；不是完整网络恢复。真实双向／TLS／安全落盘和旧手机连接FAIL复测仍待，手机新就绪尚待回复，目标active。

电脑入口的两个新失败均保留：observer-v2准备阶段因计数字面是另一字段子串而写前拒绝，没有结果目录或ADB动作；native-v1的stage_contract因文案锚不符而SOURCE FAIL，14输入保留、没有设备动作。独立observer-v3与native-v2只修有限源码锚／入口身份，完整字节及AST逆校，原候选和旧FAIL不改签。新公开ZIP均只有result.json＋README.txt，已独立逐成员SHA读回；raw／输入留在私有目录。

- [native SOURCE一键入口](HOST_MTA_GO_READONLY_NATIVE_V2_SOURCE_CHECK.cmd)，[18输入SOURCE结果](results/go-readonly-native-v2-source-20261006-070910-83c87e72/RESULTS.zip)，[两helper实际暂存](results/go-readonly-native-v2-stage-20261006-071212-8a27f67a/RESULTS.zip)
- [observer SOURCE一键入口](HOST_MTA_GO_OBSERVER_NATIVE_V3_SOURCE_CHECK.cmd)，[69输入SOURCE结果](results/go-observer-native-v3-source-20261006-070512-1a3cd4e2/RESULTS.zip)，[41资产实际暂存](results/go-observer-native-v3-stage-20261006-071244-ace348a0/RESULTS.zip)
- [固定锁open失败及原Parent闭合结果](results/go-observer-native-v3-parent-20261006-071303-36c478e4/RESULTS.zip)，[07:14后置只读结果](results/receive-radio-baseline-device-20261006-071400-a8409ebe/public-result.zip)
- [原native-v1电脑FAIL](results/go-readonly-native-v1-source-20261006-070246-ec562965/RESULTS.zip)，[详细来源和验证边界](docs/TRANSFER_RESULT_REPAIRS_V1.md)

## 2026年10月6日 6时47分 两个固定依赖路径缺失正式确认

新固定元数据入口通过6输入电脑SOURCE，并完成唯一P011只读观察：两个固定路径各两次lstat，共4次；旧STATE_ROOT及其native路径均样本稳定、typed_enoent=true／prerequisite_status=missing。原HOST和remote均0、stderr0，原厂前后文件与进程保持、Wi-Fi均连接；没有打开／列举／创建目录，也未运行Stage／Parent／Owner／UI／RF。native结果可能同源于父目录缺失，不作为独立叶子缺失认证。两个公开ZIP只含result.json和README.txt，已独立解压SHA读回匹配。

电脑实际`out/native/mta-bluez-helper`为65,832 B／`179fd01f…`、`mta-network-helper`为47,464 B／`ef3b904e…`，匹配当前Body原pins，共113,296 B，不必重建二进制。下一限定新隔离native根两个0700目录＋两个原0500文件，不补造旧State库存，不运行历史ClosedService；fresh observer必须同时机械更新Body的STATE_ROOT、Packet两helper路径、Loader／Entry／Parent实际pin链，41角色为4变37原样，Parent另属inline。原只读Leaf manifest38、Proc、业务／期限／关闭／失败门保持，先电脑接装再最小笔端验证。该候选尚未生成／暂存／运行，不把本次metadata PASS签为修复。最后原生无线仍06:38的0连接／0广播观察，非完整恢复；旧Owner pending和手机连接FAIL仍保留，目标active。

- [固定路径SOURCE一键入口](HOST_MTA_GO_OBSERVER_STATE_ROOTS_V1_SOURCE_CHECK.cmd)，[6输入SOURCE结果](results/go-observer-state-roots-v1-source-20261006-064727-c8500843/RESULTS.zip)
- [双路径类型化缺失与有限原厂保持](results/go-observer-state-roots-v1-device-readonly-20261006-064745-cdf071f0/RESULTS.zip)
- [详细依赖来源与候选边界](docs/TRANSFER_RESULT_REPAIRS_V1.md)

## 2026年10月6日 6时38分 前置目录ENOENT已捕获，仍未进入互传握手

新独立observer诊断已实际生成、64输入SOURCE通过；41文件／1,548,449 B暂存PASS，创建2目录，131原FD全部关闭，完整pin读回及前后有限原厂保持。38资产原样、3资产只改必要ROOT／实际pin及Entry失败分支；额外Parent只机械绑定。原Proc、STATE_ROOT、helpers及成功／关闭／期限门不变，没有启动Owner／界面／RF或收发。

唯一原ReadonlyDataParent调用仍FAIL（HOST0／remote1／checker1），但已经取得98 B私有首因：FileNotFoundError／errno2，原caught与Entry.failure同对象，无链或TB截断。命名空间绑定的名称／原行号投影为Entry.main534→Entry.collect467→Body.collect412→Body._anchors182→stat107；不是原函数/code身份认证，TB未输出循环中的具体path。随后root只读ADB查询旧STATE_ROOT及其native目录，均报告不存在；该输出只在工具记录中、HOST0不代签远端退出码。两项缺失与前置ENOENT相符，下一做固定两路径的正式类型化元数据核对，并查原Stage和实际native来源，不直接猜蓝牙／协议／Proc故障或绕过目录门。

本次独立Parent的原wait／reap、两EOF、9FD关闭和定时器释放通过，stdout0／stderr98、resource_pending=false；这不覆盖此前UI的Owner11目录FD未显式关闭和整体FAIL。06:23／06:38前后新的原生只读均PASS：0连接／0广播、恢复记录不存在未处理、观察器关闭及有限原厂保持，非完整网络恢复。没有手机或用户文件动作，新手机就绪仍待，真实双向／TLS／安全落盘和恢复未验收，目标active。

首电脑生成V1因CRLF锚与实际LF不符而写前FAIL；独立V2又在catalog别名作为ROOT子串的逆校中写前FAIL，两原源保持、均未创建candidate。V3只给JSON别名加精确引号后实际生成通过。公开SOURCE／Stage／Parent的旧observer_bytes字段仍为1,442,508（初始化早于payload实际总量更新）；真实catalog、固定Stage表和载体行均核1,548,449，本次如实记字段缺陷，不改历史JSON／ZIP或重跑Parent。所有新公开ZIP仅result.json＋README.txt，独立解压SHA读回匹配；raw与来源私有。

- [独立SOURCE一键入口](HOST_MTA_GO_OBSERVER_DIAG_V1_SOURCE_CHECK.cmd)，[64输入SOURCE结果](results/go-observer-diag-v1-source-20261006-063706-b4823361/RESULTS.zip)
- [41资产实际暂存PASS](results/go-observer-diag-v1-stage-20261006-063724-fcb6586e/RESULTS.zip)
- [内部ENOENT已取得、原Parent仍FAIL](results/go-observer-diag-v1-parent-20261006-063731-930bd65f/RESULTS.zip)
- [06:38后置只读PASS](results/receive-radio-baseline-device-20261006-063812-f36cc927/public-result.zip)
- [详细来源、错误与字段边界](docs/TRANSFER_RESULT_REPAIRS_V1.md)

## 2026年10月6日 6时03分 子进程退出和资源缓存已取得，内部首因待捕获

独立after-return诊断的55输入SOURCE通过，唯一新CONTROL的20秒原smoke仍整体FAIL（HOST0／remote1／checker1）。诊断仅在原Worker返回及finally之后读取已有缓存，不调用新clock、进程观察、status或close；原17字段、成功判据及600＋60秒保护保持。私有载体stdout为10,017 B，SHA-256为`8a3d9a0815ce821e6655e272a2835b2833573d823d38a2646b5b942d826038e1`，不纳入公开ZIP。

实际缓存确认child退出1且wait／reap和两条EOF均绑定原对象，stdout／stderr均0字节；Parent原9个FD关闭且EBADF验证完整、unknown=false。Owner preflight已构造并结束，但原失败保留、unknown=true；两个原目录的11个FD均未调用显式close。文件选择器registry资源数为0，但缓存没有独立原anchor，不作为完整关闭凭据。不能将进程退出后的内核回收写成原对象关闭，也不能把Owner pending改成显示误报。

原ui_ready=false、original_ui_exited=false、owner_closed=false、resource_pending=true保持，没有新页面或截图。06:02／06:03前后新的原生只读均PASS：两次观察一致、0连接／0广播、恢复记录不存在且未处理、观察器关闭及有限原厂身份保持；这不覆盖Owner内部pending，不是完整网络恢复。

下一使用新独立observer根，仅在原Entry失败分支追加≤512 B、单次FD2尝试的私有错误类型／常量原因／精确调用位置，再以原ReadonlyDataParent单次collect和原finally关闭捕获内部首因。不启动整套Owner／界面或RF，不猜Proc flags、不改旧STATE_ROOT依赖、原非零退出及关闭门。手机新就绪问题仍待回复，本轮没有手机／文件动作；真实双向、TLS、安全落盘和实际恢复未验收，目标active。

- [after-return SOURCE一键入口](HOST_MTA_FORMAL_SEND_REPAIR_UI_PREFLIGHT_V1_SOURCE_CHECK.cmd)
- [55输入SOURCE公开ZIP](results/formal-send-repair-ui-preflight-v1-source-20261006-060152-6a46dd5e/RESULTS.zip)
- [缓存已取得、原整体FAIL的公开ZIP](results/formal-send-repair-ui-preflight-v1-ui-smoke-20261006-060240-25250ea8/RESULTS.zip)
- [06:03后置只读公开ZIP](results/receive-radio-baseline-device-20261006-060315-98e17be9/public-result.zip)
- [完整失败链与下一诊断边界](docs/TRANSFER_RESULT_REPAIRS_V1.md)

## 2026年10月6日 5时47分 发送资产暂存通过，界面预检子进程失败待定位

P011 重连后，05:27 原生只读基线通过：两次观察一致、0连接／0广播、恢复记录不存在且未处理、观察器关闭、有限原厂身份保持。普通图首次暂存05:29在写入前FAIL，创建文件／目录均0，4个原FD关闭；05:37独立元数据观察确认sender、observer和ordinary三个固定根均缺失，不能据此推断消失时间或原因。

补足入口首轮SOURCE-v1在电脑端因对固定RAW_LIMIT乘法表达式调用literal_eval而FAIL，9输入快照和原件保留，没有设备动作。独立V2仅将该比较改为固定源码表达式检查，其余Stage／限制／冲突拒绝／FD／期限和关闭门不变；72输入SOURCE通过。随后仅对缺失项目根分别暂存，未改权限、删除旧记录或处理用户目录：

| 实际暂存 | 文件／字节 | 读回和资源 | 状态 |
|---|---|---|---|
| 新界面资产 | 19／4,184,758 | 38次读回，74＋27 FD关闭 | 05:30 PASS，不重复下发 |
| sender前置资产 | 27／2,402,458 | 完整pin读回，91 FD关闭 | 05:45 PASS |
| observer前置资产 | 41／1,442,508 | 完整pin读回，131 FD关闭 | 05:45 PASS |
| 新ordinary运行图 | 37／1,353,776 | 两组前置核验、342 FD关闭 | 05:46 PASS |

暂存均未启动Owner、界面、RF或收发；原厂身份和文件前后保持，Wi-Fi仍连接。新界面载体的47输入SOURCE通过，但05:46唯一20秒smoke实机整体FAIL：HOST0／remote1／checker1，ui_ready=false、original_ui_exited=false，没有新页面／截图／触摸证据。原私有诊断将错误定位到ReadonlyDataParent._drain_and_wait第716行；固定源码该行仅在observer child返回非零后抛出parent_child_failed。具体退出整数和原stderr尚未投影，不能直接签Proc动态位或协议首因。

原结果owner_closed=false、resource_pending=true必须保留。代码审查显示collect异常会跳过preflight ticket的unknown=False赋值，这是目录关闭前服务门足以拒绝的条件；实际第一个短路条件尚未投影。已构造的目录没有显式close回执，不能把对象pending当纯显示误报或全部资源闭合。Worker FD与guardian关闭，原厂UI未退出、文件和前后身份保持。05:47新的原生只读再次PASS：0连接／0广播、恢复记录不存在且未处理、观察器关闭、有限原厂保持；该外部观察不覆盖sender内部pending，也不是完整网络恢复。

下一补原返回后已有child退出／stderr和ticket／FD缓存观察，再针对实测首因窄修，不盲重同一失败CONTROL。发送载体尚未附加WATCH或截图。接收页既有导航／截图／退出通过证据保持；新手机就绪问题仍待回复，没有本轮RF、手机或文件传输，旧连接FAIL、真实双向／TLS／安全落盘及实际恢复仍待，目标active。

- [缺失根实际只读结果](results/formal-send-repair-prerequisite-roots-v1-device-readonly-20261006-053707-e0c18572/RESULTS.zip)
- [补足入口72输入SOURCE通过](results/formal-send-repair-prerequisite-assets-v2-source-20261006-054455-e5e5b406/RESULTS.zip)，[sender实际暂存](results/formal-send-repair-prerequisite-assets-v2-sender-20261006-054527-8b3f10be/RESULTS.zip)，[observer实际暂存](results/formal-send-repair-prerequisite-assets-v2-observer-20261006-054554-cb284a1c/RESULTS.zip)
- [ordinary实际暂存PASS](results/formal-send-repair-ordinary-v1-stage-20261006-054616-a4750a6b/RESULTS.zip)，[界面资产暂存PASS](results/formal-send-repair-ui-assets-v1-stage-20261006-053002-8e1e21e5/RESULTS.zip)
- [界面预检原始FAIL](results/formal-send-repair-ui-v1-ui-smoke-20261006-054638-735d05a1/RESULTS.zip)，[05:47后置只读PASS](results/receive-radio-baseline-device-20261006-054718-1725bf05/public-result.zip)
- [详细入口、失败和验证边界](docs/TRANSFER_RESULT_REPAIRS_V1.md)

## 2026年10月6日 5时19分 发送修正已接入独立电脑候选包

发送取消提示和文件选择页旧响应修正已接入新普通运行图、界面包及Worker，未部署到学习笔。普通图32角色／Startup3／helper3，实际暂存表37文件、1,353,776 B；新界面19文件、4,184,758 B，18个payload中14个原样、4个必要更新，另有SOURCE清单。取消service与此前33场景通过候选字节一致，picker与此前实际Qt9场景通过的6602 B候选一致，没有重跑这两个专项。Worker只更新8项根／SESSION／实际pin绑定，完整字节逆回及其余业务定义保持。

05:19组合SOURCE-v2通过109个实际输入，输入读取／私有快照完整、源未变、实际Boot→Owner→Outer和Stage表闭合、UI24产物及validator3／guardian2常量逆回、Worker实际绑定均核对通过。新旧业务方法执行数均0，没有暂存、目标业务、ADB、RF、手机、用户文件或原厂操作。首轮SOURCE-v1因Owner方法内必要的版本目录被误判为业务变化而FAIL，原结果及校验器保留；独立v2只在已先完成全字节正逆的Owner比较中归一这项路径，不改变候选或设备安全门。

下一软件工作是把新普通图和UI包接入独立暂存／笔端载体及WATCH根与总pin绑定；旧v5／UI-v7的HOST入口不能直接启动这个新包。发送图仍复用旧Proc角色，接收端单动态位修正不自动等于发送端已修。接收页04:48观察与退出PASS保持，最后笔端只读仍为04:50，本轮未刷新，非当前状态或完整网络恢复证明。新手机就绪问题尚待回复，真实native READY后才通知点击；旧连接失败、真实双向／TLS、安全落盘及实际恢复仍待，目标active、继续边开发边实测。

- [新包组合SOURCE一键入口（电脑端，不操作设备）](HOST_MTA_FORMAL_SEND_REPAIR_PACKAGE_V2_SOURCE_CHECK.cmd)
- [109输入SOURCE-v2通过的公开ZIP](results/formal-send-repair-package-v2-source-20261006-051904-17c59e48/public-result.zip)
- [SOURCE-v1误拒的原始FAIL](results/formal-send-repair-package-v1-source-20261006-051546-dc36121b/public-result.zip)
- [修复、实际包与待测边界](docs/TRANSFER_RESULT_REPAIRS_V1.md)

## 2026年10月6日 4时50分 当前页面截图和退出通过 手机握手待新就绪

独立capture-v2 SOURCE通过288个项目输入和1个外部输入，实际派生Worker只改变CONTROL_NAME完整常量行，业务定义及行号不变；新控制目录、HOST日志拉取与WATCH根一致，原75图／GUI20／FC9原样复用。上机前只读确认新目录不存在，旧导航目录及日志保持。04:48唯一20秒smoke实机整体PASS，HOST／remote／checker均0，自然46字段完整、READY1、WATCH读18,732 B并确认候选PID／start、FD关闭；原只读DRM取得1张480×800扫描输出图。已查看原图，候选接收页显示“准备就绪／可发现已关闭”，按钮及文字没有明显重叠；未做像素编辑，未取得物理屏幕或触摸验收。本轮没有QtTest导航、取消点击、RF或手机／文件动作，不重签此前导航回执。

20秒结束后Owner／FileCenter／音频／guardian／凭据／FD关闭、pending=false、原厂前后文件及进程核对通过。04:50新的后置只读PASS：两次观察相同、0连接／0广播、pending不存在未处理、observer关闭和有限原厂身份保持，非完整网络恢复。此前导航整体截图层FAIL仍保留；capture-v1仅SOURCE通过，上机前因复用旧独占目录被停止，没有设备执行，未删除或归档任何旧目录。

新手机握手入口已通过232输入SOURCE，载体2,015,010 B／最长行137 B，绑定当前208来源／8机械＋1业务／75角色4191766 B和普通新Runner；原phone26305／trace14820、真实READY后120秒与点击后15秒观察及cancel、strict TRIAL／关闭门保持。下一需新的小米就绪和当时基线，真实native READY后才通知点击，不接收或发送文件。旧“连接失败”、发送接装、真实双向／TLS、安全落盘及实际恢复仍待，目标active、边开发边实测；本次只是阶段通过，不是完整互传完成。

- [独占截图SOURCE](results/receive-proc-freezer-v2-capture-source-20261006-044748-35fecec6/public-result.zip)
- [页面观察与自动退出实际PASS](results/receive-proc-freezer-v2-capture-capture-only-20261006-044837-ea541f55/public-result.zip)
- [04:50后置只读PASS](results/receive-radio-baseline-device-20261006-045002-484da0a4/public-result.zip)
- [新手机握手入口SOURCE](results/phone-handoff-proc-freezer-v1-source-20261006-044233-eb04179d/public-result.zip)
- [手机操作条件和入口](docs/PHONE_HANDOFF_CLASSIFICATION_V1.md)
- [历史失败及精确修正边界](docs/TRANSFER_RESULT_REPAIRS_V1.md)

## 2026年10月6日 4时31分 导航通过但截图观察器目录错位

新Proc图的无RF导航SOURCE通过286个项目输入和1个外部输入，载体2,020,196 B／最长行668 B，GUI20未重建或重新暂存。04:26实机记录实际READY、取消确认、文件页及Received列表稳定，导航QtTest回执PASS；51字段component complete=true、remote／HOST均0，Owner／FileCenter／凭据／guardian／FD闭合、pending=false，原厂前后文件与进程核对通过。原整体checker仍为1，FAIL保留，不将组件通过替代整体通过。

失败位于截图前的WATCH：它读取旧durable-ui日志目录，而实际Worker已写入新freezer控制目录。同一SESSION和候选exe没有变化；151 B原始输出中read_bytes=0、watch_fd_closed=false说明日志未打开，candidate_live=false是默认值，未调用进程查找。DRM捕获因此没有执行，不是已证实页面或进程异常。下一独立capture-only入口只同步WATCH根并选择原Worker的20秒smoke模式，保原身份、权限、期限、关闭及截图判据，仅补视觉证据，不重放已过导航。

04:31新的后置只读PASS：两次原生观察相同、0连接／0广播、pending不存在未处理、observer关闭和有限原厂身份保持，非完整网络恢复。本轮无手机窗口或文件传输。手机入口正在纯机械接新图；旧连接失败、发送接装、真实双向／TLS、安全落盘和实际恢复仍待，目标active、继续边开发边实测。独立HOST报告v2已完成默认SOURCE检查，39输入、methods0／child未调用；将未来失败报告的配置事实单独命名，没有重跑已过63子例。

- [新导航SOURCE](results/receive-proc-freezer-v1-navigation-source-20261006-042359-2e10f2db/public-result.zip)
- [导航回执通过但截图层失败的实际结果](results/receive-proc-freezer-v1-navigation-navigation-test-20261006-042644-ebabfd03/public-result.zip)
- [04:31后置只读PASS](results/receive-radio-baseline-device-20261006-043143-650cc606/public-result.zip)
- [修复边界和当前入口](docs/TRANSFER_RESULT_REPAIRS_V1.md)

## 2026年10月6日 4时18分 单动态位修正已通过笔端启动和退出

Proc独立候选只在stable_key的同一行排除PF_FREEZER_SKIP（0x40000000），不修改原始flags和raw。其它31位、PID／启动时间／名称／父进程、线程／目录、boot／exe／命令、PF_KTHREAD、期限与资源门保持。一个实际ProcReader＋Store／ResourceBudget的HOST方法通过63个子例，40个输入与私有快照未变；不是设备或手机用例。

新独立根p011-mta-rx-freezer-v1已接装：75角色中7项为该业务变化及必要的根／pin更新，其余68角色和GUI20／FC9／原生无线组件原样复用。216输入SOURCE通过，包体4,191,766 B，仍在原4 MiB内；载体1,996,819 B／最长行122 B，原时间和输出上限不变。04:16唯一无RF笔端启动／退出PASS，实际创建74文件／4目录，Boot／Owner、Startup基线、3个ProcReader和2个STATUS通过；2349登记FD全部关闭，HOST／remote／checker均0、pending=false，原关闭判据通过。本次没有运行到UI或同锁导航helper，接收Trial明确not_requested／claim0，不把启动成功写成接收准入。

04:18退出后新的只读PASS：两次原生观察相同、0连接／0广播、pending不存在未处理、观察器闭合、有限原厂身份保持。单次启动通过不代签稳定性能、全部旧FAIL同因、完整网络恢复或旧手机连接失败已修。下一把这份实际新图接入独立无RF导航载体，复用已暂存GUI；手机窗口仍须新的手机就绪及本轮真实READY。发送接装、完整双向／TLS／安全落盘及实际恢复待，目标active，继续边开发边实测。

- [单方法63子例HOST结果](results/receive-proc-freezer-v1-host-20261006-041542-fefb6c9a/public-result.zip)
- [新图216输入SOURCE](results/receive-proc-freezer-v1-startup-source-20261006-041301-c429f0f7/public-result.zip)
- [新图笔端启动和退出PASS](results/receive-proc-freezer-v1-startup-device-20261006-041602-39b7c9d6/public-result.zip)
- [04:18退出后只读PASS](results/receive-radio-baseline-device-20261006-041821-c389ddcf/public-result.zip)
- [详细边界和一键入口](docs/TRANSFER_RESULT_REPAIRS_V1.md)

## 2026年10月6日 3时52分 已定位本轮进程基线误拒的单一动态位

新独立被动诊断只在原Worker返回并完成关闭后读取既有缓存，不增加进程读取、clock、guard或无线动作；母Worker只内存同步独占CONTROL常量，全部业务定义／行号、原51字段、期限／关闭／PASS和GUI20／runtime75保持。03:48唯一SOURCE通过272项目输入＋1外部输入，载体2,020,180 B／最长行668 B，完整Worker／carrier／main byte与AST正逆通过。

03:49唯一新CONTROL无RF实机仍按原判据FAIL，但已取得原ProcReadError的具体条件：首值对末值与线程leader的pid／start／comm／ppid全相同，flags两组XOR均为1,073,741,824（0x40000000），末线程数允许。原目录终检因OR短路未发生，诊断如实为None；不是目录保持通过，也不是PID复用导致这一次拒绝。原准备边界9.364001秒、65文件均关闭／61线程、pending=false。没有进入Trial／FileCenter／凭据／界面／导航或新同锁helper，原厂UI未退出；HOST0／remote1／checker1，原FAIL不改判。

精确Linux v4.14.174上游sched.h将该位定义为PF_FREEZER_SKIP，freezer.h在调度包装中设置／清除，proc/array.c直接导出task->flags。结合上述笔端缓存，这解释本轮原stable_key将瞬时状态当身份不变量的误拒；厂商完整内核源码未取得，不声称所有历史FAIL都同因。下一仅制作独立候选，在stable_key掩去这一位，其余flags、pid／start／comm／ppid、原raw、PF_KTHREAD、线程／exe／boot／目录／期限与资源门保持，补受影响专项并机械接装，不关闭进程检查。

03:52退出后新的笔端只读PASS：两次原生观察相同、0连接／0广播、pending不存在未处理、observer关闭、有限原厂身份保持，非完整网络恢复。此前空CLIENT根补足实机PASS和同锁观察HOST专项PASS保持，不重创建或旧测试；同锁修复仍未实际运行到。没有新手机／用户文件／RF或原厂系统改写；旧手机连接FAIL、发送接装、真实双向／TLS／安全落盘及实际恢复仍待，目标active、边开发边实测。

- [本轮被动诊断SOURCE](results/receive-proc-identity-diff-v1-source-20261006-034817-efc6ef19/public-result.zip)
- [实际差异已取得，原整轮FAIL](results/receive-proc-identity-diff-v1-navigation-test-20261006-034912-4522e1c4/public-result.zip)
- [03:52退出后只读PASS](results/receive-radio-baseline-device-20261006-035227-98ad68ef/public-result.zip)
- [实现边界、一键入口及上游依据](docs/TRANSFER_RESULT_REPAIRS_V1.md)

## 2026年10月6日 3时31分 空工作根实机补齐，进程基线仍待定位

P011 重连后已按明确目标重新核对。导航拒绝记录的实际Worker行号1557→1560绑定已修，265＋1输入SOURCE通过；随后03:06唯一无RF实机在原Startup基线提前FAIL，内部为pid_identity_changed／pid_stat，未到页面或导航，不能签前轮导航首因。

新的同锁观察候选保留原State→Trial锁顺序及两个原predicate，只防止两次观察之间插入取消；270＋1输入SOURCE和一个真实HOST线程／RLock／Event专项通过。03:18新CONTROL实机仍在同一原进程基线拒绝，准备原边界合计8.511537秒，65文件均关闭、pending=false；尚未执行新锁helper、Trial、FileCenter、凭据、UI或截图。HOST并发修复通过不是P011导航已修好，不盲重同一失败路径。

CLIENT根缺失作为独立环境问题处理：新增只补固定空目录的显式入口。第一次实机在创建前因未识别厂商父shell路径而FAIL，没有mkdir；只读核实/bin/bash.bash后仅加入这一个确切路径，并保留原失败。03:31修补后10输入SOURCE及唯一实机PASS，实际创建/var/volatile/tmp/p011-mta-client-rfinit（root:root、0700、空目录），别名／读回／两次不存在观察／旧项目进程缺席／pending不存在均核对通过。四次原生只读无线观察前后相同、0连接／0广播；原厂前后身份保持、观察器与资源闭合。没有RF、手机、用户文件或原厂系统改写；目录补齐不等于Trial准入、接收READY或完整网络恢复，不再重复创建入口。

下一只读投影原Proc拒绝时已保留的局部身份字段，区分PID／start／comm／flags／ppid、线程数及已有目录元数据条件，不新增进程读取、时钟或放宽门。复用未变GUI20／75和旧通过证据。旧手机连接FAIL未复测；新手机窗口仍须新的人工就绪、当时基线及实际native READY。发送接装、真实双向、安全落盘、TLS与实际恢复仍待，目标active，继续边开发边实测。

- [完整改动、失败与待测边界](docs/TRANSFER_RESULT_REPAIRS_V1.md)
- [同锁观察HOST专项PASS](results/receive-navigation-atomic-v1-host-20261006-031741-95a254ec/public-result.zip)
- [同锁候选的笔端基线FAIL](results/receive-navigation-atomic-v1-navigation-test-20261006-031833-bfd00e3b/public-result.zip)
- [当前空根补足SOURCE](results/prepare-empty-client-root-v1-source-20261006-033132-9d35e869/public-result.zip)
- [空根补足实际PASS及最新有限基线](results/prepare-empty-client-root-v1-prepare-20261006-033147-81f09253/public-result.zip)

## 2026年10月6日 2时47分 已取得准备工作量，导航仍被拒绝

P011 重连后已完成只读核对、GUI20 暂存及新窗口核心实机启动／关闭；核心 PASS 不代签界面或手机互通。02:07 新界面首次实机准备 11.044560 秒超原 10 秒、页面前 FAIL，原件保留。新增的独立工作量观察不改准备业务、时钟、读取、关闭、75图或GUI，只在原Worker返回后统计保留数据；261输入＋1外部输入SOURCE通过。

02:43 新CONTROL唯一无RF实机取得工作量：private35为35行／1,292,691 B，私有WPA为1行／1,351,192 B，proc comm为195次／2,236 B，profile其他为10行／2,179,325 B，均有raw；进程发现197行、其中3行非root。原边界合计9.498805秒，这次准备通过，不是A/B、稳定性能或旧超时根因已解。

随后在Worker首循环的 navigation_receive_activity 处拒绝，HOST0／remote1／checker1，整轮仍FAIL。Startup／FileCenter构造通过，候选日志有SCENE_ENTERED与FORMAL_UI_READY，但原Worker在消费日志之前失败，ui_ready=false、没有导航回执或截图；不能说候选页面从未运行。初始Trial不可用原因为client_root_missing，claim0；尚未证明这就是导航拒绝或旧手机FAIL的首因。原资源关闭、guardian恢复、凭据移除及有限原厂核对通过，pending=false。02:47 后置新只读PASS：0连接／0广播、pending不存在未处理、两次观察相同、有限原厂保持，非完整网络恢复。

手机入口的三份HOST收据读取异常保护已通过六个有限故障情形；02:29 fixture结构FAIL保留，Root仅修带finally的try选择，完整AST逆约束仍在。02:40 修补后217输入SOURCE通过，新旧协议载体长度／SHA完全一致。尚无新手机窗口，旧“点击了，连接失败”未复测；叠加诊断写入故障不在已测范围。下一补既有REFUSAL的Worker1557→实际1560绑定，取原缓存条件并核取消与空闲两次观察间的竞态；CLIENT资产缺失作为接收能力的独立问题，不作本地导航绕过。按实际工作量选优化，不盲重失败CONTROL。发送接装、真实双向、安全落盘与实际恢复仍待；目标active，边开发边实测。

- [完整改动、已测与待测边界](docs/TRANSFER_RESULT_REPAIRS_V1.md)
- [新界面准备超时 FAIL](results/receive-window-clock-ui-v1-navigation-test-20261006-020735-1555eea2/public-result.zip)
- [实际工作量与导航FAIL](results/receive-startup-workload-v1-navigation-test-20261006-024346-c06fdc98/public-result.zip)
- [最新笔端只读 PASS](results/receive-radio-baseline-device-20261006-024714-e111b4e4/public-result.zip)
- [修补后当前手机入口 SOURCE](results/phone-handoff-durable-window-v1-source-20261006-024046-5bdf977d/public-result.zip)
- [六个HOST读取故障情形PASS](results/phone-handoff-durable-window-receipt-fault-v1-host-20261006-024019-2b9141f6/public-result.zip)

## 2026年10月6日 1时57分 修正窗口后的核心实机启动通过

新窗口谓词的96项HOST隔离检查及204输入载体SOURCE通过。仅改变独立Runner的窗口关系校验，不改原期限／身份／关闭门，也不重封75或GUI20。唯一无RF实机PASS：75文件／6目录暂存，Boot／Owner／Startup、STATUS2／ProcReader3通过，2313登记FD及Owner／Startup资源闭合，checker／HOST／remote均0、stderr空、pending=false。未运行UI、广播、Wi-Fi或手机／文件传输。

本次实际retained的加减法与身份关系均True，所以本次启动通过不证明01:36旧FAIL的具体浮点值；旧FAIL与raw保留。退出后01:57新只读PASS，两次观察相同、0连接／0广播、pending不存在未处理、有限原厂身份保持；非完整网络恢复。

下一接同一修正的独立UI Runner／Worker与新CONTROL，复用已暂存GUI20／75，仅测受影响导航与退出。手机旧“点击了，连接失败”未复测，发送接装及真实双向／TLS／实际恢复仍待；目标active，继续边开发边实测。

- [完整说明及一键入口](docs/TRANSFER_RESULT_REPAIRS_V1.md)
- [窗口覆盖SOURCE](results/receive-window-clock-v1-startup-source-20261006-015512-eac62db0/public-result.zip)
- [核心实际启动PASS](results/receive-window-clock-v1-startup-device-20261006-015536-f1f746a2/public-result.zip)
- [退出后新只读PASS](results/receive-radio-baseline-device-20261006-015725-dce1de95/public-result.zip)

## 2026年10月6日 1时38分 接装与界面暂存通过 核心启动前拒绝

目标active，继续边开发边实测。完整接收核心、实际GUI20与新worker已完成接装；新UI SOURCE通过241实际输入，载体1,998,256 B，runtime75和GUI20仍各自在原4 MiB限制内。20文件／3目录已在学习笔独立候选目录暂存、40次读回通过；原载体77个与validator28个FD分别闭合，有限原厂及后置carrier核对通过。没有运行新UI，也没有RF或手机操作。

新增无RF核心入口SOURCE通过195输入，原载体与此前SOURCE逐字节相同，仅将接收请求True改False，保原60+60／Startup10／alarm240／HOST250及关闭判据。首次实机整体FAIL：HOST0／remote1，platform和payload验证通过，但第一条snapshot→check→payload拒绝，尚无FD、文件创建、Boot／Owner／Trial。严格Trial=None解析仍拒绝，原component与raw完整保留；不是无线、设备文件损坏或手机握手结论，不继续叠加界面。

用户重连后01:29只读PASS，失败后01:38新只读仍PASS：实际两次BlueZ／MGMT一致、0连接／0广播、固定pending不存在且未处理，observer关闭与有限原厂前后身份保持；不能代签完整用网恢复。最初01:27未发现目标的FAIL也保留。旧手机“点击了，连接失败”未复测。

窗口源码的精确减法等式存在可推导的浮点误拒；本次实际retained时刻未采集，不把数学反例当实测首因。新的独立窗口候选已机械生成，只改窗口谓词并保留身份、实际截止、严格正间隔与期限，不重封75图或GUI、不重跑旧业务。下一唯一受影响HOST、载体overlay与有限实机；发送status／picker和真实双向／TLS／网络恢复仍待。

- [本轮改动和分层结果](docs/TRANSFER_RESULT_REPAIRS_V1.md)
- [新UI SOURCE](results/formal-receive-durable-ui-v1-source-20261006-012004-304115e0/public-result.zip)
- [实际GUI20暂存](results/formal-receive-durable-ui-v1-stage-20261006-012949-ac67629c/public-result.zip)
- [无RF核心SOURCE](results/receive-durable-state-v1-startup-source-20261006-013553-bab4a21b/public-result.zip)
- [首次核心启动FAIL](results/receive-durable-state-v1-startup-device-20261006-013639-d76cefcb/public-result.zip)
- [失败后的新只读结果](results/receive-radio-baseline-device-20261006-013803-941d6bf3/public-result.zip)

## 2026年10月6日 完整接收候选通过电脑封装检查

目标active，继续边开发边实测。本轮将已通过专项的接收保存失败业务候选接入独立完整协议包：ROOT唯一SOURCE通过193个实际输入、164项平铺来源、五业务差分、九机械正逆和双manifest；runtime75实际4,191,752 B，原4 MiB限制余2,552 B，ordinary35／private35和FC9独立113,690 B保持。私有载体1,996,786 B／最长行122 B，Runner与全部75编码角色逐字节解压读回。仅生成并检查SOURCE，没有执行运行图或重跑旧测试。

新GUI20独立SOURCE、显式PC build及实际validator绑定核对通过，20文件／3目录总4,192,479 B，原4 MiB余1,825 B；已用实际产物封pin，原validator方法、导航、键盘接入和其他界面源保持。尚未把新核心与GUI接入同一UI worker，也未部署。发送status／picker仍是独立已测业务候选。独审发现的HOST失败留证／封存发布缺口已修正，唯一新增IO故障方法通过，child／HOST exit0、七份输入及公开ZIP独立读回一致；固定业务条件和身份不变。未重跑SOURCE／BUILD／binding或旧业务，保留各次原快照。

本轮没有ADB、RF、手机、原厂或用户文件操作。最后设备记录仍为10月5日19:13，不代签当前状态；旧“点击了，连接失败”未复测，不能称连接修好。下一接装worker、核当前只读设备基线并做受影响路径实测；新手机就绪与真实READY后才开新握手窗口。完整双向互通、TLS和实际网络恢复仍待。

- [改动范围和四项PC结果及一键入口](docs/TRANSFER_RESULT_REPAIRS_V1.md)
- [完整协议SOURCE结果](results/receive-durable-state-v1-source-20261006-004047-6ec35890/public-result.zip)
- [实际GUI构建结果](results/receive-durable-gui-v1-build-20261006-003238-812df71b/public-result.zip)
- [HOST故障留证结果](results/host-artifact-seal-v1-fault-20261006-010102-1623f13b/public-result.zip)

## 2026年10月6日 0时12分 保存失败状态与文件选择候选通过电脑验证

目标 active，继续边开发边实测。本轮补齐保存失败的上层业务候选，并完成四项针对性 HOST 单方法检查：严格 codec／Bridge、Executor／Parent 30域、真实 QML 接收提示、真实 QML 文件选择旧响应9场景。每项 child／HOST exit0、无超时，源及私有输入保持；公开 ZIP 与私有输入均经 ROOT 独立读回。旧方法和此前未变设备检查没有重跑。首次两项 QML 的 WSL 缺 PyQt5 FAIL 原流保留，改用既有 Windows Qt 后通过，没有安装依赖或改动业务 QML。

保存后取消仍为 saved_failed，ACK 严格 False，不报传输成功。专用结果诊断只尝试一次，在原 cap／FIFO／PIPE_BUF／完整先前帧内做最多一次50毫秒轮询；诊断失败不覆盖原接收异常。实际 Linux 目录／ZIP／fsync／持有管道和实际接收异常／codec／Parent 收帧已测，原生准入、Owner组合、网络及 Parent票据明确为夹具。若 Owner清理新异常替代原Storage异常，当前严格来源规则保守拒绝投递；该分支未覆盖。Parent.finish、原普通取消、关闭恢复与页面动作门保持，不把 local保存当网络恢复。

接收页严格展示“文件已保存，但传输取消/失败”，pending时仍显示恢复待核验；文件选择页增加请求代次和stage／mode核对，已复现原旧响应覆盖反例并验证返回／完成／reset隔离。HOST QML无可见窗口、不签渲染或触摸。完整 actual75／GUI20／发送部署包机械绑定正在准备，尚未接入学习笔；业务候选中的旧identity pin不能直接部署。

本轮没有ADB／RF／原厂／手机或用户文件操作；最后设备只读记录仍是10月5日19:13。新手机握手入口仍未上机，原“点击了，连接失败”未复测；完整双向互通、TLS和实际网络恢复未完成。这些状态修复不是手机连接FAIL的根因结论。

- [改动、边界、一键入口及四项结果包](docs/TRANSFER_RESULT_REPAIRS_V1.md)
- [Executor 与 Parent HOST ZIP](results/receive-durable-executor-v1-host-20261006-000626-e42bf9e8/public-result.zip)
- [codec 与 Bridge HOST ZIP](results/receive-durable-control-v1-host-20261005-235922-0c2da941/public-result.zip)
- [接收页 HOST ZIP](results/receive-durable-ui-v1-host-20261006-000546-a936dc15/public-result.zip)
- [文件选择页 HOST ZIP](results/receive-durable-picker-v1-host-20261006-000545-54ec793c/public-result.zip)

## 2026年10月5日 23时39分 两项取消与保存结果候选通过电脑检查

目标 active，继续边开发边实测。本轮没有 ADB、无线、原厂或手机操作；新握手入口仍未上机，旧“点击了，连接失败”未复测，19:13 只读记录没有重采样。两项结果边界缺陷与手机握手失败分别定位，不签手机问题已修复。

接收侧已经用真实 Linux 目录／ZIP 复现：结果完成 fsync 与发布后晚取消抛原异常，文件保留却原上层没有保存结果。新 receive-durable-result-v1 仅补 Storage/Transport 的独立保存事实，保留原异常与关闭判据、ACK=False；只采纳本次原 receiver／binding 的新发布，不采纳旧结果或被替换 receiver。ROOT 唯一新 HOST 方法 11 域通过，旧方法未重跑；实际存储 syscall 与 Transport 的假网络／确认／生命周期边界分列。关闭拒绝是夹具，绑定后置失败及关闭拒绝没有跨层 Transport 证据。Executor／IPC／Parent／桥／UI 尚未接入，实际运行图不改，不能称笔端页面已修好。

发送侧新 formal-send-cancel-status-v1 补实际 status 的 closed/sending/cancelled 投影，仅当原聚合 pending=False 时改为“已取消发送；未报告传输成功”。pending=True 保原恢复告警、已发字节和原门。ROOT 唯一新 HOST 方法 33 依赖夹具通过：真实原／新 status AST 的其他输出与调用顺序保持；不是完整 State／Session／UI 或手机测试。候选未接部署，旧 manifest 与源码保持。

原文件和历史失败不改写；一键 HOST 入口、私有 raw/输入和两项脱敏 ZIP 已保存。下一接装严格保存失败 IPC 与恢复中页面展示，再独立接装发送状态图；不把保存事实改为正常完成，也不为本轮放宽 F exit／Parent pending。发送文件选择旧异步响应覆盖新列表另已定位，尚未修复。完整双向互通及实际恢复仍待。

- [改动、证据与接装边界](docs/TRANSFER_RESULT_REPAIRS_V1.md)
- [接收 HOST ZIP](results/receive-durable-result-v1-host-20261005-233425-d235e9ce/public-result.zip)：SHA-256 `6ea7b00805c6c121c579aa54777918a77142ca2f2180e830670af3ca2f8044c6`。
- [发送状态 HOST ZIP](results/formal-send-cancel-status-v1-host-20261005-233600-531436b8/public-result.zip)：SHA-256 `63b6cceeb23a199c633dd377abf480705256886feee53d43a6df0b029ae1e4b8`。

## 2026年10月5日 23时05分 手机握手入口已接入新核心，实机复测仍待

目标 active，继续边开发边实测。本轮完成了影响下一次手机诊断的接装：旧手机入口仍绑定 compat-v2 的 Factory，与下午通过笔端启动和导航检查的新核心不同。现在新增独立手机握手入口，整体选择已验证的 classification 协议图；不单独替换 Factory，也不改写旧入口或旧失败记录。**新入口仅取得 SOURCE 通过，尚未在 P011 上执行，更没有新的手机连接结果。**

ROOT 唯一电脑端检查通过：186 个实际输入，89 个来源 pin 和七源正逆闭合，加上未改手机观察器的原增量证明；75 角色共 4172818 B，目标程序 2009162 B、最长行 122 B，在原 4 MiB／2 MiB 限制内。输入保持和私有源码 ZIP 逐条读回通过，公开 ZIP 仅含 result.json 与 README。新入口源码不再选旧 compat-v2 图，但原手机观察器、trace、严格解析器和 PASS 判据保持；没有重跑未变专项、core、GUI 或旧手机窗口。

原时间和动作范围不变：实际发现就绪后给手机一次 120 秒操作机会，peer 后最多观察 15 秒，随后原取消与关闭；Startup 10／Publication 120／Owner 600+60 及原硬超时保持。无独立预置步骤，显式设备模式仍保留原 `preflight/stage/load_owner`，不删除或绕过它。只能发现和取消，不自动接受、发送、打开文件或接管原厂界面；Parent／Factory 阶段变化也不能替代 CONNECT、TLS、文件校验和完整恢复证据。

本轮没有 ADB、无线或原厂操作。最新设备只读记录仍为 19:13 那次，不把它冒充本轮新基线。下一轮收到新的手机就绪确认后，先采集当前只读基线，再用新入口和实际 READY 复测握手；旧“点击了，连接失败”仍为未复测的 FAIL。双向互通、安全收发和实际网络恢复仍未完成。

- [操作范围与一键入口](docs/PHONE_HANDOFF_CLASSIFICATION_V1.md)
- [本轮 SOURCE 公开结果 ZIP](results/receive-handoff-classification-v1-source-20261005-230413-72ba5c75/public-result.zip)，SHA-256 `d34f0fe82670e147fb5d7a4473a24b2bf2381cfefadc67e7d4ff66287ddb4a51`。

## 2026年10月5日 19时23分 笔端导航已取得严格回执，手机连接仍待复测

目标 active，继续边开发边实测。手机最后一次“点击了，连接失败”未再次测试，本轮没有打开手机互传窗口或广播／扫描／配网／配对／用户文件收发，也没有改写原厂程序、启动项、系统分区或 NV。不能标为互传已修复或仅剩验收。

15:08 新分类协议图的唯一 core 实机预置与启动关闭 **PASS**：74文件／4目录、真实75角色／4172818 B在原4MiB内，Boot／Owner／Startup／STATUS2／ProcReader3通过，2315/2315登记FD闭合，pending=false、staging=false，有限原厂前后保持，HOST0／remote0／checker0。Trial requested=false、claim0／无Session，无 FileCenter 凭据或无线操作；这是启动层证据，不是性能 A/B 或手机 Factory 回调已推进的证据。

15:09 新独立 CONTROL 导航的实际组件51事实 **complete=true／remote0**：Startup准备五边界共9.037037秒、四粗段2.247981／0.120222／5.083597／1.585236秒，原10秒内通过；不是稳定性或同条件A/B。真实Receiver＋FileCenter／双HTTP／READY1、原QtTest事件路径、cancelled-empty观察与20秒显示通过。最终Trial cancelled／revoked、claim0／无Session；Owner／Startup／FC音频／guardian／凭据／candidate／FD关闭、pending=false，有限原厂与carrierafter读回保持。只读READY后取得当前DRM scanout，ROOT已查看，确为“已收到／暂无文件”；原像素方向480×800，无像素编辑、不代签物理触摸。

原一键报告仍 **FAIL: NavigationReceiptError**，原因已证为HOST格式误拒：设备实际日志为颜色码＋`[MM-DD HH:MM:SS:mmm] [NavigationTest.qml] [37]`前缀，并有一个尾空格；旧parser只接受裸帧／qml前缀。真实唯一15字段回执为 received_page_stable、click_count=1、七项观察true、四项禁止动作false；不是由Worker终态推断点击。原FAIL／日志／输入均保留，不覆盖为PASS。

新纯HOST vendor解析v2完成受影响单方法与同一实机记录的派生判定 **PASS**（test0／HOST0、无超时、source/raw/result均未变）。仅接受精确厂商外层或明确legacy SGR，日期时间／文件与行号绑定、唯一完整行、4MiB／2304／JSON2048／duplicate／15字段／一次点击和禁止动作门保持；FormalEntry/19不能成功。v1专项虽通过，但独审找到legacy未知CSI拼接覆盖缺口，已保留旧源／结果并在v2补8种拒绝样本。v2首fixture多余括号SyntaxError保留，修测试后唯一受影响方法通过，不重旧suite或设备。

最新未上机导航v3只换独占CONTROL和HOST解析绑定，实际Runner其余字节／Worker其余业务／GUI20／51事实／原10／120／15及600+60不改。最新SOURCE **227真实输入／bootstrap1993701 B／最长行668 B**通过，额外2项只是PC解析器与实际HOST证据；没有重GUI构建／暂存或设备窗口。v3之前绑定vendor-v1的SOURCE为历史，新SOURCE已绑定v2；不能当作新v3实机通过。

19:13 再次只读核对：两采样valid/same、observer闭合、0连接／0广播实例、pending不存在且未处置、有限原厂保持；不是完整用网或物理菜单验收。下一在新手机就绪并取得真实READY后验证Factory／CONNECT／TLS进展，再真实安全文件接收、发送与网络恢复；本轮没有这些证据。

|证据层|结果|公开ZIP SHA-256|
|---|---|---|
|新分类图真实预置／启动关闭|[设备 PASS](results/receive-profile-classification-clock-v1-device-20261005-150836-88037771/public-result.zip)|`1b124f708be845bebb9f070da6a164a16b3cbf6773da01698c91e215a284c5a5`|
|实际组件完成，旧HOST格式拒绝|[原 FAIL 保留](results/formal-receive-filecenter-navigation-classification-v2-navigation-test-20261005-150952-dc89384f/RESULTS.zip)|`9f3730ea0863208c64e4ee5a101eeca2e7f00a3f5ccd26e2e64b5a66ae8d04e1`|
|新解析专项＋既有实际回执派生|[HOST PASS](results/navigation-vendor-frame-v2-host-20261005-191955-b7881998/public-result.zip)|`66f43a0a682d5132ba78e0af3729cba9513756d433005c2bdd47c9430ecff8f4`|
|最新导航v3，无设备|[SOURCE PASS](results/formal-receive-filecenter-navigation-classification-v3-source-20261005-192036-ec0faeeb/RESULTS.zip)|`b0dc377b8d616f5b115b843ea9f1a69116ccd97da4074de766dcdddb0cb52c48`|
|最新无线只读，非完整恢复|[PASS](results/receive-radio-baseline-device-20261005-191331-162ce5d3/public-result.zip)|`96c0ff9efb2b21eade992f41af7391f129a267b75d902d5daea2cecd91cc91d9`|

公开实际导航／HOST ZIP只含有限result.json与README，不含原UI用户标识、地址、凭据或像素；原始UI日志和scanout私有保存。

## 2026年10月5日 15时01分 新分类优化已封装，先补协议图预置

手机最后一次“点击了，连接失败”仍未复测；目标 active、边开发边实测。没有开启新的手机窗口、扫描、广播、配网、配对或文件传输，也未修改原厂程序、启动、系统分区或 NV。

导航拒绝诊断 v3 的单个受影响 HOST 方法通过：原条件求值顺序及短路保持，记录当次首次拒绝组和已求值布尔值，不新增 clock／资源 IO、不用收尾状态猜失败瞬间。该专项使用窄 fixture，不代签完整 Owner 或设备。14:36 的唯一实机未到导航：原 importing 准备耗时 11.102620 秒，超过原 10 秒约 1.102620 秒；四粗段 2.782467／0.139850／6.430736／1.749568 秒，不是函数精确 wall-time 或 A/B。导航投影为 NOT_APPLICABLE。Owner／Startup 资源／guardian／工作 FD 原关闭、pending=false，独立有限原厂与载体后置读回通过，原 FAIL 保留。

分类循环 metadata-clock 优化的实际七源、双 manifest 和 definitions 已机械封装并读回：75 角色／4172818 B 在原 4 MiB 内，余 21486 B；FC9／113690 B 不变，89 个真实来源 pin。原真实 IO／SHA／导入／关闭／成功 full 和 10／120／15 秒保持。纯分类期间 Received／Handoff 完整检查及失败副作用延迟到下一真实 IO full 或成功出口，不能声称逐条失败顺序等价。先前单 HOST fixture PASS 复用，不重复未变 suite。

新分类导航 SOURCE 通过，225 实际输入／bootstrap1993697 B／最长行668 B，GUI20、公开51项、20秒显示及600+60保持。新 Factory 的 post-import 原 check_active 调用由1336移至1379；两诊断 helper 只更换该严格绑定，已做原新字节正逆及真实 Factory AST 对照，未改检查行为。14:54 唯一导航窗口在 `private_assets_required` 早期拒绝：新隔离协议图尚未预置，Owner／Trial／FileCenter／UI 未创建，READY0／无截图／无点击回执。因此不能评估分类优化耗时或导航条件。pending=false、工作 FD 闭合、原厂前后文件和后置载体读回通过；未构造资源的 false 字段不改签为已关闭，HOST0／remote1／checker1 保原 FAIL。

14:58 后置只读两采样 valid/same、observer 关闭，0 连接／0 广播实例、pending 不存在且未处置、有限原厂保持；不代签完整用网或物理触摸恢复。下一先预置新75协议图并执行新独立 core 启动关闭检查，再用新 CONTROL 观察导航；不重失败 CONTROL 或重复 GUI 暂存。新的手机就绪、真实 READY、双向互通与实际网络恢复仍待。

|证据层|结果|ZIP SHA-256|
|---|---|---|
|导航 v3 单个受影响 HOST，fixture|[PASS](results/navigation-refusal-projection-v1-host-20261005-143537-8daeba7b/public-result.zip)|`a0bcd93b776f38070ee8c788b5b68bd9c7b07036d69bbfb73cef5ca170910391`|
|v3 原准备超时，未到导航|[原 FAIL](results/formal-receive-filecenter-navigation-publication-v3-navigation-test-20261005-143609-510ffe60/RESULTS.zip)|`d93d679abf6a3d2290197290517548e3b9566e5e19d427ca3b87fe9f8dd15d02`|
|分类优化七源机械封装，无设备|[SOURCE PASS](results/receive-profile-classification-clock-v1-source-5b129268bd594e68b34f65ef/SOURCE_RESULTS.zip)|`8beb4dcfb19ed8f08eac3bc5f824466807d39b9b628188b6e3ca241d728c10c9`|
|新分类导航载体，无设备|[SOURCE PASS](results/formal-receive-filecenter-navigation-classification-v1-source-20261005-144949-b65641b3/RESULTS.zip)|`f5baf8c42a34e1defb766379e4ace9cb4810aea5a4bd6cb472910366235646be`|
|新分类导航缺协议图预置|[原 FAIL](results/formal-receive-filecenter-navigation-classification-v1-navigation-test-20261005-145435-2544356b/RESULTS.zip)|`c60c1f9a83893851eacb13b29c7385b89a59f22f28edc11dc29efa9a82d8bd6e`|
|后置无线只读，非完整恢复|[PASS](results/receive-radio-baseline-device-20261005-145801-c58dd025/public-result.zip)|`5f8de8b08fa06248d5d1c5566707e0473ea01f6b11eee660b7020efb8b2ce95f`|

## 2026年10月5日 12时18分 基线本轮通过，导航观察拒绝待定位

手机旧“点击了，连接失败”未复测，互传未打通，目标active、边开发边实测。本轮没有自动RF、手机或用户文件操作，未改原厂／系统／NV；旧Startup及actor_unknown FAIL保留。

新v2仅Worker独占CONTROL后缀、原run_fixed返回后的INNER／PROC有限投影；先验实际75图与原11row资料，再验v2单后缀。ROOT完整主读、独审、唯一SOURCE通过，195输入／bootstrap1986701 B在原2MiB内；75／4169378 B、FC9／GUI20／51／600+60／20秒保持，不重复build/stage。

12:06唯一v2窗口实际Startup、Baseline、STATUS2／ProcReader3，以及Receiver＋FileCenter／guardian／两组凭据构造通过。五原边界prepare **9.124239秒**，四粗段2.244380／0.119764／5.205172／1.554923秒，非A/B或稳定性；此前actor_unknown没有复现，不因此签根因已修复。原UI曾退出，候选私有日志确有FORMAL_UI_READY；但Worker在日志读取前以 **navigation_receive_activity** 拒绝，正式READY／双HTTP／严格QtTest／Received回执未认证，未截图。READY0代表载体尚未消费，不代表候选没进入页面。

最终Trial cancelled／revoked、claim0／无Session是原收尾结果，不能证明测试按钮已点击或失败瞬间条件。只读核对actual formal-receive-v3：空cancel在同State.lock内revoke／两Event.set后核零库存返回None，不改epoch或制造Session；HTTP线程returned确为True，未找到与observer的必然源码矛盾。具体false predicate仍待原拒绝点的有限即时DATA；不在关闭后重评猜值、不放宽门。

Owner／Startup资源／FileCenter音频／guardian／凭据移除／candidate／工作FD关闭、pending=false；有限原厂前后、文件保持及后置carrier读回通过。启动内部files_stable=false与独立后置读回分开，整轮仍FAIL；ADB HOST0／remote1／checker1，旧CONTROL不重试。12:07后只读valid/same、observer关闭、0连接0广播实例、pending缺席且未处置，非完整用网或物理恢复验收。原始UI日志含原厂用户标识，私有保留；公开ZIP仅result.json／README.txt，CRC与读回通过。

并行classification优化完成ROOT主读及**唯一受影响HOST合同PASS**：1方法／test0／HOST0／无超时／输入保持，实际profile分类前缀、Files、两Scope guard、Owner._now执行；父Context／Handoff／Trial／Directory与FD-content为明确fixture，完整daemon/profile尾部未执行。真实IO前后原full门与替换拒绝通过，不签逐条失败顺序等价／原生IO／设备收益。97801 B候选仍未机械封装或部署。

下一在原navigation guard拒绝点保存已有求值的有限布尔快照，区分idle／cancelled-empty／claim／session／expired和身份／HTTP／库存／探针／Event，不新增clock或IO，不改原门；并机械封装合同通过的classification候选后做窄实测。保原10／120／15秒、身份、IO、哈希、取消和关闭，不重未变通过或失败CONTROL。手机新就绪、真实接收READY、双向和实际网络恢复仍待。

|证据层|结果|公开ZIP SHA-256|
|---|---|---|
|新v2载体，无设备|[SOURCE PASS](results/formal-receive-filecenter-navigation-publication-v2-source-20261005-120550-107b1030/RESULTS.zip)|`545bd268f28943094360e22fa9cffcf89bb4a5b1e307c26bbf27282f79a4546d`|
|v2基线通过后，导航观察拒绝|[原FAIL](results/formal-receive-filecenter-navigation-publication-v2-navigation-test-20261005-120613-a377203a/RESULTS.zip)|`f84ab79e31a55480e09cabf6643a1072afb6a8e431f8d5512340bcc6564a4281`|
|classification单个受影响HOST，fixture|[PASS](results/receive-profile-classification-clock-v1-host-20261005-121124-ea0c7987/public-result.zip)|`1002c0049fe118d5bfe39099e297d13f774c09f9a8d3b76789f6c3cdd306a6f2`|
|最新无线只读，非完整恢复|[PASS](results/receive-radio-baseline-device-20261005-120755-4c379b6a/public-result.zip)|`536e7e896f0f05038a9cfd071263b503b5f65e936f1fb4296423c8724f1ee695`|

## 2026年10月5日 12时03分 Publication已封装，启动拒绝已区分

手机最后一次“点击了，连接失败”仍未复测，互传尚未修复。目标 active、边开发边实测。本轮无自动广播、扫描、配网、配对、手机操作或用户文件收发；未改原厂程序、启动、系统分区、驱动或 NV。

Publication 固定深路径 metadata 单块候选完成唯一受影响 HOST 合同：实际选定 Files 方法执行，1 方法／21 类替换拒绝通过；Clock／Factory／Received／内容与 FD 为 fixture，不代签完整 Owner、原生 IO 或性能。机械封装 SOURCE 和 12 项 ZIP 读回通过，真实图75／4169378 B在原4MiB内、FC9／113690 B保持。新根独立 core 真实暂存74文件／4目录，但原 post-import Startup 拒绝；登记2307 FD闭合，pending=false，HOST0／remote1／checker1，原FAIL保留。普通 Startup未执行新 Publication 分支，不能把这次失败当作该优化收益或回归证据。

新导航接装的初次 PC 构造漏选原预算 tuple，发生 `KeyError: ASSET_BYTES`，未到设备；ROOT仅补选原 exact tuple `(4191494,4166862)`，严格当前图覆盖不变，随后唯一 SOURCE PASS。新 HOST 15750 B／SHA `c28b41de32f2176393d997ab2e0baf4322102f94454431bd540343bfe379a3d7`，190实际输入保持；GUI20旧实机暂存复用、不重编或重复stage，原51事实、20秒、600+60、strict QtTest／Received／READY截图门保持。

11:55 唯一新导航窗口仍 **FAIL**，但这次越过文件准备与导入，五个原时钟边界均在、post-import原采样有效。边界差值合计 **9.103269秒**，四粗段 **2.258421／0.119761／5.172307／1.552780秒**；不是精确函数 wall-time、稳定性或同条件A/B。随后在原基线 `collect:543` 抛 `BaselineError: actor_unknown`，具体内部拒绝条件尚未投影；不是本次准备超时，也不是蓝牙或手机协议故障证据。deadline投影为 factory_binding UNKNOWN，本次不在它限定的准备失败帧，保UNKNOWN。当前实际 baseline 是v25，不按v51字段猜原因。

READY0，无QtTest点击／Received／新截图／FileCenter／凭据；原UI未退出。Owner、Startup资源、guardian和工作FD关闭、pending=false、有限原厂前后保持；载体启动内部 `files_stable=false` 与后置独立读回通过分开记录，不升级整轮PASS。ADB HOST0／remote1／checker1、原stdout／stderr与旧失败CONTROL保留。11:55前置及11:56后置只读valid/same、observer关闭、0连接0广播实例、pending缺席且未处置，不签完整用网恢复或物理界面。

下一窄候选只补原基线内部异常与 ProcObservation 的有限、after-run DATA投影，用新CONTROL；不修改基线采样、身份、期限或关闭门。进程枚举纯分类metadata clock优化也已源字节正逆／独审，但尚未执行合同、SOURCE、封装或设备：它会把纯分类期间Received／Handoff全检及失败副作用延迟到下一真实IO原full或成功出口，不能称逐条失败顺序完全等价或已提速。旧手机15秒仍是主动观察cancel，不是Factory120秒到期；旧Trial claim1与未发生Handoff frame claim保持分开。手机新就绪、双向与完整恢复仍待。

|证据层|结果|公开ZIP SHA-256|
|---|---|---|
|Publication单个受影响HOST，fixture|[PASS](results/receive-publication-anchor-clock-v1-host-20261005-113156-69a7f166/public-result.zip)|`1e09b922cff8165ef149f481d255f864b0d3594e3f4e7fabd5c5e94cb24d3805`|
|新七源机械封装及实际输出读回|[SOURCE PASS](results/receive-publication-anchor-clock-v1-source-ff9f53c3f4f042b9b56d30f3/SOURCE_RESULTS.zip)|`94030c611c91ba85fe17d319c756f7dad78139d76680d817276a6ddcf4eb8c42`|
|新core真实暂存后，原Startup拒绝|[原FAIL](results/receive-publication-anchor-clock-v1-device-20261005-114059-06b2fe0f/public-result.zip)|`e792fab27c2f24ac75ad74927e7babf13ccc36f39e3506ef6f2b19df2f609b5c`|
|新导航载体，无设备|[SOURCE PASS](results/formal-receive-filecenter-navigation-publication-v1-source-20261005-115454-023251e0/RESULTS.zip)|`7e80db290ba3d7f4dd26371ea1543758d7aa837ed90b4671dccf6fa454541592`|
|新导航准备9.103秒后，基线身份拒绝|[原FAIL](results/formal-receive-filecenter-navigation-publication-v1-navigation-test-20261005-115521-19fefaf0/RESULTS.zip)|`af183db52dedca9d59a546c4f52607bfee28f762dc57018bc37ba1283fae37d3`|
|最新无线只读，非完整恢复验收|[PASS](results/receive-radio-baseline-device-20261005-115612-5c462083/public-result.zip)|`05e39df941d3a106b2fca1a6eab6d30bd4d01aeb4b1edf3b7704cc1ac997c05e`|

## 2026年10月5日 11时18分 新导航资产暂存通过，页面前准备拒绝

手机旧“点击了，连接失败”未复测，完整互传仍未完成。目标 active、继续边开发边实测。本轮没有广播、扫描、配网、配对、手机操作或用户文件收发，没有替换原厂程序、系统分区、驱动或 NV。

已完成实际导航 GUI 的 PC 构建：20 文件 **4191494 B／4194304 B**，余 2810 B；NAV 1567 B／1580 B、原 ELF 定长及其余 399 项 QRC 保持，无字体。只读确认系统 QtTest 三个固定文件存在，不代签 import/TestEvent 运行。构建与清单证据见 [BUILD_NOTES](candidate/formal-receive-filecenter-navigation-gui-v1/BUILD_NOTES.md)。

新 Runner 仅加原严格 cancelled-empty 被动观察器；Worker 仅在 navigation_test=True 时给实际候选追加固定 argv，取消仍撤销 Trial，原 600+60、launched+20、finally、guardian、凭据和 FileCenter 关闭门保持。固定21块正逆和 SOURCE 通过，173 输入保持；协议图仍75／4166862 B，FC9仍113690 B，新导航 Runner 不属于75 payload。HOST 函数解析专项仅1方法／49个 fixture 子例，验证唯一完整15字段 QtTest 回执及45种拒绝；不是实际点击或页面通过。

11:14 新 GUI 的**真实文件暂存 PASS**：20 文件／3目录、40次读回、原77 FD和validator 28 FD全部关闭，pending/staging=false、无凭据，HOST0／remote0；carrier读回、独立原厂前后和输入保持。没有重复核心暂存或旧 suite。

11:15 唯一新导航窗口 **FAIL**，发生在真实 Startup 读准备／导入阶段，尚未进入页面。原 raw `ReceivePublicationError` 在 `startup_readonly:1305 → check_active:514`，对应 `startup_expired` 的四条件合并拒绝；本窗口没有导出各截止条件或边界时钟，不能断言具体超时量。此前成功UI的9.152052秒不代签本轮耗时或稳定性。

READY=0，QtTest未加载／无点击／无Received列表／无新截图；FileCenter和凭据未构造，原厂UI未退出，不能称导航失败来自QtTest。Owner、Startup资源、guardian和工作FD关闭通过，resource_pending=false；candidate缺席及原厂有限前后／carrier读回通过。载体ADB host0／remote1、一键checker退出1与完整原stdout／stderr私有保留，原FAIL不改判，失败CONTROL不重试。QtTest回执缺失被HOST按预期拒绝，不是独立页面根因。

11:01前置及11:18后置无线只读两采样均有效且相同、observer闭合、有限原厂保持；连接0／广播实例0、pending不存在且未处置。它们不签完整用网恢复或物理触摸。

|证据层|结果|ZIP SHA-256|
|---|---|---|
|实际 HOST 回执解析器，fixture only|[PASS](results/navigation-receipt-v1-host-20261005-111410-fed3747a/public-result.zip)|`2fb7fc8c435165e363680c840276f1611a0f4c06bbb9311958ca6cc63b84bf3b`|
|新导航载体 SOURCE，无设备|[PASS](results/formal-receive-filecenter-navigation-anchor-v1-source-20261005-111421-4ae14aa0/RESULTS.zip)|`f412d4617e111716d54ceb7a7add1a669cdc135907afda17eab911ded0177fe2`|
|GUI20 唯一实机文件暂存|[PASS](results/formal-receive-filecenter-navigation-anchor-v1-stage-20261005-111447-8133e381/RESULTS.zip)|`784448148ca15f4301d7d443dd7f0f789802fc012fce264b717f3f340c2dc525`|
|新导航窗口，页面前准备拒绝|[原FAIL](results/formal-receive-filecenter-navigation-anchor-v1-navigation-test-20261005-111528-8e81221c/RESULTS.zip)|`e72452dcea32ad54fa235c1ea6ab486b53b11904074b9103c3ff6db126c620b2`|
|试验后无线只读|[PASS](results/receive-radio-baseline-device-20261005-111828-170f861c/public-result.zip)|`8d9f2bdc0742cb87607189d7633a889a74446a3700c28afb20fcee39810e9e3c`|

再次核清旧手机证据：02:52 的六个采样证明 decrypt 已返回、Factory进入后仍 phase=new，未returned／Parent／CONNECT／TLS／文件；15.010秒是观察器主动cancel，不是观测到Factory原120秒prepare到期。旧 Trial 实际claimed=true／claim_count=1／session_attached=true，未发生的是 Handoff frame claim，不能和本轮claim0／无Session混用。

下一优先处理真正影响手机的 Publication 固定深路径祖先 metadata 重复全检。隔离候选94385 B／SHA `2933d86ab3ce25b20b4efc0eea7733770b2209cc5c5ac062c52793bfceb6da79`，singleblock spec9829 B／`f65512055f7c232d01d920e33508579b889762a0b614a0100ba372fbe230feec`；ROOT已读完整新增块与spec。仅固定Asset／usr／proc深路径可借原Publication alias clock，Startup原guard、真实IO／哈希／写入／关闭和120／15／10秒不改。**尚未 SOURCE 执行、合同测试、打包或运行，不可部署，也无实际性能收益证据**；不混入本导航试验。受影响单HOST合同正在制作，旧未变通过复用。手机下一窗口仍须新就绪、当前基线及真实READY；完整双向和实际网络恢复待。

## 2026年10月5日 10时35分 新交互路径通过，独立核心失败保留

手机最后一次“点击了，连接失败”仍未复测。本轮没有自动广播、扫描、配网、配对、手机操作或用户文件互传；目标 active，继续边开发边实测。新接收＋文件中心交互路径本轮 **PASS**，但先行 core 检查 **FAIL**，不能合并为启动已稳定或手机问题已修复。

唯一业务改动是 `_Files.anchors` 的一个完整源码块：深固定 Startup 路径的纯祖先 metadata 改用已有原 Scope metadata 时钟；入口、成功返回和真实文件 IO／哈希／导入／关闭边界仍完整校验，不跨次缓存、不延原10秒。单个受影响HOST fixture合同通过，完整 Owner/native IO/设备性能不由它代签。严格单块正逆、七源机械闭包和两载体 SOURCE 通过；实际75角色4166862 B／4194304 B，余27442 B；FC9仍113690 B／131072 B，GUI19/4180813 B、原46事实、20秒及600+60不改。

10:25 独立core已真实暂存74文件／4目录并验证private assets，但在原 `startup_readonly:1305 → check_active:514` 的 `startup_expired` 拒绝。该窗口没有导出四个截止条件或原时钟，不能报实际超时量。实际Trial START/END为None，HOST旧parser又以`result_fields`拒绝，公共component因此null；该二次报告错误不是真正设备根因。raw保留Owner／Startup资源及2315/2315登记FD闭合、pending/staging=false、有限原厂和基线一致；complete/gates/operation-idle false，原FAIL不改判。

10:27 新独占UI窗口用于补上真实边界观察，不重试旧core或失败CONTROL。原prepare、基线／STATUS2／ProcReader3、真实Receiver及FileCenter双HTTP、READY1和20秒显示、原46项与关闭链均 **PASS**。Trial ready但claim0、无Session，没有自动接收动作。五个最近原时钟均在，原postimport采样有效，合计 **9.152052秒**；四段为私有35源2.267474、WPA0.120711、profile5.209403、profile尾部＋源行组装／导入／校验1.554464秒。它是本次成功窗口的边界差值，不是精确函数wall-time或同条件A/B，也不是完整应用启动时间；同候选先行core失败的耗时差异尚未定位，不签稳定提速。

真实READY后只读live watcher／DRM取得1张原样scanout，ROOT已查看接收页；capture和相关FD关闭通过，未注入触摸。原DRM方向为480×800，界面使用原800×268横向父内容区，不因截图方向额外旋转QML。截图不代签物理触摸或Files导航。附加Proc投影仍`binding` unknown，不冒称全部诊断完成，也不推翻组件真实三个ProcReader证明。

UI的candidate／Owner／guardian／FileCenter／凭据／工作FD及原厂收尾通过，resource_pending=false、HOST0／remote0；独立有限原厂前后与carrier读回通过。10:29后置无线只读valid/same、observer关闭、0连接／0广播实例、pending不存在且未处置；不签完整用网恢复。独立core的HOST0／remote1及原始stdout／stderr、私有输入和失败保持。

|证据层|结果|ZIP SHA-256|
|---|---|---|
|单个受影响HOST，fixture|[PASS](results/receive-startup-anchor-clock-v1-host-20261005-102525-34cfb402/public-result.zip)|`9c33f77fa49f2f22ec6d3cc1b4743a0739a0068bdaa7a1e1832222c021508cfd`|
|先行独立core，无RF|[原FAIL](results/receive-startup-anchor-clock-v1-device-20261005-102535-c47b6f8f/public-result.zip)|`12a57fc9323aad3b653eb115cda110790e405b83948815ff98c9b14de9c352ea`|
|新UI与真实FC接装、关闭|[本轮PASS](results/formal-receive-startup-anchor-clock-ui-v1-ui-smoke-20261005-102755-fa68db04/RESULTS.zip)|`31bdf7112c57c1e27e95beb64b5fcdfb4fc7ba6fdd7c360f3f633ec373903eb4`|
|后置无线只读|[PASS](results/receive-radio-baseline-device-20261005-102939-3d45d81b/public-result.zip)|`78988b6b88e36a078bef8c64e8cad7a1cf0f3e527d6502cddbb714e1c1023b11`|
|脱敏派生摘要，只有JSON＋README|[当前范围](results/receive-startup-anchor-clock-v1-summary-20261005-1035/public-result.zip)|`27e435b7819047f6ef7db2478742bd925ad04787196508416f64bcc6ebdd6b28`|

公开摘要已逐项核对6份来源长度／SHA、5份报告ZIP SHA和两条目ZIP读回；不包含原流、像素、凭据、地址、用户文件或固件。下一接装现有真实Item按钮导航的三份QML／新GUI builder及原被动取消分支；未构建、argv／QtTest／导航仍待。已过未变证据复用，不重旧测试或窗口。手机下一次点击仍须新的就绪、当前基线和实际READY；完整双向互通及真实网络恢复未完成。

## 2026年10月5日 09时50分 交互准备已取得实际耗时分布

手机最后一次“点击了，连接失败”尚未复测，不能标为修复。本轮没有广播、扫描、配网、配对、手机点击或用户文件传输；目标保持 active，继续边开发边实测。交互启动仍 **FAIL**，但已经取得原准备阶段的实际粗分段数据。

新 Factory 只复制五个最近原时钟边界，不新增时钟、IO、业务检查或延长期限。一个受影响的 HOST 合同方法通过，保留原调用次数、原异常和关闭路径；严格五块正逆差分及七源封装 SOURCE 通过。实际75角色共4164961 B，仍在4194304 B上限内、余29343 B；FC9仍独立113690 B／131072 B。GUI19、原46事实、20秒显示、600+60期限和关闭链未改。

09:36 的首交互窗口在 `private_assets_required` 拒绝：本轮遗漏新隔离核心的预置。GUI stage只部署GUI19，不能代替协议图75；该失败发生在Owner／Scope／guardian创建前，没有计时数据，旧FAIL原件保留。随后按原独立core检查真实暂存新图，74文件／4目录、Boot／Owner／Startup／两组STATUS／三个ProcReader及全部2315登记FD关闭验证 **PASS**，pending=false。这不是files-only部署，也不代签交互或手机通过；失败v1 CONTROL未重试。

09:44 的新v2交互窗口仍以原 `ReceivePublicationError` 失败，实际位置为 `startup_readonly:1276 → check_active:514`。五个最近原边界均取得，最后一笔与原失败帧时钟一致；父窗口还有585.572秒，prepare身份和父边界未变，只有importing阶段原10秒prepare已到期。总计 **10.304747秒**，超过原保护 **0.304747秒**。

|最近原时钟边界之间的区间|实测秒数|
|---|---:|
|35份私有源读取|2.877296|
|WPA资产读取与长度检查|0.149783|
|运行环境profile|5.719892|
|profile尾部残差、源行组装、导入与原校验|1.557777|

profile约占总计55.5%，包含Python／WPA映像、root进程遍历、命名空间、内核配置与套接字／进程连续性核对；原厂文件和进程的独立前后核对另有记录。这里是“最近原时钟”差值，不是精确函数wall-time；profile末次原时钟之后还有返回字典组装和daemon SHA，因此末段不是纯import。相比旧窗口1.138或1.182秒超时，这不是同条件性能A/B，不能签作性能收益。

源码只读分析确认profile内有高频完整目录身份检查，但调用量推导不能代表实际耗时。现有映像、进程、配置、socket与末端连续性读取各有独立证据用途，尚无已证可以删除的冗余IO。下一优先在原已有时钟边界细分Python、PID/comm、daemon身份、namespace/config/unix和socket连续性；不跳过实际文件检查、不缓存旧配置、不放宽原身份／FD／截止门。有限纯CPU复用候选未实测，不能认为足以消除这0.304747秒超时。

本次READY=0，未进入collector，没有候选页面、截图、FileCenter构造或运行凭据，原UI未退出。Owner、guardian、工作FD、Startup资源、carrier读回与独立原厂前后核对通过，resource_pending=false；HOST退出0和远端退出1分别保留。09:46试验后无线只读valid/same、observer已关闭、连接0／广播实例0、pending不存在且未处置；这不签物理界面或完整用网恢复。

|证据层|结果与报告|ZIP SHA-256|
|---|---|---|
|脱敏派生摘要，仅result.json与README|[实测分布与范围](results/receive-startup-boundary-timing-v1-summary-20261005-0950/public-result.zip)|`a6d4c61036ea9ece89d4efd89a1795188d2a5bb02ed0e8c7c75499e9e6b427db`|
|新核心暂存、启动及关闭，无RF|[PASS](results/receive-startup-boundary-timing-v1-device-20261005-094141-b1e4ff2e/public-result.zip)|`8f6bc0926fb9e97626d70d9c45f2a12610c806d10ec3d1bc4b634dc9ac9a5407`|
|新交互准备超时，无自动RF|[原FAIL与关闭核对](results/formal-receive-startup-boundary-timing-ui-v2-ui-smoke-20261005-094435-5918ef92/RESULTS.zip)|`1e280f85aa898b008bf44d1ac29494403b0867ff9a649f17eec7e2616cc5bf84`|
|试验后无线只读|[PASS](results/receive-radio-baseline-device-20261005-094650-491af4ce/public-result.zip)|`09a42e39b35d0aa799eefd4110bdf74411ba0ef459f738157889a6ffdd46134f`|

原始stdout／stderr、输入与旧失败均私有保留；公开摘要逐项校验来源长度／SHA并读回ZIP，不包含原流、设备地址、凭据、用户文件、原厂映像或私钥。Files导航仍未设备验收；手机后续点击须有新就绪、当前基线与实际READY，本轮准备超时不等同于旧手机连接失败原因。完整双向互传及实际网络恢复未完成。

## 2026年10月5日 09时06分 交互启动仍有准备超时

准备优化的新核心单独启动通过，但接入原交互 UI 的唯一试验 **FAIL**，不能据此宣称超时已修复。手机旧连接失败仍未复测，本轮无自动 RF、手机操作或用户文件互传，目标 active。

新 Worker 只改 Runner pin、两个核心根和独占 CONTROL，四块逆转逐字等于 Worker6；HOST 复用原真实 READY 流与只读截图链，只接实际新图、严格四块逆转和有限诊断的新代码行号。GUI19/4180813 B、FC9、原46事实、20秒与600+60和关闭链不改。唯一 SOURCE 通过，149 输入，UI target1977676 B、最长行435 B；未重编或暂存未变 GUI。

09:03 唯一实机失败仍是原 `ReceivePublicationError`，`startup_readonly:1267 → check_active:509`。有限期限投影确认 importing 的原十秒 prepare 过期约 **1.138 秒**，父窗口尚余584.751秒，prepare身份和父边界未变；未进入collector，Proc投影binding unknown。相较旧UI超时约1.182秒，这不是同条件耗时A/B，不能把微小差值签作性能收益。必须分段观察实际读取、配置与导入耗时再选下一改动，不能凭单独core通过判断UI问题已经解决。

READY=0，无截图、FC companion/凭据或候选界面，原UI未退出。Owner、guardian、工作FD、Startup资源、carrier读回、原厂文件和独立前后有限核对通过，resource_pending=false；HOST0/remote1分别留存。失败CONTROL不重试。09:02试验前、09:04试验后无线只读均valid/same、0连接/0广播、pending无且未处置，不签物理或完整用网恢复。

|证据层|结果|ZIP SHA-256|
|---|---|---|
|新交互载体 SOURCE 无设备|[PASS](results/formal-receive-startup-alias-clock-ui-v1-source-20261005-090209-2896fa30/RESULTS.zip)|`520b6bb77227b0036ea6f3ee98bd7463e01601475cbad3ecaae1fd4c250ccbf6`|
|新核心交互准备超时 无自动RF|[原 FAIL 与关闭核对](results/formal-receive-startup-alias-clock-ui-v1-ui-smoke-20261005-090310-28b58ead/RESULTS.zip)|`ee5fd17583d9caeb2dca233f89ebd0c2267425b18f84360f9f4ec370d48628ea`|
|试验后无线只读|[PASS](results/receive-radio-baseline-device-20261005-090433-acb7aa55/public-result.zip)|`550a78f57458c49a1ee31fc3e02f5e60664f864f76e0a1a208b1147105e5c393`|

原流、输入和有限诊断私有留存，公开ZIP只有标量metadata/README。下一只读比较两条启动路径并确定最小分段计时方法，保原期限/文件/FD/基线门；不再盲重跑UI。Files导航源码尚未设备验证；手机下一次点击仍待新的就绪、当前基线与实际READY，双向互通未完成。

## 2026年10月5日 08时53分 准备阶段优化通过启动检查

手机上一轮“点击了，连接失败”仍未复测，不能标为修复。本轮针对已确认的 Startup 十秒准备超时减少重复目录检查，没有广播、扫描、配网、手机操作、传文件或原厂程序替换。目标保持 active，继续边开发边实测。

新 Factory 只为准备阶段固定链接的元数据检查绑定原 Owner 和原 Scope 的专用时钟。真实文件读取前后、哈希、导入、关闭、目录身份、原始函数及代码身份仍校验；十秒准备期限、父期限和 FD 关闭门不变。一个实际 HOST 专项方法通过：23 次固定链接 callback 的重复目录全检为零；原 anchors 的 7 次全检及真正 open 前的第 9 次全检仍在；关闭、阶段、时钟、函数/code 替换和空清单在注入函数调用前拒绝。此测试使用有限 fixture，不证明完整 Owner、真实文件 IO 或笔端速度。

封装器首试在 PC `delta_spec_shape` 失败，未写出候选也未操作设备：冻结差分表实际有 11 个字段，生成器只允许 5 个。原失败源码保留，新生成器严格核对全部 11 项及六个布尔值，仍实际计算五块差分的正反向字节；另修 ZIP 内源码档名与实际生成器一致。新的七源隔离包生成通过，实际 75 角色共 4164334 B，保留原 4194304 B 上限；FC9 仍独立 113690 B／131072 B，未加入私有 ServiceOwner，也未放宽来源或期限。

唯一新隔离根的实机启动和关闭检查 **PASS**：Boot/Owner 启动、原准备读取和导入、真实 Startup 基线与两组 STATUS、三个 ProcReader 均通过；74 个暂存文件、4 个目录和全部 2315 个登记 FD 关闭验证通过。原厂文件与进程和独立前后有限基线一致，resource_pending=false。Trial 始终 requested=false、claim0、无 Session；未创建文件中心 companion 或凭据，未显示候选 UI、发 HTTP 请求或开启 RF。HOST 与远端均退出 0，原始 stdout/stderr 和冻结输入私有留存。

08:51 试验前与 08:52 试验后的两次只读无线检查均有效、两采样相同、连接 0、广播实例 0，pending 不存在且未处置。它们不是物理界面或完整用网恢复验收。这次只证明新候选完成启动层的原十秒准备和关闭，不是同条件耗时 A/B，也不回填旧 UI-v6 超时或 UI-v5 actor_unknown；交互 UI 和下一次手机握手仍须验证。

|证据层|结果|ZIP SHA-256|
|---|---|---|
|受影响 HOST 专项 无设备|[PASS](results/receive-startup-alias-clock-v2-host-20261005-084858-e97c92d8/public-result.zip)|`1f4203de9bf983ae2a7b44f4c421af493759ddd575713deab032885216eef33e`|
|七源差分与实际封装 无设备|[SOURCE PASS](results/receive-startup-alias-clock-v1-source-0e48f330aef64039acde1549/SOURCE_RESULTS.zip)|`213ac7be553d7fd84b34e2b962339528cab26aac3f537444812b5d2a5b661615`|
|新载体 SOURCE 无设备|[PASS](results/receive-startup-alias-clock-v1-source-20261005-085104-cfd9f57a/public-result.zip)|`cab2ce8b86e9715cdebedb14441521649d4046a73cabeeab23cd5956e26833ee`|
|新候选实机启动和关闭 无 RF|[PASS](results/receive-startup-alias-clock-v1-device-20261005-085144-bd72f007/public-result.zip)|`689646ef68bec2d0f248ec67e560a53154719c8f351fddaed1f2553b25228623`|
|试验后无线只读|[PASS](results/receive-radio-baseline-device-20261005-085238-576d0ac6/public-result.zip)|`508534c6f4d35d833e6c5fdd6559b39b54d0d3a014f5f67f7fdea5ff804a5cf2`|

默认 [HOST 载体检查](HOST_MTA_RECEIVE_STARTUP_ALIAS_CLOCK_V1_CHECK.cmd)不操作设备；[实机入口](TEST_MTA_RECEIVE_STARTUP_ALIAS_CLOCK_V1.cmd)已由 ROOT 执行一次，不自动重试旧窗口或候选。下一步只接新核心到未变交互 UI，不合并导航或资产修改，以分开核对原四十六项和截图。真实 Item 点击导航已完成源码但未构建上机；手机仍待新的就绪通知再按当前基线、实际 READY 开启点击窗口，不接受或发送文件。

## 2026年10月5日 08时18分 接收准备超时已确认

手机“点击了，连接失败”仍未修复或重新测试。此前 decrypt 已返回，但 Factory 停在写入前 `new`，没有 Parent、CONNECT、TLS 或文件结果。本轮只做不自动开启无线的启动检查；没有广播、扫描、配网、手机点击或传文件。目标继续 active，沿已生效的边开发边实测方式推进。

UI-v6 已接入结束后的有限 Proc 投影，原 generic → deadline → inner → Proc 顺序和原 46 项事实、20 秒显示、600+60 秒期限、75 核心、FC9、19 GUI、关闭链保持。默认 SOURCE **PASS**，134 输入，target 1976928 B，最长行 435 B；Worker6 仅改独占 CONTROL 后缀，逆转后逐字等于 Worker5。

唯一实机 UI-v6 **FAIL**，这次原异常为 `ReceivePublicationError`，仍在 `startup_readonly:1177 → check_active:478`。实际有限期限投影首次区分四条件：父截止未到、prepare 身份未变、prepare 未越父截止，只有 importing 阶段 prepare 过期。父窗口尚余 584.746 秒，prepare 已超时约 **1.182 秒**，因此这次确实耗尽原 10 秒准备预算。它早于 collector，Proc 投影报告 binding unknown，不能当作取得了新的 Proc 拒绝原因。UI-v5 的 `actor_unknown` 是不同阶段的独立失败，仍待具体原观察。

本次 READY=0，未触发截图观察、未构造文件中心或运行凭据，原 UI 未退出。Owner、guardian、工作 FD、Startup 资源、carrier 读回、独立原厂前后核对通过，resource_pending=false，原厂文件保持；主机退出 0 与远端退出 1 分开留存，原 FAIL 不改判，不重跑 CONTROL6。08:11 试验前和 08:18 试验后只读无线两采样有效且相同，连接 0、广播实例 0、pending 不存在且未处置；这不是物理界面或完整用网恢复验收。

下一步缩减固定文件校验和导入准备中的重复开销，保原文件 pin、FD 闭合、实际 Owner/基线和截止，不以延长期限取得通过。Files 被动取消导航的主机证据仍有效；隔离的真实 Item 点击候选在制作，QtTest 插件和启动参数尚未实机验证，不签导航、触摸或音频通过。

|证据层|结果|ZIP SHA-256|
|---|---|---|
|UI-v6 SOURCE 无设备|[PASS](results/formal-receive-filecenter-ui-v6-source-20261005-081046-63d91172/RESULTS.zip)|`ea028ba59192179a991e7f3732f8679b248887cbb8569e06fe3ea9e3ca2d5d53`|
|UI-v6 实机准备超时与关闭核对|[原 FAIL](results/formal-receive-filecenter-ui-v6-ui-smoke-20261005-081223-acb8ab01/RESULTS.zip)|`bc497f8237821490e1126c7bed794a7077b4ff4fec949a339118347eddc00cc4`|
|试验后无线只读|[PASS](results/receive-radio-baseline-device-20261005-081816-b885d6dd/public-result.zip)|`3c8623a4b89ca28f0c9f73c54eceae6d9fc60054ff2860d1513c0d65692e7404`|

公开 ZIP 仅标量 metadata/README，原始流、输入和诊断私有留存。本轮没有新手机窗口；候选尚未取得手机连接改善证据。

## 2026年10月5日 08时00分 启动失败位置已分开记录 导航主机检查通过

手机上一轮“点击了，连接失败”仍未修复或复测：原 decrypt 已返回，Factory 随后停在写入前 `new`，未取得 Parent、CONNECT、TLS 或文件结果。冻结的 alias-clock 候选仍等待手机重新就绪。此次没有广播、扫描、配网、手机点击或传文件，完整双向互通和实际用网恢复未完成，目标继续 active。

**更正 07:34 的诊断表述。** 完整读回 UI-v4 的原始 carrier stdout 后，确认 `PRIVATE_UI_FAILURE` 已经输出，之前检索漏掉了通用 FAILURE 标记。实际异常是原 `ReceivePublicationError`，调用链为 `startup_readonly:1177 → check_active:478`；冻结源码在这个位置唯一抛出 `startup_expired`。它早于 baseline collector，不能称为旧 `io_error`。原条件同时检查父截止、prepare 对象身份、prepare 越界和 reading/importing 截止；旧日志没有这四项事实，因此暂不认定一定耗尽 10 秒。旧日志、FAIL、目录及 07:34 历史文字保留，此段为纠正后的解释。

新增 UI-v5 只隔离 CONTROL、结果标签、留存输入，并在原 worker 完成清理后追加有界期限投影；Worker 逆转后逐字等于 v4。投影只读取准确异常帧的原 `self/value` 和原 Scope 引用，不调用时钟、IO，不修改原 46 项事实、20 秒显示、600+60、恢复门、75 核心、FC9 或 19 GUI。独立只读审查和唯一 SOURCE 通过：132 输入，target 1971372 B，最长行 435 B。没有重构建或暂存未变资产。

ROOT 唯一 UI-v5 实机检查 **FAIL**，但失败位置与 v4 不同：已越过文件准备，实际进入 collector；内层原 `BaselineError(actor_unknown)` 位于 `_actors:225 → _actor_image:256 → _proc:203`。partial counts 为 `(2,1,7,251,18,1)`，原观察已开始并收尾，collector 未成功。期限投影对此不同类型错误报告 unknown，未制造截止数值。当前证据不能区分 ProcReader 的任务变化、身份变化、非 live 或截止等具体拒绝原因，下一步只补原 ProcObservation 的有限 kind/reason/stage。不能将两次失败合并为同一原因或宣称增加诊断已修复启动。

源码进一步确认本次 `_proc:203` 是第二组 live Actor 语义判断，第一组 FD/资源闭合判断已经通过；`_actor_image` 调用使用 `single=False`，因此不是“必须单线程”的拒绝。刷新前原 Actor 和实际 exe 的 pin/metadata 已通过，ProcReader 的具体返回原因仍待取得。新 [有限 Proc 投影](host/receive_startup_proc_projection_v1.py)已冻结，6137 B / `aae15e0726ae21c2d1f8b97e8249123465c67191e2928f607e149acadd264002`。ROOT 全文核对和唯一默认 SOURCE 执行通过：目标片段 5556 B / `5dae8cfec1f95fbf1b8afbb83046d797f74eb18948e9899d7499ea0aa88ae324`，Python3.5 AST 可解析，未执行 target。它须位于原 inner diagnostic 之后，重新核原对象/票据/异常帧，仅输出有限 kind/reason/stage、计数、布尔；不输出 PID、路径、argv，不调用时钟或 IO。尚未接装新设备载体或取得新的原观察，不能认定线程变化、读取截止或其他具体原因；本轮不再重复 UI5。

本轮没有 READY、文件中心构造、运行凭据或候选 UI，原 UI 未退出，截图观察未触发；HOST 流与线程/pipe 均已关闭。Owner、guardian、工作 FD、Startup 资源及原厂收尾通过，resource_pending=false，原厂文件和独立前后核对通过；HOST 0 与 remote 1 分开记录。07:50 和试验后 07:53 的两次只读无线检查均有效、两采样相同、0 连接/0 广播、pending 不存在且未处置。该有限核对不是物理界面或完整用网恢复验收。不重试已失败的 CONTROL5。

Files 生命周期修正已完成两源源码和独立审查：仅新增原取消后未认领空会话的被动观察分支，核对真实 Owner/Trial/HTTP，拒绝活动操作、无线、恢复待办及库存变化。不绕过真实 cancel，不重置或续期 Trial，不重新授予接收资格；旧 smoke 仍拒绝撤销 Trial。新 navigation_test 严格布尔、与 smoke 互斥，沿原 launched+20 秒和关闭链；额外五个字段只描述导航观察。新 Runner 85532 B / `f7a9552bc368e488a494abefcc32aaf6914d18f06ab667c3a0760e6f344ea212`，未接装 Worker 95122 B / `326b8719d01d6d9c94bcc4e308148ec8fe6043d9366d9082a95caedf02bf59af`。

ROOT 随后执行唯一 [导航 SOURCE 与 pin 绑定检查](TEST_MTA_RECEIVE_FILECENTER_NAVIGATION_V1_SOURCE.cmd)，**PASS**。四份冻结源码均满足 Python 3.5 语法；新 Runner 删除唯一 6300 B 方法后逐字回到原 Runner；原 Worker finally 和旧 smoke 段保持；新观察分支只做有限读调用、锁及局部赋值，不写字段。创建新的不可变 [bound Worker](out/receive-filecenter-navigation-v1-source-deca5a6201354c57935b43c7/bundle/ui_session.py)，95122 B / `6cd5239bdab46a584da3427e107b4ba2de38eeec9299471cec6a986a07834ec0`；只替换唯一 Runner pin，逆转后与原导航 Worker 相同，六份输入均留存且未变。没有导入运行图、运行合同测试或操作设备，不改 75/FC9/GUI。原未接装 Worker 保留，不能直接启动；生成物仍需独立设备载体/QtTest 接线和真实 Files/触摸/音频验收。

|证据层|本轮结果|ZIP SHA-256|
|---|---|---|
|UI-v5 SOURCE 无设备|[PASS](results/formal-receive-filecenter-ui-v5-source-20261005-074939-a68f096d/RESULTS.zip)|`fb6e0fbb5d9af9c30964250931abe1dbd33fd6988c6963e9644efc54867d6c3b`|
|UI-v5 Startup actor_unknown|[原 FAIL 与收尾核对](results/formal-receive-filecenter-ui-v5-ui-smoke-20261005-075154-c9feb0cb/RESULTS.zip)|`622af6d5235ee58a159b07527d2b4dcdbd189a7488e3f701a297e0b0d5ef4110`|
|当前无线只读 07:50|[PASS](results/receive-radio-baseline-device-20261005-075003-b410ee15/public-result.zip)|`9fde37ad00daa29321b16483cff32f1eab52d69aada55e4ba9dbffc521302125`|
|试验后无线只读 07:53|[PASS](results/receive-radio-baseline-device-20261005-075320-c1c1a7f9/public-result.zip)|`2e4c67c072c53310a19094f7034e1b24d474dfdde7ba8969a7b1d4c4a4195704`|
|导航 SOURCE 与不可变 pin 绑定 无设备|[PASS](out/receive-filecenter-navigation-v1-source-deca5a6201354c57935b43c7/SOURCE_RESULTS.zip)|`cf2cd5a259dbfc11e8d34352335c30dc4aab5dccb4107a29ab9bf5cc8faeda48`|

公开 ZIP 只有标量 metadata/README；原 stdout、stderr、退出、输入及诊断留在私有目录。本次没有截图。默认 [HOST SOURCE](HOST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V5_CHECK.cmd) 不操作设备；显式 UI 入口仅适用于新的独占会话，不自动重跑失败 CONTROL 或历史 START。

## 2026年10月5日 07:34 截图调度已接装 本次启动失败且未截图

手机上一轮“点击了，连接失败”仍是原 **FAIL**：decrypt返回后Factory在原观察内停于写入前new，尚无Parent／CONNECT／TLS／文件。alias-clock候选仍待新的手机就绪、当前只读基线与实际READY；本轮没有广播、配网、手机点击或传文件。完整双向与实际用网恢复未完成，目标active，继续边开发边实测。

新增HOST流式调度，仅在本轮实际stdout完整 `MTA_FORMAL_UI_READY` 行出现后，才启动原held-log／exact-live PID/start双采样观察，再直接复用固定只读DRM算法。没有Startup前shell hint，没有额外截图helper进程，不改原argv／transport／raw／receipt、Worker20秒显示、600+60、46事实、75核心、FC9或19GUI。Worker-v4仅隔离CONTROL后缀，91420 B／`53465b7cdcd576fa689d5c08e0de38a6c53a360efa76b88563e39f0182382e18`；HOST18256 B／`5ba3131f34dbcc912dc7d50a058e5a49e644a5583520fa36bdd407460807b556`。未重新构建或暂存未变资产。

新HOST合同一个实际方法、八个真实本机Python子例通过：两路完整原字节、分块／重复READY、子串／缺换行／stderr伪标记拒绝、长片段防误匹配、双pipe与独立callback、stdin、非零和超时。独审发现线程start失败清理缺口；原v1／原PASS保持，另存stream-v2（8040 B／`1dbac1b1c4c164b84f53b323acdace78175b00d838229df0251af9c7a596dc9b`）覆盖外层finally的exact HOST child回收与实际started线程／pipe闭合。新增一个真实child专项仅测试第二reader启动失败，原异常对象／partial stdout／TIMEOUT保持、child／第一reader／pipe闭合，未伪造不存在的stderr。未重跑不受影响的八子例或旧suite。截图直接复用原target12／HOST20读器，失败不签capture闭合；正常自然返回且WATCH／截图证明都通过才签。两个SOURCE历史和输入保留，07:25修订后的唯一SOURCE通过，130输入保持，target bootstrap未变。

ROOT通过[显式一键UI检查](TEST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V4.cmd)做了一次设备试验，**FAIL**。失败在Owner装载／Startup只读准备期，`reason=session_failed`、baseline与status未取得；本次有界内层诊断标记缺席，不能确认具体errno或把它称为旧io_error的同一根因。READY计数0，观察callback从未触发，未创建文件中心／凭据、未退出原UI、没有截图。HOST流完整读回且reader／callback关闭；Owner、guardian、工作FD及Startup资源关闭，pending=false，原厂文件／进程与独立前后核对通过，carrier保留并读回核对。主机0／远端1分别保留，不把主机0当业务成功，不重跑失败CONTROL。此前UI-v3通过仍有效，但不代表此次启动成功。

静态窄审还确认实际Files导航冲突：mtaFiles→原cancel→fresh status静止→Received是正确路径；但cancel撤销原Trial，Runner idle要求未撤销，Worker的显示许可又要求idle或真实接收Operation，因此空库存正常切页会被当作`closed_service_changed`。现有冻结GUI没有外部输入接口；项目已有进程内QtTest真实Item点击可复用，不猜evdev／旋转，不使用Android input。下一步补失败诊断可靠投影并修文件导航的被动观察生命周期；不重置／续期Trial，不绕开真实cancel，不把导航签回原未撤销smoke。尚无Files切页／打开、触摸、音频或新接收页截图验收。

|证据层|本轮结果|ZIP SHA-256|
|---|---|---|
|HOST正常流，一个方法八子例|[PASS](results/ready-capture-stream-v1-host-20261005-072014-f7589d87/public-result.zip)|`75462c133591d2cfd3e9d949145c84d83f5c63bd5dd10f4a0f32acb7ed92de2a`|
|HOST线程启动失败清理，一个方法一个child|[PASS](results/ready-capture-stream-v2-host-20261005-072802-d748fb94/public-result.zip)|`d5172e80b78ad64120b0fdf6e2c6da1428f2a605ba3a2be6b655bede358ec84d`|
|最终调度SOURCE，无设备|[PASS](results/formal-receive-filecenter-ui-v4-source-20261005-072526-e36424fd/RESULTS.zip)|`fd44971d42bf724bd3c531c8f5bb3a3beae8fc28ab5bf8588f31358d20d8d4cb`|
|本次设备Startup失败，恢复核对通过|[原FAIL](results/formal-receive-filecenter-ui-v4-ui-smoke-20261005-072811-59ef79cb/RESULTS.zip)|`981a84c914cccf8bec49c2ddb181a93735f29c6c2fc9f9b63d5ea53a127ff66c`|
|试验前当前无线只读，0连接／0广告|[07:25 PASS](results/receive-radio-baseline-device-20261005-072543-e11d90b8/public-result.zip)|`5372fe71142c0c263f738710819e15962ed238ff823bcdd15a284e50be20ea75`|

公开ZIP仅标量metadata／README，原stdout、stderr、退出、输入与失败诊断私有留存。本轮无图片，不签物理／手机／完整网络恢复。默认[HOST SOURCE](HOST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V4_CHECK.cmd)无设备；所有设备入口均显式、独占、限时，不自动重试既有CONTROL或历史START。

## 2026年10月5日 06:56 接收与文件中心接装实机通过 手机互通未完成

手机上一轮“点击了，连接失败”保持 **FAIL**：原 decrypt 已返回，随后 Factory 在原15秒观察内停在写入前 `new`，未产生 Parent／CONNECT／TLS／文件结果。冻结的 alias-clock 性能候选尚未进行新手机点击。本轮没有手机发现窗口、手机操作或文件传输；仍须收到新“已就绪”、完成当前只读基线与实际 READY 后才通知点击。目标 active，继续边开发边实测，不以 UI 通过代签手机互通。

本轮完成 `formal-receive-filecenter-v1` 机械闭包：75角色 **4157625 B / 4194304 B**，排列35ordinary→3helpers→35private→WPA→monitor；FC9独立 **113690 B / 131072 B**，不增加private服务Owner。definitions13159 B／`632d12d5d4f4cb7f30df634ec3e32b22ca4eadfb2dc03e3c2867cce0ff908414`。ROOT唯一 SOURCE、core无RF暂存／Boot／Owner／Startup／关闭通过：74新文件／4目录，2315登记FD全闭合、pending=false、有限原厂前后相同；Trial requested=false、claim0无Session，未构造Companion／UI或发业务HTTP。已过且未变的关闭专项／Receiver源码证据复用，不重旧suite。

真实 Receiver＋FileCenter worker 已接装：同一个实际未注册Receiver Owner模块创建Companion，两组不同的实际loopback凭据，绑定实际音频guardian，沿原父cap收尾，不自动播放音频。GUI默认接收、保原来件ID确认／拒绝／取消，使用真实FileCenter的Received目录；切页前实际cancel并观察静止，不以文件元数据伪造打开。父区域800×268，无额外偏移／旋转。PC唯一构建19部署文件／3目录 **4180813 B / 4194304 B**，候选ELF4103844 B／`2bd5aac328468f3721f017b5c61f1209ba2601a62ca6ece7c7726ea5108baf7e`；399其他QRC／ELF槽外原字节、原厂ELF保持。19资产唯一实机暂存通过，38次读回、暂存74FD／验证27FD闭合，无运行凭据。

两次失败原判和raw保留。06:35 UI-v1 **FAIL** 于真实Startup `BaselineError(io_error)`，尚未构造FileCenter或替换原UI；Owner／guardian／FD／有限原厂闭合。并行shell截图hint每200ms产生短命进程，实际Baseline先枚举全部PID再读comm、无消失容忍，存在扰动路径，但当次内层errno未取得，**不能确认根因或放宽Baseline**。06:47独立CONTROL、无启动期观察器的UI-v2过Startup，实际FC创建、两组凭据、guardian及关闭均通过，却 **FAIL** 于`qml_failed`，页面没有业务请求。新增有界私有诊断仅投影原异常有限kind／白名单code／errno／可信函数位置和partial计数，不输出异常文本、路径、凭据或raw；缺席不代表原错误不存在。

界面失败已ROOT／独立确证为凭据目录链错误：validator的全部目录含mta、toolbox两个兄弟；旧单MTA worker沿 `directory_bindings[:-1]`，末端为session/mta，但FormalEntry从session根读credentials.json。新UI-v3仅改用validator原六节点 `credential_directory_bindings`，另用独立CONTROL保留旧失败目录。Worker91420 B／`a00c8f863bb75fd65af06cbbc1a32b23322dfada55d0926cc9eedcd668068fa3`，两变化inverse与原v2完全相同。GUI／core／FC9／46事实／期限与关闭门未变，没有重新build或stage未变资产。

ROOT唯一UI-v3 SOURCE和实际 **20秒显示阶段**通过（还包含原启动和收尾，不称试验总共20秒）：Startup／2STATUS／3ProcReader、Trial初始ready但claim0无Session、原UI退出、候选UI READY、真实Receiver HTTP／FileCenter HTTP、空闲与显示结束均通过，七FC事实全true。candidate／Owner／guardian／凭据／工作FD／原厂收尾及独立前后核对通过，主机／远端0、pending=false、输入保持。常量日志scene1／ready1／failure0，已检查QML错误关键词计数0。**没有候选截图、物理触摸、Files打开、音频、RF／配网／手机收发或实际用网恢复验收**；旧io_error未复现不称底层修复。06:46无线只读两采样有效且同，连接0／广告0，pending无且未处置，有限原厂保持。

|证据层|ROOT唯一结果|ZIP SHA-256|
|---|---|---|
|core无RF启动关闭|[P011 PASS](results/receive-filecenter-v1-startup-device-20261005-062946-278fec43/public-result.zip)|`2ce8c707baa35cc10c416ab023eb414da7cda7d4f6c317f4958fb5faa8a236c2`|
|19GUI资产实机暂存|[PASS](results/formal-receive-filecenter-ui-v1-stage-20261005-063508-ebb4f7f6/RESULTS.zip)|`6dfb173ebbd0d3eb228e6e47a7628bfaf4b71d70bd9459472e7aeb210c967db9`|
|UI-v1 Startup失败|[原FAIL](results/formal-receive-filecenter-ui-v1-ui-smoke-20261005-063542-3bc958aa/RESULTS.zip)|`96de214abad626b93d257dfa55829257cfa7fe2fb0896cd04e581a45e6e25cc8`|
|UI-v2无观察器对照，Qt失败|[原FAIL](results/formal-receive-filecenter-ui-v2-ui-smoke-20261005-064723-1c03abaa/RESULTS.zip)|`ca2ee93d520de07f078202ff82ddd401db6a96712ecc5dee7c2fc6d20ba29742`|
|UI-v3凭据链修正SOURCE|[PASS](results/formal-receive-filecenter-ui-v3-source-20261005-065305-a91657ab/RESULTS.zip)|`9ee7c32450743b04df97a29ec894b296806d7186c898163bc242767ec7711ec5`|
|UI-v3实际加载、双HTTP和收尾|[P011 PASS](results/formal-receive-filecenter-ui-v3-ui-smoke-20261005-065430-cc42b4f3/RESULTS.zip)|`834838db44357c41e1b7321c701da61797c4ed46685200d3a1c048e55f897134`|
|当前无线只读|[06:46结果](results/receive-radio-baseline-device-20261005-064643-f2bba544/public-result.zip)|`e7fe000393d7d18a0b877d6bf4bd3265bbb96ee88573fcded8e86dda9b8345f1`|

新 [GUI一键PC构建](BUILD_MTA_FORMAL_RECEIVE_FILECENTER_UI_V1.cmd)只创建新不可变bundle，不调用ADB／Docker／Owner／无线；本轮未另跑此新CMD。当前 [一键SOURCE](HOST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V3_CHECK.cmd)默认无设备，[显式UI检查](TEST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V3.cmd)限时且独占，不自动重跑已完成CONTROL或历史START。下一步用实际HOST READY流安排截图观察，Startup期间不运行target waiter，再补Files切页／打开。手机性能候选待新就绪后同期限真实点击，再按结果推进非个人文件与最终双向／恢复；不伪造通过。

## 2026年10月5日 06:08 文件中心关闭专项通过 接收后端完成源码接装

本轮没有 ADB、设备、UI、无线或手机操作。源码核对发现文件中心另有历史 FD 数字复用误判：原 Store 和监听器已关闭后，其他文件复用旧数字会使关闭检查回到 false；这不是手机连接失败的已确认原因。新隔离 [Storage](candidate/filecenter-close-seal-v1/runtime/mta_filecenter_storage.py)、[Companion](candidate/filecenter-close-seal-v1/runtime/mta_filecenter_companion.py) 和 [Sender Owner 源码](candidate/filecenter-close-seal-v1/runtime/mta_client_service_owner.py) 保留实际原对象和一次关闭事件证明，后续查询不再检查或关闭历史数字。原调用报错、部分构造或证明未知仍拒绝完整关闭，父期限和原身份门不变。

ROOT 唯一 [Linux 专项结果](results/filecenter-close-seal-v1-linux-contract-20261005-055920-d8f91965/PC_RESULTS.zip)通过，ZIP SHA-256 `3fc5a8beeb65f492ef229cf668fc56e674828df43c69dc412237dcd0768e2190`。一个实际方法、7 个子例、1.383 秒、退出 0：旧目录／监听数字复用误判均复现；新封存复用后仍闭合且再次关闭未误伤真实 sentinel；原 close 前／消耗后 EIO 及真实 Semaphore 部分构造继续拒绝完整关闭。使用真实 Linux FD、socket、线程、dup2、fstat、pread，不发送 HTTP、不播放音频、不启动 RF。Owner 仅执行三个实际受影响方法，其他定义前置和临时根明确为 HOST fixture，不签完整 Owner／P011。原 stdout、stderr、输入与退出码留存；WSL 的 user-session 警告原样保留，不做系统修复。新九业务源 113690 B，仍低于 131072 B。[一键检查](TEST_MTA_FILECENTER_CLOSE_SEAL_V1.cmd)默认仅 SOURCE，显式 `--run-linux` 才执行这个专项，不运行旧 suite。

新 [Receiver 文件中心 Owner](candidate/formal-receive-filecenter-owner-v1/runtime/mta_client_service_owner.py)完成源码接装并独立差分审查：107037 B，SHA-256 `6eb891d71b5e935c6bbfdaf4a19621889cdf7c7ee5c56fcd4bcc08f89473f5a2`，相比原 Receiver 增加 28376 B。保留原两 DirectoryBinding 创建／验证顺序，封存原身份；关闭沿用原一次绝对 cap，先收尾文件中心，失败仍继续原 Receiver finalizer；目录释放与最终闭合增加真实 FC 门，原 Trial／Barrier／State／Session／HTTP／RF 方法体不改。实际 FixedSession 持有的是未注册 Receiver 模块，故 `create_filecenter(source_rows, owner_module)` 必须传该同一实际模块，不注册或伪造 Sender 影子。

ROOT 唯一 [Receiver SOURCE 结果](results/receive-filecenter-owner-v1-source-20261005-060725-4267e9c7/SOURCE_RESULTS.zip)通过，ZIP SHA-256 `3b1fc81a49be92610ca11f0e2a41f5ff595ac440269516952c8e179f4e74a558`；Python 3.5 语法、原方法差分、固定 ROOT／Boot／期限字面、显式模块参数与原封存消费体检查通过，原输入保持。[一键 SOURCE 检查](TEST_MTA_RECEIVE_FILECENTER_OWNER_V1_SOURCE.cmd)不导入或执行运行图。仅投影原 75 payload 其他项不变时为 4157560 B，距 4 MiB 余 36744 B；九 FileCenter 源保持独立输入，不加到 75 角色，也不添加 private 服务 Owner。

两组新源仍未打包：FC pins／ROOT／BOOT_PIN 故意保留隔离原值，不能直接当可部署版本启动。真实 Receiver create／partial／到期、UI worker、凭据与音频 guardian 接线和笔端文件打开／退出验收仍待；不能借 Sender 专项或先前接收页 PASS 代签。下一安全工作是机械 root／pin 闭包与真实接收 worker／文件页接线，再针对变化做有限笔端测试。手机上次仍是解密后 Factory 准备未完成，alias-clock 候选尚待新就绪实测；原“连接失败”保持，不开无人操作的新窗口，完整双向／TLS／实际用网恢复未完成，目标 active。

## 2026年10月5日 05:30 接收页面启动和关闭实机通过 手机连接仍待复测

ROOT 唯一[新接收 core 无 RF 启动关闭试验](results/receive-ui-v1-startup-device-20261005-050702-7bd73af5/public-result.zip)通过，ZIP SHA-256 `a89c58f22e378bdc765d3286009f14bf4c0c5e8084ca7e3c8d719bc80d9eaf3f`：75 个角色就位，74 个新文件／4 个目录（另一个角色原已存在），原 Boot／Owner／Startup／关闭通过，2323 个登记 FD 全部关闭，resource/staging pending=false，原厂前后有限基线相同。两份 Trial 均 requested=false、claim0、无 Session，未发业务 HTTP 请求，未启动广播、扫描、Wi-Fi、候选页面或文件传输。这一结果仅准备新 core，不签手机互通或性能。

修正 75 角色排列的新薄 v2 唯一[接收页面试验](results/formal-receive-ui-v1-ui-smoke-20261005-050951-aa8ba57c/RESULTS.zip)仍 **FAIL**，ZIP SHA-256 `b75ac5004dc9098a25e5af434f0564b8e2650ca762a2faaa6ea9868b3fb12d52`。已进入实际 Owner 的启动只读检查，但未完成 baseline/status 验证，未退出原厂 UI、未启动候选。原 Owner／guardian／worker FD 关闭、原厂恢复和独立前后核对通过，resource_pending=false。源码检查未证明 600 秒配置不兼容；原启动子预算仍为 10 秒，不通过扩限重试。旧原始失败、日志及控制目录保留。

新增 v3 薄诊断仅在原 worker 返回后向私有 stderr 投影实际异常类型、有限 code/errno 和末 8 个代码位置；没有 args、locals、账号或原始 baseline。新 Worker 只改一个固定控制目录 suffix，避免覆盖历史目录；原七源、39 字段、75 角色顺序、600+60、launched+20、guardian 与恢复门不变。[唯一 SOURCE](results/formal-receive-ui-v1-source-20261005-052442-f00f3625/RESULTS.zip)通过，SHA-256 `61c09cc54c4dadb6139855470cb31732ae10c79358e4996a3573ec9be30d7305`。

ROOT 唯一[v3 接收页 20 秒实机试验](results/formal-receive-ui-v1-ui-smoke-20261005-052822-ddca0a2d/RESULTS.zip) **PASS**，ZIP SHA-256 `1134a710ad5c6f5b17c2971c3a1f044648ade2f5c69b5db0a9f7236666420762`：主机／远端退出 0、载体 stderr 为空；实际 Startup 的 2 次状态与 3 个 proc reader 通过；Trial 初始 ready、claim0、无 Session，终态 owner_closed/revoked；候选 READY、真实 HTTP、20 秒空闲、Owner／candidate／guardian／凭据／FD 关闭与原厂恢复均通过，resource_pending=false，独立原厂前后核对和源码保持通过。未自动接收、广播、连接手机或传文件；没有候选截图及物理触摸验收。候选原始日志中的原厂初始化警告保留，不收入公开 ZIP。

本次 v2 启动失败没有复现，且 v3 未改变底层启动算法，故不能把诊断目录隔离或本次 PASS 当作该失败的根因修复。手机“点击了，连接失败”仍按 02:52 证据定位在解密后 Factory new 准备阶段；alias-clock 优化已准备，尚未实测手机效果。05:16 只读无线快照为 0 连接／0 广播实例、pending 无且未处置，不回填旧失败，也不代签本次 RF 物理状态。已请求手机退出旧页并重新就绪，回复前不开新窗口。完整 Wi-Fi／TLS／双向文件及实际用网恢复仍待，目标 active。

## 2026年10月5日 05:01 接收资产暂存通过 UI 载体排序失败已定位

ROOT 04:50 当前只读无线检查通过，0 连接、0 广播实例，pending 不存在且未处置，有限原厂基线保持。新实际接收 UI adapter／资产验证／薄载体已冻结，经 SOURCE 和独立窄审；一个真实 Receiver、原 interactive 600+60、launched+20 显示出口及原 guardian／Owner 关闭链保持，不自动广播或连接手机。[薄载体 SOURCE ZIP](results/formal-receive-ui-v1-source-20261005-045146-11522c15/RESULTS.zip) SHA-256 `b65a758e7b4e0aa6424c4a0ef793caff33379479eeb7cb8e5faa7290f57e09a6`。

ROOT 唯一[10 资产设备暂存](results/formal-receive-ui-v1-stage-20261005-045411-622e56de/RESULTS.zip)通过，SHA-256 `e9a14095408013fd6655fd9724d375ba36e311d98801f1d933dbc61cc0516c4c`。10 文件／2 目录、20 次验证读回，原暂存 45 FD 与验证 17 FD 分别全部关闭，原厂前后核对通过。该暂存不准备 75 角色的新接收 core 根，也未启动 Boot、Owner、UI 或 RF。

随后唯一[接收 UI-v1 显示试验](results/formal-receive-ui-v1-ui-smoke-20261005-045441-6cffe245/RESULTS.zip) **FAIL**，SHA-256 `7fa522dc516f6eb3b6b5762e112ad97c78be96568f652d888f1f876ce7c5b416`；载体主机退出 0、远端退出 1，实际 component 为 session_failed。UI READY／Startup／guardian／原 UI 退出均未观察，claim0、无 Session、登记 FD 关闭、resource_pending=false，独立有限原厂核对正常；不把 Owner 或原厂恢复的默认 false 字段改判。就绪观察器到期未见 READY，未抓候选截图。

ROOT 与独立源码定位核对本次实际留存 bootstrap：薄 HOST 排列为 ordinary＋private＋helpers，但原 Runner 要求 ordinary＋helpers＋private；第 36 项实际 runtime35/p011_json，预期 mta-bluez-helper，必在 validate_payload 拒绝，早于 snapshot／preflight／stage。新 v2 薄驱动只修排列并增加原顺序合同，不改七源或时间限制；另外沿用原 private_assets_required 门，先用新运行图的无 RF 启动关闭入口准备 core，再考虑显示试验。截图观察必须避开原 preflight 的“其他 Python worker”拒绝，不放宽身份门。

05:00 失败后只读无线再次通过，仍 0 连接／0 广播实例、pending 无且未处置，有限原厂前后保持。本轮没有手机发现或点击窗口、文件传输或原厂文件改写。上一轮手机连接失败不改判，下一手机点击仍待新就绪；完整双向、TLS、实际用网恢复及初始化性能待，目标 active。

## 2026年10月5日 04:31 接收关闭专项和页面构建通过 页面实机接装中

上一轮手机“点击了，连接失败”保持原判。本轮只做 PC 开发、源码核对和一个受影响的真实 Linux 专项，没有 ADB、无线、UI 或手机试验。接收 Owner 的旧 HTTP 关闭检查会重复检查已关 socket 的数字 FD；并发复用该数字可能被误判为未关闭。新隔离修复保留原 socket 对象、原身份及真实关闭返回，封存后只查原回执，不误关后来占用同一数字的资源；原线程、Trial、恢复和授权门不替换为发送 Owner。

ROOT 唯一[接收 socket Linux 专项](results/receive-socket-close-v1-linux-contract-20261005-041002-4d8ee902/PC_RESULTS.zip)通过，1 方法、0.080 秒、主机退出 0，ZIP SHA-256 为 `5f7ca7a874f60675d152f99b6812216f33e506b0f346fe9147c7333d9c355463`。实际原接收方法覆盖 socket／非 socket 复用、封存后复用、真实线程及 HTTP 借用资源拒绝；不重测未变 minhttp，不签完整 Owner 或 P011 ABI。WSL 的用户会话启动警告保留在原 stderr，没有据此修服务或重跑专项。

三份接收 QML 已冻结并经 ROOT 和独立源码窄审：入口仅用一个真实 endpoint/token，直接接收 Host；默认接收页，保留真实来件 ID 的接受／拒绝／取消，以及 claim 后仍可停止接收。信息栏优先显示真实连接、接收和广播状态。接收目录只显示真实文件元数据，不留下未接装的“查看”按钮。ROOT 唯一[PC 页面构建](out/mta-ui-receive-v1-2c3d526c2d034da16e6c4a61/PC_RESULTS.zip)通过，ZIP SHA-256 为 `c254d21321ee2d4c93434125638d6b5a789f785c2705aa09df4d9676a02771bd`：9 个 payload 加 SOURCE 共 10 个部署文件、2 个目录；原 800×268 区域无额外偏移或旋转，候选只改原 NAV 槽，399 份其他 QRC 原字节及 ELF 槽外保持，原厂文件未改。SOURCE 为 782 字节、SHA-256 `f6825699bd8fd769bc6330754def7dda16effed4ec211e0e636e9166f50b3d53`。`BUILD_MTA_RECEIVE_UI_V1.cmd` 仅 PC 构建，每次新建独立输出，不部署设备。

新的七文件运行图和薄 definitions 已冻结，经 ROOT 和独立机械 diff 窄审。实际 Receive socket 修复完整接入，minhttp 与已验证版本同字节；双域 Executor、私有 manifest 链及原 75 项 payload 闭合，GO 根和手机 alias-clock 候选未变。[SOURCE 记录](results/formal-receive-ui-v1-source-20261005-042355-record-v1/PC_RESULTS.zip) SHA-256 为 `3f9c22a3af734e98c43c4a80f8cb6eb3249886e9201a991edc3069691b0f7729`。唯一机械／pin／7 源 AST 核验完成后，末尾记录脚本因局部变量遮蔽先退出 1；原工具输出保留，随后仅用固定 definitions 路径及 10 文件 pins 补读回，不重跑图或套件，不把首失败抹成成功。

真实接收 UI adapter、独立资产验证和薄载体继续制作：使用原 interactive 600 秒活动加 60 秒关闭配置，新增 20 秒无自动无线动作的显示出口，不改原 Trial、Owner、guardian 或恢复期限。新页面和运行图尚未上笔，不能签新 QML、真实状态接口、退出恢复、触摸、手机连接或文件互通。下一手机窗口仍须新“已就绪”和实际 READY 后点击，不选择、接受或发送文件；完整双向、TLS、实际用网恢复及初始化性能仍待，目标 active。

## 2026年10月5日 03:59 新性能候选启动关闭通过 手机连接仍待复测

ROOT 在[03:52 当前无线只读检查](results/receive-radio-baseline-device-20261005-035234-002c56d0/public-result.zip)中观察到两次一致的 0 连接、0 广播实例，固定 pending 不存在且未处置，原厂文件及进程保持有限基线。公开 ZIP SHA-256 为 `a73079db7650af29c39f7a495eacf9b4474ed27f01ec2e7d20abf6a94ec7b819`。这是当前只读状态，不回填历史恢复失败，也不是手机已退出页面的人工确认。

新增薄启动入口 `host/device_receive_alias_clock_startup_v1_check.py` 只把冻结服务 envelope 尾部唯一 `receive_trial_requested=True` 改为 `False`，并验证逆转后字节完全相同；alias 六源、原 runner、phone 入口和生产图不改。原 diagnostic 60 秒活动加 60 秒关闭期限保持，不套用 phone 的 600 秒活动配置；临时 HTTP listener 仅监听回环地址，不发业务 HTTP 请求，不启动蓝牙广播、扫描、Wi-Fi、UI 或文件传输，也不处置恢复记录。

ROOT 完整审读后唯一[薄入口 SOURCE 检查](results/receive-alias-clock-startup-v1-source-20261005-035418-a66a7629/public-result.zip)通过，ZIP SHA-256 为 `84341d94c7968d77458c6efc879685fcf8a3e4bef7d1bee6349c138fbcb7587c`；随后唯一[无广播 P011 启动关闭试验](results/receive-alias-clock-startup-v1-device-20261005-035425-ad8aec8f/public-result.zip)通过，ZIP SHA-256 为 `213dfeb789dd4a27d426916bb34e3003356a9baca71f3a70cf3ea2beced8337d`。原 `component.complete`、部署读回、Boot/Owner、Startup 和关闭均通过，原厂前后基线相同，2315 个已登记 FD 全部关闭，resource/staging pending 均 false；主机和远端退出均 0、stderr 为空。两份真实 Trial 均 requested=false、claim_count=0、无 Session，开始 reason=not_requested、结束 reason=owner_closed。83 个输入和两份目标源原样留存，公开 ZIP 只含结果及 README。

这一步未执行 Publication alias callback，不证明初始化提速、Trial ready、握手或手机文件互通。“点击了，连接失败”的上一轮原判保持。已通知点击候选准备完成，仍等待手机重新就绪，不自动重开窗口。并行制作实际接收 Owner 的 socket 关闭修复与接收页面接装；不会把发送 Owner 的通过证据直接代签接收 Owner，也不修改当前冻结手机候选。完整双向、TLS、实际用网恢复及真实性能仍待，目标 active。

## 2026年10月5日 03:42 握手性能候选已冻结 主机专项通过 待手机新就绪

single-variable alias-clock-v1已完成并经ROOT与独立源码窄审：Factory固定tmp别名内部metadata/readlink采用纯原身份/取消/期限clock，原StartupReadScope、路径入口及返回后祖先检查、每次private open/read/SHA/ledger/close的full now保留；无缓存、Trial/JSON/trace或时间上限修改。新增helper先纯核原函数/代码身份再调用，ReadOwner bound-self/function保持，不写原Trial计时账本。Factory82684B，SHA-256 `f6d2f343873903a7dc77b111be3a00b03796484e6247ffc4f2988b3bd553c9da`。

作者唯一[SOURCE](results/receive-alias-clock-v1-source-20261005-033833-0df2d40b/public-result.zip)通过，SHA-256 `3cbdf5ad3360422e18764e466666f46df8f1964299189db22e1586d38ade080e`：100保存输入、原75payload、6必要root/pin闭包；target1,996,232B/max行122，SHA `0703931726d163f1da3028646d4a0cb063039b4aa42ff278335a27f7b2ab87a7`，原Handoff/Trial/trace/progress-v2字节保持，不执行旧图或suite。

ROOT首项HOST合同因测试人工AST缺lineno报错（1方法/0.029秒、退出1），[派生记录](results/receive-alias-clock-v1-contract-first-ast-error/derived-observation.md)及当时SOURCE私有输入保留，不称业务失败或PASS。随后只补测试两处fix_missing_locations，当前test12396B/SHA `f4b6c39c7aecc63e107c9f7eecdca0ada5995c01c0d6dddc575c0df49ad31b4b`；作者做这两改与原保存输入的增量AST/逆转核对，不重六图SOURCE。ROOT仅重跑[同一受影响HOST合同](results/receive-alias-clock-v1-contract-20261005-033953-9f83396b/PC_RESULTS.zip)，1方法/0.039秒通过，SHA `8a6ee5452adccb1ead37a5fe8ade1276de2026e66f4c75c4fd4ef50a8d0aa042`；实际源算法在HOST fixture观察anchors23cheap+7full、private open前9full、full拒绝时无IO、换入函数调用0及Trial账本不写。不是设备性能或真实手机互通证据。

已询问用户是否方便再次手机点击并重新就绪，尚未收到回复。新设备入口 `TEST_MTA_RECEIVE_ALIAS_CLOCK_V1.cmd --check-device` 已准备，原600+60/120+15及恢复门保持；此新候选尚未上笔，无新广播/接收/文件传输，待手机明确新就绪后先新只读基线再唯一窗口，不自动接受或发送文件。UI-v7实机关闭/截图通过沿用03:23证据，不重复未变UI；完整网络/TLS/双向文件及真实性能仍待，目标active。

## 2026年10月5日 03:23 UI关闭修正实机通过 握手准备性能版制作中

独立deploy-v5/UI-v7最终源码已冻结，复用原19个UI资产，不重构建或再次暂存它们。ROOT唯一[Linux原FD/异常清理专项](results/formal-socket-close-v5-linux-20261005-032004-fcb8aa02/PC_RESULTS.zip)通过1方法/0.065秒，ZIP SHA-256 `b9c2087fb4ceb78a6ba750769ff3ce9a0c9943a391193028b38ca7c6aac50e57`；实际Linux覆盖socket与非socket重用、封存后重用不误关、同原helper拒绝及真实BoundedSemaphore容量恢复。这不是P011 ABI或完整Owner通过。

唯一[ordinary-v5实机文件暂存](results/formal-send-filecenter-ordinary-v5-stage-20261005-031649-5120bb55/RESULTS.zip)通过37文件/1,353,583字节，SHA-256 `dd103f92ada51c28d1519a1ed575266917b070bc7343f2982c001f56068a98af`；仅新隔离目录发布和原全pin读回，不启动Owner/UI/RF，不覆盖旧根。[03:16当前无线只读](results/receive-radio-baseline-device-20261005-031611-98c4061a/public-result.zip)通过，两次观察一致0连接/0广告、固定pending不存在且未处置、原厂有限核对保持；这不是手机已退出页面的人工确认。

唯一[UI-v7笔端20秒显示试验](results/formal-send-filecenter-ui-v7-ui-smoke-20261005-032022-dd260a8e/RESULTS.zip)通过，SHA-256 `808b1e6e9ad1b07811c29f4941fff1c51a4614b5f946fde78492e8adf7d4fdb4`。真实ui_ready、原Owner正常关闭、candidate/guardian退出、临时凭据移除、worker FD关闭、stock_restored与独立原厂前后核对均true，resource_pending=false，host/remote退出均0，源码保持。本轮34条原socket回执均实际badfd、None返回/原对象fileno=-1/原封存身份成立；设备这一轮没有观察到reused，重用分支的实际证据来自上述Linux专项，不混层。原v5/v6 FAIL保持。

ROOT的固定只读ready watcher确认当前候选仍活着后立即调用DRM读取，实际[候选页面截图](results/ui-scanout-v1-device-20261005-032054-aab5cf30/private-raw/scanout-0.png)为手机互传发送页，800×268区域内文字和两侧控件完整，原厂密码键盘不再绘制到候选区域外。退出后的[原厂截图](results/ui-scanout-v1-device-20261005-032136-56245c5d/private-raw/scanout-0.png)见原菜单、电量100%；原厂自有键盘/状态栏恢复到原场景，不把截图代替物理触摸验收。两图是原始480×800 DRM方向，私有图片不收入公开ZIP。本轮没有自动搜索、接收、发送、音频或手机操作。

接收握手仍按03:00证据定位在decrypt返回后的Factory new准备阶段，用户“点击了，连接失败”保持。源码下界为35固定源与WPA完整读取至少2534次full now；仅固定临时别名内部23步检查拟改保原身份/取消/期限的轻量clock，路径入口/返回后与每次私有open/read/SHA/闭门仍保完整校验，预计full now静态下界降为878（减少65.4%），不是已测性能。新隔离alias-clock-v1制作中，不混入Trial/JSON重构、cache、trace改动或延时期限。没有新手机窗口；完整Wi-Fi/TLS/文件及双向互通仍待，目标active。

## 2026年10月5日 03:00 已确认进入解密后Factory 准备阶段占时待优化

阶段观察v2唯一[SOURCE结果](results/receive-handoff-progress-120s-v2-source-20261005-024805-7c4b482b/public-result.zip)通过，SHA-256 `e6f834f517499d2096e79d369570166e6114c1b757c62df480b824617dcbb574`；94保存输入/原75payload保持，新runtime26305B，旧图/旧suite未执行。ROOT唯一新增DATA专项1方法通过（0.032秒），并经独立源码复核；这不是设备性能验收。

收到用户新“就绪”后，ROOT在[02:52当前无线只读](results/receive-radio-baseline-device-20261005-025202-6b2ceb60/public-result.zip)通过0连接/0广告、原厂有限核对及pending不变后，执行唯一[v2真实点击阶段观察](results/receive-handoff-progress-120s-v2-device-20261005-025255-4d71cc98/public-result.zip)，SHA-256 `7ce6851a1dadd782c5cbf473bb20c30e49ab4a570d298eea4cba8a2faa759396`。用户反馈“点击了，连接失败”；没有选择或发送文件。本轮整体仍FAIL/diagnostic_complete=true，listen1/advert1/p2p1，peer25.025秒；29.646秒起连续6个有效采样为executor exact/plain present/Factory started/active=true、phase=new，returned/authenticated/ended/success=false；原Bridge赋值顺序确认decrypt已返回并进入Factory，不再将本轮定位为Crypto尚未返回。至38.888秒仍在write之前的new阶段，15.010秒观察上限后自动取消，唯一trace96 cancelled，无136拒绝或已记录原生error。

Parent/deployment/claim仍未出现，不签Wi-Fi连接、TLS或文件互通。原Owner资源、FD2319/2319、能力actor、蓝牙原前后比较0→0及有限原厂基线闭合，resource/radio/Wi-Fi pending=false；网络前后原比较通过，但没有实际用网证据，不能签完整用网恢复。手机“连接失败”与本轮主动到期取消都保留，不能仅据手机提示断言协议拒绝。已要求用户退出手机页，尚未收到退出确认；P011窗口已结束，不马上重开。

源码的Factory new阶段包含35固定源/WPA重读、实时profile、目录身份和manifest准备，多个文件路径/读前后会调用完整Handoff→Trial校验；启动scope已保留实际验证的raw源。正在评估只在严格原身份/pin和取消/期限保持的条件下复用已验证数据及减少冗余校验，尚未实现或测得各步骤耗时；原trace每行检查可能影响时序也仍为未验证假设，不通过延长窗口掩盖。独立deploy-v5/UI-v7连接关闭修正接装进行中，原v5/v6 FAIL保持，下一UI实机与手机窗口不重叠。目标active，双向文件互通仍未完成。

## 2026年10月5日 02:41 握手已进入解密尝试 关闭正常 UI连接关闭首因已捕获

用户确认本轮“点击一次、停留约20秒后退出”，没有选择或发送文件。[握手进展实机结果](results/receive-handoff-progress-120s-v1-device-20261005-022338-adf9780c/public-result.zip)整体仍 FAIL，SHA-256 `c5b7ab137dd5e8d6a51d85d4afe6c80416574886a53627977387fe6799f780fa`，但诊断完成：listen1/advert1/p2p1，Handoff received/decrypt_attempted=true；旧 _check136 invalid_owner 未出现，唯一 trace 为到期取消后的 _check96 cancelled。首次peer后15.011秒到达原观察上限，claim/Parent/deployment均未出现。原Owner资源、能力actor和FD2327/2327闭合，原厂有限基线一致、蓝牙前后字段相等且连接0/广告0，resource/radio/Wi-Fi pending=false；网络原前后比较通过，但没有实际连接/用网证据，不能签完整用网恢复、TLS或文件互通。原自动phone字段保持，人工反馈分列。

原时间序列显示：首次peer22.193秒，Bridge started/running在23.724秒已观察，decrypt_attempted在26.783秒首次观察。开始尝试前已有约4.59秒，不能全部归给Crypto。Handoff在原生解密后还有授权校验；Bridge又在Factory返回后才创建Parent和claim，故本轮attempted=true/Parent=false不足以区分解密、最终校验或Factory准备耗时。下一薄观察v2只增加原 `_executor`、factory ticket、`_plain`存在布尔及有限Factory phase，未知保留unknown，不读内容，不改变120/15秒期限、原75生产图或授权门。

[UI-v6诊断实机结果](results/formal-send-filecenter-ui-v6-ui-smoke-20261005-023128-5d5c22ae/RESULTS.zip)整体 FAIL，SHA-256 `8359f8a70af7e924ffceecdf223ebe5ea13772344cd0e789f5b5031c9d47f80f`：真实ui_ready=true，33请求均ended但只有32行closed、一行closed=false/unknown=false，34线程均ended。首异常已保存为 ServiceOwnerError socket_close_unknown，链路 `_request→minhttp.process→_SocketRef.close`。FileCenter/loader/音频原字段正常，不代签Owner；owner_closed=false/resource_pending=true保持。candidate/guardian/凭据/worker FD关闭及stock_restored、独立原厂前后核对true。当前源码将历史数字FD再次要求EBADF，可能将并发复用误判为未关，尚待有限post结果确认；minhttp在close抛错后跳过workers移除和槽位释放是确定的清理缺陷。正制作独立deploy-v5/UI-v7，保原socket身份与关闭证明、区分FD复用，并让异常清理仍执行；冻结旧候选不覆盖。

UI-v6的DRM采样在20秒窗口结束后，ROOT所见仍是正常原厂菜单/电量100%，不能签v5键盘显隐或新页面布局。下一修正实机将就绪观察与截图紧接执行，避免错过窗口；不为截图重放未修改的v6。[手机退出后的02:25只读无线](results/receive-radio-baseline-device-20261005-022541-bff3523e/public-result.zip)再次通过当前0连接/0广告及有限原厂核对，固定pending未处置，不回填旧失败。当前无试验窗口/UI/文件传输，目标active；双向文件互通、真实用网恢复和物理操作仍待。

## 2026年10月5日 02:08 手机握手已接收 解密前校验与发送UI关闭仍待定位

用户确认“两分钟窗口内已点击并退出”。[本轮真实点击结果](results/receive-phone-discovery-120s-v1-device-20261005-015523-b6f644eb/public-result.zip)整体仍 FAIL，SHA-256 `50683bbcd1e14a130fd77d507e664dd7522fb2146a92a9cc8ead56c897118c3f`：listen1/advert1/p2p1，`handoff_received=true`、`bridge_started=true`，说明新的已知字段投影已实际接受手机握手；`decrypt_attempted=false`、`claimed=false`，首异常在 Handoff._check136 的原 DATA 授权门，不能签解密、CONNECT、TLS或文件。原helper/key/线程和FD2313闭合、有限原厂保持；原Owner/radio/Wi-Fi pending=true、恢复连接比较0→1，network_after缺席，旧失败不回填。

用户退出手机后，[01:57只读蓝牙结果](results/receive-radio-baseline-device-20261005-015726-b6e4bd25/public-result.zip)通过：两采样有效一致、当前连接0/广告实例0、actor闭合、有限原厂保持、固定pending文件缺席且未处置。该当前观察不代签上一轮Owner恢复。SOURCE窄读发现原观察器在首次peer事件即取消，而State取消先撤销Trial再置Event；解密前无锁_check可能跨过早期取消检查、在DATA门见到撤销并报invalid_owner。现有trace尚不能确定拒绝子条件，保留“竞态假设”，不放宽身份门。新薄观察候选在制作：保持总120秒、75生产图和600+60期限，只在peer后有界观察原worker后续进展再取消，不自动接受/发送文件，不在单独decrypt_attempted=true时提前取消。

02:19追加：新握手进展观察候选已冻结并[唯一SOURCE通过](results/receive-handoff-progress-120s-v1-source-20261005-021820-caabc090/public-result.zip)，SHA-256 `327fd6f540d0a58da8b67bbb2c0a757c0bf4cd6394571f5e0cdc446843368f3b`；92保存输入、原75payload保持，只有新观察runtime21406B改变，target1992694B/maxline122，旧图AST/执行与旧test均0。ROOT唯一新HOST专项1方法通过（0.039秒）：实际进展决策/截止表达式/peer分支和严格解析有限DATA合同；独立源码复核确认锁顺序、实际Parent字段、unknown/原finally边界。不是设备解密或网络验收。首次peer后最多15秒且不续原120秒期限，attempted-only不取消；native/failed/ended/request、或claimed+原F引用库存、或到期才原cancel/close。可能实际走到Parent/F Wi-Fi初始化，F引用库存不等于连接或恢复。已询问用户下一轮就绪，尚未启动新窗口；新一键 `TEST_MTA_RECEIVE_HANDOFF_PROGRESS_120S_V1.cmd` 仅在ROOT确认当前状态及用户READY后执行。

新版UI-v5两项受影响HOST逻辑通过，19资产/3目录4184498B已[实机暂存读回通过](results/formal-send-filecenter-ui-v5-assets-stage-20261005-020416-636f9f17/RESULTS.zip)，stage FD74与validator FD27/38次读回闭合，无UI/RF。随后唯一[20秒UI-v5实机](results/formal-send-filecenter-ui-v5-ui-smoke-20261005-020457-ea2a4a3a/RESULTS.zip)整体FAIL，SHA-256 `0f258fe57c123d23ec258ffa3d6eaae494ca7e5ac14b3abcb76c93650eb7c3fb`：真实ui_ready=true、没有已记录QML错误；candidate/guardian/凭据/worker FD关闭和stock_restored及独立原厂前后检查true，但owner_closed=false/resource_pending=true，GUARD_OWNER_UNKNOWN，最终关闭原因仍待窄诊断。首DRM截图发生在候选启动前，不能签新vk显隐或布局；[退出后DRM截图](results/ui-scanout-v1-device-20261005-020741-10f1e728/result.json)ROOT实际查看为正常原厂菜单、电量100%，不代签物理触摸。[02:07当前只读蓝牙](results/receive-radio-baseline-device-20261005-020741-ad64de38/public-result.zip)再次为连接0/广告0，无无线操作，不回填UI或接收失败。当前无窗口、UI或传输运行，目标active，完整双向文件互通尚未完成。

## 2026年10月5日 01:43 新根启动实机修复通过 手机看见但未点击

compat-v2六源机械闭包/两份清单的独立SOURCE通过，ROOT唯一两项新HOST目录表达式和两域manifest专项通过；已通过Handoff字段投影保持原字节，不重跑capture/旧suite。ROOT唯一 [v2实际设备窗口](results/receive-handoff-compat-v2-device-20261005-014010-0acc50a0/public-result.zip)通过，SHA-256 `99604441c5b4e55aad1787d8b6e6ffb6792f242e8809f5b6b969e5183ef99502`：启动只读与Owner真实通过、13.043秒观察到广播就绪、45.001秒机会正常关闭，host/remote0、stderr0；listen1/advert1/p2p0/error0/closed1/stop1。原资源/FD2313闭合，有限原厂前后基线保持、蓝牙比较字段全相等且连接0/广告实例0，Owner/radio/Wi-Fi pending=false。网络未使用，不能签用网恢复。

用户反馈“看到了没赶上”，只记录人工发现，未点击且无Handoff，不能将本轮窗口PASS升级为兼容握手/解密/TLS/文件或双向互通通过；自动phone字段保持原值。旧compat-v1启动FAIL和早前真实点击的Owner/radio FAIL均保留。当前无窗口或传输运行。

正在派生两分钟手机机会的薄观察包：只调整机会120秒、有限观察135秒/行数上限等匹配解析，不改冻结v2生产图、Owner600+清理60秒、15秒就绪要求、点击活动取消与恢复谓词。由于用户多次未赶上45秒，下一轮须再次就绪，实际READY后点击；不重复未改变的生产图全套检查。键盘v5仅PC候选在制作，尚无新的界面设备验收。

## 2026年10月5日 01:24 兼容解析专项通过 新根启动固定路径遗漏已定位

ROOT唯一运行新兼容解析专项 `python -B -m unittest discover -s tests -p test_receive_handoff_compat_v1.py -v`：两方法通过，实际新capture解析段和新manifest合同受测；不是完整Owner、加密解密或手机互通测试。独立SOURCE已通过5派生源逐字节及新构成，原75业务图与旧失败保存，未重放旧suite。

手机已就绪后ROOT唯一运行 [兼容v1设备首测](results/receive-handoff-compat-v1-device-20261005-012101-d990c1b3/public-result.zip)，SHA-256 `4e3f447824128d5f5566b2dc80a7cd069640ce91e4b2f06dffa89a6053ca3cfa`，整体FAIL。实际Boot已加载、Owner启动只读被调用但未通过，discover_start尚未调用，没有listen/advert/READY/握手或文件；host0/remote1/stderr0。原资源闭合、FD2315/2315和有限原厂前后基线保持，pending=false，不因此改判功能通过。

原raw有限ERROR_DETAIL确切为 Factory.startup_readonly1051→Executor._import_verified_sources420；ROOT核实际原Executor417–420仍写死`/var/volatile/tmp/p011-mta-formal-receive-v3/runtime35`，新Factory传compat-v1固定根而被source_invalid拒绝。这是隔离候选接装漏项，不是本次手机、蓝牙或解密故障。正在派生新compat-v2：仅换该固定来源目录并传播对应ordinary/private同一Executor及依赖pin，不加任意路径白名单；Handoff沿用已定向通过的字段投影。首失败及未知inner投影保留，不盲重试旧源。当前无窗口/传输运行，已告知手机暂不用点击。

## 2026年10月5日 01:12 发送界面真实启动与恢复通过 截图仍有布局待改

ROOT唯一新ordinary-v4/UI-v4默认SOURCE各通过，只生成受影响载荷/语法/预算，不跑旧suite。随后 [新ordinary暂存结果](results/formal-send-filecenter-ordinary-v4-stage-20261005-010618-96d7edef/RESULTS.zip)通过：37文件/3目录新建，1346543B、原FD342/342及carrier已闭，两前置sender27/observer41只读核验，pending=false、原厂身份和Wi-Fi保持；19UI资产未重暂存或重构建。

唯一 [20秒UI-v4实机结果](results/formal-send-filecenter-ui-v4-ui-smoke-20261005-010653-8aebb71f/RESULTS.zip)通过：真实ui_ready/原厂退出、candidate退出、Owner关闭、guardian退出、凭据移除、worker FD关闭及stock_restored均true、pending=false；host/remote均0、stderr0（push进度另存）。五私有日志取得，有限原厂文件/进程核对通过。没有自动RF、接收、发送或音频，不签触摸、网络用后恢复、父期限故障或手机互通；filecenter_parent_deadline_verified仍false不回填。

ROOT实际 [候选DRM截图记录](results/ui-scanout-v1-device-20261005-010728-fb013091/result.json)取得并查看，确为手机互传发送页，但父区域外仍有“请输入密码”的原厂键盘区域，页面文案和未接装接收功能仍待改。图片保持private-raw，不进公开ZIP；原DRM方向不作新增QML旋转。退出后 [原厂DRM截图记录](results/ui-scanout-v1-device-20261005-011152-e72695f2/result.json)实际查看为原厂主菜单，电量100%及时间正常；屏幕物理输出/触摸没有人工验收，不凭此补签。原UI-v2/v3失败仍保留，缺fcntl的依赖修正在本轮新Owner/UI启动链有实际通过证据，非完整互传完成。

接收Handoff兼容修正版仍在隔离接装（只投影七个已知字段、保原wire/加密校验）。当前无候选、发现窗口或传输运行；继续制作和当前受影响测试，手机待下一轮及时点击，不需持续留在搜索页。

## 2026年10月5日 01:00 点击首因确认 额外握手字段被本实现拒绝

用户已按READY通知点击一次，新的 [实际点击诊断ZIP](results/receive-handoff-trace-v1-device-20261005-005109-f1f9c7e8/public-result.zip)保留整体FAIL，SHA-256 d07db237f1fb58e177b7ed166709c56a401a226a0ae577111db676351067613d。实际listen1/advert1/p2p1，原capture首HandoffError invalid_event在165行，170为自身异常重新抛出。严格Base64、1..2048字节、重编码和原JSON解码已通过；原生接收首字符对象与p011_json返回类型相结合，首因可窄定为至少一个额外根字段不在七字段白名单，而不是“未识别的设备”标签阻止点击、解密失败或Wi-Fi故障。字段名和值未记录，不补造。P2pInfo.from_dict尚未执行、handoff_received=false、Bridge未启动、无文件/TLS。

真实恢复比较两次唯一差异为connected_devices 0→1；广告实例0及其他全部比较字段一致，原helper/reader/key/worker/reap和FD2319/2319已闭、有限原厂基线一致，但原Owner/radio pending=true仍如实FAIL。用户随后确认退出小米互传，[退出后只读结果](results/receive-radio-baseline-device-20261005-005327-47f7bc73/public-result.zip)通过，两观察有效一致、连接0/广告实例0、actor闭合、原厂保持、固定pending文件缺席且未清记录。当前无发现/传输运行；当前有限观察不回填原Owner整轮恢复。

ROOT当前读取的上游 [CatShare接收代码](https://github.com/kmod-midori/CatShare/blob/main/app/src/main/java/moe/reimu/catshare/services/GattServerService.kt)以JsonWithUnknownKeys解析P2pInfo，[JSON设置](https://github.com/kmod-midori/CatShare/blob/main/app/src/main/java/moe/reimu/catshare/utils/JsonUtils.kt)明确ignoreUnknownKeys=true；cattysend真实P2pInfo同为已知字段类型反序列化，非小米官方源码或认证。据此制作隔离兼容候选：忽略未知扩展，仅七个已支持字段进入原P2pInfo校验，保原wire及原密钥/来源/必需字段/长度/JSON边界，不猜扩展字段含义或赋予权限。尚未签新候选设备或互通。原helper停止未主动断开incoming Device1；全Device1 Disconnect会影响同一设备其他profile，正在独立SOURCE评估，不直接加入全局断开。

发送v4窄接装已完成，[受影响SOURCE结果](results/formal-send-observer-libc-v4-source-20261005-005111-a2a315cd/RESULTS.zip)通过25保存输入及逆转逐字节，原sender/19UI资产复用，5普通角色和机械root/pin改动；未跑旧suite或设备。首checker ASCII解码中文注释失败原件保留，窄修UTF-8后另通过，生产源未改。v4 ordinary37文件新根暂存和薄UI入口在制作，未签UI或完整发送。

## 2026年10月5日 00:50 发现名称已确认 新观察子程序实机通过

新的 [Handoff诊断窗口结果](results/receive-handoff-trace-v1-device-20261005-004233-1f728692/public-result.zip)实际通过45秒发现机会及正常关闭，host/remote均0、stderr0。用户反馈小米显示“P011／未识别的设备”，并明确尚未点击；人工发现另列，原自动phone字段不回填。native listen1/advert1/p2p0，trace事件为空、handoff未收到，不能签点击握手或收文件。原停止和Owner资源闭合、runner FD2311/2311、有限原厂基线保持、resource_pending=false；原蓝牙前后连接0/广告实例0，所有已观察比较字段一致，radio/wifi pending=false。网络未使用，不冒充用网恢复。窗口已经结束，没有传输运行；下一次必须在真实READY后点击一次，不能将窗口外点击算作本轮。

新诊断只投影原Handoff异常种类、代码位置及原恢复比较，不保存载荷、口令、地址、帧局部值或异常文本，不改原接收业务图。当前runtime为14820B／990cbf387893706e263abc43aa4fdc728782c4a0a88de531d5a1a53274862657。新SOURCE与真实HOST线程受影响专项各已通过；HOST线程夹具不代表P011回调，实机本轮没有触发Handoff。00:10点击后的原FAIL、Owner/radio未闭合记录仍保留，不由此次无点击的正常关闭覆盖。

发送端缺失fcntl适配已完成设备层验证：[41资产暂存读回](results/go-observer-libc-v1-stage-20261005-003513-20273db7/RESULTS.zip)通过，新建41文件/2目录共1442508B，stage FD131/131已闭；[实际Parent/child检查](results/go-observer-libc-v1-parent-20261005-003527-59ed2847/RESULTS.zip)通过，原collect/close、两个PIPE EOF、子程序退出0及reap完成，Parent持有资源已闭、pending=false，原厂身份和Wi-Fi保持。只改独立兼容根的Entry libc IO及根/pin，38资产复用原字节，不修改系统Python。首次薄HOST SOURCE因缺少纯literal辅助函数失败的原件保留，窄修后SOURCE另通过；不是UI或发送互通验收。正在将该真实通过的观察子程序窄接入新v4 Owner/UI，复用19项既有界面资产，不重构建或重放旧业务套件。目标active，完整双向文件传输尚未完成。

## 2026年10月5日 00:20 手机发现已确认 点击后的交接失败与恢复待核

用户已明确反馈第二轮“小米原厂互传出现新设备，随后点过设备”，因此本轮手机发现有人工证据，不再记为未发现。自动运行器的 `phone_tested=false` 原字段不回填，人工反馈与自动结果分列。第一轮 [45秒机会结果](results/receive-phone-discovery-v1-device-20261005-000619-22a9cb44/public-result.zip)正常关闭、pending=false，但用户未赶上，不能作手机验收。

第二轮 [点击设备后的原失败 ZIP](results/receive-phone-discovery-v1-device-20261005-000959-3f9fc9cf/public-result.zip)保留 FAIL，SHA-256 `cdd92f8a421db5236a1968a65116594b4caf50ff88c1ac8612a62ee6527227be`。实际广告就绪3.380秒，之后约10.029秒结束；真实 listen1/advert1/p2p1，handoff_received=false、Bridge未启动，没有文件接收或TLS传输。原 discover_stop 已返回，helper/reader/key/worker及runner FD2319/2319闭合、有限原厂基线一致，但Owner闭合未通过、resource_pending=true、radio_restore_pending=true、network_zero_known=false。Wi-Fi pending=false不代签整体恢复。停止请求、进程消失或普通Wi-Fi仍在均不能覆盖这个原失败。

SOURCE定位：实际 State.native_event 在 p2p 回调调用原 Handoff.capture 后捕获并丢弃异常；现有 raw 只保留终末 finish_owner→close，不能补造交接的首因。当前实际 Handoff 使用原 DATA ticket，而非旧v13的receive_available布尔门；不按旧源猜改准入。原蓝牙恢复核对失败会提前阻断零网络分支，因此 network_zero_known=false 本身不证明已改Wi-Fi。下一项是窄核实际DATA/协议合同并保留原异常与蓝牙前后匹配的有限投影，不直接重开无线、不清pending或旧目录。

用户已确认退出手机互传，ROOT唯一 [退出后只读蓝牙结果](results/receive-radio-baseline-device-20261005-002340-3ac3f871/public-result.zip)通过：两次原观察有效且一致、已连接设备0/广告实例0，观察actor及pipe关闭/reap，有限原厂身份保持。本次固定pending路径不存在，没有删除或修改记录；原phone报告的radio/Owner pending是当次恢复未证，不回填成通过。此次仅在独占新临时目录暂存固定只读helper并采样，没有扫描/广告/配对/断开/Wi-Fi/接收动作；两次当前观察一致不代签上一轮完整恢复。

发送端独立 observer-libc-v1 四源/41资产已完成最窄 SOURCE 检查与主审：只替换缺失fcntl的Entry IO ABI及根/pin，38资产原字节保持。下一项只暂存新独立根并真实验证Parent/child collect与close，不启动Owner/UI/RF、不改系统Python；本阶段源码通过不是实机修复或发送界面验收。目标active，采用边开发边实测，完整双向互通未完成。

## 2026年10月5日 00:07 UI首因已定位 缺少子程序fcntl适配

唯一UI-v3诊断实测仍FAIL：[诊断结果ZIP](results/formal-send-filecenter-ui-v3-ui-smoke-20261004-235552-03a1ded2/RESULTS.zip)。真实私有exception投影已取得，阶段停在sender_start，原链为Owner.start→_prepare_send_trial→ReadonlyDataParent.collect→_drain_and_wait第716行；该行确切为parent_child_failed，即真实两个PIPE EOF与wait/reap后子程序退出非零，不是UI绘制或主期限不足。原Owner未知/pending=true不改写；原厂文件/进程仍核对通过，候选和凭据没有启动/创建，五份私有日志取得。

SOURCE核对实际Observer41清单的Entry94，_LinuxIo.validate第115行仍import fcntl，而Parent libc-v1只适配了父进程。ROOT当前显式P011 transport只读执行`/usr/bin/python3.5 -I -B -c "import fcntl"`，实际ImportError: No module named fcntl。Entry main捕获错误直接return1不打印，因此吻合本轮child_failed；Loader/Body未发现同一fcntl依赖。正在制作独立observer-libc-v1的最窄4源码/41文件目录，先真实验证子程序collect/close，再接Sender/Owner/UI。不覆盖旧observer资产、不安装或替换系统Python、不扩大期限或放宽准入。

手机发现测试采用独立接收链路：真实广告就绪后单次45秒机会，原600+60 profile只构造一次，手机连接活动立即取消，不自动收文件。此时已启动首窗口并询问手机结果；实际手机结果与本轮末态恢复仍待，不因底层广播或窗口开启推导互通成功。

## 2026年10月4日 23:49 接收真实广播通过 发送界面首测失败待窄诊断

ROOT 主读锁忙修正版后唯一运行 `TEST_MTA_RECEIVE_ADVERTISE_SMOKE_V3.cmd`，实际 host0/remote0/stderr0：[接收广播结果 ZIP](results/receive-advertise-smoke-v3-device-20261004-234633-cac59c4e/public-result.zip)，SHA-256 `e6fe5dfac1f0f837813acc892dcb9c43d9417bb1acc5603ac47426ef10b889f1`。真实 listen1/advert1，观察期15秒内广告就绪；锁忙14次后原字段和actor身份核对通过，没有手机/晚到handoff。原 discover_stop 和finalizer完成，末态closed1/stop1，helper已reap/reader退出/closed、key闭合、worker退出，runner FD2319/2319及能力/Owner资源已闭，前后有限原厂基线一致、resource_pending=false。网络未使用且zero_known=true，radio/wifi pending=false；不是实际用网恢复、GATT/TLS/收文件或手机互通通过。原闭门component complete=false单独保留，新广告smoke complete=true不篡改旧谓词。

前一轮 [广告v2失败 ZIP](results/receive-advertise-smoke-v2-device-20261004-233309-dfbcf82a/public-result.zip)确实已调用 discover_start，但observer在100ms取状态锁失败时提前报 `observation_lock_unknown`，没有等到native事件。新runtime独立版本化，锁忙返回待观察并在原15/60秒绝对期限内继续；真身份/字段失败仍拒绝，全程锁忙仍失败。只补一项真实HOST Thread/RLock受影响测试与新SOURCE检查，未重放旧业务图/套件，也未覆盖前两轮失败。

固定发送UI19文件/3目录共4182242B已实际 [暂存读回通过](results/formal-send-filecenter-ui-v2-stage-20261004-233855-9a19f124/RESULTS.zip)：stage74/74、validator27/27 FD闭、19文件38次读回，原厂身份保持，无UI/RF。随后唯一 [20秒UI首测结果](results/formal-send-filecenter-ui-v2-ui-smoke-20261004-234351-f29fa9be/RESULTS.zip)整体FAIL：服务启动阶段未完成，ui_ready=false、未退出原厂/启动候选/无线，Owner闭合未确认、credentials_removed=false、resource_pending=true。实际guardian已退出、worker FD闭、原厂文件/进程前后核对通过；原失败不改为PASS。后续精确私有日志显示GUARD_OWNER_UNKNOWN与无音频producer，两份candidate日志为空；有限只读进程检查未见候选/guardian/Python，资产目录没有credentials.json。

本轮只读 [DRM截图结果 ZIP](results/ui-scanout-v1-device-20261004-234409-3fbef163/public-result.zip)核取当前scanout，主代理查看到原厂页面而非候选，不能签UI验收或物理触摸。原最内服务异常没有被当前日志保留，正在做仅阶段/有限异常投影的UI-v3，保持原cap、pending与同一19文件，不重build或盲重试。已询问小米15Ultra是否可进行发现阶段；手机双向文件仍NOT_TESTED，目标active、执行继续采用边开发边实测。

## 2026年10月4日 23:30 无无线启动诊断完成 本轮错误未再现

ROOT 主读新投影和薄 HOST 后，唯一运行 `HOST_MTA_RECEIVE_STARTUP_DIAGNOSTIC_V2.cmd --check-device`：[本轮脱敏 ZIP](results/receive-startup-diagnostic-v2-device-startup-20261004-232743-c8f4d998/public-result.zip)，SHA-256 `843003a3e4b99173afe0935b2609ac07e275a9f20e680c4b240304c296dd3557`。实际 host0 / remote1 / stderr0，诊断完成且来源保持；本轮 Owner/startup/两次 status 完成，原 trial START ready/available=true、claim0，END owner_closed/revoked=true。FD2319/2319、原能力 actor/Owner/只读基线资源闭合，前后有限基线一致、pending=false。没有 action、广告、扫描、UI、握手或收文件。

本轮未再现 io_error，inner projection 为 not_available；不据此推断首错误原因、标为已修或提升首失败。原 closed-policy component complete=false/remote1 仍保留；诊断完成不冒充设备互传 PASS。此前失败 raw 的新严格派生 [诊断 ZIP](results/receive-startup-diagnostic-v2-derive-existing-20261004-232605-043a0a71/public-result.zip) 明确 FAIL_STARTUP_BEFORE_RECEIVE，原记录未改。

接下来在真实15秒广告试验同次带原异常投影，以便失败再现时直接定位，不重复已通过的 startup-only 检查。发送 UI-v2 的 pin 切片已修，实际九源字节正向及错误数量/长度/哈希/顺序拒绝检查通过；资产暂存与20秒真实 UI smoke 入口在制作。屏幕只读截图入口也已 SOURCE 检查，通过后可在 UI运行时读取当前 DRM scanout，图片保持私有，不进入公开 ZIP。

## 2026年10月4日 23:16 接收广播试验在启动基线阶段停止 无无线动作

ROOT 已唯一实际运行新 `TEST_MTA_RECEIVE_ADVERTISE_SMOKE_V1.cmd`。本轮整体 FAIL：[原脱敏 ZIP](results/receive-advertise-smoke-v1-device-20261004-231318-830d3b8c/public-result.zip)，SHA-256 `e8e437868c2e402488104414d504a545de74afc1fb635d83198bf9776c1a7bf0`。实际 ADB host0 / remote1 / stderr0；原错误为接收 Owner 启动只读基线的 `ValueError: io_error`，定位到 `mta_client_baseline.collect` 第543行。Owner 未启动完成、trial START/END 均为 None，尚未调用 `discover_start`，没有广告、手机握手或收文件。原错误原因还需窄诊断，不把它猜成无线损坏、归档失败或期限不足。

实际原 component 的原厂文件/进程及前后有限基线一致，Owner 和两个能力 actor 已闭，所持 runner FD 2317/2317 已闭，resource_pending=false；这只签已观察的启动失败收尾，不冒充真实 RF 或完整网络恢复。HOST 又调用旧 trial parser 拒绝 None，故首报告保留 `observation_received=false` 和 `host_error=ValueError`。下一新增独立诊断解析原 raw，准确保留此实机失败，不为修报告重跑设备或放宽原接收门。

发送 UI-v2 的真实 ELF/QRC 产物已完成 PC 构建（不依赖 Docker），19 项资产、3目录、399 原资源及槽外字节保持。主审实际入口发现 FC9 pin 三元组切片错误，尚未部署；按这个具体问题补一项真实字节校验，接着制作薄 stage/UI smoke。UI/guardian、实际 RF、手机互通和双向文件验收仍待，目标 active。

## 2026年10月4日 23:06 关闭期限修正已接装 v3 并通过实机正常生命周期

ROOT 实际运行新 v3 SOURCE 一键，104 份来源保存/读回及改动图检查通过：[SOURCE ZIP](results/formal-send-filecenter-deploy-source-20261004-225501-21000000/SOURCE_RESULTS.zip)。从真实 v2 Owner 派生，固定 FileCenter 两业务源更新，原 close 传 `cleanup_until=self._cleanup_until_original`；新独立 sender/ordinary 根及 Boot→Owner→outer pins 同步，不替换 v2、旧域 Owner 或历史结果。FC9 为 99972 B，131072 B 上限及既有程序/载荷/行/时间限制未增加。

随后 ROOT 唯一实际运行新 carrier-v3 三批：

| 实际批次与脱敏 ZIP | 新建文件/目录 | 原 stage FD 已闭 | 实际库存 |
| --- | --- | --- | --- |
| [sender](results/formal-send-filecenter-stage-carrier-v3-20261004-230156-55c781cf/RESULTS.zip) | 27 / 3 | 91 / 91 | 独立新根 |
| [observer](results/formal-send-filecenter-stage-carrier-v3-20261004-230208-1421c67d/RESULTS.zip) | 0 / 0 | 133 / 133 | 41 项原库存完整读回复用 |
| [ordinary](results/formal-send-filecenter-stage-carrier-v3-20261004-230221-a88395f2/RESULTS.zip) | 37 / 3 | 342 / 342 | 独立新根；两前置、两服务父目录核对 |

三批暂存、字节/SHA/尾帧/内部 timer/承载 FD 关闭通过，pending=false，原厂身份及 Wi-Fi 连接保持。没有 Boot/Owner/UI/RF 业务启动；三份新承载两文件均保留，不覆盖既有库存。

再由 ROOT 窄派生实际 `TEST_MTA_FORMAL_SEND_FILECENTER_SERVICE_V3.cmd`，先默认 PC 核验通过，随后显式 device 真实启动 v3 Boot/Owner/State、原九源文件中心 create、立即原 close，通过。[实机脱敏 ZIP](results/formal-send-filecenter-service-v3-20261004-230530-dac85e6b/RESULTS.zip) SHA-256 `8f705af90bc034f8817d4e5f957ccde10edffc62b19f6447600370cadb3b8bca`。外壳2/2、Boot32/32、Owner71/71、目录链11/11所持 FD及两个能力 actor 闭合，Owner/FileCenter/State/HTTP/目录/外壳原关闭均 true、pending=false、timer释放；前后有限原厂身份保持、Wi-Fi连接，实际命令 host/remote0、stderr0（push进度另存）。实际调用包含新期限组件，但只签正常生命周期，不冒充 P011 持锁故障、guardian、物理音频、完整网络恢复或手机验收。仍不发行凭据/调用业务HTTP/UI/音频/收发/RF；初始化可能补建固定用户目录的范围不隐去。

发送 UI-v1 的真实接线已落盘；审查发现的 stopped 容器接口错误已修，唯一窄 PC 接口检查通过，明确 Audio/时钟模型边界、无 ACK/进程/设备。它仍拒绝未构建资产，不宣称可部署。后续独立 UI-v2 消费实际 v3 并复用本地纯 Python ELF/QRC 构建器，另并行制作真实接收短时广告/停止检查；接收可以先试，不等发送 UI 全成。手机发现、GATT、TLS、用户确认及双向文件互通仍未验收，目标 active、未完成。

## 2026年10月4日 22:45 新发送服务及文件中心实机创建关闭通过 期限修正版主机通过

ROOT 先实际运行新一键入口 `TEST_MTA_FORMAL_SEND_FILECENTER_SERVICE_V2.cmd` 默认 PC 核验，通过；随后唯一加 `--check-device` 实际运行已暂存 v2 Boot32/Owner/State，调用原 Owner 的九源 `create_filecenter`，立即原外壳 close，实机通过。[本次脱敏 ZIP](results/formal-send-filecenter-service-v2-20261004-224353-cfcbccc9/RESULTS.zip) SHA-256 为 `0220cb190d2bc338f3272fe75dfb8af02efc508e8e13a885e2845c7b8af332c7`。

实际 start/create/原定义核对均为 true，Owner、文件中心、State、MTA HTTP、目录与外壳原关闭检查均通过，resource_pending=false。外壳源 2/2、Boot 源 32/32、Owner 资产 71/71、目录链 11/11 个已持有 FD 核关闭；两个真实能力子进程闭合、MTA HTTP 请求 0/服务线程 1。内部 timer 释放，承载目录两文件稳定并已关闭载荷句柄。实际启动/承载/前后基线的 host/remote 均为 0、stderr 为 0；两次 adb push 退出 0，stderr 为传输进度、remote 退出不适用。原厂文件/进程身份前后保持，Wi-Fi 前后均连接。

本次不申请发送、不调用凭据/业务 HTTP、界面、音频、无线扫描或收发；不签全网络恢复或手机互通。正常构造可能创建固定用户子目录，此范围已在公报明确，不宣称设备零写入。v2 的原 FileCenter 仍未接父清理期限，正常关闭 PASS 不能代签异常锁等待或硬截止。

独立 `filecenter-deadline-v2` 已修 worker/actor/audio 锁等待、被动关闭检查、启动失败回滚及失败后查询/重试续期。新专项实际 [Windows ZIP](results/filecenter-deadline-v2-windows-20261004-224207-427a822b/PC_RESULTS.zip) 为 7 方法/5 PASS/2 POSIX skip；[Linux ZIP](results/filecenter-deadline-v2-linux-20261004-224208-92589543/PC_RESULTS.zip) 只跑三个受影响方法，3 PASS，均退出 0。实际持锁关闭约 78–109ms 返回；两种实际 POSIX 子进程 reader 故障约 200ms 父期限返回 pending、保留原对象；过期查询和重试不续期。首次 Linux fixture 绑定错误保留，修正后仅复测失败及受影响方法，不重放旧 v1。

这些主机测试使用真实锁/线程/HTTP/POSIX 子进程，同时含明确标记的 gst argv 与 Thread 故障注入；不是完整 Owner、guardian、P011 异常关闭或物理音频验收。新两业务源将从实际 v2 Owner 窄接装至独立 deploy-v3，不替换已通过的 v2 或旧记录；发送 UI worker 继续真实接线。手机双向收发仍 NOT_TESTED，目标 active、未完成。

## 2026年10月4日 22:26 目标卡 active 新服务与文件中心开始实际接装

本轮目标卡查询为 active，正文仍旧；执行顺序以用户后续指定及 [GOAL.md](GOAL.md) 的“边开发边实测”为准。下方旧 paused 记录保留原时点，不代表当前状态。

ROOT 本轮只读能力检查通过，[脱敏结果 ZIP](../../logs/MtaP011-Readonly-20261004-222618-974600.sanitized.zip)确认 P011 原厂文件/进程身份匹配且前后不变、Wi-Fi 已连接、ConnMan/BlueZ D-Bus owner 存在，无临时菜单/P2P socket；仍为 ARMv7/Python3.5.5、无 stdlib json。没有启动候选、无线或手机收发。

接下来直接验证已暂存 v2 的实际 Boot/Owner 与原文件中心构造、正常关闭，不申请发送、不调用音频或发行文件中心凭据，不把启动检查误记为互通验收。独立父期限修正版和发送界面接线并行开发，旧接收 worker 保持独立；不能将接收外壳直接换成发送外壳或伪造 receive_available。手机测试不因未完成的软件步骤而被整体禁止。

## 2026年10月4日 22:12 三批 v2 资产实机暂存通过 未启动业务或无线

ROOT 按新固定载荷分别实际运行 carrier-v2 的 sender、observer、ordinary，一键 CMD 和远端暂存均通过。三批新建资产共 105 文件、9 目录；另各有两份载荷 carrier 文件保留在独立私有临时目录。每次完整字节/大小/SHA 读回、原程序尾帧、timer 释放、carrier/FD0 及原 stage 所持 FD 关闭均通过，pending=false；前后原厂文件/进程身份保持，Wi-Fi 均连接。没有覆盖旧发送 runtime 根，没有运行 Boot/Owner/native helper/UI/RF 或手机传输。

| 实际批次与脱敏结果 ZIP | 新建文件/目录 | stage 持有/关闭 FD | 额外前置检查 |
| --- | --- | --- | --- |
| [sender](results/formal-send-filecenter-stage-carrier-v2-20261004-221014-b486f62b/RESULTS.zip) | 27 / 3 | 91 / 91 | 无 |
| [observer](results/formal-send-filecenter-stage-carrier-v2-20261004-221059-807bbef5/RESULTS.zip) | 41 / 2 | 131 / 131 | 无 |
| [ordinary](results/formal-send-filecenter-stage-carrier-v2-20261004-221106-0a25dde4/RESULTS.zip) | 37 / 4 | 342 / 342 | 两个资产前置库存通过，两个服务父目录核对 |

新正式发送与 FileCenter 图已经具备本轮资产启动条件，但这些 PASS 只签 files-only 暂存，不证明构造/播放/界面、发送准入、网络恢复或实际双向互通。接收原图此前的 observed-ready/原关闭仍为独立证据，不从暂存推导接收成功。下一阶段可在手机可用时先做临时接收界面及原厂发现/一份非个人小文件实验，同时推进新发送 Owner/FileCenter 服务启动和父期限接装；不等全部软件完成后才试手机。当前没有候选界面或无线收发运行，目标未完成，应用目标卡仍 paused/旧正文。

## 2026年10月4日 22:06 独立发送 v2 来源组装通过 尚未暂存

ROOT 唯一运行 `HOST_MTA_FORMAL_SEND_FILECENTER_DEPLOY_V2_SOURCE_CHECK.cmd` 实际退出 0，[新 SOURCE ZIP](results/formal-send-filecenter-deploy-source-20261004-220624-21000000/SOURCE_RESULTS.zip)通过，104 份当前输入保存并读回。新发送资产根为 `/var/volatile/tmp/p011-mta-go-send-filecenter-v2-assets`，普通根为 `/tmp/p011-mta-formal-send-filecenter-deploy-v2` 及其固定物理路径；observer-v85 原路径和载荷未改。发送 27 项载荷原字节 2402458 B，wire SHA 仍为 `7658efbe12a20b7fecb1302e90659cf64cab5157fb6268cb2cbd126a9a718ed0`；新 bootstrap 77540 B，SHA `0ee547c43e1eed5f8336f9108113f32daa95dfa8fe17c932f9a867e1c9abe9d1`。普通为 37 文件/1346297 B，observer41/1440449 B。

新增 Publication 的 ASSET_ROOT 同步新发送根；Boot、Owner、outer 和 State/Trial/terminal 的消费者/模块根及 pins 同步普通 v2。只核改动图和固定组装合同，不执行旧 HOST 模型或业务。原 stager 方法全文比较一致，变更为固定 profile 表/根和普通 pins；每 program/bootstrap2MiB、decoded/wire4MiB、256字节行、inner120/outer180等上限未增加。FC9仍为独立UI调用源，父期限候选未在本图接装。此结果纯电脑组装，不代签实际暂存、Boot/Owner/FileCenter/UI/RF或手机，下一步通过新固定载荷 carrier 做 files-only 实机暂存。

## 2026年10月4日 22:01 CLIENT 归档后接收资格观察已就绪

ROOT 唯一直接用 Python 运行 `host/device_receive_admission_observe_v1_check.py --check-device` 服务模式，未双击 CMD；一键入口为 `CHECK_MTA_RECEIVE_ADMISSION_OBSERVE_V1.cmd`。[实际脱敏 ZIP](results/receive-admission-observe-v1-service-20261004-215951-eb75ba91/public-result.zip)分类为 observed-ready，观察层通过，SHA-256 `c81617fc4b500c915cc75d82a13bff8eebacb170e49a9105118c58665907b932`。START 的 requested/available、startup/probe/radio/network 与 barrier_clear 均为 true、reason=ready；claim_count=0、没有 Operation/Session。END 为 owner_closed/revoked、available=false，仍为零 claim。原 Owner、启动采样、两个能力进程与运行器的 2319 个持有 FD 均核关闭，前后有限原厂基线一致，资源及暂存 pending=false。

此次重用原 75 项载荷、原业务 runner 与 TARGET_SERVICE，没有改 complete 或业务门禁，也不重跑旧模型/角色 AST/HTTP smoke。实际 host0/remote1、stderr0、component_complete=false/gates_remained_closed=false 原样保留：旧 runner 专门签“资格始终关闭”，因此资格就绪不满足其旧闭门 complete；新入口只按真实准入状态、关闭和基线分类，不将原 remote1 伪改为成功退出。运行器确已调用 Boot/Owner，本次没有业务文件/目录创建、界面、HTTP 动作、扫描、广播或收文件。观察层 PASS 不是 RF、完整网络恢复、手机或真实接收 PASS。

手机可用性已向用户询问，未从未答复推定可操作；尚未开接收窗口。发送侧继续独立 v2 资产根接线，解决接收子集与完整发送共用旧根的库存合同冲突，不处理旧目录。最终组合 UI/FileCenter、父期限接装、真实手机双向互通与收尾仍需推进，未宣称只剩人工测试或目标完成。

## 2026年10月4日 21:55 发送旧资产库存差异已只读确认

[本次实机只读结果](results/sender-top-inventory-20261004-215535-3eac1dcc/result.json)观察固定旧发送根的直属库存两次，稳定且 top_exact=false：实际只有 runtime 一个目录，要求的 native、source-manifest.json 不在顶层。命令 2665 字符，没有大 stdin 回退；host/remote 均 0，5 个持有目录 FD 均关闭，未读文件内容、未写设备、未启动 RF。历史 stage 日志没有保留异常 code，仍不回填；当前结果独立证明当前 existing_conflict 条件。

接收候选 runner 的 GO_ROOT 恰与该旧根相同，源码 inspect_root('go')/stage 只要求 deployment 的 runtime 子集；这解释了接收与完整发送资产的目录合同冲突，但不是旧目录创建者的实机溯源证明。新发送候选将改用独立版本资产根与普通运行根，保留旧根，不凭本次 CLIENT 归档授权处置它。接收侧继续观察未改业务图的当前准入与关闭事实；尚未开启无线接收或手机互通。

## 2026年10月4日 21:49 两个 CLIENT 条件归档通过 发送载荷通道已实测

用户本轮已明确授权两份固定 CLIENT 来源的条件核验、备份与归档。21:34 的[实际结果](results/client-source-archive-v1-archive-20261004-213443-5ebfe35a/result.json)通过：62 文件、8 目录、4548465 字节来源/元数据/完整 SHA 核对及当前相关进程、控制目录和锁检查满足本入口范围；电脑原样备份与私有 ZIP 核对通过。随后重新核验，执行两次精确 rename，两次返回和归档读回均通过，原 CLIENT 根已空。没有删除数据或处理其他目录，没有启动服务、无线或接收。电脑备份为本结果目录下 private-backup/originals.private.zip，含项目原件，仅本地保留；设备归档位于易失目录，长期恢复应保留电脑备份。进程采样未覆盖所有 FD，不能宣称完整排他、排除并发竞态或证明历史网络恢复。

[脱敏归档 ZIP](results/client-source-archive-v1-archive-20261004-213443-5ebfe35a/public-result.zip) SHA-256 为 `226ec18b364af2779e723ae8752f58612c844e817f01854f5aa9009e1e30227d`。实际 verify/archive 的 host 和 remote 均为 0、stderr 均为空；两次 adb pull 的 host 为 0，stderr 是传输进度，remote 退出不适用。备份 SHA 为 `0e6205297a34c2c9a7d168c2c6bd812c061ca82742203c6c49391a00c82224f7`。归档成功不代签接收准入、恢复或手机互通。

发送部署另新增固定文件 carrier 适配，仅传输暂存程序和载荷，不自动执行业务 Boot/Owner/native/RF。保留三次实际实验：21:36 自身 mkdir 改变父目录 nlink，旧关闭比较误拒；21:38 已传输文件，但 Python 3.5 的 dup2 返回 None 与标准输入 closefd=False 使启动守卫误拒。分别窄修关闭父目录身份比较与实际 FD0 关闭核对，失败原件未改。21:40 的[真实 ARM 结果](results/formal-send-filecenter-stage-carrier-v1-20261004-214042-70868902/result.json)已通过载荷/程序 SHA、尾帧、外层 timer 释放及 carrier/stdin/原 stage FD 全部关闭，原暂存程序确实执行；整体仍 FAIL/stage_refused，业务创建文件和目录均为 0，现有库存未被覆盖。当前诊断重点是固定旧发送根的直属库存是否匹配，不从仅有 StageError 类型补造历史错误 code。

[本次发送结果 ZIP](results/formal-send-filecenter-stage-carrier-v1-20261004-214042-70868902/RESULTS.zip)仅签实际传输和拒绝事实。原厂文件/进程身份保持，Wi-Fi 前后均连接；载荷 carrier 与中间失败目录保留，不自动清理。没有运行手机接收/发送、无线发现、界面或重启。下一步是只读定位库存差异，并观察 CLIENT 归档后原接收服务准入；不得将旧 checker 期待 client_history 拒绝的 PASS 谓词直接当作当前成功标准。FileCenter 父期限接装、组合 UI 与真实双向手机验收仍待。工作区按新目标继续当前请求，应用目标卡仍为 paused/旧正文，未由工具修改。

## 2026年10月4日 21:16 当前占用检查通过 暂存入口发现旧 ADB 限制

21:12 的[固定来源进程只读结果](results/client-source-proc-readonly-v1-readonly-20261004-211209-fd629605/public-result.zip)通过：197/197 进程 exe/argv 已观察，无读取未知或上限命中，进程库存前后稳定；固定来源路径匹配 actor 0，现场现存锁身份 1、/proc/locks 完整读取且匹配锁 0，固定目录稳定、原 FD 关闭。仅匹配 actor 才检查 FD，all_process_fds_scanned 仍 false；不能说扫描了全部 FD、完整恢复或接收准入。

21:16 唯一运行新资产暂存入口 sender，结果[整体失败](results/formal-send-filecenter-stage-v1-20261004-211644-3fe6f8e7/RESULTS.zip)。ADB 明确返回 `device only supports allocating a pty`，channel 和只读 after 均是 host1/stdout0，实际暂存程序未执行，stage_invoked=false，无候选资产写入。原失败/远端 unknown 不回填；该失败定位到旧 ADB 通道限制，不是业务暂存通过。独立 carrier 入口正在适配：固定程序/载荷用新私有临时目录承载并核验，不将大数据写入 PTY，仍不启动 Boot/Owner/helper/RF。

用户随后已明确允许仅两个已识别 CLIENT 目录在来源/当前占用核验满足后原样备份并归档。预期固定范围为 62 文件/8 目录、4548465 B；当前仍未实际备份或移动。先逐文件实机核验、PC 私有备份及读回，再重核现场库存与占用；未满足就停止，不删除、不扩到其他目录或启动无线。

## 2026年10月4日 21:01 CLIENT 来源已识别 新部署载荷通过 PC 检查

按新目标实际继续只读实测和实现。CLIENT 首次元数据采样没有完成长单行输入，远端 alarm 退出 142；[首轮原件](results/client-history-readonly-v1-readonly-20261004-204635-4aabdc22/result.json)保留，不改为通过。仅修主机传输为 256 字节短片段，并独立保存真实远端退出后，[第二轮元数据采样](results/client-history-readonly-v1-readonly-20261004-204952-689d3968/public-result.zip)通过：固定根稳定、两份条目、原 FD 已关闭、P2P pending 缺席，没有修改历史或启动无线。

20:56 的[四份清单只读采样](results/client-source-metadata-readonly-v1-readonly-20261004-205654-2bdd781d/public-result.zip)通过，host/remote 0、stderr 0，两个 ctrl 目录条目和套接字均为 0。已有私有原件与本地固定生成格式对照：v40 为已识别的 static-source-not-ready 清单，8 项部署/准入/RF/收发/手机布尔声明全部 false；v11 为已识别的旧初始化部署数据，但其旧入口可能执行实际初始化。清单是 DATA，不证明设备 runtime 字节、当前 actor 缺席、恢复或接收准入；没有 journal.json 也不能补签这些结论。原 Barrier 仅因 CLIENT 根非空就拒 client_history；尚未改变旧门禁、删除或归档旧条目。

21:01 ROOT 首次运行[独立发送/文件中心部署 SOURCE](results/formal-send-filecenter-deploy-source-20261004-210122-75000000/SOURCE_RESULTS.zip)通过：104 份输入保持，三批固定 bootstrap/wire 已生成，普通组合使用新的版本化根；不覆盖不同或部分旧资产库存。Linux HOST 聚焦关闭消费测试首次通过，1 方法/4 子例/退出 0，真实非零 FD 经原 stager 单次关闭后返回 errno EBADF，并由新 bootstrap 被动读回接受；None 和 EPERM 仍拒。该测试没有执行 Stage.stage、timer、Boot/Owner、设备或 RF，工具输出是测试记录，未制作独立测试 ZIP。

独立 `candidate/filecenter-deadline-v1` 已将父绝对清理期限传到主要 HTTP/音频等待；专项 Windows 6 通过/2 POSIX 跳过，WSL Linux 8/8 通过，超时保留原资源并报告 pending。它尚未接装上述部署图，完整 Owner 组合、音频物理输出及 P011 关闭均未验收。窄源码复核仍发现 worker/actor/audio 锁获取没有 timeout，Audio.play 启动异常的原 2+1 秒回滚与 reader 已启动分支未接父期限；不能称整个关闭具有严格硬截止保证。

下一项有效试验是固定 CLIENT 来源的当前进程占用只读检查，以及上述固定临时资产的真实暂存/读回。当前没有开启手机接收窗口，真实双向互通、生产接收准入和完整恢复仍待，不称仅剩人工测试。

## 2026年10月4日 20:39 按新目标继续 设备只读基线通过

用户已再次明确要求继续执行，本轮按“边开发边实测”的新目标推进，不因应用目标卡仍为 paused 而停止当前已授权请求。该卡旧正文和自动续跑状态未由工具修改，不能将当前执行报告为目标卡恢复。

P011 与模拟器同时连接，实际入口按 P011 product/model 单独选择 transport 3。20:38 的[接收前置只读结果](results/receive-prerequisite-readonly-20261004-203812-943e6f51/result.json)完整双轮通过，原厂文件/进程身份匹配、网络文件/进程和接口身份保持；已知项目 actors 为 0，无 P2P pending、自有接口、UI/native 锁或临时菜单。报告中的 observed_blockers_clear 只覆盖该检查的范围，不含 CLIENT 历史条目分类，也不证明接收准入或完整网络恢复。

20:39 的[只读能力结果](../../logs/MtaP011-Readonly-20261004-203907-112993/result.json)确认 Wi-Fi 已连接、ConnMan/BlueZ 有 D-Bus owner，原厂身份匹配且前后不变；仍是 ARMv7/Python 3.5.5、无 stdlib json。iw 不可用、wpa modes 仅返回 AP，不能由此否定已另行实测的 P2P 能力。本轮两次入口都没有设备写入、RF/连接动作、重启或旧记录处置；手机互通仍 NOT_TESTED，原始 stdout/stderr 和退出记录留在本地私有目录。

当前并行步骤：读取固定 CLIENT 历史目录的实际形状/记录状态以定位空库存拒门；补新发送/文件中心组合的独立部署根与库存接线；修正组件等待未按父绝对期限裁剪的接点。不为普通相关只读诊断另设授权关卡，但不会删除、归档或绕过未知记录，也不因这些软件步骤未全部完成而阻止独立可测阶段。

## 2026年10月4日 执行方式更新：允许边开发边实测

用户已取消“全部软件完成后才推进到仅剩人工手机测试”的前置要求。今后按小段实现、风险相称的必要检查、有限实测、根据日志修正的顺序迭代；P011 或手机试验可以在功能尚不完整时进行，已通过且未受影响的证据不重复验证。最终双向互通、原厂保护、安全落盘及恢复的验收要求不变。普通任务相关只读诊断可先行，不能仅由历史目录非空推定活动会话；既有记录的归档/删除/覆盖授权仍不得扩大。

完整生效目标和边界见 [GOAL.md](GOAL.md)。本次只修改执行政策，没有新增设备或手机测试结果，没有部署候选、处理 CLIENT 记录或改判历史结果。应用目标卡本次查询为 `paused`，旧正文尚未由应用侧修改；工作区目标更新不代表目标卡已经恢复。下方带时点的“active”“仅剩人工”及“只读分类许可尚待”等表述保留为当时记录，当前迭代方式以本节和 GOAL 顶部为准。

## 2026年10月4日 20:10 发送与文件中心组合 SOURCE 通过 未部署

ROOT完整阅读新checker/CMD、组合Owner与新增关闭检查，首次唯一运行 `HOST_MTA_FORMAL_SEND_FILECENTER_SOURCE_CHECK.cmd`，实际外层退出0。[新SOURCE ZIP](results/formal-send-filecenter-source-20261004-201008-160a4f06/SOURCE_RESULTS.zip)1261 B / `eaa1bd3ea2f753876f0baa2772a6e3e0eea807711f0e97b16ab49a4e33f467f5`。52份输入原样保存并读回；纯AST核三个新源码、旧Boot/Owner/已通过duplex外壳三个合同及原FileCenter recipe，不导入或运行这些业务源。普通32角色只有storage由14335 B升级到原DirectoryBinding源55562 B，其余31源未改；普通源码1078024 B，FileCenter9源仍91295 B/原131072 B上限。新Boot除说明和该storage pin外AST不变，新outer除Boot/Owner两pin外原字节不变。原Boot10秒、每源2MiB未提高；本SOURCE不组装程序或wire。

冻结的新图位于 `candidate/formal-send-filecenter-v1/runtime`：Owner82369 B / `4772f6975f8f09699e4dcf269a6ed4bdbb7a6ac429b8dca03a3a1193745a4fce`，Boot19511 B / `bcef49b2cf70565725eb7e853183be64f6d07f91133bea81a1e845f636ad0631`，outer24023 B / `c5e9f1d1ec2c2cc7bc722769e1c701a8d5a7c6102ac92ccd6d9c66d00123fee7`。checker16493 B / `cca631ec5705637b0d392450980752eafc5ce5ac710e1923bcf702a93504b051`，CMD395 B / `3d827217e934459464d04e17544c36d3ec0c5fbef986e1e4d93a453b13d0d63c`。原SOURCE/HOST通过图与历史结果未修改。

实际源码新增固定九源FileCenter创建入口，真实持有user/Received的原DirectoryBinding及原State/Server，创建前保留原Companion。关闭先FileCenter/media/audio，再传输服务，最后目录；后续Received初始化失败不再抑制先前完整user目录的已知关闭。部分创建保留原子对象、FD与原错误，仅可认证原件才尝试原关闭，未知仍pending且不签全闭。独审另发现成功创建路径漏核store/socket子资源，已在本次SOURCE执行前补齐：先保留原Store/Socket/两个FD及元数据，关闭前核原引用和live身份；关闭后必须同一原对象rootfd=None/fileno=-1且两个原FD实际EBADF。最终窄审已核该修补及outer字节一致；修补前79831 B/48b17身份没有通过记录，不能代用为最终源。

这份结果只证明固定源码合同与身份，不证明上述构造/关闭路径实际运行成功。checker trace与decision原件保留，business/device退出为NOT_RUN，报告runtime/graph/Boot/Owner/FileCenter/guardian/Native/RF/P011/phone/restoration/admission均False；没有业务stdout/stderr或持久化CMD原退出文件，不补造。当前未改ADB、设备文件、无线或CLIENT历史。

随后独立PS/.NET纯读核52份expected/current/inventory/snapshot，合计1501949 B逐文件原字节/size/SHA差异0；20固定来源身份和ordinary32实际pins均一致。result38字段1094 B、trace90 B及原decision0/两项NOT_RUN逐字节匹配，所有未执行标记保持False。ZIP仅result.json1094 B与README.txt1077 B，解压与相邻原件相同，独算CRC为f6d9bd06/b078e83a。ROOT也只读核52份原件和ZIP双成员一致；未重跑检查器或业务，不补造独立CMD退出原件。

真实产品接点仍待：独立版本化target root与stager接入新库存（现有stager仍指旧图，原canonical ROOT只是SOURCE合同，不准覆盖不同旧complete库存）；固定发送UI接同worker原FileCenter及真实audio guardian后再发行独立凭据；父层原绝对期限接入发送/接收worker切换；原Companion组件等待的父期限裁剪、整组构造与部分失败收尾、生产归档消费者及最终实机/手机验收。目标active，不能称只剩人工测试。最新实机接收拒门仍沿用16:21的client_history，不从目录非空推断活动状态，窄只读分类许可尚待；GO64授权仅对应16:16已完成的单记录归档和16:20回查，不扩到CLIENT。

## 2026年10月4日 19:44 发送启动真实定时器与输入 HOST 通过

[新HOST ZIP](results/formal-send-stage-bootstrap-timer-host-20261004-194411-1e2ca752/HOST_RESULTS.zip)通过1个新方法/3个固定真实子进程。三组均在电脑WSL Linux x86_64/root/Python3.13直接执行19:29的固定bootstrap，真实PIPE传入各批原wire，SIGALRM/ITIMER_REAL、monotonic与线程原语没有模型替代。原framed end确实验证；实际保留原stage/错误对象、outer180/inner120原期限，结束时getitimer真实清零且handler为SIG_DFL。每个被测child仍是原SystemExit(1)、原StageError('platform')，方法/WSL/checker/外层CMD才为0；这是预期的非ARM平台拒绝，绝非P011暂存成功。实际暂存FD、文件写入及目录创建均0。

17份当前/保存输入保持原字节。测试12152 B / `762a0283a579def26fc5612c1fa938e48e9b40e9a2e2fe04eef8d0d92f64056e`，最终checker16735 B / `475d6ef3a4aa87b4bbf9de7a2b26a8b4785ec4429c81ef83a8e8cd26b3526721`，CMD392 B / `d3a4d9e9a6c0a39cf2a80c50d0aff9d61f6559322e6651ffbaabb381328b9b00`。ZIP2072 B / `1d1cea83cd9a6f8bcf2810e30a61d0f973bcdbef4bb5771107740cf5038a2c47`。完整外层stdout1882 B / `fbafcb988d98cc7a120733de28b607c7efe4159aff47dd1e521d7851d920b7f1`、stderr225 B / `fa18444489303bf10e507d662921d60194d84f6c68353b0cd0f6b8ed39619518`和三个child独立raw/原退出均保留；Ran1/OK，不重跑旧方法/生成器。公开ZIP仅result.json/README.txt，device-exit原NOT_RUN_DEVICE/reportnull。

两个首轮SOURCE失败目录 `formal-send-stage-bootstrap-timer-host-20261004-194054-748f696e` 与 `formal-send-stage-bootstrap-timer-host-20261004-194302-a69aaa37` 保持原FAIL，均未执行WSL或child。实际只读诊断分别发现Windows Path.stat/fstat ctime语义不同、CMD扩展名导致跨接口mode许可位不同；仅修电脑checker：同接口前后仍全9字段一致，Windows跨接口核dev/ino、文件类型、uid/gid/nlink/size/mtime，Linux跨接口仍全9。原wrapper、data、test、wire及全部业务源未改，不放宽目标平台或Linux权限。

该HOST不等待180秒实际到期触发，也不证明物理stdin EOF、ARM完整stage、业务Boot/Owner、Native、RF、P011页面、手机收发或恢复。30秒HOST子超时只是自身containment，90秒WSL外层超时同样unknown，不能借kill签关闭；本次三child正常按原退出终结，未kill。新的 `HOST_MTA_FORMAL_SEND_STAGE_BOOTSTRAP_TIMER_CHECK.cmd` 仅电脑范围。完整目标active；发送FileCenter组合Owner及最终UI/模式切换、生产归档消费、独立版本化部署和实际手机验收仍待，无新CLIENT权限或设备动作。

19:54独立PS/.NET只读复核完成：17项expected/current/inventory/snapshot集合、完整字节、尺寸及SHA全部一致；外层raw、三个原退出0和Ran1/OK对应。三child各18项私有原件精确匹配，原exit均1、stderr0，最初unknown事实保留，验证后的stage/bootstrap整dict与原marker一致。真实timer清零、默认handler、固定尾帧与非ARM平台拒绝确认；timeout/containment kill均False。ZIP仅result.json3420 B和README.txt1258 B，解压原字节相同，独算CRC为4c55f6be/6583f848。两个旧SOURCE FAIL仍为false，输入0/16、child未执行。独核没有运行或编辑源；CMD0是ROOT工具观察，没有额外持久化CMD原退出文件，不补造。

## 2026年10月4日 19:40 父绝对期限接口实现并通过 HOST

新独立 `candidate/duplex-window-v1/runtime` 的发送/接收runner已实现必填父活动/清理绝对期限：只能使用父首次创建窗口的剩余时间，活动上限仍600秒，清理期限合同严格为父活动截止加60秒；诊断profile仍最多60秒。保留原父双float、父tuple、profile截止和window tuple，子期限按较早值裁剪，不重置Trial或续期。原Boot/Owner/目录/业务/Native方法和pins未改；尚未接装最终UI，不能称重复手机接收已可用。发送result里原window_seconds仍表示600/60 profile上限，不是已裁剪的实际剩余；后续正式UI必须读取实际until显示剩余，不能按该标签重新计时。

[新HOST ZIP](results/duplex-window-host-20261004-194054-affdd24c/public-result.zip)由ROOT实际执行新 `HOST_MTA_DUPLEX_WINDOW_CHECK.cmd` 通过，child/checker/外层CMD0，6份保存输入，四组固定检查，旧方法0。真正执行新完整源码定义的constructor/window_current/check，使用电脑真实monotonic、线程、PID和未启动资源库存；验证两发送/两接收worker共享原绝对期限、诊断较短上限、无效/过期/非有限/过长父期限拒绝、原tuple或值变更拒绝。纯Python3.5 AST核只改两个constructor/window_current及run_fixed，加接收math导入；其余业务定义未改。没有执行start/run_fixed/run/close、Boot/Owner、服务、暂存、RF或设备。ZIP1146 B / `00e7def1d7dd43dd780fac207229496b40b8a586d9c8b5eb270b75345472038f`；stdout305 B / `6fd51116ec7dc7de07d06f16d569a7533a0abe389511e8a24f9b142153cc558f`，stderr0，remote NOT_RUN_DEVICE/report null。

首轮结果 `results/duplex-window-host-20261004-193830-d09f572f` 保持FAIL：SOURCE审计发现接收副本漏math import，child尚未调用、raw为空。仅补该导入并更新两个新pin后受影响复测通过，不重跑旧HOST。新接收82938 B / `bc176c2d74671dbbddac1dab9cfe5e2567d358b873241342ae5fb169334bd9a1`，发送24023 B / `154a073f88d50c4c71ec7562f830f4e91a459e7e67508a7e24369611df1964e7`。此结果不签父界面producer、完整worker切换、生产归档消费、P011或小米15 Ultra互通。目标active，CLIENT历史权限未扩大；发送FileCenter真实组合Owner正在制作。

## 2026年10月4日 19:29 发送有界启动源码组装通过

[新SOURCE ZIP](results/formal-send-stage-bootstrap-source-20261004-192915-8da878a7/SOURCE_RESULTS.zip)由ROOT首次执行新 `HOST_MTA_FORMAL_SEND_STAGE_BOOTSTRAP_SOURCE_CHECK.cmd` 生成，外层退出0，101份输入保存并读回。原90份SOURCE输入、三个原program和wire逐字节复用，不调用旧生成器或重新执行旧测试。ZIP1652 B，SHA256 `30e326f8648727d6c23d3f1974ae24f84a5d54ce1087f1030d5cd3ddba98350d`，仅公开result.json与README.txt。

新 `candidate/formal-send-stage-bootstrap-v1` 实际wrapper只接受三个固定profile，无任意source/path/deadline接口；stdin只交给原wire reader，不作为源码输入。首次原monotonic创建outer180绝对期限，拒绝既有SIGALRM handler/timer，然后建立真实ITIMER_REAL再调用原程序；原inner120保持，读帧后只恢复原outer剩余。原STAGE_RESULT、SystemExit和错误对象保留，固定尾帧不冒充物理stdin EOF。只在原stage库存已知关闭且原FD实际EBADF后释放自有timer；未知库存继续pending，不盲目补close或续期。默认main无暂存动作，CMD仅PC SOURCE。

数据模块69849 B / `f2c1e165a4e4394365d30ffac9d7fc28d3ab03f4573cbbfba5ec98424ebf93c1`，wrapper13207 B / `c304c4abc854425b51b0f8c8bae3c90361fbfcef5413414a107df9e530169f7d`；checker19997 B / `aede2e43410f7f3a78fb715c077e567da84ba47d9dfa9c5d4290e3b8795b60d3`，CMD238 B / `845da60c51a3cac80175eaa202fd7d965d6bddffe88ea76ae6272fdeaa25f286`。三套新bootstrap程序75607/75609/75609 B，最长行115 B，在原2MiB/256行上限内；原wire4MiB、decoded4MiB限制不变。

ROOT另纯读/AST审计101份保存/current字节、三份数据严格Base64/zlib解码与原program、三套新封装解码与当前数据/wrapper、原wire复用及ZIP双成员原字节/CRC，差异0。该检查没有运行wrapper、原program、stage或业务图；actual_timer_tested、device及physical_stdin_eof_verified均False，下一阶段为真实Linux timer/输入接线HOST。没有新的ADB、CLIENT历史、Native或RF动作；实际产品接装缺口见19:25节，完整目标active。

## 2026年10月4日 19:25 发送暂存真实 Linux 文件操作通过

[本轮结果 ZIP](results/formal-send-stage-linux-io-host-20261004-192504-7cc25185/public-result.zip)由 ROOT 唯一执行新 `HOST_MTA_FORMAL_SEND_STAGE_LINUX_IO_CHECK.cmd` 生成。1个新方法、20个固定子例通过，Linux child、WSL host、checker和外层CMD均退出0；旧方法重放0。实际环境为电脑 WSL 的 Linux x86_64、root、Python3.13.12。没有调用ADB、Docker、设备或无线。ZIP2128 B，SHA256 `01ca497dc3b07ef28c4d22c663a77e0e22e10a642c70f4c91a30437f5ebc96de`。

正常分支执行原 FixedStage 的构造、真实时钟和线程检查、目录FD、NOFOLLOW/CLOEXEC/EXCL打开、写入、fsync、读回、完整库存复核和关闭后EBADF。三组原资产27/41/37共105件实际写入只在本测试新建并核身份的Linux临时目录中，分别复核两次；原4MiB单组载荷与120秒限制未提高。四种明确命名的OS故障注入及一项FD库存变更与正常路径分开记录。unknown/collision原库存没有被测试外部清理伪装成生产关闭；外部HOST只关闭自己另行保留和认证的FD，随后移除自身专有临时目录。

本结果不签 `platform/aliases/parents/service_parents/payload/stage` 整体调用，不执行业务资产、Boot、Owner、Native/helper或归档消费者，也不签ARM、P011页面、手机收发或网络恢复。电脑90秒timeout只约束WSL外层；本轮正常子进程退出0，不将外层超时停止当作Linux子资源已闭合。stdout1919 B / `0a3e978b4f2fa85b5752ca413fee7205593a5f0c43cd222000372f0cd9e4d003`、stderr189 B / `6cf0342fd1a107233f3e68ff427f9be0cb7f2225b89ae6013c968c942b1e02ac`完整保留，包括WSL的systemd用户会话警告；unittest实际Ran1/OK。remote原件为NOT_RUN_DEVICE，报告remote_exit仍null。

91份保存输入和当前源逐字节、尺寸及SHA一致。生产stager仍37382 B / `cdb73ecb883ee72a3cb8e45726987b3da2fc7d92fe1cb8c73a0b2de82f743806`；新test27380 B / `97a31af2bc9002c5f6b04da05c034f19764b478816a88620fe1856e4555ff495`、checker15912 B / `46700af189d28f4b6de32cb22b7a76139e873653cd0eb1ced02c473524634e23`、CMD319 B / `84220fa72fd88ad5d11fc2643659b6f74f8ce36204c347fde48fdd68954cad3a`。独立PS/.NET纯读审核另核91输入、raw、20序列/唯一标记、各原退出、ZIP仅result.json/README.txt原字节与CRC，差异0，没有重跑测试。

完整目标仍active，下一步不只是增加测试。源码检查已确认三个实际产品缺口：当前最终UI接的是接收服务，发送需独立干净worker及自己的端点/文件ID；发送Owner尚无FileCenter所要求的真实用户目录/接收目录DirBinding，不能用路径或布尔值替代；重复接收需真实结束旧FileCenter、Session/finalizer与Owner并归档原新run，再建新worker和一次性Trial，而新worker期限必须裁剪到父层首次创建的绝对截止时间，不能续出新的600秒。正在新增独立组合Owner和父期限接口，旧通过源及历史结果不改。生产归档消费、完整启动/组合UI、P011与小米15 Ultra双向互通仍未完成。设备CLIENT历史的窄只读分类仍待对应授权，本轮没有处理该目录。

## 2026年10月4日 19:00 新界面异常收尾 HOST 32例通过

ROOT完整阅读新测试、checker及CMD并核固定尺寸/SHA后，唯一实际运行 `HOST_MTA_RECEIVE_FILECENTER_ARCHIVE_COORDINATION_CHECK.cmd`。[新HOST ZIP](results/receive-filecenter-archive-coordination-host-20261004-190055-3a9ab7d9/public-result.zip)通过1个新方法/32个严格固定子例，child/host/checker和外层CMD退出均0，Ran1/OK，旧方法0。原stdout2251 B、stderr103 B均私有保留；remote原件为NOT_RUN_HOST_ONLY且report字段null，不补写设备结果。ZIP1692 B / SHA256 `2d48e06ab36fec569b136f01d37dde9874ecf8c7bd156bc869dd66764ece34ac`。

本次执行冻结worker选中的10个实际helper及UiSessionError；真正run_fixed只做构造配方/finally顺序AST核对，不运行。HOST当前线程身份为真实Python原语；Owner、State、Gate、clock、Companion、guardian、原模块/定义/FD库存、finish/cleanup回调与归档DATA全部明确为模型。32例覆盖缓存True但实时Companion或guardian未闭、原creator被替换不得调用、被动检查异常保留、认证原件取消的三个独立调用、前一错误不跳过后续、原cleanup剩余裁剪/过期零等待/不续期、不重复取消，以及归档额外键/未知reason/缺原件/Namespace变化/矛盾rename/布尔历史数/Native或receive grant拒绝。该HOST不签实际State取消、真实Owner或归档消费者关闭、整图、Linux阻塞IO、P011页面/音频、手机收发或无线恢复；所有这些actual_*及verified标记False。

四份输入保存与当前源一致。测试26164 B / `1a13cb0a876992ccb35dcd2a3ee13ae9ec5557bb36b3fa2b8c02a2c4da0c0489`；checker11288 B / `78db0e20a7c4bbf95b9ebd197e829c79e76f73d46eb832f6a6add710ad9fe42d`；CMD333 B / `0d2b0f4f033f84bf09e24b8a9686ba3b7b07851c2abab365b9bd2f6acd68fbe3`；worker仍104680/04d3bbbb，未改18:52已通过SOURCE输入。ROOT另纯读/AST审计四输入、两raw字节/SHA、32序列/一个contracts标记、Ran1/OK、三个退出及remote原件、scope边界、ZIP仅result.json/README.txt双成员原字节，差异0；不重跑旧Audio13、Send26、State16或Gate18。

本轮无ADB、Qt、RF、实机暂存或CLIENT历史动作；GO64已授权单记录处置和回查沿用16:16/16:20，实际接收拒门仍沿用16:21的client_history，窄只读分类许可尚未收到。完整目标active，仍有软件工作：发送stager的真实Linux临时文件系统行为、实际外层timer/输入帧接线、生产归档原件消费、完整Boot/Owner和最终组合入口。当前发送程序要求先建立真实ITIMER_REAL、覆盖原120秒；PC生成器不是该有界执行外壳，直接运行会outer_deadline拒绝。不得以新增HOST32或SOURCE替代这些层，也不因软件通过而绕过设备历史边界。

独立PS/.NET只读审计随后另核四输入/快照/当前原字节与SHA、两raw尺寸/SHA、32例与fixture/checker精确顺序、唯一contracts/Ran1/OK、原host/child/checker0和remote NOT_RUN、13个模型标志及未执行边界、ZIP严格双成员原字节/独立CRC，差异0。审计没有执行Python、业务模块、旧测试或设备，不将HOST结果升级为P011全闭或生产归档通过。

## 2026年10月4日 18:52 文件中心与接收归档界面 SOURCE 接装通过

本节接续18:24规划，不改写下方历史测试。本轮没有ADB、Qt、RF、实机暂存或CLIENT历史动作。已授权的GO64单记录处置和回查仍复用16:16/16:20证据；最新实际接收准入仍是16:21的 `client_history`。目录非空不是活动客户端证明，现有授权不扩大到CLIENT读取、归档或豁免。窄只读分类的授权请求尚未获得答复，软件工作继续；目标保持active，不能称只剩人工测试。

18:52 [新界面接装SOURCE ZIP](results/receive-filecenter-archive-v1-source-20261004-185256-6fcc6c45/public-result.zip)首次实际组装通过，外层checker退出0。107份输入原样保存；原74份integrated输入、36普通/34Boot/35私有角色、76项协议载荷未变。新UI程序2083733 B，距原2MiB上限13419 B；默认/启用服务程序1994265/1994264 B与18:21程序字节相同；三套最长物理行均122 B，没有提高256 B上限。协议载荷仍4164389 B/原4MiB cap；FileCenter9源91295 B在独立131072 B cap内，只有UI含一份，不追加到服务payload。b6原19件GUI资产4182249 B仅保存核验，不安装。ZIP1849 B / SHA256 `5d8ef6e1692174ba6444e3b5b73c6d0293a074eef84b59f9c17ffbd9a76fb62f`。

ROOT另纯AST严格Base64/zlib解码三套程序，与107份保存输入逐字节核对；UI的76+9项、runner/worker/validator尺寸及SHA一致，不执行业务模块。新旧worker顶层AST比对为原30项未变、2个窗口守恒函数与run_fixed改变、新增5个收尾/投影函数、无移除，旧Audio13及发送26例未重放。UI程序SHA `0e401ea09edb551a8373eb86aaa0133c0a6247e84054ecbfabca929e3bdfe457`。

独立PS/.NET只读审核另核107项当前/保存/库存尺寸、SHA与原字节、原74输入复用、两服务程序与18:21原件相同、三程序实际预算及ZIP双成员原字节/CRC，差异0。20项非设备/非业务执行标志均exact False、旧方法和历史检查数0；SOURCE没有设备raw或remote结果，不能补写设备退出0或资源闭合成功。

新候选位于 `candidate/receive-filecenter-archive-v1`。worker104680 B / `04d3bbbbda2bccf67b29154a5b481d70cecb17647dc8cec51eb045c679d24a7c`，绑定integrated runner80671/dab382、新服务根和独立exclusive控制目录；原600秒窗口及cleanup cap不续期。固定可信构造选择receive/profile/archive策略，浏览器不提供策略参数，也不自动开始接收。

实际finally先关原FileCenter，再实时核原 `_filecenter_current`、Companion.closed与音频guardian库存，缓存close=True不足以继续finish_owner。未知闭合转入新拒绝归档收尾：仅对认证的原Owner/State定义撤销Trial、停止HTTP并实际State.close，等待裁剪为原cleanup期限内0至30秒；调用和原错误保留，不调用Owner.close、归档或目录释放，不修改不可变policy。只有真实Owner闭合后才复制runner保存的归档结果，公开固定12个标量；Native/receive grant始终False、旧历史检查数严格0。未知仍保留resource_pending，不发送OWNER_CLOSED_REPORTED。

新 `candidate/receive-filecenter-archive-v1/HOST_SOURCE.cmd` **只有电脑端源码检查**，拒绝参数，没有设备启动分支。checker37674 B / `3040a3628b1b4fb8b840f3fc81d2dc950f695366c08730c5e4a1f7a7b0766e64`；CMD246 B / `98bb00d3e1fe5ad20566a9dd04ce1c02c56bae8ce2d8b4e444de306f4e989146`。旧worker、9源、validator、b6资产、旧入口与结果保留。此结果不签新收尾HOST、整图运行、生产归档原件消费、P011页面/音频、手机收发或无线恢复；还需新聚焦HOST、发送暂存行为、完整启动与最终有界组合入口，再进入有明确权限的实机验收。

## 2026年10月4日 18:24 收尾 HOST 与新整合 SOURCE 通过 尚无新的实机互传

本节接续17:53状态，不反写下方历史原判。本轮没有ADB、Qt、RF、设备文件暂存或CLIENT历史操作。已授权的单条GO64归档及独立回查仍沿用16:16/16:20实机证据；最新实际接收准入仍沿用16:21的 `client_history`。非空目录不是活动客户端证明，旧GO64授权不扩大到CLIENT读取、处置或豁免；该目录的窄只读分类仍待对应授权。目标保持active，不能称只剩人工测试。

18:12 [新增收尾预算HOST ZIP](results/formal-send-cleanup-budget-host-20261004-181234-3d5a8874/public-result.zip)通过1个新增方法/26子例，原child/checker及外层退出0、Ran1/OK、旧方法0。执行实际选中的State close/probe、Owner close和外壳close函数，使用真实HOST锁/Event；clock、process、pipe、OS FD、Session/Trial及部分原Owner/Loader库存明确是模型。覆盖原剩余期限裁剪、过期零等待但仍收尾、部分构造不调用close、未知/外来actor不触碰、失败不跳过其它原资源及原错误保留。没有执行整State/Boot/Owner启动、Session worker/finalizer、Linux阻塞IO、Native或设备。ROOT独立核六份保存/当前输入、raw stdout/stderr、原退出记录和ZIP双成员一致，错误0。ZIP1308 B / `c622d5c50acaa97042f949899c1e8f327e07c3843fc4c3d4abcbcb73018689bd`；remote为NOT_RUN_HOST_ONLY，不能补写设备退出0。入口 `HOST_MTA_FORMAL_SEND_CLEANUP_BUDGET_CHECK.cmd` 仅此HOST范围，原State16/Gate18未重跑。

18:21 [新接收归档整合SOURCE ZIP](results/receive-completed-archive-integrated-v1-source-20261004-182126-3009f0ec/public-result.zip)通过首次电脑端实际组装：74保存输入、36普通角色/34 Boot角色/35隔离CLIENT角色、76payload；原始payload4164389 B仍低于4MiB，default/enabled服务程序分别1994265/1994264 B仍低于2MiB，实际最长行122 B。ROOT另纯AST逐76项解码与保存原输入比对，runner80671 B一致；两套程序除固定archive policy外AST完全相同，不执行目标图。独立PS/.NET另核74输入/保存/当前尺寸SHA和原字节一致、原草稿两源未变、两实际程序身份/预算一致及ZIP双成员逐字节一致，错误0；原remote记录NOT_INVOKED，report的host/remote字段仍null。公开ZIP1755 B / SHA256 `36e4c0696a19c986a263ede7018a096444a2acf3cfa7da809ec5b6a2cfc76ca4`。

有效新图位于 `candidate/receive-completed-archive-v1/integrated`：Executor仅迁移固定私有runtime35路径，CLIENT工作根不变；Factory/Bridge/Boot/Owner/ordinary/runner已级联封印。runner在Boot加载完成后才登记真实 `startup_readonly_private_owner`，同名冲突拒绝，部分exec原模块保留，补上生产归档_capture的真实模块登记缺口；Boot executor首项硬编码尺寸亦已同步117755。Owner80828 B / `94c368319b62a0ecd556c12df58773c31719b9df7f47aad863579c283be888ce`；Boot19850 B / `ad2d733b0eb8bd3699acd9025c3ab569ec3a5eccef6bec16b9c658a811bf940f`；runner80671 B / `dab38234422d0ff41407c46dbaecc7385d05ef06932610eb65f4dce49fd7653b`。原草稿Owner80798/f9ef和归档消费者41932/fef9原字节保留，旧入口/测试/结果不改不重跑。

新 `candidate/receive-completed-archive-v1/integrated/HOST_SOURCE.cmd` 默认仅PC SOURCE，会分别组装policy为False/True的两套固定程序，但都不执行；原Owner的archive/receive-trial默认False。人工显式加入 `--check-device` 会实际调用设备，`--archive-completed-receives` 必须与其联用才选择True；本轮未使用这些参数，源码结果不是设备授权。此次source_runtime_graph_executed=False、production_archive_consumer_tested=False、old_test_methods=0；生产_capture、真实Owner关闭、Native/网络恢复、UI/FileCenter worker迁移均未验收。下一轮接收必须在原Session/finalizer/Owner真正闭合、仅保留归档本未来成功run后重新创建有界Owner/Gate，不能重置同一个Trial或清空旧CLIENT历史。

18:24 [发送三批暂存SOURCE ZIP](results/formal-send-stage-source-20261004-182447-21000000/SOURCE_RESULTS.zip)通过修正版首次生成，外层退出0、90保存输入；sender27/Observer41/ordinary37共105个唯一目标。三批解码后分别2402458/1440449/1266713 B，各自低于原4MiB；实际program23954/25816/25230 B、wire1218562/475365/468929 B，分别低于2MiB/4MiB。ROOT独立逐帧严格解码比对原输入、固定模式/路径、三批和105目标唯一性、wire SHA及固定trailer，错误0；program最长行132/136/138 B，wire最长行100/102/102 B，未提高256 B行上限。ZIP1215 B / `06ed18040d44c8c8817f18aca0ad0329d165045412a3a27898c10bb102c367b3`，精确result/README两成员与相邻原件字节一致。

首次18:21发送SOURCE失败仍保留：[原FAIL ZIP](results/formal-send-stage-source-20261004-182126-37000000/SOURCE_RESULTS.zip)，825 B / `59527cb3b9da8c6cb4339d228564d9f4b9c3ba78960cca1c80d57c3470936218`；90输入保留、零批程序、外层退出1。原因是PC检查器用literal_eval读取固定 `4*1024*1024` 乘法表达式；修正版仅白名单核这一固定AST形状并增加有限error_code，不eval/exec、不改预算、不反写失败。最新generator17979 B / `db79f3f1b7ef7ac3dc1fb92865d4d2583a7539f7c5cd62be3a3537d55c52d45c`；stager37382 B / `cdb73ecb883ee72a3cb8e45726987b3da2fc7d92fe1cb8c73a0b2de82f743806`，入口 `HOST_MTA_FORMAL_SEND_STAGE_SOURCE_CHECK.cmd` 没有设备transport。

stager源码对新文件使用原目录FD、NOFOLLOW/EXCL及读回；完整旧树只读复核，partial/conflict保留并拒绝，不覆盖/删除/修权限。独审修复重复FD的所有冲突原票据必须unknown拒关，以及整树读回末尾对全部文件完整metadata再核两个缺口。ordinary阶段核实际sender/Observer完整树，不制造跨进程receipt或普通源别名。未来每批固定120秒绝对期限，受控bootstrap需先建立默认SIGALRM handler与一次180秒原timer，读取只恢复原剩余时间、不续期；固定trailer不证明stdin物理EOF。此次stage_executed/Boot/Owner/helper/send/receive/RF/restoration/phone均False，没有HOST文件系统行为或实机暂存通过。

尚需新增完整启动与暂存行为验证、接收生产原件消费、FileCenter/UI新图接装和最终有界组合入口，然后才到有明确权限的P011运行/真实手机收发/无线恢复/触摸音频物理验收。现有电脑端SOURCE与有限HOST不能替代上述层；设备CLIENT边界不绕过。README已补当前状态导航，旧时间章节继续作为历史证据保留。

文件中心接装的下一步已只读定位，尚未实施：用独立新UI worker/PC checker绑定本integrated runner、服务根和新exclusive控制目录；600秒原窗口不续期，由固定入口显式选择归档策略，不接受浏览器策略参数。保留先关Companion/媒体/音频及其线程、再finish_owner的顺序，之后才复制有限归档事实。9份FileCenter源91295 B和b6原19件GUI资产可原字节复用，不复制到service的76件payload。否则仅并入9源就达4255684 B，超过4MiB。旧UI相对旧service开销85016 B；新UI按此开销估算2079281 B、距2MiB仅17871 B，此为规划值不是组装验收，必须实际生成核原cap，超限就停止而非提高上限。原图/旧worker/checker/结果继续保留。

## 2026年10月4日 17:53 最终发送源码封印通过 实机历史边界不变

本节更新上一次17:35源码检查之后的当前身份，不反写旧SOURCE或HOST原结果。本轮后半段没有新增ADB、RF、Qt或CLIENT历史操作。用户授权的单条GO64备份归档和独立回查已完成，仍以16:16/16:20原实机结果为准；接收准入仍沿用16:21的 `client_history` 拒门。只列目录得到非空，不能推论记录活跃；旧单记录授权不扩大到CLIENT历史的读取、处置或豁免。目标保持active。

17:53 [最终发送图 SOURCE ZIP](results/formal-send-graph-source-20261004-175333-a3f2ac28/public-result.zip)通过新增一次固定源码检查，外层退出0：44份保存输入，32普通角色/3启动源/3helper，35 Python3.5 AST；普通源1036797 B，Boot32 shape、来源路径/模式及Boot→Owner→外壳交叉pin一致。2MiB程序/4MiBwire/10秒Boot原上限未提高，sender25/Observer41/WPA仍独立引用，没有在此重新执行或验证私有资产。ZIP1096 B / `665156104ce6a59e5884252e3bdab7c3f9650b68b2360cd7acc41af91539c182`。入口 `HOST_MTA_FORMAL_SEND_GRAPH_SOURCE_CHECK.cmd` 仅PC源码，不导入或运行目标模块，不落地资产、不启动无线。

最新State145518 B / `4c580381a6ed2988ea6fa8f968e8145d3ac21748b49e7e5e9eff7809c55b8c43`；Boot19217 B / `db3c016b2d4a296b029cf1a7cd41da5595d677dd9ab7aa9fb2a477ba44afb2c4`；Owner46866 B / `60a5010c02d9e545b437877a939f73eb93fb1262dfeec37e3bf8d714ecf553bc`；外壳21984 B / `290aa340a0aa646563625a2c64297886f11393f6f1e9986920fa9daee63aca19`；固定ordinary清单18219 B / `0aff3d932addb257962cb1aa89857784ddaaec945d34ee75c43e95fab15d2fb1`。均与保存输入一致。

源码窄修使迟到close仍尝试原Owner/Loader/源码FD收尾，保留原失败；Session等待和只读能力探针等待按原剩余期限裁剪，不续期，过期使用零等待而不跳过已知收尾。原未知actor不重试、不操作外来进程；未完整构造的Session不调用close/cancel。最终原actors被动复核不再仅凭旧closed缓存：身份失效的原件仍保留错误并降closed=False。Owner仅对已观察的固定 `/mnt/data` 节点作局部身份适配，没有改变设备权限。以上是源码实现和只读审查范围，不签实际限时清理、Native关闭、Linux阻塞IO期限或完整恢复。

新SOURCE还逐项比较17:25保存的原HOST输入：实际被测五个State方法及整个Operation AST不变，因此复用原16用例的限定范围，没有重跑它们或旧Gate18。State HOST入口仅机械更新当前源pin；新增close/probe方法不在该原16用例中，不能将其通过扩大为新收尾HOST通过。独立PS/.NET回查44份保存/当前输入尺寸、SHA及逐字节零差异，四个SOURCE未调用原标记一致，ZIP精确两个成员且与公开result/README原字节一致；错误0。SOURCE报告host/remote字段仍null，新旧HOST方法均0，不补写成设备退出0。

仍需新增聚焦收尾预算HOST、完整Boot/Owner/外壳运行图、最终程序/stager与文件中心组合启动链；未来完成接收归档候选仍Boot UNSEALED/默认关闭，生产原件消费者尚未执行。设备CLIENT历史的窄只读分类仍待对应授权；手机双向互传、RF后恢复与触摸/音频等物理验收未完成，不能称只剩人工测试。17:32归档SOURCE的17份保存输入/当前源及ZIP双成员亦已独立回查零差异，旧模型HOST与实际设备层继续分别记录。

## 2026年10月4日 新发送构造与归档 HOST 通过 启动源码审计继续

本轮没有新增设备、RF、Qt 或 CLIENT 历史动作。旧 GO64 的实际单记录归档和独立回查沿用下方16:16/16:20原结果，不重复处置；实际接收拒门仍沿用16:21的 `client_history`。用户授权只覆盖这一个旧 GO64，现有 CLIENT 历史的窄只读分类请求尚无新答复，不归档、删除或绕过它。完整互传目标保持 active，手机双向互通和 RF 后恢复未验收。

17:25 [新发送 State HOST ZIP](results/formal-send-state-constructor-host-20261004-172535-d5209d55/public-result.zip)通过新增1方法/16用例，原child和外层退出0、Ran1/OK、旧方法0。执行实际选中的五个 State 函数、原 Operation 构造和未启动的原 Session78 构造；锁、Event、未启动Thread为真实HOST资源，Trial、回调、分配失败、旧Session关闭、启动解析、终态依赖及worker身份为明示模型。验证部分Session对象/线程/首异常保留、claim/attach失败拒门，以及最终期限失败后不能仅凭已保存refs误报独立恢复。末期限成功后才发行原四元完成票据，失败/unknown原件仍保留。没有执行整State构造、原Owner/Parent、Session worker/finalizer、Native或P011。

ROOT另以PS/.NET独核五份保存输入与当时当前源字节/尺寸/SHA一致、原stdout/stderr/host退出与ZIP两个成员一致。ZIP1131 B / `1e0b1ca206dea66a24da124b1d9d2cf0a3d43622156de23d67d1fd6d2510e814`；remote未调用，字段null。入口 `HOST_MTA_FORMAL_SEND_STATE_CONSTRUCTOR_CHECK.cmd` 仅此HOST范围，不签完整发送图或恢复。该结果源State为139711 B / `a227e7ad56cf9d9e04eedc986064b2b764144eeaabf466cfaca9299980d72dec`；后续源码变化按单独证据标注，不反写历史。

17:26 [未来完成会话归档 HOST ZIP](results/receive-completed-archive-host-20261004-172648-16d8865d/public-result.zip)通过新增1方法/16子例，原child/外层退出0、旧0。执行实际行政IO函数的先登记再打开、原FD关闭、现存flock锁、journal CAS、ARM382 NOREPLACE契约、同inode读回、父目录同步、到期和不重试控制流；OS/ARM/libc/clock/journalcodec及原Owner/Factory/Parent/State闭合边界明确是隔离模型。实际生产 `_capture`、原件消费者、Owner、Linux/ARM和设备均未执行。ROOT另独核五输入/当前源/raw/退出/ZIP双成员一致；ZIP1462 B / `88c252304f6d599b86e7f7db90b218206475153ac19f31268f3c25a0c10cb898`，remote null。入口 `HOST_MTA_RECEIVE_COMPLETED_ARCHIVE_CHECK.cmd` 不是设备归档授权。

HOST之后复核生产前置，ROOT仅在归档 `_capture` 与 `_check_originals` 加入 `owner._startup_closed() is True` 的两个必需条件，防止后置Owner闭合代替rename前置。17:32 [新归档 SOURCE ZIP](results/receive-completed-archive-startup-source-20261004-173249-f7364355/public-result.zip)通过17份保存输入、Python3.5 AST和原HOST/raw消费：逆转这两个条件后全文AST与原41822 B生产源一致，所有实际被测行政IO AST、原模型方法及checker业务AST未变；只机械更新源pin，HOST新旧方法均0，未重放16子例。最新归档源41932 B / `fef9d58f9d8359e8407500c9d461a1842e52f6e90cf2d670c2c0088a92d888ca`。ZIP980 B / `852b688f72ff9616638218471f1e63b79ed2009ee6772923786f33b7d7d2a8dc`。原件消费者仍未测试，归档Owner的Boot明确UNSEALED、策略默认False；实际StartupScope.closed仅在原Owner线程被动核原库存，不新取clock/观察。新 `HOST_MTA_RECEIVE_COMPLETED_ARCHIVE_SOURCE_CHECK.cmd` 默认只PC源码，不处置旧历史。

17:35 [新发送图 SOURCE ZIP](results/formal-send-graph-source-20261004-173523-bb1d8d0d/public-result.zip)通过当时43份输入、32普通角色/3启动源/3 helper固定字节、35 Python3.5 AST、Boot32 shape及Owner/外壳交叉pin；普通源1030990 B，2MiB程序/4MiBwire/10秒Boot上限未提高，25/41/WPA私有资产仍独立引用。ZIP962 B / `dfe9ad7b76d919949fa34a57f9f63f78c5654d3a0f48f0469fc1289831ff0497`。这没有封装程序/stager、执行Boot/Owner/外壳或HOST整图。随后独立审查修正Owner仅 `/mnt/data` 的已观察固定node所有权，不能用该旧SOURCE结果给新字节自动签通过；限时关闭审查又发现迟到close跳过Owner，以及Session/probe固定等待未裁剪，正在窄修源码并重封相应身份。旧SOURCE/两HOST的输入与原判均保留，待新增SOURCE和聚焦关闭预算证据，不重复已通过Gate18或State16。

## 2026年10月4日 文件中心音频异常收尾 HOST 通过 重复接收与发送继续源码修复

16:31 [新的音频 guardian HOST 包](results/receive-filecenter-guardian-audio-host-20261004-163110-e2301de3/public-result.zip)通过一个新增方法、13 个用例，原 host exit=0、unittest 为 OK，旧方法重放=0。执行当前已冻结 Audio/UI 的实际函数，覆盖先登记再放行、错误 ACK 不放行、放行前原媒体 FD 改变、未知 Popen 保留未决、原锁下 ACK 与终态排序、有限库存和逐个已知 actor 收尾。HOST 的日志、管道元数据、线程和锁是真实资源；目标 /proc、进程启动、信号、ACK/native IO 明确是模型，生产调用顺序仅 AST 核对。没有执行 P011、真实原 Owner/Native guardian、物理音频或原厂恢复，不以 HOST 通过签这些层。

ROOT 已另以 PowerShell/.NET 只读核对六份保存输入与当前来源逐字节/尺寸/SHA 一致、原 stdout/stderr 和退出记录一致，以及 ZIP 精确两个成员与相邻公开原件一致。ZIP 为1048 B，SHA256 `e7a26a81e8daf52eafff348dcfe18cf81d4252c197eba4c8103cec613bd2ea03`；原 stdout7428 B、stderr100 B。远端没有调用，原记录为 NOT_RUN_HOST_ONLY，result 的 remote_exit 保持 null。此前16:25组合 SOURCE 与此次 HOST 分别保留，未重跑旧四个产品测试包。

源码还确认一个重复使用缺陷：当前 Factory 新建接收 run 后只关闭 FD、保留运行树，而空库存 Barrier 会因此拒绝下一轮。正在制作独立的未来完成会话归档候选，只允许在原 Session 与 finalizer 真正退出、原恢复及关闭原件可消费后，无覆盖保留归档本 Factory 新建的那个 run；未知或未完成继续拒绝，不重置已认领 Trial。此软件工作不读取、处置或豁免设备现有 CLIENT 历史。设备历史只读分类请求仍待用户答复，本轮没有新增 ADB、RF、Qt 或历史操作。

独立 `formal-send-v1` 正在接装已有原 GO25/Observer41，区分一次启动准备资格与实际 Native/RF 权限，并补真实终态消费、ConnMan/BlueZ 前后比较及完整固定资产身份。该候选尚未最终冻结或执行新 SOURCE/HOST 检查，不能称发送已可用。目标 active；当前实际设备拒门仍为 client_history，真实手机收件、发送及 RF 后完整恢复均未验收。下方历史原判不改。

16:54 [发送固定资产 SOURCE](results/formal-send-assets-source-20261004-165406-fadc64d5/public-result.zip)新增一次通过：原sender25共1047589 B、Observer41共1440449 B逐项与原来源表一致；Loader/report38与落地库存41分开核对，原8096 B观察清单、发送完整清单与四项baseline pin、固定WPA ARM32 ELF形状均核对。Publisher除说明和新BUNDLE清单SHA以外的 AST 与原v90一致。ROOT另以PS/.NET只读核65份输入/保存源/当前源零差异、ZIP两个成员与公开原件一致；ZIP836 B，SHA256 `ba7a82ade2ae3a36003c071c59ad6ca38a34b027328047ef1962fd5a2fa7f7ae`。58个Python3.5 AST不导入或执行目标模块；host/remote原执行字段均null，无旧测试重放。新入口 `HOST_MTA_FORMAL_SEND_ASSET_CHECK.cmd` 仅资产SOURCE，未核新的Gate/State/Owner/Boot运行图，也不启动、推送或许可发送。新的完整sender图仍在实施。

17:01 [新发送阶段 HOST 包](results/formal-send-trial-host-20261004-170139-244fa52c/public-result.zip)通过1个新增方法/18个用例，child exit0、Ran1/OK，旧方法0。执行冻结的新 `mta_send_trial.py`（22034 B / `d54e8f94621cb86484f8303a603f11ce05dfad3e2231f3bb202bc5ff9ecd95d4`）及原Session78真实构造，核 available→claim→attach_session→allows→revoke 的分阶段、一次性库存、真实 `_lease_owner`/`_direction` 接口、取消/过期及来源/原件变更拒绝。锁、Event和未启动Thread对象为真实HOST资源；Owner/State、readonly Parent/packet/EOF/wait和Native资产是明示模型，没有运行Session worker/finalizer、Parent、startup、Native或P011。认领只表示启动准备，Native、production及restoration投影仍False；这不是完整State/Owner图的运行证明。

ROOT另独核五份输入与保存/当前源零差异、stdout/stderr尺寸/SHA、原host-exit0及ZIP两个成员原bytes。ZIP1034 B / `31f8ccd822c4b3eca870a9a39b9d4179088608c49f7889cc9bc10ac5d7d8383f`；remote未调用且字段null。新 `HOST_MTA_FORMAL_SEND_TRIAL_CHECK.cmd` 只执行此新HOST方法，不启动设备或发送。真实终态/独立网络恢复的State与Owner/Boot仍在SOURCE实施，未封装或运行。

## 2026年10月4日 旧 GO64 单记录已归档 接收预检转为 CLIENT 历史拒门

16:16 已按用户明确授权完成这一个旧 GO64 的条件处置，[原实机结果](results/go64-single-retirement-20261004-161656-9c9facf4/public-result.zip)通过。先保存并读回电脑端原340 B pending与7138 B journal，再在同一次持原device/journal OFD锁的核验中确认旧actor/task及端点不存在、当前两次完整只读网络DATA稳定，配置与历史一致。仅允许原厂Z03的PID/start变化（exe/argv未变）及IPv6使用/引用计数变化；其余五个原厂后台actor身份相同。ARM `renameat2(RENAME_NOREPLACE)`将原pending inode无覆盖移动至其原run目录的 `go-pending.archived-20261004-v1`，原路径已不存在，原inode/字节保持，两个目录fsync，journal原字节及完整metadata未改，实际FD关闭。没有删除记录、改写journal、处置CLIENT历史、RF或候选接收。此为行政归档，不补签旧Native库存关闭、原Snapshot.key或旧restored receipt。

16:20 [独立只读回查](results/go64-archive-postcheck-20261004-162010-b9f7a8b7/public-result.zip)通过：再次持现存原锁，两次核原归档inode/metadata/字节、原journal/metadata、同boot、旧actor路径缺失与原pending路径缺失；所有实际FD关闭。该回查不观察原厂网络，不能单独签网络恢复。

16:21 [重新启动接收预检](results/receive-interactive-v1-service-20261004-162135-452741d1/public-result.zip)保留FAIL：原host/remote=0、component_complete=True，Boot/Owner及能力采集正常，实际2315 FD和服务资源关闭，限定原厂文件/进程/启动基线前后一致；接收Gate的真实初始拒绝原因已经由 `pending_exists` 变为 `client_history`。claim=0、未附加Session，没有广播/扫描/切网/收件或Qt接管；关闭后Gate撤销为 `owner_closed`。公开passed=False不是执行崩溃，也不能改成接收可用。用户授权明确排除CLIENT历史，不自动归档、删除、结束或绕过这些记录；下一阶段需要核清这一独立边界并取得对应处置授权。

旧网络只读v1的proc格式FAIL、v2的codec接口FAIL及v3 HOST输出解析FAIL原件均保留。v3实际remote=0完整DATA由独立保存raw审计确认，不能反写v3原HOST结果为PASS。新的FileCenter audio guardian已SOURCE冻结，ROOT只机械封印validator pin；最新worker89778 B / `89c2af00763f86393aa39b528ec01615adfd04b69a4866b747fd41bbfdd74147`，Audio8773 B / `dd559da62af71042b11ada6ba26ee574548daace3650b9a9e99f8dbfe737d154`，9Python源总91295 B。b6的19文件资产不包含这些Python源，保留既有GUI构建，不重构或改历史清单；它们由新的运行封装清单关联。新guardian HOST和组合SOURCE仍按各自新证据验收，不沿用旧四包给新异常恢复签通过。目标active，真正手机互通、RF后恢复及发送仍未验收。

16:25 [文件中心组合SOURCE](results/receive-filecenter-v1-source-20261004-162537-3a5ac434/public-result.zip)通过104份来源、75个原服务payload、9份新增FileCenter源及19个既有GUI资产的固定身份；service/UI程序分别1976955/2061971 B，仍小于原2MiB，原131072 B九源上限不变。此次只在PC解析源码及封装，没有HOST运行图、ADB、GUI资产落地、Qt或RF；SOURCE的host/remote字段为null。新guardian运行契约仍待独立HOST结果，不冒充设备恢复证明。

两归档公开ZIP已另由PS/.NET只读独审原字节与CRC，只有result/README；size/SHA分别1262 / `2ea7defecb3082a77ecffd2d72d8300a4e8132644e2aa8a6d8f1437e6c0557d9`及772 / `af4effee1555c6a820ad355a348eec351f015db1d6d9f29829246b372e1cff44`。两轮原host0/stderr0/唯一RESULT、OK、remote0，公开标志与实际结果一致。真实 `client_history` barrier只对固定CLIENT根的原FD列目录并拒绝任何有效非空库存，不读取、stat或解释条目；它只证明目录非空，不能推论有活动客户端。下一步先请求该历史目录的窄只读分类，再按明确记录和保留方案决定处置授权；不直接清空或绕过门。

## 2026年10月4日 旧 GO64 条件处置获授权 交互窗口与文件中心候选继续完善

本节覆盖下方历史中“单记录条件处置仍待授权”的当前状态，不改变其当时原判。用户现已明确允许：先核对这一个旧 GO64 记录确属本项目、相关旧进程退出且网络基线可验证，再将该记录原样备份归档并结束旧会话；核验不满足就停止。不涉及 CLIENT 历史目录或无线修复。截至本节记录，旧 pending 尚未结束，旧 journal 的 `restore_intent`、原错误及 restored=null 保留，不把行政归档当作旧 Native 库存关闭、完整恢复或接收准入证明。

15:22 新的[当前设备只读结果](results/device-state-readonly-20261004-152217-9e559fdb/public-result.zip)与[旧记录只读结果](results/go-pending-readonly-20261004-152225-8188956e/public-result.zip)通过。前者两次观察原厂三文件 pin、所列进程身份、boot、网卡及所读路由稳定，wlan0、一个 PHY 与一个蓝牙适配器存在；它不确认 Wi-Fi 已连接或完整网络恢复。后者原340 B pending 与7138 B journal 与历史原字节匹配、旧期限已过，持原 device/journal OFD 锁两次检查旧 F/守护进程 PID/task 路径均不存在，项目 netdev、旧活跃 Unix 端点和旧文件系统端点计数均0；16个实际 FD 均关闭。没有设备写入、进程信号、helper、RF、候选启动或记录处置。ROOT独立审计原host/remote=0、唯一原标记、私有原结果与公开ZIP字节/CRC；两ZIP为786/1194 B，SHA分别为 `e2c1e53f3d7d6c127970c3441e4953d660bf1269ec3a4dc372dfc50db136fca4` / `77505112b19e457d5557267d60e54dbd20c97dbe1ffa5211c1f7004c1a4c9d88`。非-netdev P2P及完整历史网络基线仍待实际只读核对，不能用sysfs零计数代替。

新的 `receive-interactive-v1` 把接收入口改成原构造起算、启动耗时扣除的固定600秒交互窗口，不从READY续期；Session300秒、Factory120秒及原收尾/守护上限未提高。它不会自动搜索、扫描或发送。[窗口HOST结果](results/receive-interactive-window-host-20261004-145436-3ca4fcf3/public-result.zip)为新1方法16域，原child退出0；[固定源码检查](results/receive-interactive-v1-source-20261004-150505-5788f6df/public-result.zip)通过76来源/75payload和Python3.5 AST，两程序1976955/2004588 B仍小于2MiB。原结果和内嵌payload已经ROOT独审；没有执行此候选的P011/Qt/RF/手机图。`TEST_MTA_RECEIVE_INTERACTIVE_V1.cmd`默认SOURCE，不能将SOURCE通过称手机接收通过。

新 `receive-filecenter-v1` 将收到的文件接到同一个用户根下真正的文件中心，包含列表、TXT、图片、音视频打开及返回接收页；loopback媒体使用实际留存的原文件FD与随机能力票据，不重新打开用户路径。双loopback端口、不同token和五字段凭据接线尚为SOURCE。新增HOST结果分别是[产品20契约](results/receive-filecenter-product-host-20261004-150650-5526fc34/public-result.zip)、[音频回包3契约](results/receive-filecenter-audio-callback-host-20261004-151025-ee6f7b07/public-result.zip)、[部分资源6契约](results/receive-filecenter-partial-resource-host-20261004-151537-8c520f84/public-result.zip)、[loading3契约](results/receive-filecenter-audio-loading-host-20261004-151953-62d82cbf/public-result.zip)。四者各仅新1方法、child退出0、输入/raw/ZIP独审一致；首个产品包之后有两个源文件变更，其历史PASS不等于最终整体重测。HOST Qt5.15与模型不签笔端Qt5.10、Linux竞态、无线恢复或手机验收，旧失败保留。

PC已唯一构建会话 `b6a84fe755092535bb996f40` 的界面资产：18载荷加SOURCE共19文件、三个目录，4182249 B小于原4MiB；候选ELF4103844 B，SHA `6e8d5aab7a9c0af6e83ba2d4eb09c37054f175de294169c099357f300aef985c`。构建核400QRC资源/399未改资源；ROOT另核文件pin、清单、SOURCE、ELF固定槽外原字节。原builder未快照，随后仅修改PC扫描条数上限，不能称当前builder字节已重构建。未推送资产、未启动界面、未替换原厂Z03。新增19文件validator已SOURCE冻结；其独立凭据目录链不包含同层mta/toolbox目录。

SOURCE审查发现新音频 gst-play 子进程不在旧UI guardian的异常恢复库存，正常Companion.close覆盖它，但worker异常时旧guardian不能代签音频回收；正在补原件通告和有限停止边界。新的FileCenter组合UI尚未封装/测试，validator pin故意未封印，不能启动。另需新的资产stager和启动envelope。原GO发送资产及恢复链仍未接入公开send入口。目标保持active；真实手机接收、实际RF后完整恢复、小米15 Ultra原厂双向互通、发送均未验收，尚有明确软件工作，不是只剩人工测试。原raw、设备标识和凭据继续私存，下方历史不改。

## 2026年10月4日 接收数据交接与界面策略修正 新 v3 源码检查通过

14:39 新的不可变 `formal-receive-v3` 候选完成 [SOURCE 检查](results/formal-receive-v3-source-20261004-143935-3b83d048/public-result.zip)，外层退出 0。固定清单仍为 ordinary35/private35、Boot33 和 75 项 payload；核 76 份来源，9 个改变角色、runner/UI 及两份短行程序的 Python 3.5 AST 和交叉固定身份。service 程序 1976397 B、UI 程序 2002356 B，均未提高 2 MiB 上限。这一入口没有执行 HOST 平台运行图、ADB、Qt 或无线动作；报告中的 host/remote 执行字段保持 null，而不是补写设备退出 0。旧 v2、旧失败、旧恢复记录和 CLIENT 历史库存保留。

独立只读审计确认 76 份保存输入、清单和当前源码逐字节一致，两程序内嵌的各 75 项 payload 与保存源一致；总原始 payload 为 4113520 B，小于原 4 MiB 上限，短行最长 122 B。旧 v2 的 76 份来源也未改变。公开 ZIP 为 1914 B，SHA256 `23c4d293d089a952b33210df44081f02a18e32bf6819ea76d785a6719a6dcb0e`，精确只有 result.json/README.txt，成员原字节和 CRC 一致。private-raw 中的 NOT_INVOKED 标记只说明未调用远端，不是原执行退出码。

发现并修正了两处原来被旧 pending 先行拒门掩盖的软件阻挡。第一处是 Handoff 构造仍要求旧的 `receive_available=True`，而一次性接收设计有意保留该全局开关为 False；原 reader 的 capture 与原 worker 的 decrypt/claim 也不能共用 RF 线程门。新 Gate/State/Handoff 只许可同一个已认领 Operation/Session 的数据交接，仍核原构造票据、原线程、来源、epoch、期限、取消和撤销；不授予额外 RF 权限。原 Bridge 的合法 WiFi pending 不再挡同任务数据交接。部分构造失败保留原对象、票据及首异常，不调用未完成对象的 cancel，不清引用冒充收尾。

第二处是旧 UI 的 FixedSession 没有请求接收试验，且首帧复用严格闭门 idle 会拒绝已经具备资格的原 Gate。新 UI 明确请求一次性策略，首帧检查原 Owner 的空任务库存；后续仅监视原 owned receive operation 和实际 HTTP 线程。没有自动开始搜索、扫描或发送。公开字段区分资格观察、claim、终态与实际操作；`radio_admission` 只表示观察到资格，不表示发生 RF。结束仍核原 Gate 撤销及全部原资源关闭，不续期。v3 尚未在 P011 或 Qt 执行。

新增 HOST 证据分层如下，不重跑已通过项：

- [界面空库存测试](results/receive-ui-inventory-host-20261004-142426-c2cb8df5/public-result.zip)：1 个新方法、21 个契约，原 child/host 退出 0，stdout/stderr、4 份输入和 ZIP 已独立核验。随后只机械更新 runner 的根路径和 pin，实际被测的 idle、空库存和 load_owner 三段 AST 未变。
- [数据交接测试](results/receive-handoff-trial-host-20261004-142923-b882f344/public-result.zip)：1 个新方法、20 个子例，保留的原 unittest 摘要为 OK，两个真实 HOST 线程覆盖 worker/reader。10 份输入、原 stdout/stderr 和 ZIP 已独立核验；原 child exit 没有单独留存，保持 null，不能称完整 checker PASS。完整 State、实际 Session task、原生 helper、P011、手机和恢复没有执行。
- 界面策略测试：工具观察到 1 个新方法、6 个子域、退出 0；没有分别持久化原 stdout/stderr 或输入快照，不补造 raw 或结果 ZIP。被测两个纯 helper 的 AST hash 在最终机械封装后仍相同。这是 HOST 模型证据，不是 Qt 或原 Gate 实机验收。

最新设备证据仍为下方 13:54 的 v2 启动/拒门/关闭测试；不能将本次 v3 SOURCE 与 HOST 结果升级为真实接收或完整 RF 后恢复。接收实测已有授权，旧 GO64 单记录的条件备份归档和结束仍待单独授权，不清理、不绕过、不扩展到 CLIENT 历史目录。`TEST_MTA_FORMAL_RECEIVE_V3.cmd` 默认 SOURCE-only，显式设备分支仍是有界启动诊断；UI 仍为 20/60 秒诊断窗口，不是长时间手机接收入口。

目标保持 active，仍有软件工作：封装适合真实手机交互的有界接收窗口；把 Received 列表真正接到同用户根下的工具箱文件中心并提供打开/预览；完成原 GO 发送资产与独立恢复链封装。手机真实收件、完整无线恢复、小米 15 Ultra 原厂双向互通及发送均未验收，尚不能宣称只剩人工测试。下方历史保持原判。

## 2026年10月4日 一次性接收接线实机通过 旧恢复记录仍阻挡开启

13:54 新候选在 P011 上完成真实 Boot、Owner、启动采集、能力查询及关闭。一次性接收试验策略已由固定入口明确请求；实际 Gate 返回 `pending_exists`，可用性为 False，认领数为 0，未绑定 Session。结束时原 Gate 已撤销，原因是 `owner_closed`；原 Owner、State、启动采集及能力 actor 的关闭检查通过。本轮不是接收成功，没有广播、扫描、切网、手机连接或文件传输，完整 RF 后恢复也未验收。

[本轮实机 ZIP](results/formal-receive-v2-service-20261004-135419-50d40eb4/public-result.zip)记录 host/remote=0、stderr=0 B，两个原能力 actor、两次启动 STATUS、三个 proc reader 关闭，以及 runner 2325 个原 FD 全部关闭。只在新的 volatile 候选根创建 4 个目录及 74 个文件；原厂三文件、所列进程、boot、路由、接口身份和旧记录指纹的限定基线前后相同。没有 Qt 接管、重启、原厂文件或启动项替换。Barrier 只核旧 pending 元数据；原基线按固定文件字节只读计算指纹，不解析、不备份、不归档、不结束记录。CLIENT 历史库存本轮没有处置；旧 pending 先行阻挡，不能宣称已经验证 CLIENT 两轮空库存。

新封装为 35 个普通角色、35 个私有角色、三个助手、WPA 及独立 monitor，共 75 项 payload；原 Boot 加载其中 33 个普通定义。[SOURCE ZIP](results/formal-receive-v2-source-20261004-135409-bbc57ee5/public-result.zip)通过八个改变或新增角色、runner/UI 及两份短行程序的 AST 和交叉身份检查，HOST 没有执行平台模拟图。独立 PowerShell/.NET 核验确认 SOURCE 与实机结果各 76 份来源和保存快照、两份程序零差异；ZIP 只有 result.json 与 README.txt，两成员字节与保存件一致。实机原 raw 的 SHA、host=0 与唯一 RESULT、TRIAL_START、TRIAL_END、OK、EXIT=0 标记一致。实机 ZIP 为 2457 B，SHA256 `646804a82479a65d47b6b1d92b5f648d1f0f766fe8aa5cd1d3abff119e6e7efb`。原 raw、设备标识及输入继续私存；旧正式 State、Owner 和 provenance 候选尺寸与 SHA 未变。

接线已把一次性资格绑定到原 Owner、Factory、启动采集、能力 actor、Received 目录、Operation、Session、epoch 与服务期限。构造前保留原任务与票据，失败不能清引用或造备用收尾。公开可用性在认领后关闭，原 worker 继续核自己的绑定。自己的合法无线 pending 不再挡回 listen/advert；同 State 的来源绑定恢复 probe 可以追加，但既有原 actor 不可替换或原地改变结果。Gate 关闭只证明撤销和认领库存，不替代 State、Session、Parent 或 RF 恢复。

14:01 [首次新 HOST 结果](results/receive-trial-wiring-host-20261004-140139-12ce7251/public-result.zip)中 Gate 21 个子例与 Owner 6 个子例通过；State 夹具未传入 `time`，六个构造子例失败，整个结果保持 FAIL，原 raw 未改。只补夹具 import 与命名空间后，14:02 [仅 State 的重测](results/receive-trial-wiring-host-20261004-140231-76cd2c87/public-result.zip)通过一个方法、六个子例；已通过的 Gate、Owner 以及实机测试没有重跑，生产图没有修改。三个方法各自取得通过证据；首次三方法包不能改称整体 PASS。这些测试执行实际 Gate 或抽取的实际 State/Owner 方法，Scope、IO、Session、资产和祖先关闭明确为 HOST 模型，不证明实机活动接收。旧方法为 0。

随后独立 PowerShell/.NET 核验这两个 HOST 包的各 11 份保存输入、stdout/stderr 原字节尺寸与 SHA、host 退出和 ZIP 两成员字节均相符。首次包与当前来源仅 State 夹具不同，逐行差异只含 `time` import 及命名空间补入；其余十份来源不变，重测包十一份当前来源零差异。首次 FAIL 及其原快照保留，不把夹具补正反写到历史结果。

新 PC 一键入口 `HOST_MTA_FORMAL_RECEIVE_V2_CHECK.cmd` 只核固定源码，`HOST_MTA_RECEIVE_TRIAL_WIRING_CHECK.cmd` 只跑上述三项新 HOST 方法。`TEST_MTA_FORMAL_RECEIVE_V2.cmd` 只做本轮有界接线和旧记录拒门诊断，不是手机收件启动工具，不清理或绕过旧记录。目标保持 active；接收实测已有授权，但旧 GO64 单记录的条件备份归档和结束仍待单独授权，不含 CLIENT 历史目录。真实接收、RF 后恢复、小米 15 Ultra 原厂互通和发送仍未验收。下方历史原判保留。

## 2026年10月4日 新能力查询函数实机通过 收件仍未开启

13:16 新能力查询函数在 P011 的实际 Python 3.5 上执行通过。只执行从新候选抽出的四个原函数，认证并复用已存在的固定 BlueZ helper；两次原生能力查询均与各自原 Popen、argv、stdout、stderr、解析返回字典及原 actor 库存绑定。两个进程已退出，原管道关闭；两次完整蓝牙观察一致。认证文件的 FD 也实际关闭。这里认证 FD 与随后按固定路径执行的 Popen 是不同资源，不能宣称 helper 经该认证 FD 执行。

[本轮实机 ZIP](results/receive-probe-provenance-device-20261004-131622-cd46dc7a/public-result.zip)记录 host/remote=0、stderr=0 B，限定原厂三文件与所列进程、boot、路由、旧 pending metadata 及 helper 身份前后相同。没有设备落地、原厂写入、Qt 接管、重启、广播、扫描、切网或收件；State、Owner 和完整部署图均未构造。旧 pending 本轮仍存在，未打开其内容或改动。该包为 1467 B，SHA256 `fab39856149038103ab71a183f28cbf0c88fb4c431d18517abd67d793f61c4d4`；源和短行程序的 [SOURCE ZIP](results/receive-probe-provenance-source-20261004-131612-4c52c327/public-result.zip)先行通过。

新 State 候选现在强留原能力 actor、输出、返回对象及 canonical JSON；被复制、替换或原地改写的结果不能用于 radio 比较。超时后的原清理调用、输出和首错误不被覆盖。原 State 的 69 个未改类方法保持逐文本一致；构造、两个 probes 方法和 radio verify 共四个类方法改变，正式旧 State 和已通过图未改。[13:11 新 HOST ZIP](results/receive-probe-provenance-host-20261004-131117-7dc1a9d2/public-result.zip)通过一个方法、八个真实 HOST fixture 子进程（含 12 秒超时）及 16 个突变子例，旧方法为 0。13:10 首次 fixture 因 Windows 文本输出 CRLF 与预期 LF 不同而失败；只把 fixture 改为确定字节输出后重测新方法，原失败结果保留，未改判或规范化原 raw。

新固定 publication barrier 只读取旧 pending 元数据，并以原 Owner 的线程、方法和期限约束真实 anchored directory FD。CLIENT 根必须已存在、安全且两轮完整库存为空；任何历史、未知、替换或竞态都拒绝，不读取历史内容或处置旧记录。原 open 返回后先实际留存 fstat 身份，晚到期限仍能关闭该原 FD，关闭不续期。[13:17 新 HOST ZIP](results/receive-publication-barrier-host-20261004-131755-2bbbb39e/public-result.zip)通过一个方法、26 个子例，Python 3.5 AST 通过。Owner、IO、metadata、FD 与 Linux flags 都明确为 HOST 模型，尚未在真实 Owner 接装；clear 仅表示局部无阻挡，不能授予 RF。原 Factory 与 Provider 的晚期门保持不变。

独立 PowerShell/.NET 核验确认上述四个新结果的 22 份来源/保存快照/当前来源零差异，SOURCE 与实机保存程序和抽取函数尺寸/SHA 一致；各 ZIP 均只有 result.json/README.txt，两成员字节与保存结果和固定说明一致。实机原 raw 尺寸/SHA、host 退出和唯一 RESULT/OK/EXIT 标记一致。原日志、私有标识和输入快照不进入公开 ZIP。新一键入口 `HOST_MTA_RECEIVE_PROBE_PROVENANCE_CHECK.cmd` 与 `HOST_MTA_RECEIVE_PUBLICATION_BARRIER_CHECK.cmd` 仅在电脑测试；`TEST_MTA_RECEIVE_PROBE_READONLY.cmd` 仅执行上述新函数只读实机诊断，不是收件启动工具。

目标仍 active。新的有界接收实测已有授权；旧 GO64 单记录的条件备份归档/结束仍未获授权，不能扩展到 CLIENT 历史目录。软件接线仍需在原 Owner 启动观察后、HTTP 前核原 scope/collection 的资源并封住采集窗口，绑定一次性接收认领到原 Operation、Session、epoch、Factory 和期限。启动采集器只能由原启动线程核验，后续 HTTP/Session 线程不能重入。公开可用性在认领后关闭，原已认领 worker 应核原绑定，不能被自己的 False 阻断。取消/到期保留全部原件，由原 Session finalizer 收尾；不能清引用、复用 claim 或续期。新两个候选未封入新部署图，收发门仍关闭，正式 RF 后恢复和小米 15 Ultra 收发未验收。下方保留历史原判。

## 2026年10月4日 新接收部署链实机启动和关闭通过

12:49 新的正式接收候选在 P011 实际接装、启动和关闭通过。固定清单包含 33 个普通角色、35 个私有角色、3 个原生助手、WPA 和独立 UI monitor，共 73 项 payload；这不是新测试发行版或接收准入。新 State、Boot、Owner、Factory、Bridge 和 runner 已绑定同一组真实源码尺寸与 SHA。观察器在新 volatile 根直下固定为 0700，两个原 helper 保持 0500；Owner 先用原资产 FD 认证并关闭，实际观察时仍由原 Observer 独立持有、复核并执行其原 FD。

[本轮实机接装 ZIP](results/formal-receive-v1-service-20261004-124946-a4c74288/public-result.zip)记录原 Boot 和 Owner 启动、启动 Baseline 与两次认证 STATUS、3 个原 proc reader、2 个能力 actor 关闭，以及原 Owner.close 通过。runner 的 2311 个已记录 FD 全部关闭，原厂三文件、所列进程、boot、路由、接口身份和原恢复记录指纹的限定基线前后相同；host/remote 退出均为 0，stderr 为 0 B。只新建 4 个目录及 72 个文件于 `/var/volatile/tmp/p011-mta-formal-receive-v1`，没有覆盖旧候选、原厂文件、启动项或分区。没有接管 Qt、重启、广播、MTA 搜索、切网或收件。旧 HTTP 九请求没有重放，本轮有意保持 http_verified=False、HTTP 请求与 client 库存均为 0。随后只读 lstat 再确认旧 pending 仍为 340 B 普通文件；未读取其内容或处理该记录。

[12:49 SOURCE 接装 ZIP](results/formal-receive-v1-source-20261004-124930-79949bfd/public-result.zip)通过六个改动角色、runner/UI 和两份短行 envelope 的 Python 3.5 AST 及交叉固定身份检查；不模拟或执行主机平台图。[12:42 被动收尾 HOST ZIP](results/formal-receive-terminal-host-20261004-124250-2e6baafa/public-result.zip)通过 1 个新方法、16 个子例，旧方法为 0。Owner 不再从外部线程重新调用实际恢复；只有原 Session、回调、Parent 及两份原网络观察闭合，才允许 runner 接受保留原 Operation 的结束状态，不能清引用代替收尾。Session、Parent 与祖先关闭库存在该测试中明确为 HOST 模型；原接收活动分支及恢复尚未在 P011 执行。

独立 PowerShell/.NET 核验确认 SOURCE/实机包各 74 份当前来源与保存快照、两份程序零差异，实机原 raw 尺寸与 SHA、唯一 RESULT/OK/EXIT 标记及 host/remote=0 一致；两 ZIP 均只有 result.json 和 README.txt，成员字节与保存件一致。实机 ZIP 为 2420 B，SHA256 `5956eef6b0e8658980ab45f299af623e87691ff4dbc83c27f83e3dfba0b531a7`。终态 HOST 包 7 份来源零差异、原一方法摘要与两个唯一 marker 均一致。输入、两个组装程序、原 stdout/stderr 和退出保留私有，不公开设备标识或凭据。

新的 `HOST_MTA_FORMAL_RECEIVE_V1_CHECK.cmd` 默认只检查电脑源码；`TEST_MTA_FORMAL_RECEIVE_V1.cmd` 明确只做上述闭门实机接装，不能当作接收启动工具。新 UI worker 已接真实 held-FD monitor 和显示循环，但本轮未重复旧 Qt 验收，也未运行新 UI 候选。目标仍 active，真实手机收发和完整 RF 后恢复未验收。你的接收实测授权已明确；仍缺旧 GO64 单记录的条件备份归档/结束授权，不能扩展到 CLIENT 历史目录。软件还需在 Owner 原启动观察结束、HTTP 前接同原对象的接收准入与固定只读 publication barrier，并强留原能力 actor 的 stdout/返回对象关联；不能只翻转 receive_available 或把只读 DATA 当作 RF 许可。

## 2026年10月4日 网络观察实机通过 接收收尾候选通过主机测试

12:05 新 ConnMan 观察器及实际 Python 3.5 生产器在 P011 只读执行两次通过。每次从校验尺寸和 SHA 的原 ARM 文件描述符启动该子进程，完整读取、回收并关闭原管道与文件描述符；退出均为 0，stderr 均为 0 B。两次服务身份、WiFi technology 和 service 库存严格一致；当时 technology 为 1、service 为 0。空 service 是真实 ConnMan 库存，不代表断网，也不能证明非空服务的 IP/DNS 分支已在本机覆盖。本观察器不读取磁盘 profile 字节，不代替 CLIENT 内部的 WPA、接口、路由和恢复检查。

[本轮实机结果 ZIP](results/receive-network-observer-device-20261004-120503-d87751a4/public-result.zip)和[ARM 构建结果 ZIP](results/receive-network-observer-build-20261004-120127-0ce26786/public-result.zip)只含 result 与 README。原 stdout、stderr、设备标识和输入快照保留私有。独立只读核验已确认来源、原退出、标记及 ZIP 成员字节和 CRC 一致。仅在唯一新 volatile 目录写入 46008 B 观察器；原厂三文件与所列进程前后相同，旧恢复记录仍存在且指纹不变。没有扫描、广播、切网、收件、页面接管、重启或旧记录处置。

新接收 State 候选已接入真正的收件前网络观察和原 Session 收尾线程中的独立终态比较。只有原 CLIENT Bridge/Parent 的恢复、回收、EOF 和资源关闭检查通过，才比较终态；未知资源、变更的服务身份或配置、超过原结束期限的旧观察不能签恢复。未启动过网络 creator 的提前取消只关闭已知原库存，保留任务首错误，不冒充完成过传输。被动 UI 监视谓词也已实现，允许观察原接收运行与收尾，拒绝外来或未知作用域；尚未接入正式显示循环。

[12:12 新增主机测试 ZIP](results/receive-network-integration-host-20261004-121235-7a1491cb/public-result.zip)通过 9 个新方法，旧方法为 0；两个未执行候选的 Python 3.5 AST 通过。非空 service/IP/DNS、Session/Bridge 和 UI 上下游明确属于 HOST 模型，不升级为实机恢复或手机互传。独立只读核验确认 70 份来源/快照/当前源零差异，三个原 marker 各唯一、九方法原摘要与 host=0 一致；5084 B ZIP 两成员原字节及 CRC 一致，SHA256 为 `f5624ae62e79bbfb1b343598abdd309b72d87e268d4b158fe0fb60057b4b63a4`。原输出及失败保留规则不变。PC 一键入口为 `HOST_MTA_RECEIVE_NETWORK_INTEGRATION_CHECK.cmd`；`TEST_MTA_NETWORK_BASELINE_READONLY.cmd` 只做上述独立只读实机观察，不是正式收件。

目标仍 active，收发准入仍关闭。下一步必须把新 State、固定观察器和监视谓词接入真实 Owner/部署入口，并处理正式 runner 收尾仍要求严格 idle、而原接收关闭后保留 Operation 的不一致；不能清空原引用代替恢复。旧恢复记录的条件备份归档尚待授权，CLIENT 历史库存本轮未处理。小米 15 Ultra 原厂收件、传输后完整网络恢复、发送和物理操作均未验收，尚不是只剩人工测试。下方保留历史原判。

## 2026年10月4日 完整蓝牙只读观察实机通过，收件仍未开放

11:33 的新原生观察器在 P011 实际执行两次通过：BlueZ unique owner、Adapter Discovering／Discoverable／Pairable、完整 MGMT settings、广告实例 ID 集合、Connected Device 对象集合均为已知数据，严格前后比较一致；本轮连接设备数和广告实例数均为 0。两个原观察进程退出均为 0、stderr 均为 0 B，原管道关闭且已 reap。限定原厂三文件和所列进程前后相同，原 GO64 pending 确实仍存在且指纹未改变。这是只读基线可用证据，不是经过 RF 操作后的完整恢复证据，更不是手机收件。

[本轮实机结果](results/receive-radio-baseline-device-20261004-113359-6ca81c0f/public-result.zip)只含 result／README；原 bus owner、设备路径和原 stdout／stderr 保留私有。仅在唯一新 volatile 目录落地 74920 B 观察器，不覆盖旧 helper／原厂文件／启动项／分区；没有 listen、advertise、scan、配对、断开、切网、Qt 接管或重启。11:29 首次脚本传输超时的 [原失败结果](results/receive-radio-baseline-device-20261004-112924-7593e31b/public-result.zip)保持 FAIL。11:32 独立检查确认该次目录未创建、匹配诊断进程为 0；随后只修正 HOST 传输为短行分段，并在 stdin 读取前加原始有限 alarm，才取得上述新通过结果，不改判首轮。

新增接收 State 候选 `candidate/receive-radio-lifecycle-v1` 已修正 helper 关闭时的提前停止读取：撤销新命令后继续读到真实 EOF，保留迟到的 cleanup／ownership_lost 回调；原 Popen、管道和线程保持原件，非零／强制退出、读错误或超时不签正常闭合。其蓝牙恢复消费器已接入严格 schema 比较，拒绝缺字段、未知 owner、同数量但不同的 peer／广告 ID，以及未关闭的能力探测。该 State 尚未进入正式固定部署图，收发门仍 False。

[新增 HOST 13 项测试](results/receive-radio-lifecycle-host-20261004-112537-32527f8d/public-result.zip)通过，含真实 HOST fixture 子进程／管道／线程和实际 parser／State 方法；旧测试重放为 0，两个新源码的 Python 3.5 AST 通过。fixture 不是原生 helper 或 P011。[新 ARM 构建](results/receive-radio-baseline-build-20261004-112415-de67547c/public-result.zip)通过，未覆盖原 out/native；公开包不含厂商依赖或二进制。两包原输入／raw／退出与 ZIP 内容独立字节核对一致。

正式 UI 新入口 `TEST_MTA_FORMAL_UI_STARTUP_V4.cmd` 已真正接到原 v4 Owner／启动采集器，在 UI 凭据与原厂页面接管之前核真实启动观察；[11:34 SOURCE 检查](results/formal-ui-startup-v4-source-20261004-113416-81d638ac/public-result.zip)通过，默认只访问电脑，未重复 Qt／实机闭门页面验收。仍未允许活动 receive operation，不能当作已能收件。

本轮源码核对更正了此前“蓝牙／手机凭据尚未接装”的笼统判断：原 GATT WriteValue → capture／decrypt → Factory／Parent → CLIENT association／DORA → Transfer／SafeZipReceiver 和 CLIENT 内部 Store／FinishReceipt 恢复链已存在。实际待补的是正式 Owner 的真实接收准入、正式 UI 对原 owned operation 的监视，以及外层独立 ConnMan owner／service／profile 终态观察；旧 GO64 pending 和 CLIENT 根历史 inventory 也是独立 publication 门，不能绕过或从只读结果签清除。目标仍 active，仍有软件工作，小米 15 Ultra 原厂收发均未验收。下方保留各历史时点原判。

## 2026年10月4日 实机启动采集与资源关闭通过，手机接收仍未验收

10:58 的第四轮独立启动诊断首次通过：真实 canonical Boot/Owner 启动，在 HTTP 线程之前完成实际 ARM/STA Baseline 和两次认证 WPA STATUS，三份原 ProcReader 经原 Store/Budget 绑定；随后 9 次本地 HTTP 和 9 个客户端验证均通过。原 Owner/startup 资源关闭、两个能力查询 actor 及 runner 2299/2299 FD 关闭通过，本轮 resource/staging pending 均 False。工具外层、ADB host、remote 退出均 0，stderr 0 B。限定原厂三文件、所列进程和基线前后一致；这不是完整无线恢复或物理界面验收。

本次只新建独立 `/tmp/p011-mta-state-startup-v4` 对应的 4 个目录、68 个候选文件，不覆盖 v1/v2/v3 或其他项目根。原厂/启动项/无线与系统分区不改，没有扫描、配对、切网、手机操作、收发、Qt 接管或重启。`receive_admission=False`、`send_admission=False`、`phone_tested=False`、`full_network_restore_verified=False` 仍保留，旧 GO64 pending 不处理，收发门全程关闭。

WPA 枚举窄修已实际接装：只对数字进程 comm 的原 ENOENT/ESRCH、确认从未返回句柄的实际 open receipt 允许继续；原异常、票据和 attempted=False 保留。真实 FD 关闭证明不包括这些未打开记录，但全库存仍审计；取得 FD 后的错误、必需 actor、唯一 daemon、程序/端点/响应认证与预算仍严格。新增 HOST 模型的 18 个子情形通过，未重跑旧测试。10:50 首次 HOST FAIL 定位到新异常变量与外层 error 重名，以及测试防护干扰框架错误记录；这两项窄修后 10:54 唯一受影响重测通过，首次 FAIL 的快照/raw/结果包保留，不改判。

[第四轮实机结果 ZIP](results/startup-readonly-v4-service-20261004-105823-8c22f9c3/public-result.zip)，SHA256 `8c052672dc307a7ce724dea093e6836d6b48cde294b738750e4832b7a2f7f30a`；[18 项 HOST 模型结果](results/wpa-comm-no-fd-v26-host-20261004-025407-f3f871e4/public-result.zip)，SHA256 `180924bece86a51f11868ecfbb77a128f09afdf47bbd112e1ce775ea73e6d0a7`。HOST 目录以 UTC 命名。Root 已读核实机完整结果、原 RESULT/OK/EXIT 各唯一、原 host/remote 退出及目标源 SHA；实机原 stdout 1763133 B，目标源 1757908 B，66 固定来源保留。原始错误标记为空，没有补签此前 v2/v3 Owner 关闭。公开 ZIP 只含 result/README；私有 raw、输入快照及未公开设备数据留本地。

独立 PS/.NET 原件复核随后通过：66 固定输入/当前源/快照原字节和 SHA 零差异，31/35 来源表及 runner pins 一致；实机唯一三标记、完整结果、无错误投影及原 host/remote 退出一致。实机 ZIP 为 2037 B，result/README 原字节与 CRC `3ddab23f`/`062294fe` 均一致。另一个独审已全文核 v4 源码差异、稳定 schema v1、collector 复用及新 AST 范围；18 项 HOST 的 13 份输入、原标记/成功摘要/退出及双成员 ZIP 原字节/CRC 也一致。独审没有执行或重复设备/测试。实机报告未公开实际跳过的进程数量，不据 PASS 断言这一轮一定触发了 ENOENT 分支；该分支的正反行为由上述 HOST 模型验证。

[新实机一键入口](TEST_MTA_RECEIVE_STARTUP_READONLY_V4.cmd)只做上述关闭收发的启动诊断，不是安装正式接收功能或开启手机互传；[新增 HOST 一键入口](HOST_MTA_WPA_COMM_NO_FD_V26_CHECK.cmd)只访问电脑。新实机检查只对五份普通候选和新 WPA 源共六份做 Python 3.5 AST，runner/envelope 各一次，旧模块 AST/旧测试重放为 0；原 collector 20426 B/2e49… 保持 v3 原字节。

启动采集这一具体软件缺口已得到实机正向证据。接下来仍需原蓝牙/手机凭据接装、完整无线恢复链和小米15 Ultra真实文件收件；不能只翻转收发开关。已重新向用户询问旧 GO64 未完成记录的条件备份/归档权限，答复前保持原件；若原资源无法核实退出也不终结记录。目标仍 active，尚不是只剩人工验收。下方各失败/通过时点均保留原判。

## 2026年10月4日 实机启动诊断定位到 WPA 进程枚举，接收尚未开放

本轮依照用户的接收实机测试授权，先完成新的只读基线检查，再执行三份独立、固定来源的闭门启动候选。没有扫描、配对、切网、收发、Qt 页面接管、重启、原厂文件/启动项/分区替换或旧 GO64 pending 处理。旧记录仍保留；手机真实互通和完整无线恢复尚未验证。

09:48 只读基线通过：识别到 P011、原厂三文件匹配且前后相同，Wi-Fi 已连接，ConnMan/BlueZ 服务存在。10:04 v1 完整落地并启动原 Owner，但 Factory 在遍历 `/proc` 时误把非 root 进程目录当成必须的 root 管理路径，失败于路径校验；本轮 Owner/startup 资源关闭通过。10:08 独立只读观察确认 198 个稳定数字进程目录中有 3 个非 root 目录，没有改权限或结束进程。v2 只加入候选选择预筛选，但我们接装时误把 Factory 的协议标识改成 v2、Owner 仍是 v1，10:19 被原件一致性检查拒绝；该轮 Owner/startup 关闭未通过，不能用 runner FD 关闭或进程退出补签。

v3 恢复稳定协议标识，保持身份认证和固定来源约束。10:30 实机已越过 Factory/profile/私有导入，进入真实 Baseline 和 WPA STATUS source；在读取枚举出的数字进程 `comm` 时遇到原 `FileNotFoundError(errno=2)`，上层报告 `BaselineError(io_error)`。这不是 WPA 程序丢失或 ARM 打开常量错误：固定 trace 指向进程枚举读取，`_ReadFiles` 使用 ARM O_NOFOLLOW/CLOEXEC。STATUS 目前没有处理进程在枚举后退出的已知未打开记录，正在制作窄修；不会伪造 FD 关闭尝试或降低必需 WPA/端点/响应认证。

v3 结论仍为 FAIL：实际新建 4 个目录、68 个候选文件，Boot 和两个能力查询 actor 的关闭通过；HTTP/客户端请求 0。原 runner FD 2302/2302 关闭、限定原厂文件/进程/基线前后相同，但 `resource_pending=True`、`owner_resources_closed=False`、`startup_resources_closed=False` 保留。不能解释为已完成接收、Owner 关闭或完整恢复，也不把 gate 检查未执行的 False 当作实际收发门已打开。

[v3 实机结果 ZIP](results/startup-readonly-v3-service-20261004-103004-59545b88/public-result.zip)为 2373 B，SHA256 `669d481fe1069934e8029334b87e1cc8d428699f4108f17dda4f4cdc4163ae5d`。独立 PS/.NET 只读核验确认 66 份固定输入/快照原字节及 SHA 一致，原始五类标记唯一，主机退出 0、远端退出 1，完整结果和错误投影一致；公开包仅 result/README，原字节和 CRC 一致。原日志/私有快照保留在本地，三轮历史失败不改判。[v1 原失败](results/startup-readonly-service-20261004-100423-d77a0c90/public-result.zip)、[v2 原失败](results/startup-readonly-v2-service-20261004-101923-443aa428/public-result.zip)及[只读进程归属观察](results/startup-proc-ownership-20261004-100824-2ce6bd4c/public-result.zip)分别保留。

目标仍 active，仍有软件工作。下一步为新固定版本的 STATUS 枚举兼容修复及受影响的实机启动/关闭验证；不重复已经通过的界面、原生构建或 BLE 专项。下方历史状态保持各自时点的原判。

## 2026年10月4日 接收启动采集候选主机检查通过

09:42 本地首次 HOST 检查通过：新增两个方法、九个检查域，两个实际子进程退出 0、无超时、旧方法执行数 0；外层 checker 退出 0 有本轮工具观察。检查只运行电脑上的固定源码和明确模型，本轮没有 ADB、设备写入、无线操作、Qt、Docker 或旧记录处置。结果目录用 UTC 命名，不是本地凌晨执行。

独立候选 `candidate/receive-startup-readonly-v1` 已接好实际启动调用：Owner 在原 State／探测资源关闭后、HTTP 线程创建前同步调用 Factory；Factory 读取真实固定私有源和 profile，复用 F 的 35 模块隔离导入器；新的 collector 用原 Store 绑定 ProcReader 预算，以 ARM 的 O_NOFOLLOW 常量读取实际 Baseline／认证 WPA STATUS。源码没有构造假 handoff／LoadedDeployment，也没有执行 acquire／租约／收件或继承原 wpa_cli 子进程路径。收发准入仍 False；这是已接装的源码设计，不是已运行的 P011 观察。

本轮修正了三个具体异常边界：一个原关闭方法报错后，其余已知资源仍各自尝试关闭；原启动超时／纯构造错误不再被关闭状态错误覆盖；collect 先保留原 ticket／collection，再由实际 run 检查活动期限，避免过期时失去原异常和对象。未进入 IO 的已知纯构造失败与已进入 IO 的未知资源分别判定，不能据未分配对象推导设备 FD 已关闭。

HOST 实际验证了 35 模块的隔离加载、完整图校验先于 exec、原 F 与 JSON 身份、未知私有导入拒绝，以及原 Store／Budget／Proc／Baseline 纯构造的异常保留。Scope 和独立关闭控制为明确 HOST 模型；没有成功的 Baseline／STATUS 采集，没有真实 Factory／Owner 启动，也没有签硬件 FD 关闭。六件新运行源码各做一次 Python 3.5 AST，私有 35 项、普通 29 项加 Boot／Owner 共 31 行来源与校验值一致。已经通过的旧测试没有重跑。

[一键 HOST 检查](HOST_MTA_RECEIVE_STARTUP_READONLY_CHECK.cmd)只访问电脑，不连接 P011。[5062 B 结果 ZIP](results/receive-startup-readonly-host-20261004-014247-94d3b4c2/public-result.zip)，SHA256 `73bae1ad132f33c0df695259c37fdce885904b51bf17524c4350e930dc3c434a`。64 份输入快照、两组原 stdout／stderr 分开保留；公开包只有 result／README，不含 raw、凭据或厂商程序。原 stderr 各 100 B 是 unittest 成功摘要，不声称 stderr 为空。

独立 PS/.NET 只读核验完成：64 原文件与快照的字节／尺寸／SHA 零差异；两组原输出的摘要、唯一完整成功标记和 Ran 1 test／OK 格式与报告一致。ZIP 的 result 13555 B／CRC `bcc91530`、README 450 B／CRC `12b42f26` 解压后原字节一致；静态来源图也独立核了 35／31 行和 Boot／Owner29 项。独审未执行 Python、AST、测试或设备，不把该读回升级为实机层。

新固定根为 `/tmp/p011-mta-state-startup-v1`，不覆盖先前实机通过的 state-v69。新候选尚未部署或在笔上启动，旧 GO64 pending 保留且条件归档／终结仍待明确授权。下一步是新的固定来源部署与实机 ARM／STA 采集，再对接真实蓝牙、手机凭据和无线恢复；不能把这次 HOST 通过当作接收开放。小米 15 Ultra 双向原厂互通尚未通过，目标仍 active，仍有软件工作，不是只剩人工验收。下方历史时点保留原判。

## 2026年10月4日 正式界面实机启动与退出恢复通过，接收仍未开放

08:58 的 v2 闭门界面会话实机通过：真实 Boot／Owner 启动，固定互传页面 READY，页面发出实际 HTTP 请求，随后原 Owner.close、临时凭据撤回、候选及独立 guardian 退出、worker FD 关闭和限定原厂恢复均通过。本轮没有新增资源 pending；工具外层、ADB host、remote 均退出 0，stderr 0 B。没有请求 MTA 接收、扫描或发送，也没有处理旧 GO64 pending、重启或更换原厂／启动项／分区。

[1868 B 实机界面结果包](results/formal-ui-session-v1-closed-ui-20261004-085811-1a5c9759/public-result.zip)，SHA256 `225e6011331e6de52f6e1d478bf4f2f55e5a340a28b231a486fce2f91e837aa8`；[1766 B v2 SOURCE 结果](results/formal-ui-session-v1-source-20261004-085628-0067955e/public-result.zip)，SHA256 `11db44b50058ab67d75b0b3890f79dc42b630e252a4124a0f360260d894b1227`。原 stdout 1767791 B／`a7e72ac54dfa5db317accea569c528f97d499ffa16fbf1c6ac9896ab0fafd7f5`；目标脚本 1763285 B／`4dbf3cdcf5b78706822acfa998098cfff91ce5b647c56b896167fedfc0e29027`，仍低于 2 MiB。当前 worker 40610 B／`5ab355ea2d710af94854bff6360149638a15c54be11bf4431a36295e8d15368e`，HOST 22392 B／`1b74810eb00db1ef6f1befa613aaf345a0c7cbff07bade0540c12012eeac64b2`。

两轮各 68 份源码快照保留。独立 PS/.NET 核验确认实际 READY／RESULT／OK／EXIT 各唯一、14 个字段与报告一致、快照与 SOURCE 原字节相同；公开 ZIP 只有结果和说明，成员原字节及 CRC `c784c7d9`／`97f7ff64` 一致。未重跑已经通过的构建、安装、BLE、管道或 HTTP 专项。当前固定 CONTROL 已使用，后续实机尝试须新建经审核的会话标识，不能直接重跑并覆盖本轮日志。

08:50 的首次闭门 UI 会话 FAIL 原件保留：[1877 B 原失败结果](results/formal-ui-session-v1-closed-ui-20261004-085015-bd517c87/public-result.zip)。有限私有 trace 定位到实际 TERM 后 `/proc` 暂态读取，未把已退出过程当作稳定 live 身份。v2 仅在原 TERM 5 秒／候选 KILL 3 秒等待内短重读 `process_unknown`；截止仍未知即失败，身份变化立即失败，未知不能授权升级 KILL。原信号身份门、Boot／Owner 和收发门未放宽。首次失败也确认原 Owner 收尾、凭据撤回及限定原厂恢复，但不能改判页面启动通过。

08:58:40 还只读抓取并实际查看了 [DRM 原生扫描输出](results/mta-drm-capture-private-20261004-085840/crtc-75-scanout.png)：480×800、pitch1920，页面显示“互传暂不可用／接收能力尚未就绪”，与后台 receive_available=False 相符。没有唤醒、改变亮度／息屏、模拟触摸或写图形缓冲。原生全扫描输出包含内容区之外像素，不能据此签物理可见范围、触摸或页面错位验收；截图及 raw 只留本地，不进入公开 ZIP。

接收诊断剩余两个独立阻挡：Factory／CLIENT 会拒绝仍保留的旧 GO64 pending；生产接收还缺 HTTP 多线程前真实 ARM／STA startup 观察，以及实际蓝牙和完整无线恢复链。默认 Baseline 的主机 O_NOFOLLOW 常量和未绑定 ProcReader 不能直接在 ARM 上充当验证，须复用真实私有 collector／Store 资源绑定，不能伪造 LoadedDeployment、handoff 或只翻转两个 False。已通过的 DIAG BLE 广播／取消不是手机凭据到 Factory 的完整收件链，不重复测试或升级为接收准入。旧记录的条件归档／终结需独立授权，目前不处置。

当前通过层为依赖落地、实际页面／HTTP、原 Owner 收尾和有限原厂恢复；小米 15 Ultra 手机收件、完整网络恢复、物理触摸及生产接收准入均未通过。目标仍 active，仍有软件工作，不是只剩人工验收。下方历史时点保持原判。

## 2026年10月4日 正式界面资产实机落地通过

08:45 固定结束帧版 SOURCE 首次通过，08:46 唯一受影响 P011 部署重测通过；旧 EOF 失败原件不改判。这是本轮首次实际写 UI 资产：独占新建三个项目目录与十个固定文件（九件资产＋SOURCE），不覆盖现有文件，不删除或遍历其他 UI session。原厂三文件的固定 SHA 及实际完整 metadata 在首写前和操作后相同；原 45/45 个 stager FD、validator 17/17 个 FD 全部关闭。真实 validator 核十文件、20 次读回、两轮目录库存/路径绑定和无 credentials，resource/staging pending False。

工具外层、ADB host 与 remote 实际退出均 0，stderr0；raw stdout3542959 B／`fed2764bba38475661176f335fe741f0bf708a2f147e4b4cc3f93236a8b69991`。脚本31586 B／`83ca9162faf0db1c58465716871160c0043ab78384e68c997c75db1cb35b6aeb`，wire3502697 B／`d9b5681edc7fb7be85b2f904ddb8afd853a548fc4d636f66d7233fd67f031bd0`；只读严格十帧＋86 B SHA-bearing结束帧，不再等待物理EOF。明确 `physical_stdin_eof_verified=False`，尾外字节不读取/执行，也不声称不存在。原SOURCE2MiB、raw4MiB、wire6MiB预算和60s活动/180s外层保持。

stager43171 B／`962d1de014bb7f1be677ed997eaae67c13f88e204d916bb9a8526d0b9a6b0a4c`，validator10489/e58原样。两轮各13快照，公开包仍只有result/README，不含厂商ELF、wire、raw或凭证：[资产实机结果](results/formal-ui-assets-stage-20261004-084628-3ffcea0f/public-result.zip) SHA `9bf8b79a94376782af74c25e11c07b0e3ce9aeae444046ab45b4752d50b49f95`；[修正版SOURCE结果](results/formal-ui-assets-source-20261004-084504-f1d58ab6/public-result.zip) SHA `1cb90bc39f08883aae0c3fc8371b0b8bd3319a4ad09c3e110bb02fb757d977b0`。独立源码及原件复核完成，29字段、13快照、2368 B实机ZIP原字节与CRC `545fe509`／`423d8840` 均一致。

本次只有文件落地与真实校验；没有Qt、Boot、Owner、RF或收发，没有更换原厂/启动项/分区、处理旧pending或重启。原厂进程和物理页面未验证，不签完整网络恢复或手机互通。worker39516/114972的SOURCE已审，HOST闭门会话入口的首个PC-only检查通过，尚未启动；正补有限异常trace，避免运行失败后丢失因果。目标active，仍有软件工作，不是已完成接收。

## 2026年10月4日 接收依赖安装实机通过

08:07 的新 SOURCE 检查与 08:09 的唯一 P011 依赖安装均通过。安装前先核现有普通 State、GO deployment、用户目录与限定原厂基线；只新建一个 `runtime35` 目录及 36 个固定文件，即 35 份接收模块和一个私有 WPA 程序。新文件尺寸、完整 SHA、root 属主和 0400／0500 权限已读回，2307/2307 个本轮原 FD 关闭，resource/staging pending 均为 False。已有文件没有覆盖、修补、chmod 或删除；遇到已有残缺、额外项或不匹配内容时仍保留拒绝。

工具外层、ADB host 和 remote 实际退出均为 0，stderr 为 0 B。原 stdout 1743273 B／`c9ca9b757db684ecf6e5bec93598efec28d4237b4f2978e8977dc6a07625c7c5`，目标源码 1738296 B／`df38828e4da3ec426d96cbc010e64e9c3b3b58db1ed6c84e7099d8c983b0ffad`；ROOT 读核唯一结果及退出标记，33 个组件字段与公开结果一致。两轮各保留 65 份去重来源快照。固定 payload 68 项共 3799863 B，SOURCE envelope 实际 1738297 B，小于既有 2 MiB 上限，没有按未压缩理论值扩大预算。

本次安装没有加载 Boot/Owner、执行私有模块或 WPA，没有启动能力查询 helper、HTTP、Qt、广播、扫描或收发；这些未运行服务的关闭字段为 False，不解释为服务关闭失败。限定原厂三文件、所列进程及父身份、boot、旧 pending 摘要、IPv4 路由和接口名/ifindex 的 before/after 相同，但没有签完整原网络恢复或物理原厂界面健康。未替换原厂、启动项或分区，未重启、配对、切网或处理旧记录。新候选依赖保留在项目临时目录。

[1863 B 实机安装结果包](results/closed-service-private-assets-20261004-080937-8039cbf2/public-result.zip)，SHA256 `37988b1d33ffbec5b9f5bd8ffd4aadf2d8d2aa611f5ae44ec7dee95978920cfa`；[1477 B SOURCE 结果包](results/closed-service-source-20261004-080726-603cc942/public-result.zip)，SHA256 `a431a592be3bb58ffdce54cc975e47a7e3aa1cd3129bf9e0139d22d2fd6c643f`。两个公开包各仅 result/README；raw 与源码快照只留本地。[现一键入口](TEST_MTA_CLOSED_SERVICE.cmd)加 `--install-private-assets` 才执行固定依赖安装，默认仍为闭门服务模式。新 runner 60600 B／`b335d069e6ebb9ed216380f0a9b21b4329ddee353a6f8aaf29fe0db3e9744ee2`，checker 22984 B／`27710225a5591ee68146fb14c612b93675347f8caf5488464c441b56f975b9a8`，CMD 262 B／`efb9e2c6bf28d28a7c48aacf2d485dfeccd7e35c04f3ec297362093b327d8980`。独立 SOURCE 审核确认固定私有 manifest 的三字段、35 pins、模式互斥和新增分支；源码及原件独审均已完成，没有重复实际安装或旧专项。

两个新结果随后完成独立 PS/.NET 原件核验：各65快照与当前源码零差异；实机 raw 的33字段逐值相同，三个标记唯一，实际退出及尺寸/SHA一致。两公开包只含result/README，原字节与CRC吻合；实机成员CRC为 `25483802`／`cb7b8fb2`，SOURCE成员CRC为 `7c46fe99`／`cb7b8fb2`。独审没有执行或重跑源码、测试或设备。

正式界面的九件固定资产校验器 `ui_assets.py` 已制作并由 ROOT 全文审查，10489 B／`e58de146a8274402af0535972b8179f1d7a973320f3437935a29212a962e6507`。它只在显式调用时只读验证固定页面目录，两轮库存前均重置原目录 FD offset，核 SOURCE/文件/目录绑定并关闭原 FD；还未执行、下发或启动 Qt。

08:29 新 UI 资产部署入口的首次 PC-only SOURCE 检查 FAIL，未调用 ADB、未写设备；[原 FAIL 结果包](results/formal-ui-assets-source-20261004-082935-85ce9b78/public-result.zip)保留，SHA `c1d5c850bafc5380f5409401f7be3a6a163f5b7564282bdf0cbc0d758f4f5415`。进一步只读组装诊断确认 `target_source_budget`：固定 ELF 的压缩 base64 源码片段 3502793 B，全部资产片段 3523139 B，超出既有 2 MiB SOURCE 上限。正在改为小脚本加固定 ASCII 资产尾帧；不直接抬脚本预算，也不使用未知二进制传输。更早独审发现的两行缩进问题已窄修，原版本没有执行到设备。

08:38 小脚本＋ASCII 尾帧修正版 PC-only SOURCE 首次通过，13 份快照保留；实际脚本 30750 B／`ca3afffb385bae83ef7e178700ec55a2580d414181c56c034132ff248da3be75`，wire 3502611 B／`d27a5bcc1af1c7d2794a1c986db104f616f00ba6aec69e8a50b99d5cc8e31563`。独审只用 PS/.NET 核十帧解压后的实际尺寸/SHA/快照、脚本长度/行界及 ZIP 原字节/CRC；[1905 B SOURCE 包](results/formal-ui-assets-source-20261004-083839-46526727/public-result.zip) SHA `d5ac5a8d76ce3c0123ae11bfa73ef1ef6d7c9917842c89b569a4510816ed4cd1`。

08:39 该方案唯一实机部署尝试 FAIL：host0／remote1／stderr0，28 个组件字段及有限 trace 指向生成程序 `payload:103` 的最后 `read_stdin(1)`，在十帧和完整数据 SHA 已通过后，等待真实 stdin EOF 到原 60 秒截止。新目录/文件均 0，原 FD 库存 0、resource/staging pending False；没有 stock 观察、validator、Qt、Boot、Owner 或 RF 操作。不能把 host0 解释为成功，也不把未观察 stock 签为恢复通过。[2221 B 原 FAIL 包](results/formal-ui-assets-stage-20261004-083939-dfdad4bc/public-result.zip) SHA `e43422b6f615a6847cfa02481f758b17d23c5cedcfe5f433eb21f2a25f322d60`。正在窄修固定长度/SHA/结束帧，不再等待这条 ADB 会话不提供的物理 EOF；不增加超时，不虚签 EOF。

同一 worker 持有原 Owner、独立 guardian 恢复界面的 worker 已完成 SOURCE 及全文复核：39516 B／`114972219d079e101c1a22912e57b1824c6e85d455ed4ceb15668ea550993cf4`，尚未执行，HOST 入口接装中。不能签实际页面或服务交接。接收依赖缺失这一软件缺口已补齐；真实启动/恢复准入、旧记录条件处理及小米 15 Ultra 原厂收件仍未完成。目标 active，尚非只剩人工。

## 2026年10月4日 关闭收发的服务实机启动通过

07:32 的新只读预检首次通过，随后 07:34 的首次完整闭门服务也在 P011 上通过。两次外层 checker、ADB host 和 remote 均退出 0，stderr 均为 0 B；原始输出、各轮 37 份输入快照及两个公开 ZIP 已读回并经独立 PS/.NET 核对尺寸、SHA、原字节与 CRC。没有重跑已通过的 Qt、管道或旧组件专项。

这次窄修只改变诊断扫描器对已退出进程残留的分类：持有原 proc/task/fd 目录 FD，两轮核实原身份及路径关系、Z 状态、线程数 1、task 仅原 PID、空 FD/cmdline、exe ENOENT，才允许枚举继续。原厂六类、其父进程、Python 和已知 MTA helper 的身份检查保持严格，未知观察仍失败，race32 不变。实际预检三次扫描均为稳定内核线程 157、race0、符合上述事实的 other Z 两个；这不证明其历史来源，也不终结旧记录。最新 runner 为 52719 B／`31137adf959651a68500b26b287e9d535c97f7d451f3bff10bd7d066c88bcf1b`，checker 为 19038 B／`91621737dc182dc1b2f3ae64a54a0f1a8ac1beab8255e4088d364d53d33b49d6`。前三次 FAIL 和 raw 原判保留。

预检创建目录/文件、Boot/helper/HTTP 均为 0，本次 1556/1556 个原 FD 已关闭。原厂三文件摘要、所列进程身份及父进程、boot、旧 pending 摘要、IPv4 路由和接口名/ifindex 的限定 before/after 比较相同。[1695 B 只读预检结果](results/closed-service-preflight-20261004-073259-9905acaa/public-result.zip)，SHA256 `faa7f8c43ac9be677706b73dca84a13a245ab9da1ba656e4eaf5792aa8d10401`。

完整模式随后独占新建 5 个项目目录、32 个候选文件，未覆盖既有文件：29 份 State 模块、两个原生能力 helper 和一份 GO deployment。原路径及文件尺寸、SHA、权限、目录关系已核实。真实 canonical Boot 加载 28 角色，原 Owner/State 构造并启动；两个只读能力查询 actor 收尾，9 次真实 loopback HTTP 请求验证一次性 bootstrap、授权拒绝、状态/文件目录读取及关闭收发时拒绝动作。9 个客户端及对应服务端连接/worker 均收尾，实际执行原 Owner.close，目录借用、HTTP 线程、能力查询和本次 2198/2198 个原 FD 均已闭合。没有资源或暂存 pending，收发/扫描门全程关闭，限定 before/after 基线相同。[1705 B 首次笔端服务结果](results/closed-service-service-20261004-073430-64e6ac7c/public-result.zip)，SHA256 `48ac5a946b3d5683cccba855a0a9d59c6a215a7fc24f361706d6ebfaed5c369c`。

[一键诊断入口](TEST_MTA_CLOSED_SERVICE.cmd)默认执行上述有界闭门服务；只读模式另加 `--preflight-only`。直接运行 host checker 而不传 `--check-device` 才是 PC-only。公开 ZIP 只含 result/README，不含 raw、token 或文件列表。项目候选文件保留供后续接装；未替换原厂、启动项或无线/系统分区，没有 RF、网络切换、配对、重启或旧 pending 删除。

07:48 又完成首次 PC-only 正式界面构建，子进程和工具观察的 host exit 均为 0，分别保留 stdout 3572 B、stderr 0 B。新构建器只复用已审的单 QRC 槽算法，不调用旧 Bili build/worker。新副本 4103844 B／`16bca110706007b7f9d6a8d2e928e80ff4b586dfe32a5515d298a8a2bed96ce4`，实际重枚举 400 资源、399 原记录不变、槽外及总长度相同；NaviPanel 压缩使用 1551/1580 B。两个固定 QML 壳加六件原样前端随新 ELF 共 9 件 SOURCE，实际清单 SHA 为 `b414da2d8fd5ec1b274e286023e304036b68246c387ce4b8bd6c633d23fc4057`。未创建凭证文件、未下发或启动 Qt、没有使用 QuickTest。[本地构建结果](out/mta-ui-2890bb25f7f13f2f735fde8a/build-result.json)与[原始构建日志目录](results/formal-ui-native-build-v1-host-20261004-074857-79d3037f)保留；copied vendor ELF 不打包进公开诊断 ZIP。真实 Owner 凭证、worker/guardian、页面退出和原厂界面恢复仍需接装。

下一软件缺口已具体定位：Factory 固定读取 State 下的 runtime35 和私有 WPA，而本次只部署了普通图。现有 private35 原表及 WPA 实际输入 pins 已核；安装方案只允许固定35完整集合和唯一 WPA，缺失才独占创建，已有残缺/额外项保留拒绝，尚未实施。目标源码采用 zlib 后 base64，尚未生成该额外资产 envelope，不能据未压缩理论上界擅自放宽现有 2 MiB 入口上限。另需在 HTTP 多线程启动前正确建立真实 startup 观察，并补足独立 DBus 发现/可发现/连接集合与网络恢复证据，不用界面布尔量替代。

当前通过的是服务启动与收尾、PC 候选构建，不是手机收件、笔端页面或原网络完整恢复。正式接收/发送准入仍 False，旧记录条件处理答复尚待；不直接执行旧 Bili 脚本或清旧 GO64 pending。目标 active，仍有软件自主接装工作，尚非只剩人工。

本地界面产物随后完成独立 PS/.NET 数据核验：9 件 SOURCE、8 个输入、6 个原样拷贝与2个模板渲染全部匹配，实际解析两件 ELF 各400 QRC，399完整记录及槽外原字节相同；NaviPanel 解压6029 B与嵌入源一致，29 B填充为0，Adler32有效。原stdout派生JSON与build-result一致，12产物文件没有credentials。独审未重跑构建或运行Qt/设备；这仍只支持 PC 构建，不签实际页面。

## 2026年10月4日 组合页面与实机预检诊断

新的六件组合前端已保留发送准备、设备选择和完成确认，并合入接收归档下载与解包校验进度。06:54 的单次电脑 Qt 检查通过：一个新方法、四域、子进程和外层退出 0，无超时或旧测试重放。14 份输入快照及公开六成员 ZIP 已独立核原字节、SHA 和 CRC；两张实际 800×268 截图已查看，未见布局错位。HTTP 操作是明确模型，没有启动服务、访问设备或授予收发准入。[65703 B 电脑端结果](results/formal-ui-composition-v1-host-20261003-225400-e60f6b5a/public-result.zip)，SHA256 `0c704f803bc2347e55df0bc602dbd521a6ce350a20f85097a1bae15ac30f90c6`；[一键电脑检查](HOST_MTA_FORMAL_UI_COMPOSITION_V1_CHECK.cmd)。该结果目录按 UTC 命名，正式原生界面启动器及笔端前端接装尚未完成。

已新增固定来源闭门服务诊断入口，默认仅 PC 源检查；实机须显式参数，`--preflight-only` 不写文件、不运行 Boot/helper/HTTP。完整模式只可独占创建缺失的项目候选，已有冲突或未知条目保留拒绝；原厂、启动项、无线、旧 pending 不改。原目录 FD 与 parent/name/alias 关系在创建和写入前后重核。收发和扫描仍关闭，不能用该入口签手机互通。

本轮实际运行三次只读预检，各对应明确的检查器修改，不重跑已通过的 Qt 或管道专项。07:01 首次停止于枚举过程把无 exe 的进程计为消失超过 32；124/124 个本次打开的原 FD 已关闭。随后按 Linux 4.14 的真实 PF_KTHREAD 和双读身份窄修分类，保持原竞态上限。07:08 实机观察到 134 个稳定内核线程、消失计数 0，随后停在仍存在的用户态无 exe 分支。07:15 仅增加私有分类后再次确认：两次观察均为 state Z、comm_class other、非内核线程、身份稳定、exe errno 2；不属于六个跟踪名称或已知 Python/MTA helper 的名称类别。此分类不能证明该进程与项目无关，也不能仅凭 Z 证明整个线程组退出；没有增加 Z 豁免或发 kill/wait。

最新预检仍 FAIL，ADB host 0、remote 1、外层 1，stderr 0 B；本次 796/796 个原 FD 已关闭，创建文件/目录、Boot、helper 和 HTTP 均为 0。before/after 基线没有形成，初始化为 False 的 stock 字段不是摘要不匹配结论，也不签旧 pending 相同、原网恢复或原厂功能健康。[1700 B 最新脱敏诊断](results/closed-service-preflight-20261004-071536-e9c352e1/public-result.zip)，SHA256 `7194fd91fffbb01e86bb5615799a0945c2c3a93b04415f00b6b11e067d7126ed`；前三次原 raw、37 份各轮来源快照及失败结果均保留，raw 不进入公开包。原始 stdout 的输入回显只在派生解析中规范化。

当前 runner 为 47738 B／`340c10afa332118ca1d5416d9905c45cdd238d007bed9432a9cf5aaf7a180f3d`；checker 为 19038 B／`68b89c3217cf36813b173581d77cf87cdb3795e013b35f7ae63c3eb32a858ca3`。下一步只研究闭门枚举对经线程组事实证实的未跟踪僵尸的处理，跟踪原厂进程、其父进程及未知状态继续拒绝；没有改生产接收图或恢复门。正式接收、手机收件和完整恢复仍未通过。旧记录条件处理答复尚待，目标 active，尚非只剩人工。Docker 引擎本轮只读查询不可连接，未启动或重置；它不影响本次预检，但后续原生编译仍需可用构建环境。

## 2026年10月4日 Parent 管道兼容修复

两份 Parent 已新增独立 libc 兼容候选，取消对目标缺失的 Python fcntl 模块的依赖。仅修改底层 flags 适配和说明；保留平台门、管道身份及读回、原期限、已知资源关闭和未知状态保留。Boot 和 Owner 只更新相应固定来源摘要，新的普通 definition 表 30 行全部实际匹配，其中仅四行改变；其他三张来源表、旧源码和已核验离线包保持原字节。

06:07 的首次 HOST Linux 专项通过：一个新方法、五域十夹具，两份新 Parent 各一次 Python 3.5 AST。真实 libc／管道验证非阻塞标志读回、EAGAIN、字节写读、EOF 以及 12 个原 FD 关闭后的 EBADF；ARM／Python／root 条件与 errno 故障是明确模型。子进程退出 0、无超时和 WSL 警告。外层 checker 的退出字段未单独持久化，不补签其 host0。原始 stdout 158 B、stderr 98 B 均严格匹配专项输出，五份快照与来源一致，独立审计核对 ZIP 原字节和 CRC。[1859 B 脱敏结果](results/parent-libc-pipe-host-20261003-220704-017951e10a274f59a4cc41d623eb5463/public-result.zip)，SHA256 `5ee62b72453eef60802d302136df5f278da1d362da6961025fc95d5bc38dbda2`；[PC 一键入口](HOST_MTA_PARENT_LIBC_PIPE_CHECK.cmd)。目录按 UTC 命名。

06:22 的单次 P011 管道组件核验也通过。两份完整冻结源码只在内存私有模块中加载，原 `_LinuxIo.validate` 在实际 ARM／Python 3.5.5／root 环境执行，不投影平台。两条真实管道完成 NONBLOCK、EAGAIN、固定字节写读、EOF、GET／SET 的 EBADF，四个原 FD 各关闭一次。测试程序比较的原厂三文件及六类进程身份、boot、旧 pending 摘要、IPv4 路由和接口名／ifindex前后相同；不将这项有限基线比较称为原网络完整恢复或原厂全部功能健康。

本轮 checker 退出 0 有工具观察；分别保存的 ADB host exit／remote exit 均为 0。原 stdout 50107 B 包含输入回显，stderr 0 B，原件不改；派生 RESULT／OK／退出标记各恰一条。五份快照与 48493 B 远端源码已读回，独审另解压两件嵌入源码并逐字节比对，核公开 ZIP 字节与 CRC。[1431 B 实机脱敏结果](results/parent-libc-pipe-device-20261004-062225-6fb177d4/public-result.zip)，SHA256 `877fa0f0214a82bb32e843a26402ee79618a3c5b33601151794040c7b296a17f`；[显式单次实机入口](TEST_MTA_PARENT_LIBC_PIPE.cmd)。未部署文件、改无线、重启或处理旧记录。

仍未运行 Parent.collect、完整 Boot 服务或接收准入，也未完成手机收件。现有离线包保持旧输入，未据兼容专项晋升为新运行发行。旧记录的条件归档和终结已向用户询问，尚未收到新答复，不据接收测试授权自动处理旧记录。目标 active，正式收发仍 False，尚非只剩人工。

## 2026年10月4日 固定来源候选包已核验

最新普通服务 30 角色、私有接收 35 角色、发送 25 角色和独立观察 41 角色，现有了对应的 PC 离线打包入口。四张原表逐字保留，131 个角色对应 80 份不同源码；只有同目标、同字节的 GoDeployment 双角色合并，其他同名不同版本按各自目录保留。另收三份原生二进制、六件未接装前端和 22 件现有许可及构建材料。WPA 二进制保留接收和发送两个目标，Terminal Parent 按独立角色文件名保存。

05:41 的第四次电脑端打包首次成功，主机退出 0，原 stdout 385 B、stderr 0 B。前三次失败原件保留；首轮只有固定失败标记，没有单独签具体原因。后续 traceback 和独立元数据探针定位到本 Windows Python 的 lstat 与 fstat 对 ctime、CMD 可执行模式位报告不同，窄修仅调整跨 API 的比较；两侧自身完整元数据、文件编号、类型、大小、修改时间、原字节和 SHA 校验仍保留。失败目录守卫也已修正，只有本次目录实际创建成功后才写失败副本。这些失败分支的修正经过源码复核，没有额外故障注入或重跑旧专项。

成功包的 171 个成员、118 份输入快照已读回。独立 .NET 审计核对全部成员尺寸、SHA、原字节和中央目录 CRC，并重建目标映射，134 个安装意图无冲突。CATALOG 的 169 项不含自身与 README；result.json 在 ZIP 外。来源当前字节与快照一致，旧结果和失败 raw 不改。[8883129 B 离线固定来源包](results/mta-fixed-source-bundle-v1-20261003-214143-2bdcb2e6c5504180b30fb5a83665624d/mta-fixed-source-bundle-v1.zip)，SHA256 `c5e9cf85169aedbf0fd8d7590f44d2e3d3eb200f2b850d3f42fa7f59e87b2e27`；[电脑端包装结果](results/mta-fixed-source-bundle-v1-20261003-214143-2bdcb2e6c5504180b30fb5a83665624d/result.json)；[PC 一键打包入口](HOST_MTA_FIXED_SOURCE_BUNDLE.cmd)。目录按 UTC 命名，本地执行为 10 月 4 日。

这不是可运行发行、安装器、完整图测试或实机收件。包内源码和构建材料不会自动执行，权限只是安装意图；未生成生产 source-manifest、未设置 GO Publication 封印。服务、收发准入、无线、前端接线、设备、手机和恢复验证均未因此开放或通过。本阶段无候选运行、AST、ADB、部署、重启、无线切换或旧记录处理。

还核清了旧记录的作用范围：GO64 pending 会阻断 Factory 的新任务发布，但不等同于 WifiBackend 读取的 mta-network 租约，不能据此断定关闭收发的只读 HTTP 服务必然不能启动。State 的接收及发送准入仍被源码独立设为 False；实际启动与恢复准入、前端接线和手机收件仍未完成。两份 Parent 的实际采集路径还延迟依赖目标缺失的 fcntl，已得到窄兼容方案，但尚未实现；它不阻断普通定义加载。旧记录安全归档和终结授权尚待。目标 active，尚非只剩人工。

## 2026年10月4日 05:00：HTTP 借用收尾专项通过，完整接收仍未开放

在原 auth-clock-v2 上新增独立 `receive-http-directory-close-v3`，旧源和历史结果不改。修正的是开放接收前的生命周期合同缺口，不据此认定之前的设备异常由它造成：释放接收目录前，必须同时确认原 State 已收尾、HTTP 原线程实际不再存活、原 join 返回已知、连接已关闭且 worker 库存为空。检查使用非阻塞锁，不增加等待、延长期限或重新执行恢复。原异常、线程、连接和目录引用继续保留，未知/失败状态不能被到期或“已停止”标签升级为成功。

新 Owner 为 42663 B，SHA256 `6aba9a6f60109b7fb3568e7b85e58889e76dbff99da9f633604ad408e94c029c`。新的 30 行 HOST definition 表只更新 Owner 一行，原 schema/顺序与其他来源不变；ROOT 与独立 SOURCE 审阅已核实际摘要，private35 和 Boot/State 不改。完整 State 沿用原 close 返回和原恢复检查；partial State 只有按实际构造顺序确认未启动操作、原 probes 已闭合时，才能释放已知目录，整体服务仍不签关闭。

新的 HOST Linux 收尾专项首次通过：一个新增方法、六域八夹具，旧方法 0，唯一子进程退出 0、无超时、无 WSL 警告；只对新 Owner 做一次 Python 3.5 AST。实际执行新 Owner 的构造和受影响收尾方法，使用真实临时目录 FD、socketpair、Thread/Event/join，并检查物理 close/EBADF。活线程阶段拒绝关闭目录，结束后正常关闭；未知线程/连接、完整或 partial State 的活动借用和原 close 异常保持未闭合；重复 close 不续预算、不重发 join/State.close。没有覆盖实际 join 异常，也不将 partial State 的已知安全释放分支签为已运行。

Boot、State、Server/HTTP-handler 祖先为明确模型，最后一例 cleanup-expiry 是时钟故障注入，不是实际等待 60 秒。未启动真实 HTTP 服务、Factory、Parent 或 Native，不签 P011、手机、RF、恢复或准入。七份输入及原始 stdout/stderr 已读回，ROOT 与独审均核来源/摘要及 ZIP 成员原字节，独审另核 CRC；raw 不改写、不含于公开包。[1614 B 脱敏 HOST 结果 ZIP](results/receive-http-directory-close-host-20261003-210000-4ff4d34f/public-result.zip)，SHA256 `086b320d68fc483322bc7b6569e728191037e208f11bece030291fc81785aaf7`；[PC 一键专项入口](HOST_MTA_RECEIVE_HTTP_DIRECTORY_CLOSE_CHECK.cmd)。目录按 UTC 命名，实际本地为 10 月 4 日 05:00。

这个阶段未访问 P011、修改旧 pending、切换无线、部署代码或重启。此前实机仅补齐空 `Received` 目录，完整图启动、准入、网络恢复和小米 15 Ultra 的收件仍待验证。旧记录的安全归档/终结授权尚未收到，正式收发仍 False，目标 active，尚非只剩人工。

## 2026年10月4日 04:07：实机接收目录已补齐，完整收件仍未开放

接收实机诊断中发现固定 `Received` 目录缺失。首次只读检查保留 FAIL：笔端正常退出，五个本次打开的目录 FD 均关闭；该轮只确认容量接口存在，并未执行容量查询。[首次只读结果](results/receive-directory-readonly-20261004-031556-386b4d6d/public-result.zip)不改写为通过。

在用户允许接收实机测试的范围内，单次初始化实际建立了 `/mnt/data/p011-toolbox/user/Received`，权限 0700，保持为空。沿原目录 FD 检查身份，实际容量查询通过，11 个本次打开的原始目录 FD 均关闭、关闭错误 0。前后原厂三文件摘要、boot 身份摘要、旧 pending 原字节摘要、IPv4 路由和网卡名列表一致。这是限定目录组件核验，不是进程、蓝牙、完整网络恢复或手机收件证明；未部署代码、启动完整接收、切换无线、重启、清旧记录或替换原厂。[1294 B 脱敏实机 ZIP](results/receive-directory-initialize-20261004-035209-c39ba898/public-result.zip)，SHA256 `84feb83f25d564dbe7f107bceb4425448984e9c8417660ba96d8d5e162149eb4`；[单次目录初始化入口](TEST_MTA_RECEIVE_DIRECTORY_INITIALIZE.cmd)。实际原件、六份来源与 ZIP 已分别读回并独立核对。

新的绑定目录 Storage 通过七个 HOST Linux 领域，覆盖中文提交、目录/祖先被替换、符号链接拒绝、取消清理和固定子目录初始化；不代表 P011 已提交文件。[主机目录 FD 结果](results/receive-directory-fd-host-20261004-034447-ef95c2f6/public-result.zip)。双 TLS 绑定目录联调的子测试实际退出 0，中文/二进制文件经 Registry/FileStore 读回、双方 ACK 和资源关闭均通过；原 checker 因一条 WSL 用户会话警告整体判 FAIL，失败原件保留。后续仅离线核对原始结果与十二份来源，没有重跑或重签完整准入：[1827 B 原件复核 ZIP](results/receive-bound-result-review-20261003-195433-12252cb5/public-result.zip)，SHA256 `de1e5c270546f3dcb88099d085ebce94943af1d6c0d3cbdd725fc4442b958d64`。测试清理/parser 的后续修订未执行。

接装还发现 Transport 错把同时间基准的原 lease 包装时钟与目录层底层时钟要求为同一个 callable，导致合法链路被拒绝。独立 clock-v2 只取消该跨层身份要求，仍保留两层各自期限、原目录身份、上界和取消检查。一个新增方法、四个 HOST Linux 构造/检查领域首次通过，未连接 socket、未执行 Native lease 或手机；旧方法 0。[双时钟专项 ZIP](results/receive-directory-clock-host-20261004-040655-386ff7fa/public-result.zip)，SHA256 `ebbc138a399fc8c2f74cde97cec542ffe7c67d2b8b66c979230f5aeef6d07d93`；[单次主机入口](HOST_MTA_RECEIVE_DIRECTORY_CLOCK_CHECK.cmd)。

Owner/State/Factory/F 的目录借用与关闭顺序已在新候选源码接装。04:16 的单次 HOST 静态核对首次通过：60 份输入快照一致，6 个新适配文件各一次 Python 3.5 AST，复用这些树核对固定来源与角色。普通 28 角色及额外 Boot/Owner 共 30 行，private 图 35 行；两表共有 56 个去重源码。普通图的 `mta_files` 已接已测 v67 中文版本；private 图没有这个 Registry 角色，仅有原生账本 `mta_client_files`，没有添加角色。源码准入门仍为 False。没有动态加载候选定义、启动子进程或访问设备，不签完整图、发布封印或恢复：[接装静态结果 ZIP](results/receive-directory-adapters-source-20261003-201624-375cf5b5/public-result.zip)，SHA256 `e6c392b2b67ceaf4cf83e7aae61ae9923ef3751df5301fac8265fd66bf8584ad`；[PC 一键静态入口](HOST_MTA_RECEIVE_DIRECTORY_ADAPTERS_SOURCE_CHECK.cmd)。结果目录按 UTC 命名，实际本地为 10 月 4 日。

静态核对后的独立源码复查定位到 v1 图的确定运行阻断：Factory 给 Loader 的读源时钟为 `attempt.now`；Bridge 已保存 factory 返回值后再次调用 Loader.authenticate，但该发布时钟仍要求返回值未保存，并受 prepare 阶段上界限制，故会在 Parent/F 启动前拒绝。该问题不在上述静态语法/摘要专项范围内，原 v1/60 快照和 PASS 原件保留。另做 auth-clock-v2 窄候选：认证目录用原 Binding 时钟及原任务上界，发布读源的阶段检查保持，验证结果单独记录，不冒称 v1 已运行通过。

auth-clock-v2 已冻结为五件新源；State 沿用 v1，不改准入。ROOT 和独审核对两张新 HOST 来源表的 35/30 行、全部实际摘要及 Factory/Bridge/Boot/Owner 常量连锁一致。唯一逻辑改动是后续目录认证使用原 Binding 时钟；该对象仍由 Storage 原 period 检查限制，没有续期。新 F 的 Python 3.5 AST 与一个新增方法四个认证领域实际通过（子进程退出 0）：发布阶段结束后可认证、任务到期拒绝、Binding 到期拒绝、目录 inode 变化拒绝。完整 F/控制 codec 的实际函数执行，但 Binding、文件系统与已关闭读源库存为明确模型，未运行 Loader.load、Factory 发布或 Parent。原 checker 因 stdout 的 Windows CRLF 不等于 LF-only marker 判整体 FAIL，原件保留；其 stderr 本已按 CRLF 派生匹配，不是失败原因。后续只离线核七份来源和原件，确认该四域子测试通过，没有重跑或重签准入：[认证专项原件复核 ZIP](results/receive-directory-auth-clock-offline-review-20261003-203800-0808d485/public-result.zip)，SHA256 `00618ae7fc116dafe64b782f264506544be4032755f8391fc43b370e66af3460`。未来 harness 仅接受两种精确 marker，修订未执行。

旧 GO64 pending 仍在，未取得安全归档/终结授权或完整恢复证明；正式接收准入保持 False。仍需完成固定图实际启动、开放准入前的 HTTP/目录借用收尾合同、旧记录处理、有效 DeviceInfo 和小米 15 Ultra 确认接收/落盘/收尾。目标 active，尚非只剩人工。

## 2026年10月4日 接收数据面和界面联调

新增真实 HOST 组件联调首次通过：PreparedSend → SenderPump → ReceiverTransport → SafeZipReceiver → FileRegistry → 工具箱 FileStore。两条实际 TCP/TLS 连接、确认前阻止下载、中文及二进制文件提交、文件中心内容与 SHA 读回、双方完成 ACK、socket／文件资源和临时目录收尾均已核对。只运行一个新方法，旧方法 0；loopback 构造准入和 HOST socket owner 明确为测试适配，不签 State/F、P011、手机或物理网络恢复。11 份来源快照、raw 和两成员 1785 B ZIP 已独立读回：[联调结果](results/receive-filecenter-host-20261004-023351-fd431cde/public-result.zip)，SHA256 `855dddd50c2860691bd1023b75a76776841ceeca1003d5c312d666ab71ef2872`。

接收页面已区分“归档已下载”和“解包校验”；归档总量未知时不显示百分比，逐块处理不称为完整 CRC／保存／手机确认成功。八个新的 HOST Qt 状态显示场景首次通过，两张实际 800×268 HOST 截图已查看；这是界面数据夹具，不是真机收件。单次入口：[HOST_MTA_RECEIVE_PROGRESS_UI_CHECK.cmd](HOST_MTA_RECEIVE_PROGRESS_UI_CHECK.cmd)；[六成员结果 ZIP](results/receive-progress-ui-host-20261003-184755-a09b1500/public-result.zip)，SHA256 `cad559a71aba595ddfe18b3551c7715564f37beb7fdce25d5334a46e95e3a2df`。该目录按 UTC 命名，实际本地测试为 10 月 4 日。

独立生命周期候选已补接收原服务绝对期限及先 State/Session 收尾、后 HTTP join 的顺序；保留原 operation 和资源身份，不清引用凑关闭。新 State → Boot → Owner pins 一致；三个受影响目标源码的 Python 3.5 语法与一个新方法六域通过，来源及结果独立核验：[生命周期结果](results/receive-lifecycle-host-20261004-024934-63cb8505/public-result.zip)，SHA256 `e4cf71fc911aeaab3a4ec33b9500a75a423dd5d7c9c584048fab933628822f83`。测试只抽取受影响原函数，Session78 实际执行，FS／HTTP actor／native restore 为明确夹具；没有执行完整 Boot/F 或部署。

旧 pending 的历史归属已核为同 boot 的 GO64 reservation；原 journal 为 restore_intent/generation 4，尚未进入 CREATE／GroupAdd／IP。2026年10月4日 02:55 的新 P011 限定只读检查实际通过，ADB 主机／笔端均退出 0：两个已有锁可取得；旧 F／watchdog 进程及线程路径连续两轮未见；项目 netdev、旧任务活跃 Unix 端点和对应文件端点两轮均为 0；16 个检查用原始 FD 均关闭、关闭错误 0。pending／journal 原字节、身份和 generation 保持不变。结果已读回并核对两成员 ZIP 的 CRC 与原字节：[1194 B 只读诊断结果](results/go-pending-readonly-20261004-025538-0c05a390/public-result.zip)，SHA256 `7edc7fd71c4a1ae01c17e90e68217458a5890bf9ee8e50b1b8801a74d8bf48bf`。这只证明所列路径／端点的现场缺席，不是原 Proc25 absence ticket、非 netdev P2P WDEV 缺席、完整网络恢复或旧 Native 资源关闭证明；没有 reconcile、终结／删除 pending、启动 helper 或签发接收准入。

正式收件仍关闭：还缺旧记录安全终结、三处 `/mnt/data` 现场身份与目录 FD 适配、实际启动准入和完整 P011／小米 15 Ultra 收件。旧记录的备份归档与终结需单独授权；不能直接删除 marker 或以当前 Wi-Fi 正常代替旧恢复证明。无本轮配对、Wi-Fi 切换、重启、记录删除或原厂替换；目标 active，尚非只剩人工。

## 2026-10-04：终末管道、模块装配与 BLE 组件通过，完整接收未开放

用户已明确允许接收实机测试。本轮先取得当前 P011 只读证据：原厂文件及进程身份稳定，wlan0/phy0 存在，Wi-Fi 状态为 COMPLETED，BlueZ Powered=True、Discovering=False。旧 pending 仍在，340 字节，与历史摘要相同且属于当前 boot；没有删除，也没有把到期或原厂稳定当作完整恢复。接收前独立双观察完成，但 observed_blockers_clear=False。

HOST95 的实际 Linux 三管道专项首次通过八个新场景；HOST98 的实际 Boot 加载/认证和 Owner 角色校验通过两个新域、28 角色。HOST98 的 FS/FD/PID/clock 为模型，State 未构造，Parent 未 collect，未签生产封印或准入。结果原件与 ZIP 已独立读回，旧通过测试未重放。[新证据与剩余边界](CURRENT_TERMINAL_CHANNEL_V94_FINDING.md#2026-10-04-增量证据)。

独立 BLE 组件已实机通过，整轮约 7.1 秒：原 helper ready、GATT 注册、31/31 字节 DIAG 广播 TTL 5、广告结束、GATT 注销、STOP/原 stdin EOF、原进程正常退出与七个原始子进程/FD 闭合均有证据。独立后检确认 helper 不在、Wi-Fi COMPLETED、原厂文件 hash 及关键进程符合基线，pending 原字节保留；本轮新建的空 hci 锁已释放并保留，属于唯一计划内变化。结果：[1662 B 脱敏 ZIP](results/receive-ble-component-20261004-020624-4ac444f2/public-result.zip)；[单次组件测试入口](TEST_MTA_RECEIVE_BLE_COMPONENT.cmd)不是完整收件入口。首轮因目标没有 fcntl 模块在 RF 之前失败，修成现有 libc ABI 后通过，失败原件未改。

完整接收尚不能启动：State96 receive_available 明确为 False，固定发布器还拒绝当前 pending。不能把 BLE 组件通过当作生产准入或完整恢复；尚需接收准入/旧任务归属核验、真实 DeviceInfo 和手机握手、接收确认与文件落盘/收尾验收。本轮无配对/Connect、Wi-Fi/P2P 切换、文件提交、原厂替换或归档 START。生产收发仍为 False，小米 15 Ultra 真实互通未测试；本轮在组件诊断及独立收尾后停止。

## 2026-10-03 最新 终末私有通道主机专项通过

新 Packet94 的请求和完整响应通道首次通过两个域、26 个独立场景（3 有效、23 拒绝）；四个新 runtime 的 Python 3.5 语法检查通过。Body/Loader/Entry 已完成源码接线，但未动态运行，不能签终末采样、管道或恢复。已修正 F 与 parent GO 清理期限不必相等，观察者受三个原 cleanup 上限共同限制；FD0 保留到全部文件操作结束，防止描述符复用误拒。ROOT f1ace5 host/child0、无超时，十二份输入及四成员 2588 B ZIP 经 ROOT c7e625 与独立原件核对 6fdbdb 一致，SHA 06fc6f62d84eefad9c37b1d31c164e86567bb4b71faab4ccaa7678ab103c440b。[源码身份、结果与剩余接线](CURRENT_TERMINAL_CHANNEL_V94_FINDING.md)。Parent95 三管道源码已完成、运行验证及原 worker 恢复消费、最终部署封印、真接收准入、P011 与小米 15 Ultra 双向仍待。目标 active，生产收发 False，尚非仅人工；本阶段无设备或无线操作，下文历史保持。

## 2026-10-03 最新：完整终末身份 HOST93 首次通过，独立观察 Body/Loader 为源码

F93 新完整Actor与原ChildTicket结果，Bridge93严格消费，保4096整包上限和原首错误。ROOT `9b4be6` 唯一新方法两域18明确模型夹具首次PASS，host/child0、无超时；12源+test及plan/checker/CMD共16实际快照，strict raw/四成员3031B ZIP经ROOT `aa2e42`与独立原件`fb9a8a`核对，SHA `02fdaa7d4a7ca2d455b72493881dbe1a489f3170875757b0bf1cfdb2c7af54d2`。纯发行/消费实际算法，restore/FD/启动/reap明确模型，不签物理恢复。新Body连续两锁→Journal前读→双Snapshot→新absence→后读→动态库存闭合、新Loader仅Body pin已SOURCE；未AST/运行或接Entry/Parent/State。[固定来源、限定结果包与下一接线](CURRENT_TERMINAL_IDENTITY_V93_FINDING.md)。到task期后的清理区间仍pending，不假传新task cap；正式通道/部署封印/接收准入/P011与小米15 Ultra双向仍待。目标active、生产收发False、非仅人工，本阶段无ADB/RF/重启/清记录，下文历史保留。

## 2026-10-03 最新：Parent异常路径有界收尾，HOST92首次通过

新增独立 Parent92 沿用原 cleanup_until 与剩余预算，失败后排空原已知两 pipe、两 EOF 才原 wait 一次，保首错误、不再解析/发 report、不重启或续期。ROOT `7aecf8` 唯一新方法首次八域／11明确模型夹具 PASS，host/child0／无超时；仅新Parent targetAST1，11快照/strict raw/四成员2684B ZIP经ROOT `976ff0`与独立实际原件读审一致，SHA `f02b3eccb3fedab9f20c28f8a9a855357118c83f02a466d332de36a735473965`。实际Parent/Packet算法，ARM/process/pipe/FD/clock为模型，不签物理闭合；Boot91仍钉Parent89，新候选尚未接图或部署。[准确来源、结果包与独立恢复真实接点](CURRENT_PARENT_FAILURE_CLEANUP_V92_FINDING.md)。完整Journal/recorded-actor absence的终末producer、最终资产封印、接收准入/正式服务、P011/小米15 Ultra互通仍待；目标active、生产收发False、非仅人工。本轮无ADB/RF/重启/清记录，下文历史不改。

## 2026-10-03 最新：普通27角色加载接线与25源资产索引，HOST91首次通过

Boot91 加 Parent89 并更新 Loader/Pub/Bridge90，Owner91 同步原角色合同；原期限、23个未变角色及收发关闭策略不变。ROOT `91e277` 唯一新方法／两受影响域首次 PASS，实际普通定义 load/authenticate 与 Owner 原 role 校验；FS/FD/PID/clock及Owner构造前对象是明确模型，不签服务或采集。仅两新 targetAST、34快照与四成员4066B ZIP已双只读核，SHA `dd1dcce4b2fdf2f2493901748585d17e9632b7f28080874dd7f9e5e4d214130f`。25源 HOST 索引逐序/字节一致，但不是目标manifest，未加载私有GO/RO图或封印。[准确源码、限定结果包、终末恢复具体缺口与下一步](CURRENT_FIXED_BOOT_ASSETS_V91_FINDING.md)。Parent失败收尾／独立Journal和absence／正式资产部署封印／真接收准入及P011、小米互通仍待；目标active、生产收发False、非仅人工。本阶段无ADB／无线／重启／清记录，下文历史不改。

## 2026-10-03 最新：发送前任务绑定与新基线对照，HOST90 首 FAIL／R2 六剩余分支通过

v90 五件新源将原 Parent 只读结果接入同 worker Publisher，START 只传有界任务绑定 DATA，GO 私有图加入原 Codec85，实际新基线完整稳定键匹配后才允许进入 reserve；原期限不续，生产封印仍为空。R1 ROOT `a0af85` 整体 FAIL 保留：六个分支因测试模型缺 watchdog 在新比较前阻断，五新 targetAST 通过。R2 ROOT `0542a4` 只补模型原构造字段并首次执行剩余两域六分支 PASS，旧方法0、targetAST0，不合成九域 PASS。各16快照／原 raw／ZIP已 ROOT 与独立只读审核一致核，R2四成员3028B SHA `e69c445e4367142f9f03b12028b319118f53866ad3b736d30398bdc2b4e280e1`。[冻结源、准确模型层、两次原件与剩余接线](CURRENT_SEND_PREFLIGHT_KEY_V90_FINDING.md)。普通 Boot／最终资产表封印／独立终末恢复／真接收准入及 P011、小米15 Ultra互通仍待；生产收发False、目标active、尚非仅人工。本阶段无ADB／RF／重启／清旧记录，下文历史保持。

## 2026-10-03 最新：固定41源部署器与完整Parent通道，HOST89首次通过

新增Stager／Parent真实源码，ROOT `a8223e` 九新领域／15owner夹具首次PASS，旧方法0；真实Linux临时FS验证41文件／47FD／85fsync及known-close，目标anchors／ARM／clock为模型。Parent完整算法／private5纯DATA实际执行，Popen／pipe／EOF／wait是明确模型。两新targetAST、48快照、strict raw及4成员ZIP4902B已ROOT `4cc8a0`及独审`373c60`一致核，[详细来源、范围、结果包与剩余接线](CURRENT_READONLY_OWNER_V89_FINDING.md)。不签真实ARM／Parent launch／Loader38／helper／collect／目标部署／RF／恢复／准入；异常未reap仍pending，cleanup5不是失败finalizer。Pub／F新基线／独立终末恢复／最终seal／真接收与设备手机仍待，目标active、生产收发False、尚非仅人工；本阶段无ADB／重启／清旧记录。下文历史保持。

## 2026-10-03 最新：Parent回执、完整packet入口、原服务期限的三新HOST专项

ROOT `d42123` 三个新方法首次各一次通过（16／13／10组）、旧方法0；四新runtime AST、59输入、三严格raw及8成员ZIP6409字节已ROOT `2dea5c`／独审`54476d`一致核。Parent child/EOF/reap、Entry FS/FD/clock、Owner Boot/State/Server全模型，pure SnapshotData／packet算法实执行；不代签真实collect／helper／Parent launch／State构造／RF／恢复／准入。Entry r1保留未执行，r2只补private writer一次门；Owner88传原服务cap而非load片段。[新源、准确范围与结果包](CURRENT_SEND_PARENT_ENTRY_OWNER_V88_FINDING.md)。正式资产表／stager／Parent完整通道、F新基线及独立终末恢复仍在制，生产收发False、目标active、尚非仅人工。本阶段无ADB／重启／清旧记录；下文历史保留。

## 2026-10-03 最新：完整Snapshot、readonly定义与真实恢复返回DATA的受影响HOST专项

ROOT `125650` 三个新方法各一次通过，原旧方法0；四新runtime语法、56输入快照、三原raw与8成员ZIP已ROOT和另一位只读审计者一致核对。Snapshot为实际纯算法；Loader38/body为明确FS/FD/PID/clock/process模型；F84为7个原类型DATA模型域＋1默认SOURCE断言，不运行真实restore/FD2。仍缺Parent完整通道／实际退出消费、F新基线同次核对、独立终末网络恢复与正式准入，当前继续制作，不是只剩人工。[来源、精确范围与结果包](CURRENT_SEND_FINISH_OBSERVER_V85_FINDING.md)。本阶段无ADB／RF／重启／清旧记录，目标active、生产收发False；下文历史保留。

## 2026-10-03 最新：资源释放专项通过，真实HOST界面截图与固定加载接线

Key79 的15个边界模型通过并核9快照／结果ZIP；异常native free不再按key.closed误算已闭合。UI80前两轮整体FAIL保留，R3仅末两域通过并取得实际800×268 HOST Qt截图，未合成原八域PASS，不代签P011／HTTP服务／手机。Pub82-r2本地readback已SOURCE接线；Boot83首次4域HOST定义加载通过、32快照/ZIP双审计，FS/FD/PID/clock是明确模型，未执行Pub正向preflight。实际准入／独立恢复仍待；当前生产收发关闭，目标active、尚非仅人工。[来源、结果包、截图与准确边界](CURRENT_SEND_RESOURCE_UI_BOOT_V83_FINDING.md)。本阶段无ADB／RF／重启／清记录；下文历史保留。

## 2026-10-03 最新：发送进度 HOST77 通过，State78 接线仍为源码

ROOT `0bcb0f` 唯一新方法／18夹具通过，实际Linux私有管道与进度算法、27目标语法／32快照／四成员ZIP已ROOT和作者只读核验；五个Session78期限模型亦通过，不代签真实worker/finalizer。State78同worker文件准备→F/listener→扫描选择接线已SOURCE双读，准入仍拒绝、独立Native恢复未补；发现key释放异常联合闭合缺口，79窄修和新发送页在制。[固定来源、准确层级、结果包与剩余缺口](CURRENT_SEND_PROGRESS_STATE_V78_FINDING.md)。本阶段无设备/RF/重启/清记录，旧pending和恢复未证保持，目标active、生产收发关闭、尚非仅人工。下文历史正文保留。

## 2026-10-03 最新：Native76 真实 Linux TCP/TLS 专项通过

ROOT `9839fc` 新 R5 唯一场景 child0／无超时，真实 lo 原socket监听/接纳/TLS/FD移交关闭、双连接完整ZIP与终末ACK通过；`b161f3` 和独审核31快照／公开四成员ZIP一致。早期四轮FAIL原件保留；最终只修WSL模拟手机socket的lo路由，不改生产Native/Pump或原25秒期限。GO/IP/DHCP/STA是明确祖先模型，不能升级实际无线。[当前证据、来源、结果包和剩余接线](CURRENT_GO_SEND_TRANSPORT_V76_FINDING.md)。Parent/F为SOURCE、Publisher未封印、实时进度与State接线在制；没有P011／手机／RF／重启／清记录，设备旧pending与完整恢复未证不改。目标active、生产收发仍关闭，尚非仅人工。下文历史正文保留。

## 2026-10-03 最新：实际归档＋无线程双 TLS 数据面首测通过

新 `PreparedSend` 与 `SenderPump` 已完成，ROOT `5b299d` 唯一首次执行 HOST 六场景 PASS，host/child0、无超时、旧测试方法0。实际 FileRegistry→stored ZIP/固定 OpenSSL→两条 loopback TLS/WS/HTTPS，验证完整文件字节、短写、取消、提前完成/错误任务拒绝与绝对超时；服务侧无新线程，原连接/档 FD/临时目录关闭均检查。ROOT `9f1740` 与独立只读审查已核11快照、严格raw与四成员ZIP一致。[新实现、固定来源、结果包及未完成接线](CURRENT_SENDER_PUMP_FINDING.md)。这是实际 HOST 数据面，不是 Native Linux ownership、GO/GATT、部署、P011、小米或物理恢复通过。原20秒service未扩，实际Native accept/TLS、发送IPC、接收admission、正式入口与真机仍待；小米15 Ultra版本未知，旧pending/完整恢复未证不回填，本轮无设备操作。目标active，尚非仅人工。下文历史正文保留。

## 2026-10-03 最新：真实 GO 凭据/TCP 绑定 producer 已补，HOST75 专项通过

新 Native75 发行原私有事件/当前 STATUS 凭据，并按原接口与 GO IP 创建 bound nonblocking TCP；原 worker/service cap 不续，未知 TCP 阻 DHCP/IP/group 删除。Bootstrap75 增显式发送接点及 TCP-first restore，默认诊断 run 不自动发送。ROOT `fdb92e` 唯一新方法首次 PASS：凭据4有效/16拒绝、Native模型14域/23拒绝，旧测试方法0；`ceb69e` 与独立 `abf06d` 核27快照/raw/四成员ZIP一致。[准确来源、结果包和剩余链](CURRENT_GO_SEND_BASIS_V75_FINDING.md)。完整Native定义的受影响算法执行，但旧owner/IP/DHCP/OS是明确模型；未listen/accept/TLS/GATT、未完整图/部署/设备/手机/物理恢复。真实对端绑定、非阻塞双TLS、发送IPC、接收admission及正式入口仍待；原20秒成本未测，旧pending/恢复未证及设备许可未回复保持。目标active，尚非仅人工。下文历史正文保留。

## 2026-10-03 最新：DHCP setup 与首次 service 已分开，HOST74 限定通过

v74 四件新源保留原 session／配额／关闭，setup 的实际出版 IO 同样夹到原期限；最终实际 IP／UDP 检查后才首次发 service cap。v73 严格恢复状态已纳入本轮源码。ROOT `d960cf` 唯一新方法／七个 Server 模型场景通过；`ec0297`／独立 `d11448` 核 30 快照、raw 与四成员 ZIP 一致，无旧测试重放。[冻结来源、结果与真实接点](CURRENT_GO_DHCP_SETUP_V74_FINDING.md)。源码采样 21→9 不等于真机加速或原中间时间点等价；Native／Store／Loader／完整图未动态执行，未部署／设备／RF／手机。F60 现有默认 run 已有同 worker L3 生命周期调用；实际部署、发送 scoped/IPC producer、接收真实 admission 仍待。旧 pending／完整恢复未证不改，目标 active、尚非仅人工。下文历史正文原 bytes 保留。

## 2026-10-03 最新：GO＋IP/DHCP 编排主机通过，恢复状态误报已独立修正

v72 将 typed L3 合入当前 20 源，ROOT 唯一首测 14 个编排模型场景通过，33 快照／四成员 ZIP 双审计一致；未执行完整图、Native 无线或设备。[精确来源、结果和成本风险](CURRENT_GO_TYPED_LIVE_V72_FINDING.md)。v73 仅修 restored 状态投影，9 个新增状态向量通过，4 快照／结果包双审计一致；尚未纳入 v72 图或部署。[最窄修正与边界](CURRENT_GO_RESTORED_STATUS_V73_FINDING.md)。DHCP 准备仍占用原 20 秒服务期限，完整快照与资源余量风险未关闭，真实 provider／admission／正式接线仍待。旧 pending 和完整恢复未证保持；无设备操作，目标 active、尚非仅人工。下文历史正文原 bytes 保留。

## 2026-10-03 最新：GO 同 worker 保留阶段已补，HOST71 生命周期模型通过

独立 v71 候选增加 prepare_live，默认入口仍恢复，原 restore 未改。ROOT 唯一新方法／十模型场景通过，22 快照和四成员 ZIP 双重只读审计通过；无部署／RF／IP-DHCP／provider／真实恢复结论。[范围、固定 pins、原件与待接点](CURRENT_GO_LIVE_OWNER_V71_FINDING.md)。设备旧 pending 与完整恢复未证保持，目标 active、尚非仅人工。下文历史正文原 bytes 保留。

## 2026-10-03 最新：P011 窄只读刷新，生产接收／发送缺口已交叉核对

原厂三文件与升级后 pin 一致，wlan0 up，旧 340 B pending 仍存在且摘要未变；观察到既定进程及 Z03 原厂父循环参数，但完整网络／actor／恢复未证。未重启、清记录或启动 RF。源码审计确认接收缺真实 admission、发送缺完整 network provider、正式服务与工具箱仍待接线，不能只翻 available。[本轮证据和四项最短剩余链](CURRENT_TRANSFER_GAPS_20261003.md)。小米 15 Ultra 已记录，系统／互传版本未知；正常重启许可仍待，目标 active。以下历史正文保持原判。

## 2026-10-03 最新：固定服务入口已补，HOST70 首 FAIL／r2 九项有限通过

新 owner 保留原期限、原对象及失败库存，scan／receive／send 仍 False。首测整体 FAIL 保留，正常 HTTP 有限完成；测试漏清 minhttp，r2 只补测九个未进入场景 PASS，28 快照／四成员 ZIP 已双重只读核对，未重跑 normal_http。[准确范围、pins、两次原始结果与剩余步骤](CURRENT_SERVICE_OWNER_V70_FINDING.md)。本轮无设备操作或部署；接收准入 producer、工厂正向、真实无线与小米 15 Ultra 双向互通仍待，GO64 pending／完整恢复未证及设备处置许可仍待。目标 active，尚非仅人工。旧正文逐字保留。

## 2026-10-03 最新：v69-r3 接收部署源码与定义启动 HOST 有限通过

新增固定接收部署工厂、同域定义 boot 和被动 FD 闭合桥；不翻转接收准入。ROOT 首次新 HOST 专项通过，一个方法/八情形/旧方法0；25 快照与四成员 ZIP 已双重只读核对。[准确范围、来源及结果包](CURRENT_RECEIVE_FACTORY_V69_FINDING.md)。工厂正向、State/Server 入口及真实接收准入仍待；GO64 pending/完整恢复未证、正常重启与仅处理本次记录的许可仍待。对端为小米 15 Ultra，目标 active，尚非仅剩人工。本次下文旧正文逐字保留。

## 2026-10-03 最新：HOST68-r2 文件打开竞态有限通过，原件双审核封口

ROOT `f0e026` 唯一首次直接运行checker PASS：host0／0.922秒／无超时，一个新方法、8个独立页面case、旧方法0。ROOT `4653e9` 与独立只读审核已核6份snapshot、严格raw、ZIP、原QML及旧未执行test；[四成员脱敏ZIP](results/file-navigation-v68-r2-host-20261002-231004-f906dab9/public-result.zip) 2114 B，SHA `5d40652cf28191dbba6646c8032b00c4bcf951d642cefd4d6029ee3218c53a1b`。

本次只签实际HOST QML的文件打开／返回／换目录／离页／刷新／同路径新请求／传输页竞态；请求为in-memory，音频调用是派生inert代理，VideoPane也为inert。HOST Qt5.15.2／PyQt5.15.11不代签P011 Qt5.10、触摸、物理播放或MTA。独立原audio response生命周期尚未修复／测试；候选未部署，CMD只SOURCE核对未点击，旧68test仅SOURCE夹具断言阻断、从未执行。[四件pins、8个case与边界](CURRENT_FILE_NAVIGATION_V68_FINDING.md)。

GO64整体FAIL／pending／完整恢复未证、本轮正常重启及本次临时记录处理许可仍待，手机／RF／生产收发仍未通过。小米15 Ultra已记录、系统及互传版本未知；目标active，尚非仅人工验收。67及更早正文原bytes保留，本次仅DOC新增，没有执行Qt、测试、入口或设备操作。

## 2026-10-03 最新：HOST67 中文路径有限通过，原件双审核封口

ROOT `3c6d64` 唯一首次 HOST67 执行 PASS：host0／0.266秒／无超时，六个新方法、旧方法0。ROOT `4ddf01` 与独立只读审核已核7份输入snapshot、严格raw、ZIP及原件一致；[四成员脱敏ZIP](results/file-utf8-v67-host-20261002-225639-020ef5cd/public-result.zip) 2199 B，SHA `1c02c20d46ba05c2f088dd014fe7fb09809ae943200438e9b8598b5332372acb`。

范围是局部 ASCII/POSIX 路径代理＋真实 HOST 临时文件系统，覆盖中文目录／ZIP接收／不透明文件选择／同名不覆盖／取消清本次目录／非法UTF-8裁剪及既有文件中心 HOST 读回。67未部署，原runtime两件保持；不代签真实POSIX locale、P011目录FD分支、设备收发、手机、RF或恢复。[五件pins、六方法与准确边界](CURRENT_FILE_UTF8_V67_FINDING.md)。

actual64仍整体FAIL／pending／完整恢复未证，本轮正常重启及本次临时记录处理许可仍待；手机与生产收发仍False。已记录小米15 Ultra，系统／原厂互传版本未知；目标active，尚非仅人工验收。下文历史正文按原时点原bytes保留，本次仅DOC顶部追加，没有执行代码、测试或设备操作。

## 2026-10-03 最新：HOST66 首次限定通过，独立原件复审已PASS封口

ROOT `136546` 唯一首次执行HOST66新方法 PASS：host0／0.375秒／无超时，新方法1、旧方法0；[四成员脱敏ZIP](results/go-private-diagnostic-v66-host-model-20261002-222536-4f4de80a/public-result.zip) 5210 B，SHA `bf3ff01235a9e5809e5a69679f9bd7df451d93963e513328adef2edc92ea690d`。ROOT `3a84fe` 已核实际23份snapshot／两graph、raw严格marker与Ran1 OK、ZIP CRC及逐bytes原件审计PASS；独立实际原件复审已PASS封口，双重审计仅签本次有限模型原件。

范围仅12项timing／33项stat（含10纯parser vector）／9个domain／4项FD2边界／160次observer callback，实际私有17定义＋普通Proc1。不是实际Loader／auth／业务流程／进程FD生命周期／设备／性能／完整恢复通过。stdout128 B SHA `2cdeb187966f091d1756db3fa61d3aa887dc9c79307fcbd7d7fed84c5aa3d70b`；stderr100 B SHA `e8361bc01311df8a0baf2d772958a0777953ac11516cbff713dbbb3f88eeb255`。没有重跑旧方法，也不补签旧65 SOURCE域阻断或旧设备失败。[65-r2来源和准确边界](CURRENT_GO_PRIVATE_DIAGNOSTIC_V65_FINDING.md)。

65-r2仍无设备结果；actual64仍wholeFAIL／pending／完整恢复未证，本轮正常重启及临时记录处理许可尚待，不自动清记录或重试RF。手机／生产收发仍False；目标active，真实GO、typed IP-DHCP、State／文件中心与小米15 Ultra原厂双向仍需自主制作，尚非仅人工。下文旧状态按原时点逐字保留，本次只有DOC顶部追加，无source／test／raw／results或设备操作。

## 2026-10-03 最新：65-r2 SOURCE／PC 载荷通过，设备与 HOST66 尚未运行

v65-r2 五件已由 ROOT `a73baf` 完整窄diff主审和独立 SOURCE 复审封口；ROOT `510a67` 核整个 Native／F 业务 AST 逆诊断后分别等于62／60，`429fc1` 核实际52源 Python3.5 AST、52份base64与3个blob逐字往返 PASS。零token载荷4424579 B，SHA `7d3d0300087ac03c6f455af964c00109be172a807870522ae22a545d0a97e1af`。这是源码和纯PC来源检查，不是运行候选、受影响算法、设备、性能或恢复通过。

原65五件冻结保留：实际 Loader 保持 running F、却重建私有 Proc；旧 F 普通顶层 Proc 引用与实际部署不同域，故仅 SOURCE 域阻断、从未执行。65-r2 改为实际私有 Native／Proc 域保留 parser tuple；原业务门／库存／期限不改。诊断保留最多32轮计时、仅格式化首二末二，优先PROC60／纯PROC65六位差异，private head2048／总16KiB／原单FD2保持；新增observer开销不是性能收益。[五件准确pins与诊断边界](CURRENT_GO_PRIVATE_DIAGNOSTIC_V65_FINDING.md)。

HOST66 新受影响专项仍在制作；65-r2 无实际设备结果、没有重放旧模型或旧设备候选。actual64 仍wholeFAIL：原channel10内stock STATUS文件读取deadline，恢复另拒Proc `pid_identity_changed`；journal generation4／restore_intent、RF intent=false，实际pending仍在，完整Native恢复／after完整基线未证。当前窄只读六原厂actor及wlan0 UP等事实不能代签恢复。本轮正常重启及仅处理临时记录的用户许可尚待，不自动清pending或重试RF。[64原失败与资源边界](CURRENT_GO_ACTIVE_BUDGET_V64_FINDING.md)。

目标仍active、非仅剩人工；真实GO、typed IP／DHCP、State／文件中心及小米15 Ultra原厂双向尚未完成，ready／生产收发／手机均False。以下所有旧“当前／最新／下一”按原时点保留，原失败与日志不回填。本次仅DOC更新，无源码／测试／raw／results或设备操作。

## 2026-10-03 最新：64实机整体失败，暂不重试

ROOT `c90e47`：唯一64设备测试HOST0 / remote1 / 102.140秒无超时；已走过初始双轮、reserve及watchdog，原channel10内新单轮快照在stock STATUS文件读取deadline。恢复阶段另拒绝Proc `pid_identity_changed`，journal generation4/restore_intent、无CREATE/GROUP_ADD；实际pending仍在，after只读报pending_exists，完整恢复未证。ROOT `9df444`已核52源/载荷/六副本/raw/已知闭合库存与[两成员失败ZIP](results/go-active-budget-v64-20261002-213823-170ca3c0/public-result.zip)，2044 B / SHA `825b43b0c1e496f3ccc78dc87cbec31c9892af4b98a34eac0fa8f65bed0a6b75`；原件核验通过不是整轮成功。

当前窄只读 `fe3633`：原厂六进程PID/start/exe仍在、wlan0 UP及默认路由仍有、测试watchdog已缺席；不替代完整基线恢复。没有删除pending、重试RF或修改原厂文件。正常重启并仅处理这一轮临时记录的用户许可尚待；SOURCE继续补私有计时/原stat差异诊断。手机小米15 Ultra无需操作，GO/IP-DHCP/收发仍False、目标active、尚非仅人工。[详情](CURRENT_GO_ACTIVE_BUDGET_V64_FINDING.md)。以下旧状态保留原时点。

## 2026-10-03 最新：HOST63-r2 两受影响域通过，64设备结果尚待

ROOT `2aeefe` 唯一 HOST63-r2 模型方法实际首测PASS，结果 `results/go-fresh-boundary-v63-r2-host-model-20261002-213131-c40f5696`：host0 / 0.906秒 / 无超时。仅两个受影响负向域；原stdout固定计数 domains2 / refusals2 / full_runs2 / interface_fresh1 / uncertain_close_once1 / old10_replayed0，physical RF0。28私有输入与[四成员脱敏ZIP](results/go-fresh-boundary-v63-r2-host-model-20261002-213131-c40f5696/public-result.zip) 6680 B已核，SHA `df2f47f9e5a774e4072ecbfdfd5cf56fe756232665572d26210b1b899f4b5abd`。

ROOT `f5d9f5` 纯PC原件审计与独立实际原件复审PASS。ROOT两个临时审计夹具错误 `b0ca2f` 漏checker / `d954b7` 使用错误nested path保留；修正审计后通过，没有重跑模型方法。原HOST63 wholeFAIL与10完成域有限证据不改；旧10域重放0，不合成为新12域或63 wholePASS，也不签硬件 / 完整Native恢复。

v64 SOURCE / PC分配边界已清楚，ROOT准备唯一设备执行；截至本次更新尚无64设备结果。active75不是整链保证、局部15/10/20保持，62入口未跑的量级理由不是实测。[64来源与范围](CURRENT_GO_ACTIVE_BUDGET_V64_FINDING.md)。GO60实际wholeFAIL / resource_pending=true / fullNativeRestore=false历史保持，生产收发 / ready / IP-DHCP / 手机false；目标active、非仅人工。以下旧“最新 / 下一”均为各原时点历史，原日志与失败不回填。

## 2026-10-03 最新入口：62/64 仅 PC，HOST63 整体失败，设备64未运行

v62：ROOT `354264` 完整52源 Python3.5 AST / 4415968 B载荷往返及独立 SOURCE 审查通过；中间 active 消费改为一次真实完整新快照，初始 / 恢复仍双轮。未运行62设备入口：13 active round × 此前仅两次约4.3–5.1秒的量级外推提示原45秒可能不足，不是62性能实测或严格下界。[62来源与语义取舍](CURRENT_GO_FRESH_BOUNDARY_V62_FINDING.md)。

v64：Stage `8c00ea5c…` / HOST `e09f9d9e…` 独立 SOURCE 审查通过；只将父侧一次 active45→75、首余量135→165，原 outer180 / cleanup60 / post30 / HOST210和局部15/10/20不变。ROOT `778726` 漏 phase 的 prefix 夹具 FAIL保留；`0eb248` 改为实际5语句前缀后6例（3发行 / 3拒绝）及52源AST / 4416516 B载荷通过，只签纯分配与PC来源。所有设备64尚未运行，不签局部reserve10已解决。[64预算与证据](CURRENT_GO_ACTIVE_BUDGET_V64_FINDING.md)。

HOST63：ROOT `149c48` 唯一首测整体FAIL，host1 / 7.563秒 / 无超时，结果尾标 `e8bb57ca`。ROOT `b3fa61` 与独立原件审计PASS只核原raw / 28输入 / 失败包；10个完成子域保留有限模型证据，公开整体通过字段仍false。interface_extra过早注入导致命中原caps门，close_unknown强求best-effort日志导致夹具断言失败；r2只补这两个受影响域，在制、未运行，不合成63 wholePASS。[两成员失败ZIP](results/go-fresh-boundary-v63-host-model-20261002-212107-e8bb57ca/public-result.zip)：6783 B，SHA `dd23aea2018e594fe2a8479dd0a4481210382610ddddcaaff583e01f1262521f`。

GO60实际wholeFAIL / resource_pending=true / fullNativeRestore=false，以及RFintentfalse / journalNone原判保持；手机和生产收发false。目标仍active，真实GO、typed IP-DHCP、State、文件中心与小米15 Ultra原厂双向尚有自主工作，非仅人工。下一先完成两域受影响验证，再由ROOT决定唯一64实机；本次DOC同步没有源码、模型或设备操作。以下所有旧“最新 / 下一”均按原时点作为历史保留。

最新GO60终末（2026-10-03）：ROOT唯一 `1f7434` / session91404 → `508e30`，HOST0 / remote1、50.953秒无超时、wholeFAIL。初次baseline15两SNAP均完整约4.284363 / 5.067999秒、second left5.645070；随后Store.reserve原10秒经baseline_current / stable_snapshot / actors-file-check deadline。PROC60unavailable、此前native_actor_unknown本轮未复现，不宣已修或原因已定。ROOT `8fa6e8` 核52实际源 / 4415192 B载荷 / 六副本 / raw / 已观察库存闭合，前后完整Snapshot.key相同 / pending缺席；GO60实际原件独审现已封口PASS，与ROOT一致；仅原件审计通过，不改变整体FAIL / 资源未知。RFintentfalse / journalNone / resource_pendingtrue / whole+fullNativeRestorefalse保留。下一只SOURCE优化方案、先审重复核验成本，不增全部cap、不重跑旧候选；生产false / 目标active / 尚非仅人工。[本轮失败ZIP与准确范围](CURRENT_GO_PROC_DIAGNOSTIC_V60_FINDING.md)。

HOST61 `032c74` 唯一模型专项host0 / 0.875秒 / 无超时PASS；七独立域 / 八真实Proc拒绝 / 六首次原件、纯formatter / 私有输出界限通过。ROOT `8a96e6` 与实际原件独审均已核29快照 / raw / 四成员ZIP7047 B SHA `875de4842da97fc2d706119bc13feac6eb948fa2349fbb8c43a04d6e8e27c1d4`。until301 / scope16仅HOST，不是实机45、baseline性能或完整Native恢复；不能补签GO58 / GO60失败。以下各“最新 / 下一”均按原时点作为历史保留。

最新GO58终末（2026-10-03）：ROOT唯一 `054ff7` / session41741 → `fe8dca`，HOST0 / remote1、39.312秒无超时，整体FAIL。第一snapshot完整约4.252474秒，第二轮partial在 `_pins→_proc` 拒绝 `native_actor_unknown`，剩6.482050秒，非deadline；原F未导出Proc具体子原因，不猜IO / task / history_closed或设备坏。ROOT `6675e7` 已核52源 / 4407656 B载荷 / 原raw、已观察库存闭合、完整前后Snapshot.key相等 / pending缺席；RF intent=false、journal=None、resource_pending=true、whole / fullNativeRestore=false保持，实际58原件独审已核与ROOT一致；仅原件审计PASS，不改变整轮FAIL或未导出Native资源未知。下一仅私有Proc诊断设计，不改cap / 不执行新trial。生产false / 目标active / 非仅人工。[原失败ZIP和准确分层](CURRENT_GO_BASELINE_BUDGET_V58_FINDING.md)。

HOST59（2026-10-03）：ROOT `6c4bdc` 唯一期限边界方法0.937秒、无超时PASS，9模型case / 4实际发行 / 7原拒绝。ROOT `dd6167` 与实际原件独审已核28私有快照 / 当前bytes / raw / 公私门与四成员ZIP6103 B，SHA `0b3a6a11cd4c4e193a5cff48451240accb5e7393bd2bcab23a28f48a5f8036e1`；仅该模型专项与原件审计PASS。原until301仅HOST模型、不是实机45；不签baseline完成 / 性能 / late_begin / restore，不补签GO58整体通过。[一键模型入口与否定范围](CURRENT_GO_BASELINE_BUDGET_V58_FINDING.md)。

此前候选SOURCE时点（2026-10-03 v58）：首次完整基线内部预算 10→15 秒，仍夹原一次 45 秒活动期；其余阶段、完整双轮、取消、恢复上限和库存门保持。四件源码主审 / 独审、52 源 Python3.5 AST、默认 PC 和完整载荷预检通过，当时受影响 BOUND 专项在制，尚未运行新设备试验。原 56-r2 整体 FAIL 保留；生产 false / 目标 active / 非仅人工。[新预算范围与事实](CURRENT_GO_BASELINE_BUDGET_V58_FINDING.md)。下面各时点按原记录保留。

最新终末（2026-10-03）：HOST57-r2 因夹具把原局部期限 4.0 误判为 11.0 而整体 FAIL，四个受影响 Native 调用均未到达；隔离 57-r3 唯一方法只补两 case × 两域，4 affected / 4 refused PASS，经 ROOT `8ff62c` 和独审核验。首轮完成的 38 子例没有重跑，不能合成新 42 全套 PASS。

正式 56-r2 唯一实机 `bd8705` / session54795 → `5a669f` 已终末：HOST0 / remote1、41.094 秒、无超时，整体 FAIL。第一轮完整约 4.30594 秒；第二轮在 rest 的 `_stock_status→_unix→_record→_check` 原截止门拒绝，Unix factory 尚未调用、尾段不完整。left = -0.02203603 只是失败时刻的余量，不能称仅差 22ms 就完整通过。ROOT `075b7f` 与独审已核实际源 / 载荷 / raw / 已观察库存闭合、完整前后 Snapshot.key 相等及 pending 缺席；实际原件审计通过不改变整轮 FAIL。RF intent=false、journal=None、resource_pending=true、whole / full native restore=false，未导出 Native 库存不代签恢复。[准确结果、SHA 与边界](CURRENT_GO_OWNER_COALESCE_V56_FINDING.md)。

下一方案待性能与预算评估，不承诺原十秒可达，也不写已有确定新候选在制。目标 active、生产收发 false；真实 GO / typed IP-DHCP / State / 文件中心 / 小米 15 Ultra 原厂双向仍有自主工作，尚非仅人工。以下原时点内容及旧“下一步”保持为历史。

最新 SOURCE：v56 三源调整与 17 图 Python3.5 AST 已过，但独审发现 Entry / Store 实例 wrapper 替换会改变快路径认证顺序，故不执行初版。隔离 v56-r2 补两原 wrapper 身份，新 HOST57 两图 42 子例准备中；尚未证明性能收益。手机已记为小米 15 Ultra，暂不需人工；GO55 原 FAIL 保持，目标 active、生产收发 false。[修正范围与下一步](CURRENT_GO_OWNER_COALESCE_V56_FINDING.md)。以下历史保持。

最新GO55耗时实测：整体0/1、42秒FAIL，首轮5.209秒完成、二轮pins在原stage10截止拒绝；两轮actors3.601/3.976秒为主要时间段（含实际IO+纯门），并未证明全是auth成本。前后完整原厂网络一致/pending缺席/已观察资源闭合，未RFintent/journalNone/Native整体恢复未签。下一56仅同纯块重复认证合并、仍需新HOST/实机，目标active、生产false。[耗时、ZIP与优化边界](CURRENT_GO_BASELINE_TIMING_V55_FINDING.md)。以下历史保持。

最新GO52已实际结束：0/1、42.250秒，整体FAIL于原stage10基线pins/Proc deadline，20候选/真实child/退出absence已核、RFintent未观察/journal缺席。前后完整原厂网络Snapshot.key一致、pending缺席及已观察资源闭合，仍不签完整原生恢复。新HOST53十paired/20域专项PASS，typed54仅20图SOURCE/AST；下一私有阶段耗时定位，不扩时限，目标active、生产false。[回执与脱敏ZIP](CURRENT_GO_PIN_DIGEST_V49_RESULTS_README.md)。以下历史保持。

最新只读51实机0/0、12.156秒两轮PASS：35源/实际载荷/raw/418collector+20Proc/17datagram/四ZIP3915B已核；完整原厂网络等当前47基线、pending前后缺席，无候选写/RF。新comm-ENOENT票据0，所以不签新skip分支实证；新的10paired HOST已源码冻结在复审，GO52尚未执行。目标active、互传生产false。[当前分层回执](CURRENT_GO_PIN_DIGEST_V49_RESULTS_README.md)。以下历史保持。

最新终末GO49整体FAIL于候选写入前：原只读枚举的PID在comm初次open时ENOENT，原异常/未得FD票据已保，318collector/19Proc闭合，0写/0child/0RF，未验证摘要优化性能。随后独立当前只读两轮PASS，原厂及完整网络与此前一致、pending缺席；不是完整恢复代签。readonly51／Native52窄修已SOURCE／AST，新成对HOST在制、只读51实测待结果；目标active、生产false。[当前原因/ZIP/边界](CURRENT_GO_PIN_DIGEST_V49_RESULTS_README.md)。以下历史保持。

v49 新唯一 HOST pin 专项首次 PASS：两轮 12 独立读／12 真 SHA、四种原拒绝及不确定关闭保留；26 实际私有输入／四成员脱敏 ZIP 经主审和独审。正式候选默认 PC／52 源 AST／载荷往返已过，唯一实机尚待终末，不签十秒性能或 GO 成功。typed50 仅 20 图 SOURCE／AST；完整目标 active、生产收发 false。[当前证据](CURRENT_GO_PIN_DIGEST_V49_RESULTS_README.md)。以下历史保持。

SOURCE增量（v49，未部署）：same-read摘要去重Native／17map已冻结并ROOT完整窄diff／独审／17图hash及Python3.5AST通过；schema及其余16源保持。6独立读／freshProc／metadata／deadline／finallyclose不减，仅每round SHA12→6，实际性能未验。新唯一HOST组件因果方法在制，不重跑旧频率场景。当前实机事实仍是下方GO47整体FAIL，生产false、目标active。[准确范围](CURRENT_GO_READONLY_DIAGNOSTIC_V47_FINDING.md)。

最新终末（2026-10-03 GO47）：正式试验0／1、42.281秒无超时；before／after完整只读一致、pending缺席，20候选文件准备／真实子入口／退出absence通过，但首基线10秒阶段在_pins→_proc截止复核FAIL、reserve／RF前、journal缺席；整轮FAIL／原生恢复未签。ROOTactualgraph/raw/已观察库存及脱敏ZIP已核。下一仅消除同一次image数据的重复SHA，不放宽门／时限；typedIP-DHCP v48仅SOURCE／AST，gen20接线尚待。生产关闭、目标active。[首因边界／ZIP／源码进度](CURRENT_GO_READONLY_DIAGNOSTIC_V47_FINDING.md)。以下历史保持。

最新终末（2026-10-03 v46／v47）：v46正式试验在原before只读采集io_error处FAIL，未stage／fork／建组／RF；原errno/path没有保留，不能臆定原因。随后独立v39-r2及新增v47私有诊断只读均PASS，完整原厂／网络与试验前一致、pending缺席、资源闭合；旧错误未复现，不回填FAIL。r2四项HOST拒绝已完整PASS。正在隔离将相同诊断接入正式before／after，未执行新建组；生产关闭、目标active。[当前回执／ZIP／边界](CURRENT_GO_FREQUENCY_V46_RESULTS_README.md)。以下保留各历史时点。

当前入口（2026-10-03 v46）：只读实机两轮关联缓存/完整基线通过（2412MHz、BI100、11.953秒），资源及 pending 已核；不触发扫描/建组。新因果 HOST 首次因测试空元组断言 FAIL，正向/两AP场景已完成的有限模型证据保留，r2只补四个受影响拒绝场景。正式候选 SOURCE/AST/载荷通过，尚无 v46 实机 GO；生产关闭、目标active。[当前证据与 ZIP](CURRENT_GO_FREQUENCY_V46_RESULTS_README.md)。以下历史保持。

源码增量（2026-10-02 v46）：频率兼容Native与17图已冻结，ROOT／独立窄diff及17源Python3.5 AST通过；不是HOST或设备通过。缺kernel频道仍核实际ASSOCIATED BSS，GO仍核真实事件／APSTATUS，原门／期限／额度不放宽。只读GET_SCAN前置与因果HOST在制，生产收发false、目标active。[当前首因及源码范围](CURRENT_GO_FREQUENCY_V45_FINDING.md)。

当前入口（2026-10-02 v45首因）：正式GO仍FAIL，但取得577B私有原trace，确定baseline阶段必需kernel频道属性的错误假设；独立只读raw两次wlan0缺attr38、实际STATUS2412MHz。前后完整原厂／网络一致、pending缺席、已观察资源闭合，不签完整恢复。v46窄兼容与只读GET_SCAN前置在制；typedGO-IP／DHCP v43仅SOURCE冻结且仍有同阻点。收发关闭、目标active。[首因／范围／ZIP](CURRENT_GO_FREQUENCY_V45_FINDING.md)。以下历史保持。

当前入口（2026-10-02 v44／独立只读）：私有入口诊断仍FAIL（exit1／stderr0／journal缺席），after检查因actor_unknown未完成。随后独立只读PASS，两轮当前原厂／网络与v44之前baseline一致、global pending缺席；不改判原FAIL或签完整恢复。下一v45只输出run已保留的原失败trace；GO-IP／DHCP源码在制，生产收发false、目标active。[结果ZIP／事实边界](CURRENT_GO_DIAGNOSTIC_V44_RESULTS_README.md)。以下历史保持。

当前入口（2026-10-02 v42-r2）：正式 GO bootstrap 首次实机 FAIL，子入口 exit1、journal 缺席、未观察 RF 意图；原始失败和日志保留。前后原厂／网络基线一致，父端已观察资源闭合，但完整原生恢复未签署。下一独立 v44 仅补私有失败诊断，typed GO-IP／DHCP v43 在制；生产收发关闭、目标 active，小米15 Ultra手机验收尚待。[结果 ZIP／边界](CURRENT_GO_BOOTSTRAP_V42_RESULTS_README.md)。以下保留历史。

当前入口（2026-10-02 v41-r2）：真实笔端 GO Loader／看门狗首测 PASS，正常到期退出、通知 EOF 与子进程锁释放已核实；前后原厂／网络基线一致，全部已观察资源闭合。无线控制器、正式建组、IP／DHCP 与手机收发尚未测，生产准入关闭；下一实际正式 bootstrap 有界创建与恢复。目标 active。[本轮结果 ZIP／范围](CURRENT_GO_WATCHDOG_V41_RESULTS_README.md)，以下保留历史。

当前入口（2026-10-02 v40-r2）：首次 P011 静态准备 PASS，候选文件已写入、读回并封存，前后完整原厂／网络基线一致，写入及采集资源闭合；没有启动互传或无线链路。GO17 r4 为独立 HOST 模型 PASS，真实子进程／看门狗、GO／CLIENT 网络运行和小米 15 Ultra 双向收发仍待。下一做无 RF 的真实 Loader／看门狗生命周期验证；收发保持关闭，目标 active。具体结果与范围统一见 [最新检查点](docs/LATEST_CHECKPOINT.md) 顶部，以下保留历史时点。

当前入口（18:29新事实/18:41归档）：[最新检查点](docs/LATEST_CHECKPOINT.md)。真实隔离HOST B+C+Owner启动身份/持久化/退出组合通过；P011重连后18:25仅三原厂文件与CLI身份只读通过，无CLI/RF/重启/旧pending操作。原网恢复/真实Provider和手机双向仍未通过，目标active。新270成员公开ZIP冻结18:41之前；以下旧入口及带时点段落保持历史，不扩大其验收范围。

当前入口（17:36）：[最新检查点](docs/LATEST_CHECKPOINT.md)。B/clear主审+独立审核完成，ROOT唯一隔离Linux完整事务PASS（92组件/7辅助原FD、device-last、终末unlink/fsync/readback）；restore producer为合成，生产收发仍关闭，P011/手机层未通过。baseline collector独立审中，preexec/postexec登记下一制作。最新设备尝试172839未找到ready P011，未发设备命令；不以旧15:19观测冒充当前状态，不自动重启/清旧记录。完整目标active。

当前入口（16:35）：[最新检查点](docs/LATEST_CHECKPOINT.md)。日志锁交接A已ROOT/独立复审，45和精准2项HOST分批记录，不升级旧实际Linux PASS。B实际Store、Pending终末清理、固定只读baseline collector并行制作，实际Provider/网络恢复仍缺，生产收发关闭，目标active。最新ZIP16:10已独立238成员校验，仅冻结更早事务阶段，不含当前在制源码。设备无线缺席原因未建立，不自行重启或清旧记录。

当前入口（15:00）：[最新检查点](docs/LATEST_CHECKPOINT.md)。三阶段finish核心ec2d927已实作并102项本组件通过；pending cc90ea2仅create/verify/close已审，真实Linux7个组件FD关闭通过但保留marker；direct-child0a9a02已审、真实Linux69bab0门闸/exec/readback/OFD-offset/wait/absence与9父FD闭合通过；实时GO关联fd3d561已审但只有HOST fake查询。17组件分别保留首ERROR/FAIL和增量，不累计为新套测。完整Store/Provider、设备恢复、手机仍未完成，生产收发false；新own-marker准入尚未实现，目标active。本阶段没有P011/ADB/RF/旧pending操作。

当前入口（14:03）：[最新检查点](docs/LATEST_CHECKPOINT.md)。文件选择、Session方向、扫描交接、发送worker与State接线已完成分层HOST专项及ROOT/独立源码复审。worker最后6项修晚回调，State初版34项/最后6项修factory前取消；各自原fixture FAIL与旧SHA保留，14组件不累加为新项目套测。真实Provider/完整Store/P011网络恢复/手机双向仍未完成，生产send禁用；三阶段终结是下一已审设计，不是实现，设备和旧pending没有新操作，目标active。

12:49追加：新preparation Store首次记录事务29项HOST通过，ROOT全文复审；隔离HOST Linux命名空间真实组合14FD关闭验证通过，首合成fixture FAIL另存原判。不是完整RF Store或P011恢复。发送worker与文件选择资源漏洞正在实现，尚无完成/测试结论；设备事实和旧pending未更改，目标active，统一 [最新检查点](docs/LATEST_CHECKPOINT.md)。

最新入口（2026-10-01 12:28）：[最新检查点](docs/LATEST_CHECKPOINT.md)。安全文件层最终9受影响HOST通过，另有真实Linux17FD验证；协调锁37项FakeOS通过，另有真实Linux三FD adapter验证。完整acquire/同OFD继承/Store/Provider/F-D恢复和生产双向链路尚未完成，不是仅剩人工。本检查点没有P011/RF/旧pending操作，11:32设备前置FAIL和旧恢复FAIL原判保持。目标active，以下是历史时点。

最新入口（2026-10-01 11:36）：[最新检查点](docs/LATEST_CHECKPOINT.md)。113255只读设备入口三步完整/原厂与有限基线相同，但phy选择FAIL、wlan0未观察，caps查询未启动；112454首frame FAIL与旧V9恢复FAIL均保留。proc最终窄修已审并有WSL Linux自读，不代表P011/reap/OFD。安全文件层正在制作，真实Store/Provider/worker和手机仍待；目标active，不自动新RF/UI/旧恢复或清pending。以下段落为历史时点。

当前简明入口：[最新检查点](docs/LATEST_CHECKPOINT.md)（2026-10-01 10:56）。CLIENT owner关闭异常修正与实际Linux caps只读transport代码已审、分别有HOST增量证据；不是最终源码全批或设备/手机通过。私有Journal codec、proc actor reader与固定只读caps设备入口继续制作。094137旧FAIL保持；10:11完整进程补充观察不是旧退出收据，旧pending及原网恢复未闭合。目标active，下方保留历史时点。

最新追加：2026-10-01 09:21（以下为历史时点，不代表当前无线状态）。091512-316513 全套 HOST 实际 1322 run＝1289 PASS/33 skip、0 fail/error，25 份 runtime Python3.5 AST；不是 P011 或手机验收。精确收据纯检查组件55项 HOST 和当前恢复只读入口15项 HOST 已审查。

091400-682a4364 唯一实际恢复只读检查 FAIL 于 actors，未恢复、未写网络/journal/pending，两个 netlink 实际关闭。四组固定文件元数据相同；该次完整 before/after 实际完全相同，但 wifi.completed 两端均 false，所以旧字段 full_current_baseline_unchanged=false 不代表本次检查改变网络。与084811退出记录相比 same boot/原厂及6个网络进程身份/pending相同，而原STA连接、接口、IPv4与IPv6 routes 已在两次观察之间变化；旧STA和owned IPv4行已不在新dump。原因/发生时间未知，不归因原厂、用户或修改，不将地址消失当作恢复成功。当前暂停RF/UI/恢复写入，制作独立固定actor与归属分层只读诊断；不直接执行旧recover、flush、删接口或重启。目标active，DHCP/CLIENT/生产双向worker/手机仍待。

最新追加：2026-10-01 08:56。TTY只读084503已完整一致观测，三类prior actor两次计数均0，本次PTY ICANON/ECHO=true；不能反推旧PTY。新bounded入口仅展开两处纯literal，固定全部pins/完整AST与50秒超时；15项HOST通过。084730无RF preflight实际PASS，12步完整返回、四组元数据和全双栈原网基线相等。084811唯一TTL20功能轮首次GO_IP_READY=true、L3accepted、IPconfirmed，但cleanup失败，整轮FAIL：自有GO接口、IPv4地址/部分自动路由及pending尚有残留；原厂/原STA/原IPv6、全部原进程和boot保持。禁止新RF/UI/重复recover/重启；先固定同run精确receipt只读诊断，再审查窄恢复。当前不是完整网络恢复PASS。旧082419超时、所有历史失败不改写。

CLIENT控制codec已主线程全文审查/40项HOST完成；独立CLIENT RF-init计划和最新State无RF smoke计划已审查但尚未实施。它们不升级关联/新UI或手机互通；目标active，实际IP完整退出、DHCP、CLIENT、生产双向worker与手机清单仍未完成。

最新追加：2026-10-01 08:29。State/外部 finalizer 接线已完成主线程全文审查和受影响专项：92 run＝90 PASS/2既有POSIX skip；实际 worker 退出、完整 transport/raw 关闭、helper/key/probe actor 闭合后才恢复同归属租约。显式 recover 不因旧 journal 缺失伪报成功；两个有限 UI 入口保留未知启动和精确 inode/process 占用。DHCP CLIENT socket 适配33项HOST通过。以上均尚未在 P011 新 UI/关联/DHCP 运行，不升级生产双向互通，旧777整合结果不手工累加。

V9 功能入口17项HOST通过、runtime28项HOST通过后，ROOT冻结 `1d695a9e8056e11f`（manifest `1d695a9e8056e11f20039cd3f5b3f6982645a61993f7013fbd76d81064df8c06`），唯一新入口082419在 initial_prior_journals只读核验超时：rf_trial_invoked=false，未创建owned run、未安装地址。新8文件权限/完整readback通过；finally独立原厂/STA/完整IPv4地址、全表路由/规则、IPv6/boot/进程/接口保持，无MTA/P2P/私有WPA/actor/pending。该FAIL不是V9路由功能结果，也没有IP安装收据。正在离线定位源码传送/历史核验耗时，不盲重试或加时限。

fixed V8本机生成pyc已在原七payload/full manifest原样核验后，可恢复地移入私有HOST隔离目录；生成进程未知，原strict八文件validator恢复通过，历史失败不改写。固定e069 WPA的源码/编译记录支持CLIENT8入口，但现caps仅派生STA+GO/AP，CLIENT仍须真实组合/关联/恢复证明。私有CLIENT控制codec正在制作；目标active，实际IP/DHCP/CLIENT/双向worker/手机未完成。

最新追加：2026-10-01 07:57。V8唯一实机 `logs/MtaP011-DeviceP2pV8RouteDiag-20261001-075353-9ad31b4d`、候选 `7e98dbf4a03abcfa`、checker `1000b427…ac713` 已完成，仍为IP安装FAIL，但取得准确原因：同次第二行路由prefix=8、destination_class=multicast，source/source_prefix/gateway全zero、flags仅UP、invalid_fields=[]；我们旧10..64前缀门禁拒绝了该实际route，而非carrier或/128。Linux4.14主源码addrconf_add_mroute会为非loopback接口增加ff00::/8 UP路由；这是本次profile相符的来源依据，不把coarseclass冒充完整canonical地址证明。V9功能候选只将精确canonical ff00::/8、零源/网关、仅UP且最多一行的profile例外一致接create/restore/STAcleanup，仍在制作，未实际执行或开放发送。

V8初次/最后old16＋fixedV7eight只读全pins/metadata通过，仅新八文件fd设置0400/0500；最后完整基线与第一相同，14原生事件均0。失败内部cleanup与独立原厂/STA/完整IPv4地址/全部表路由/规则、IPv6/boot/进程/接口保持，无P2P/MTA/私有WPA/actor/pending；journal=reconciled/ip=None，无安装收据。HOST入口22项与V8runtime30项是独立专项，未相加为新整合。073152真实UDP lo环回PASS保持，并新增固定checker SHA一键DEVICE_UDP_LOOPBACK_CHECK.cmd；没有复跑UDP、重启、DHCP、数据socket或手机。State与DHCP CLIENT socket仍在接线/专项回归，目标active。

最新追加：2026-10-01 07:32。仅修正HOST对精确完整源码回显的识别后，新的UDP环回唯一实机执行通过（`logs/MtaP011-UdpLoopback-20261001-073152-11ad27e3`，checker `33190525…fd87`）：两个真实socket、四条合成数据报，数值IP_PKTINFO=8、lo接口绑定与读回、sendmsg/recvmsg的实际来源/目的/ifindex/ancillary校验、两个socket关闭读回和0失败均通过；前后原厂身份、STA、进程/接口/boot、主IPv4路由及完整IPv6指纹相同。没有RF、IP/路由/DNS写、UDP67/68、P2P绑定、DHCP或手机。该基线不含IPv4全表/address/policy，不能与V7完整IPv4验收混称。独立复核脱敏ZIP成员/CRC/边界通过，SHA `7fe2c0696e9a31f4d6ce434847543648013dd2332a3229ce299c442d0fc8413c`。072329原FAIL与raw保持；ROOT离线精确剥除该次回显后确认其两个strict baseline本来相同，不重判原入口通过。

最新追加：2026-10-01 07:24。V7 的唯一 TTL20 实机试验已执行（`logs/MtaP011-DeviceP2pV7L3Diag-20261001-072210-d0ad939a`，候选 `3cbd5bf8e5c718b9`），结果仍为 FAIL，但首次准确区分：一个 IPv6 地址已接受，第二个同次观察的 IPv6 路由被 `route_prefix` 拒绝，`route_prefix_is_128=false`。因此本轮不是 `/128` 拒绝；实际前缀和目的类型尚未知，不能直接认定为 multicast。原生14事件均0，新8文件权限/完整SHA/身份读回通过，旧16文件未写、前后metadata保持；失败内部cleanup与独立原厂/STA/全IPv4地址、所有表路由、规则/IPv6/接口/进程/boot均保持，无actor/pending。没有IP安装收据、DHCP、数据socket或手机。

UDP环回首次入口（`logs/MtaP011-UdpLoopback-20261001-072329-0cfa2813`）FAIL于before解析，`udp_trial_invoked=false`；两次远端程序实际exit0，但正常ADB stdin源码回显被固定三行解析拒绝。不能把公开恢复false误读为原厂已变化，也不能称内核UDP通过。正在窄修精确源码回显识别/短命令传送，私有raw与该FAIL保留。新两阶段TransferSession纯核心47项HOST通过，完整raw/lifecycle证明与实际worker/finalizer退出后才恢复；尚未接入State，现有调用链提前恢复问题仍待修。动态DHCP CLIENT45项、V7独立入口24项都是各自HOST专项，不手工加总成新的整合。目标active，实际IP/DHCP/CLIENT/双向worker和手机仍未完成。

最新追加：2026-10-01 06:50。transport 精确关闭证明已制作并在 P011 新候选 `8844c5681f2c36e9` 实测通过（`logs/MtaP011-DeviceTls-20261001-064951-2a568c8a`）：TLSv1.2、两份合成文件 1,050,940 B/ZIP 1,051,228 B、完整内容 SHA 与双方 ACK、sender/receiver exact raw 关闭证明通过；threads/sockets/processes/actors/unknown pending 均为 0，临时证书/接收文件清理、独立原厂身份保持通过。仅新候选精确八文件权限设置，没有 RF、UI、用户文件或手机。HOST 最新已归档整合为063938-580208：777项、744通过/33跳过/零失败错误、20个runtime Python3.5 AST；不含之后新增TLS入口20项或V7专项45项，不能相加当新整合。063809的直接入口ImportError（729项/4errors）记录保持，已补 project root 导入路径。V7只增加IPv6子门禁固定诊断，45项HOST通过，不放宽/128、gateway或carrier，尚无V7实机执行。目标active，实际IP/DHCP/CLIENT/双向worker/手机仍未完成；以下06:17及更早证据保留。

更新：2026-10-01 06:17。目标保持 active，尚未完成或发布。V4 的独立 P2P GO 限时建组已实机通过；V5 的 IP 配置试验在 ip_create 失败，没有取得 IP-ready 或有效安装收据。V6diag 首次入口053019在历史journal权限准入被拒绝、没有RF/IP；060853已完成精确16文件fd权限规范，0400/0500及完整身份/哈希读回通过。新的独立无stage/push/chmod入口经主线程审查后，在061551实际启动了唯一一次TTL20试验：14项原生事件均0、初始化成功，ip_create明确拒绝于interface_l3；六项观察全部true，包括carrier_is_up，不能再把本轮原因猜为载波未就绪。IPv6地址与该接口IPv6路由两个子条件尚需区分，不降低检查门槛。失败后完整原厂/STA、全IPv4地址/全部表路由/规则及IPv6独立恢复通过，自有资源/pending清空，journal=reconciled/ip=None；无安装收据不是恢复失败。工具箱接入、TLS文件核心和蓝牙桥接另有运行证据；实际IP/DHCP、双向Wi-Fi文件链路及真实手机互通仍未完成，正式发送能力仍关闭。

## 已验证部分

| 项目 | 记录与结果 | 证据边界 |
| --- | --- | --- |
| HOST 核心与服务 | results/host-20261001-052915-624590/result.json：606 项，573 通过、0 失败、0 错误、33 跳过；19 个 runtime 文件 Python 3.5 语法通过；含纯 DHCP 29、DHCP socket 44、自有 IP、V6diag 内存诊断39和新 harness47 | Windows 跳过 31 项 POSIX IP/原子 journal 检查及 2 项原权限检查；不称 606 项全部通过。Linux HOST 与实机证据分别保留，旧509记录不改写 |
| Linux HOST 自有 IP 租约 | results/owned-ip-host-20261001-043347-0e487f/result.json、unittest.txt：48 项、0 失败/错误/跳过 | FakeLock/FakeKernel 与真实 POSIX journal/fsync；恢复对象重建不等于真实 fork、继承 flock 或实机父死 watchdog 验收。保留既有合并工具输出，未伪造分离 stdout/stderr |
| HOST DHCP socket 适配 | runtime/mta_dhcp_server.py、tests/test_dhcp_server.py：44 项通过，精确接口/pktinfo/source68、实际子网广播、关联准入、有界取消和晚 socket 清理 | 假 socket + 真实纯 codec，不是 UDP67 内核绑定、手机 DHCP 或生产发送；ACK 发出仍不等于手机已配置 IP，不自动解除 TLS deny-all |
| HOST 接口受限 TCP 工厂 | runtime/mta_scoped_sockets.py、tests/test_scoped_sockets.py：56项假socket/proof检查；强制共享租约锁、confirmed/fsync/持久完整读回、实际端点、接口绑定及精确handoff关闭证明 | 没有实际TCP、ADB或生产接线；CLIENT证明提供者尚未实现，TLS detach/raw fd=-1不能表示transport已经关闭 |
| HOST 动态 DHCP CLIENT 纯核心 | runtime/mta_dhcp_client_core.py、tests/test_dhcp_client_core.py：45项HOST通过，动态Offer/ACK服务器与地址/掩码pin、原REQUEST租期、有界重发/取消/NAK/预算/恶意包与Python3.5 AST | 不创建socket或安装IP，不推导固定.1/网关；配置不是关联/地址收据或互传端点证明。实际UDP、ARP冲突检测、owned CLIENT及手机未验证；未包含在063938的777记录 |
| HOST 两阶段 TransferSession | runtime/mta_transfer_session.py、tests/test_transfer_session.py：47项HOST通过，真实PC线程、exact worker/finalizer/start未知保留、全部7 pending计数与raw闭合证明、释放/restore严格顺序、取消/预算/超限/迟到对象与结果事实保留 | lease/transport/scoped均为fake；未接State，不能据独立组件宣称生产worker问题已修。State与UI pending占用合同正在接线，不开放native能力 |
| HOST 服务故障回归 | 独立 test_service_integration.py 26 项通过；覆盖丢租约、旧回调、清理失败、文件身份和已落盘后通知失败 | helper 为明确 fixture；TLS/ZIP/实际字节部分为真实主机链路 |
| HOST 网络恢复 | results/network-host/summary.json：私有 D-Bus mock、prepare、崩溃恢复、profile/hash/boot/actor/ConnMan 身份保护 | 不能代表原厂联网可被 ConnMan 恢复 |
| HOST QML 生命周期 | results/ui-host-lifecycle-post-gates/HOST_ONLY-result.json：6 项、8 张截图、零 warnings，Qt 5.15.2 | 旧回复隔离和键盘覆盖回归，不是光学全屏验收 |
| P011 基础运行 | logs/MtaP011-RuntimeSmoke-20260930-191929-730843/result.json：严格 JSON、协议、P256/ECDH/AES、合成 ZIP 落盘通过 | 对应当时候选 1e81420f7d2603e4，不升级后来改动证据 |
| P011 QML | logs/MtaP011-DeviceUi-20260930-201857-6e1291ae/result.json：Qt 5.10/Wayland、800×268 五页截图与本地服务关闭通过 | 候选 f612e4ca8e79fa8a；合成目录，不广播、不切网 |
| P011 蓝牙桥接 | logs/MtaP011-BluezTrial-20260930-195922-516283/result.json：自有 GATT、5 秒广播、实际广告实例、3 秒扫描、退出恢复通过 | 候选 8c13ef06352adb6e；没有配对、对端连接或 Wi-Fi 操作 |
| P011 网络准备 | logs/MtaP011-NetworkPrepare-20260930-202124-222179/result.json：只读快照准备、600 journal 创建/取消清理、Wi-Fi 指纹和原厂状态一致 | 不执行 Connect/Scan/凭据 Agent，不证明切网恢复 |
| P011 TLS 文件核心 | logs/MtaP011-DeviceTls-20261001-015853-8b278882/result.json：Python 3.5/OpenSSL 1.0.2p、TLSv1.2 双连接、2 个合成文件 1,050,940 字节、ZIP 1,051,228 字节收发和 SHA-256/完成 ACK/资源释放均通过；初始 deny-all/一次授权、两次源端点工厂及一次绑定监听端口工厂读回通过 | 候选 bd98466e6016e3e8；包含取消/late-listener race 修正。race 专项为 HOST，笔端本轮为普通传输回归；不操作无线、不证明 SO_BINDTODEVICE 或手机互通。此前所有 PASS/FAIL 原记录保留 |
| HOST 工具箱接入 | results/toolbox-integration-ui/result.json：24 项、10 张图、零 QML 警告；20 项旧源码 SHA 不变 | Qt 5.15.2；两个 loopback 服务，共用合成目录，不操作设备 |
| P011 工具箱接入 | logs/MtaP011-ToolboxUi-20261001-010106-8862ad20/result.json：Qt 5.10 页面跳转、Received/不透明 ID、真实键盘取消、fresh cancel→status 返回、首页标题/16 B 显示断言、两服务关闭与原厂独立检查通过，8 张图 | 候选 af24c3fe42891a33；首轮 0507562a70a02b1a 截图发现返回后标题遗留，已修正并新增本轮断言；不是光学全屏或手机互通 |
| P011 首轮 P2P | logs/MtaP011-DeviceP2p-20260930-205426-c3ac37fe/result.json：FAIL，private_wpa_exit，未 GO ready；原厂文件/进程、完整 Wi-Fi 指纹、IPv4 路由未变 | 源码证实 early gate 的传参时机不符预期，但不等于已取得本轮退出根因。自有 netdev 转 STA、旧清理拒绝；另有配置/构建冲突需按版本分开归因 |
| P011 第二版 P2P | logs/MtaP011-DeviceP2pV2-20261001-015014-3b76e733/result.json：FAIL，未 GO ready；OSError 尚无具体 errno，owned/process/config 未保存 | 候选 f100d4ea35acf9af；本轮 journal reconciled、pending/owned 资源皆无，原厂/Wi-Fi/完整接口/IPv4/IPv6/boot 独立保持。不是建组 PASS，不需要重复 recover |
| P011 V3 暖/冷对照 | 022112-fc590b0e：interface_create/new_interface/EIO；同候选 eaf5b85a187eb73f 正常重启后 023349-fe630cf7：越过创建但 private_spawn/lease_error，均 FAIL | 暖轮内核有 SIPC command msgbuf 不可用链；冷轮后续只读证实已保存子进程。两轮完整独立恢复通过；不能把暖轮永久解释为类型不支持或全局 RAM 不足 |
| 正常重启和新启动 | MtaP011-NormalReboot-20261001-023005-d1bbea10：仅一次正常 reboot，初次限时等待 FAIL；MtaP011-BootReadOnly-20261001-023304-9c8871df：之后独立确认新 boot、原厂哈希/进程、Wi-Fi、无项目残留 PASS | 依既有用户调试授权；无恢复出厂/刷写。后续 PASS 不覆盖初次等待超时，实体触摸未人工验收 |
| P011 无 RF 配置对照 | MtaP011-WpaConfigNoRf-20261001-025636-5a66dea7：固定 WPA 原配置 exit255，唯一删除 update_config=0 后 exit0；版本命令 exit0；完整原厂与双栈网络基线相同 | CONFIG_NO_CONFIG_WRITE 会移除该配置解析字段。确认配置兼容问题，不代表驱动/GO/手机；早期版本全文等值断言 FAIL 原样保留，不当加载器故障 |
| P011 V4 GO-only | MtaP011-DeviceP2pV4-20261001-030738-1772afe3：候选 43a77d612f32fba5，14 项数值原生初始化/退出事件均为 0；GO-ready、完整 cleanup、独立 stock/Wi-Fi/接口/进程/IPv4/IPv6/boot/pending/journal 全通过 | 唯一删除17字节不兼容配置，原生 binaries/其余行为不变；仅 TTL20 建组，无 IP/DHCP、BLE、UI、用户文件或手机互通，正式 send=false |
| IPv4 纯核心 | runtime/mta_ip.py 与 tests/test_ip.py：60 项 HOST 通过，严格完整地址/全部表路由/规则、冲突选择、NEWADDR/DELADDR 字节和 ACK；含历史私有 dump 离线解析 | 纯组件无 socket/网络动作，没有地址配置或手机证据 |
| P011 IPv4 实时只读 | MtaP011-IpCoreReadOnly-20261001-034723-58f50b59、035650-66a4c890：同候选 92b7279adad8ad39，实际 Python3.5 导入、两套完整稳定视图、2地址/9路由/3默认规则、永久无限期、私网候选、实际 kernel sender/socket port/6递增seq、socket关闭及独立原厂基线一致 PASS；第二次 checker 显式判断/优化模式门禁 | 不启用 RF、不安装 IP/DHCP、不接用户文件或手机。全 IPv4 视图为阶段内一致证据，独立前后为主IPv4路由/fullIPv6及原厂/接口/进程/Wi-Fi；补充作者 HOST 快照，不改历史结果 |
| P011 V5 GO-IP 首次试验 | MtaP011-DeviceP2pV5-20261001-044609-c53555d6：候选 0f2a45489fd3e03b，FAIL，ip_create/lease_error/errno0；14 项原生事件均为 0，无 IP-ready；失败事件内 cleanup.complete=true、ip_restored=true、ip_stage=none、control socket 已关闭 | 独立完整 IPv4 地址/全部表路由/规则、完整 IPv6、stock/STA/进程/接口/boot 均相等；无自有 actor/接口/pending，journal=reconciled/ip=None。成功专用 public cleanup/receipt 字段为 false，不推翻独立恢复 PASS，也不代表地址安装通过。carrier 门禁只是待验证假设 |
| HOST V6diag 固定门禁诊断 | results/v6diag-host-20261001-051618-55379f：39项 PC HOST；新 runtime 82bb5ba7…，仅增加固定枚举/六项可选bool和最早拒绝记录，保留原创建/恢复门槛 | FakeKernel/MemoryJournal，不是实际 fsync、RF、IP安装或手机。主线程另审查47项harness及精确7payload，旧V5保持不变 |
| P011 V6diag 准入失败 | MtaP011-DeviceP2pV6Diag-20261001-053019-ffaa543c：候选916a02d44aeeaf0d，FAIL；prior_journals阶段，检查6份记录、unsafe1/blocked0、pending clear；rf_trial_invoked=false | 仅安装新隔离候选并只读检查，未进入RF/IP试验、未创建试验会话。之后 Wi-Fi COMPLETED，无P2P/MTA接口、私有WPA或actor/pending。没有before网络快照，报告比较字段false是未满足比较，不是改坏网络的证据；需独立只读核验具体原因，不能删历史记录或自动recover/retry |
| P011 历史journal精确只读诊断 | MtaP011-PriorJournalReadOnly-20261001-054328-59c5c157：check_complete PASS，3次host/remote exit均0；第6份schema3记录拒绝于prior_context/historical_manifest_permissions，仍prior_admission_clear=false | 只读诊断PASS不是GO/IP准入或互传PASS。具体manifest的文件类型/属主/权限子项仍待固定元数据/全部pins读取，不猜0666或uid。完整before/after原厂、STA、全IPv4/IPv6、原进程/接口/boot相同，无项目actor/接口/pending；未删除journal或修改权限/网络 |
| P011 固定候选权限与哈希只读 | MtaP011-CandidatePermissionsReadOnly-20261001-055734-dd922b01：16文件完整SHA/精确大小、属主、regular/no-symlink均通过；两候选清单+runtime均0666、native均0700，因此permissions_gate_satisfied=false | check_complete PASS仅代表采集完成且完整原基线相同，不代表权限已修复或IP准入。O_NOFOLLOW/fstat/有界精确读取/最终身份复核；3次host/remote exit均0，无chmod/chown/RF/IP/恢复/重试 |
| P011 精确候选权限规范 | MtaP011-CandidatePermissionsNormalize-20261001-060853-204a0e0a：16fd先完整验证归属/nlink1/全pins，16次fchmod、16次0400/0500/身份/全SHA读回、16fd关闭/0失败；normalization_complete PASS | 确实修改项目文件权限，不伪装只读；没有改内容/属主/旧journal、原厂或网络，无RF/IP/自动重试。完整原厂、STA、IPv4/IPv6、接口/进程/boot前后相同；不等于历史准入、IP或手机PASS |
| P011 V6diag 新独立入口实际试验 | MtaP011-DeviceP2pV6DiagPermissions-20261001-061551-48fbed57：候选916a02d44aeeaf0d，FAIL；两轮16文件/旧pins/prior门禁及完整pre-RF基线相等，rf_trial_invoked=true；14项原生事件均0、early_init_success=true；ip_create拒绝interface_l3，六项bool全部true（含carrier） | 没有stage/push/chmod、恢复/重试、DHCP、应用TCP、BLE/UI/用户文件/手机。failed_trial_cleanup_complete=true；全IPv4地址/路由表/规则、IPv6、stock/STA/进程/接口/boot独立保持；无actor/pending，journal严格归属且reconciled/ip=None。未生成成功专用IP/cleanup收据，不能把对应false误读成恢复失败或安装通过 |
| P011 UDP API 只读 | MtaP011-UdpApiReadOnly-20261001-043409-b782aaca：实际 Python3.5 的 recvmsg/sendmsg/CMSG_SPACE、SO_BINDTODEVICE、SO_BROADCAST 等 API 存在，原厂和网络基线一致 | 未创建 UDP socket。IP_PKTINFO Python 名称未暴露，Linux UAPI 数值 8 的内核支持仍须实测；实际 bind/pktinfo/关联/DHCP/手机均 NOT_TESTED |
| P011 V7 精确L3诊断 | MtaP011-DeviceP2pV7L3Diag-20261001-072210-d0ad939a：唯一TTL20、3cbd5bf8e5c718b9，FAIL；IPv6地址接受，第二行route_prefix拒绝、不是/128。新8文件完整验证和权限设置，旧16文件不写，原生14事件均0 | 全IPv4地址/所有表路由/规则和IPv6、原厂/STA/进程/接口/boot独立保持，无actor/pending。无IP安装收据；prefix/class尚未知，V8只增诊断，尚未执行。成功专用receipt/cleanup字段false不掩盖失败内部cleanupTrue |
| P011 UDP环回内核检查 | MtaP011-UdpLoopback-20261001-073152-11ad27e3：2真实socket/4合成数据报、IP_PKTINFO数值8/lo绑定、精确ancillary/source/readback、2关闭/0失败、独立原厂与网络指纹保持，PASS | 仅loopback，不启用RF/IP/DHCP端口，不是P2P绑定、ARP、关联/端点、DHCP或手机。独立IPv4只比较主路由不是所有表/地址/规则；旧072329解析FAIL不覆盖 |
| P011 V8同次路由诊断 | MtaP011-DeviceP2pV8RouteDiag-20261001-075353-9ad31b4d：7e98dbf4a03abcfa，唯一TTL20；FAIL route_prefix，准确prefix8/multicast、zero source/source_prefix/gateway、仅UP/无未知标志；new8权限/全pin/身份、old16＋V7eight只读及原生14事件通过 | 完整原厂/STA/全IPv4地址/所有表路由/规则/IPv6独立保持，无actor/pending；无IP安装收据。coarseclass不是canonical字符串或自动来源证明；V9严格例外功能候选尚未实测，诊断FAIL不重判安装通过 |
| P011 自有残留清理 | logs/MtaP011-OwnedStaRecovery-20261001-005053-aeb32151/result.json：归属/同 boot/actor 退出/完整接口/无数据地址与路由均核实；仅按 WDEV 删除，独立确认只剩原 wlan0，原厂与 Wi-Fi/路由保持 | 不全局停服务或 flush；当前 journal 已 reconciliation，原 FAIL 保留。IPv6 原路由仅证明这次清理前后不变，首轮未采 IPv6 基线 |
| ARM 构建 | results/native-build-20260930-201806-825963/result.json：BlueZ、ConnMan 和只读 nl80211 三个辅助程序 | 不附带原厂 GLib/GIO 库；构建不是无线链路验收 |

上表 logs/... 相对工作区根 D:/project/P011，results/... 相对当前候选目录。所有笔端试验均保留原厂文件哈希、PID/start time/parent/exe 的独立前后核验。未改动启动项、无线固件、NV 或系统分区。

## Wi-Fi 归属结论

只读检查确认：当前 wpa_cli wlan0 为 COMPLETED，但 ConnMan 的 GetServices 正常返回空数组，Wi-Fi 服务和已连接 Wi-Fi 服务均为零。两个原厂 supplicant 中，管理 wlan0 的实例没有系统 D-Bus 接口；提供系统 D-Bus 的实例没有注册 wlan0。wifiPowered=true 因而不能证明 ConnMan 管理当前原厂连接。

原厂 ConnMan 存储存在未知扁平文件，尚不能证明临时服务会使用 upstream 的 service/settings 格式。按名称删除或强行接管可能使原网络无法恢复，因此生产编译 MTA_CONNMAN_STA_VERIFIED=0，**ConnMan 切网接收默认不可用**。页面如实显示原因，不能为了演示把能力改成 true。prepare 只读功能仍可测试。

驱动的 nl80211 声明包括 STA、AP、P2P CLIENT、GO、DEVICE，并声明可同时使用 STA 与 P2P CLIENT/GO；STA 与普通 AP 不在同一组合内。原厂 wpa_supplicant 的接口不含 P2P 管理命令。这说明应研究独立 P2P 接口与私有管理实例，不说明硬件已经能够稳定建组或传文件。

独立官方 wpa_supplicant 和静态 libnl 的 ARM 构建使用内部加密，不注册系统 D-Bus，不替换原厂管理程序。V3 暖轮 EIO 与冷轮配置解析失败分属不同阶段；无 RF 单变量对照确认配置冲突后，V4 首次完整通过私有初始化、GO 建组和退出。这个窗口证明该路线可运行，不证明暖状态命令池问题永不复发或无线全部功能已恢复。实际 IP/DHCP、受限接口 socket 和双向文件数据仍需逐步实测才开放能力；纯 DHCP HOST 核心不创建 socket 或配置网络。

V4 冻结 manifest SHA-256：43a77d612f32fba5ecbcddfe03be5e9aca2a81f1981e2790a099f8cca5e82ae5；runtime SHA-256：ef2f087444c149a988b5b3895225960e85c03d702aa5a084cef62e6222ccf334。V1/V2/V3、主 runtime 与历史结果均保留，没有把旧失败重判。

## 已修复的安全和界面问题

- 持久 Wi-Fi 后端与 active lease；恢复失败不丢失对象、不允许下一轮覆盖，不把第二次 Stop 当作恢复证明。
- helper/read/watchdog 会话身份隔离；启动 IPC 失败及关闭异常保留归属。旧回调不能重新激活扫描或广播。
- 文件 ID 只有路径与文件身份均不变时复用；刷新目录不会让旧选择静默指向新内容。
- 原子落盘、对端 ACK 和网络恢复分别记录。通知失败不否认已经保存的文件，也不伪造手机完成。
- 键盘由父级页面控制显示；取消/完成后不覆盖文件页。宿主 catalog/bootstrap 旧回复被隔离，切换服务清空旧选择。
- UI 只使用 token header，缺能力即禁用；发现设备不等于可发送。改名与发现状态的忙碌定义一致。
- 发送监听器初始 deny-all；只有调用方核实当前租约真实关联/DHCP 后才可一次授权，不能让首到连接抢占 WS，也不能换 IP。
- 发送完成 ACK 仅在最后真实写操作已开始时等待本地计数提交，避免已发完最后一块的调度竞态；未下载/提前确认仍拒绝。HOST 有确定性复现，首次整合失败保留。
- 接收传输支持内部 socket_factory/source_ip 配对参数，真实源/目标端点读回失败即关闭、绝不走默认网络回退；工厂还需后续 owned lease 实现接口绑定，不从 QML 暴露。
- 发送监听工厂原子接管：close/cancel 后才返回的 socket 立即关闭，不依赖已执行过的 close 再次清理。完成 ACK 期间取消不会发出未提交的 completed 回调；回调在内部锁外，避免服务接线交叉锁。
- TLS transport 追踪实际 raw/TLS、wrapper 与调用线程、OpenSSL 子进程和自有临时文件身份；raw fd=-1 不冒充 TLS 已关闭。`close()`/`closed()`/精确 closure proof 有界等待，未明资源保留 cleanup_pending。49项HOST故障专项及064951普通P011回环通过；网络恢复调用方还须确保实际worker退出，不能只看close请求。

## 下一步

1. 工具箱返回标题/字节显示及 TLS 准入/连接与监听工厂已完成受影响的实机回归；生产发送仍未开放。
2. journal/pending v3、自有IP子租约与同一guard/watchdog责任链已制作。V8于075353已确认我们拒绝实际/8 multicast，仅UP/zero source/gateway；下一步V9只允许exact canonical ff00::/8 profile且最多一行，create/restore/STAcleanup保持一致，其余原门禁不变。功能候选需独立HOST审查与有限实机验证，不把coarse诊断或Linux来源当实际地址收据。旧候选字节和每轮FAIL保持；不自动recover/retry。故障分层见docs/P2P_TRIAL_V8_ROUTE_PLAN.md与各历史计划。
3. DHCP socket 适配已有 HOST 证据；必须等实际自有 IP 收据通过，才验证 UDP67 绑定/pktinfo/真实关联和有界恢复，再连接 BLE 凭据与 TLS/WSS 实际发送。不得根据 DHCP ACK 自报就认定手机已配置或自动授权数据连接。
4. 研究使用独立 P2P CLIENT 接入手机网络的接收路径，避免不明 ConnMan 原网恢复。需要实际关联、DHCP client 和可信 GO 服务端点，不能猜固定网段的 .1 地址；不能把当前禁用路径当已完成接收功能。
   动态DORA纯核心已完成45项HOST检查；真实UDP/链路入口、ARP/端点证明和CLIENT IP子租约仍待。服务层两阶段Session正在补齐：实际worker退出与transport/scoped关闭均核验后才恢复网络，不凭worker返回或清空引用表示退出。
5. 完成双向服务状态机、一键启动/停止、取消/超时恢复与脱敏结果包。已有一键只读/HOST/UI/核心入口不是完整互传 START。
6. 真实手机原厂互传进行双向、多文件实际内容校验、拒绝/取消/失败恢复，并核对手机完成提示。

**仍有自主开发与实机平台工作，不是只剩人工测试。** 真实手机互通未测试，目标不能完成。具体安全门槛见 GOAL.md、docs/NETWORK_BACKEND.md、docs/SERVICE_REVIEW.md；历史原始记录不改写。
最新18:29：目标active。B+C+Owner真实隔离HOST组合通过，但network/restore合成；P011重连后18:25只读文件身份通过，未执行无线/CLI、重启或处理旧pending。完整Provider、网络恢复和手机双向互通未完成，两阶段Lease/daemon端点事实继续制作。当前事实统一见 docs/LATEST_CHECKPOINT.md；下方保留历史原判。
