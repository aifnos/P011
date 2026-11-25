# 原厂 WPA authenticated STATUS 组件

状态：当前 ARM 窄适配候选仅源码/HOST Fake；旧3722候选实际在平台校验阶段拒绝，尚未发送STATUS。旧失败不覆盖当前新候选，RF及手机均未验。
仅新增 `mta_client_wpa_status.py`、对应专项测试、本文。没有改 Baseline、Store、TwoPhase、Provider、旧冻结或生产能力。

2026-10-01 ROOT增量：此前3722源的真实调用07b9dd在source/socket前失败，原判保留；5edae9同一实际只读raw核定P011 O_NOFOLLOW=0x8000，而旧Baseline要求0x20000。仅在本组件的LinuxIo验证及ReadFiles默认open窄覆盖实际ARM flags（armv7l/little/root与实际常量都须匹配），显式/proc/exe flags保持0x80000；不修改冻结Baseline。支持的固定Baseline原因码不再一律隐藏成io_error。旧43方法历史证据不重写；本增量专项和新来源pins另记。

ROOT 1c09d3仅新增3个ARM/flags/错误码方法与直接受影响3方法：6 PASS，0.020s，host0；未执行真实系统读、socket或设备操作。这三个方法为新增，累计46不同方法具备分批证据，不是当前46整批通过。原基线 SHA 仍ce8fe17b…13f08；Windows/WSL结果不可替代本机ARM ABI。

## 具体实现而非新的事实检查器

- `AuthenticatedStatusReader(manifest=None, source=None, timeout=3.0, _io=None, _proc_reader=None, _clock=None)` 构造纯；`read_status(deadline)` 一次同步 STATUS、无重试。
- manifest 私有固定 7键：daemon_exe/daemon_sha256/endpoint/real_uid/real_gid/namespace_kind/config_sha256。不是 UI/HTTP 参数，也不是 pin 来源认证；缺 manifest 默认 unavailable。
- 默认具体 `LinuxStatusSource` 复用现有 Baseline 文件票据/读取/once-close，以及 actual `ProcReader`。不调用 Baseline.collect/_status、CLI/Popen或 netlink。
- 每个 `ProcReader.read_*` 前先登记私有 call-ticket，再保存 exact reader；每次来源至多4调用，两次共8。异常或 pending observation 保存原 reader、原返回/异常与其 `_fd_refs`/`_open_attempt` 所属对象，不因局部变量退出丢失强引用，不替该 owner 重读或重关。预算在新 reader 构造前拒绝。
- 它实际读取单线程 F、唯一 original supplicant 完整 Actor、argv SHA/真实 IDs、namespace 两端所有条目、pathname+live proc exe完整映像SHA/metadata、endpoint与root-owner锚、`/proc/net/unix` inode与 daemon fd 表。
- endpoint父链仅有界逐级lstat/readlink解析root-owned symlink，保存原pathname/resolvedendpoint/每级原metadata+target，完整前后复核；不调用realpath猜target，拒循环/预算/不可信任父目录，不因symlink模式0777拒绝其内核忽略的权限位。resolved最终仍要求root-owner nonwritable目录及受限socket。
- 尾 slash 疑虑经静态核查排除：现有 `target.split('/')` 保留末尾空组件，SOCK仍有 pending，原谓词要求DIR而拒绝。未改 resolver 或加冗余守卫；回归覆盖最终绝对/相对/多尾 slash 拒绝，以及中间目录 link 带尾 slash 正常解析。
- 固定 pathname socket inode与 sockfs inode分开，不能拿 lstat inode代替 daemon socket归属。
- 每次来源读取所有实际文件关闭/EBADF后发行 registry 绑定观察；认证 exact consumer/对象/内容/资源。最多512个source文件票据，用现有core.CloseProof每组至多128个原资源逐项闭合，不改core上限/不以aggregate bool替代原资源。无关已闭合 `/proc` 文件数量变化不是daemon身份变化。
- 可信注入只是 HOST/Future内部接线，不能凭 authenticate(None) 或 public facts PASS 当 Linux 实证。
- pre/post 是两次同boot/身份/映像/namespace/endpoint观察，不是原子快照；拒同一个缓存观察。正常 task R/S变化不冒充换PID，但非live任务拒绝。

## Namespace policy

- `full4_present`：实际两端 namespace目录同完整集合；至少 mnt/net/pid/user存在，所有实际条目 links一致，不填缺失条目。
- `namespaces_disabled_cgroup_mnt`：只有exact(cgroup,mnt)，实际config.gz有界解压、完整 **plain config SHA**匹配固定pin、唯一 `# CONFIG_NAMESPACES is not set`。
- 本策略保留配置缺席语义，不把未列NET/PID/USER子符号伪填n；也不把本地事实collector的namespace_profile升为SOCKET来源认证。
- 已观察P011 kernelprofile事实并不证明本组件在实际原厂daemon/endpoint/ABI上工作。实际manifest生产者/部署来源图仍未装配。

## 一次读与资源

- fixed AF_UNIX/SOCK_DGRAM、显式随机16B abstract local、不写/unlink文件、不autobind/fallback；PASSCRED=1/readback、CLOEXEC/不可继承读回。
- connect精确固定endpoint，仅 `b'STATUS'` 一次6B；不ATTACH、不SCAN/PING、不创建连接/配对或修改网络。
- 每报文必须exact一条12B SCM_CREDENTIALS，实际PID/real UID/GID与fresh daemon一致；source/peer/local读回一致；拒FAIL/UNKNOWN COMMAND/events/重复字段/非法STATUS。
- recvmsg保留完整原返回后再解析；MSG_CMSG_CLOEXEC，16KiB+1与253rights预算。拒RIGHTS但先登记、独立关闭所有已知返回原FD；重复/碰撞/畸形/截断/未知创建保留强引用和sticky pending，不猜close。
- socket原引用与原FD稳定身份，独立once-close、wrapper fileno=-1与原FD EBADF。异常来源、factory、receive的未知不因close已知socket而清除。
- budget共享单调≤3s，先型别/范围后finite；CPython3.5纳秒ROUND_CEILING timeout读回。不是硬抢占任意OS IO或可信回调。
- 返回私有raw/fields/digest/frequency/completed/source_authenticated；public仅固定枚举/计数/布尔，无路径、Actor、SSID、IP或凭据。STATUS completed不是关联、恢复、RF、收发准入。

## 后续装配与未验层

ROOT另审将其fresh读回接入 Baseline._status，并作为 LinuxClientInitProvider.snapshot /真实restore producer的来源。不能只替换接口就开生产gate。
必须实际固定daemon/endpoint/映像/config来源图，实测PASSCRED/12B ucred/abstract/recvmsg返回flags与所有original close，然后才声明P011来源认证读回。
实际CLIENT/GO、地址、DHCP、恢复与手机收发未由本组件验证；没有调用/清除旧pending。

## HOST 专项记录

工具均Windows `exec_command`，PC Python3.12.0 `python.exe -B`；系统读取、open/close、socket、Proc均Fake。未运行实际Linux、WSL、P011、RF或手机。

| 工具/批次 | 实际方法/结果 | 原判与窄修 |
| --- | --- | --- |
| 96bac6，首次 discover | 35，13PASS/22ERROR，0.961s，exit1；HOST wall1.3724047s | 原ERROR保留。负例helper误名fail覆写unittest.TestCase.fail导致递归大输出；另HOST socket模块缺AF_UNIX常量，不是Linux设备错误。 |
| 84106f，原成功路径精确1 | 1ERROR，0.002s，exit1；wall0.3616662s | helper更名后仍io_error，原判保留。 |
| 705844，私有Fake诊断 | 非unittest；host0 | 仅Fake路径确认AttributeError/宿主可选socket.AF_UNIX缺席；没有真实socket。 |
| cf9db0，原22ERROR精确复跑 | 22，21PASS/1FAIL，0.024s，exit1；wall0.4187213s | 固定Linux UAPI数字，不依赖Windows可选常量。余1是AST tripwire误将docstring中的subprocess.当调用，原FAIL保留。 |
| 9c287d，余1＋unknown ancillary新1 | 2PASS，0.013s，exit0；wall0.4272537s | tripwire改为实际AST Call/command bytes检查，未知control保留资源不确定性。 |
| d0dff7，新source库存1＋直接受影响2 | 3PASS，0.010s，exit0；wall0.397656s | 大于128原票据分组CloseProof＋full/reduced成功路径，未扩大旧core预算。 |
| ba0d97，新无关proc数量1＋受影响3 | 4PASS，0.025s，exit0；wall0.4854306s | 与daemon稳定事实分开；source库存/缓存拒绝/最终runtime Python3.5 AST。 |
| ec8e08，reader库存/尾slash新5＋直接受影响6 | 11PASS，0.030s，exit0；wall0.519365s | default reader 调用前登记、异常/pending原owner保留、4/8预算；尾slash仅回归、原resolver不变。full/reduced/缓存与三项symlink/AST受影响方法，未重跑整批。 |

截至ec8e08历史快照，43个不同方法按上述分批各有通过证据，**不是一次43整批通过或项目套测**。首35中已通过13项未重复；其余复跑均有明确受影响来源。后续ROOT ARM增量及累计46另见顶部记录。
首次命令：`python.exe -B -m unittest discover -s tests -p test_client_wpa_status.py -v`。
后续仅显式命名 `test_client_wpa_status.ClientWpaStatusTests.<method>`，工具输出保留原方法及判定；ec8e08当时最后一次仅上述11方法。
没有写额外结果目录、打包或修改历史报告；ROOT可另归档这些源码/HOST证据。

## 主来源

协议字段参考已完整读取的项目 `CLIENT_WPA_STATUS_AUTH_NEXT.md` 与固定官方2.12发布包；原厂daemon实际版本不由此推定。
[官方控制接口](https://w1.fi/wpa_supplicant/devel/ctrl_iface_page.html) 支持独立STATUS command连接。
[Linux4.14 ucred/PASSCRED](https://github.com/torvalds/linux/blob/v4.14/include/net/scm.h#L102-L128) 与 [Unix发送凭据](https://github.com/torvalds/linux/blob/v4.14/net/unix/af_unix.c#L1484-L1504) 为逐报文核验依据。
[SCM fd安装](https://github.com/torvalds/linux/blob/v4.14/net/core/scm.c#L241-L310) 说明拒绝报文也须处理实际安装FD。
特权root可在Linux权限规则下提供其他凭据；本组件不抵御已被控制的root，不宣称端到端手机认证。
