# 有界 UDP 环回平台检查

仅新增 `host/device_udp_loopback.py`、`tests/test_device_udp_loopback.py` 与本文；不修改任何既有 helper、候选、gate 或历史结果。本轮只实现和运行 HOST fake 专项，不执行 ADB、实际 socket、实机、冻结或全套。

## 固定入口及源码

默认/`--source-check-only` 只读取指定主机文件、验证依赖 SHA、生成 Python 3.5 AST，不初始化 Adb/socket、不生成正式冻结。实际唯一入口为 `--execute-reviewed --expected-checker-sha256 <审阅后的完整SHA>`；固定当前 checker 哈希必须匹配，先验证所有源码/依赖再导入及实例化已审 `Adb`，由其识别唯一 P011 并显式 `-t`。CLI 不接受接口、地址、端口、TTL 或任意命令。

依赖 pin：`mta_safety.py` = `03f77794db1fa8bebf44f56a479d5feaa6aef0e0f490ad4e577ad5bb6b190a81`；`device_probe.py` = `e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348`。设备端直接内联 safety，不从任何可变候选目录导入代码。源检查报告记录 checker/依赖/两份生成源码 SHA。

## UDP 主体

只使用 `lo`、IPv4 loopback 和 bind(端口0)得到的不同临时端口，拒绝小于1024/非整数端口；从不使用 UDP67/68。最多两个 AF_INET/SOCK_DGRAM socket、两轮共四条固定合成数据报，每包≤64 bytes；不是接入网络或 DHCP 试验。

实际检查 socket `IP_PKTINFO=8` setsockopt + getsockopt=1、`SO_BINDTODEVICE` 的固定 lo 设置/读回、`/sys/class/net/lo/ifindex` 正整数及前后相同。native `I4s4s` 必须12 bytes；sendmsg 明确选择该实际 ifindex 和 loopback 本地源。recvmsg 核对实际 ifindex、spec_dst、dst、对方实际源端口/源地址、完整合成 payload、单一12-byte pktinfo ancillary；拒绝任何 flags、TRUNC/CMSG_TRUNC、未知/额外 ancillary 或截断。

UDP 设置/交换共享3秒 monotonic budget；每次阻塞操作的 timeout 取剩余预算，无无限重试/过滤噪声循环/额外事务。HOST 设备阶段共享20秒准入/等待 budget，包含已审 Adb 最多15秒目标选取和 before/UDP/after调用；不足保留 UDP+after 时间则不启动主体。它不是硬抢占 OS IO 的绝对20秒保证，固定文件/hash/sysfs读取只能受外层 Adb timeout 约束，异常清理另有有界等待。预算/传输异常不自动重试、恢复或改变网络。若 ADB 超时且无法取得最终结果，不能宣称所有 socket 已关闭。

创建后立即记录资源，即使初始 fileno 读取失败也尝试清理。FD0 是合法值；初始 FD 必须非负且不同，关闭后必须严格为-1。finally 对每个 socket 独立尝试 close 和 readback，某一失败不跳过其余；未取得初始 FD、未关闭或关闭读回失败均不 PASS。

常量/布局依据 Linux v4.14 原厂上游 [in.h](https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/in.h) 的 IP_PKTINFO 与 in_pktinfo，以及 [asm-generic/socket.h](https://github.com/torvalds/linux/blob/v4.14/include/uapi/asm-generic/socket.h) 的 SO_BINDTODEVICE。正 ifindex 的 native uint32 编码与该平台 int32 同位宽；本工具不接受负 ifindex。源码/API 存在不等于内核已接受；只有 ROOT 实际执行的对应结果才能补该层证据。

## 独立基线与公开边界

before/after 为独立只读取样：固定三原厂文件 hash、Z03/control_engine/weston PID/start/exe/parent、网络进程 identity/参数指纹、所有 sysfs interface 标识、原 wlan0 的完整 wpa status 指纹、boot 指纹、`/proc/net/route` IPv4主表和完整 IPv6地址/路由指纹。取样失败不能用 partial 内容放行，前后全对象必须严格相等。每次 WPA status 查询只对自己持有的 Popen 句柄清理；任何异常均尝试终止未退出的 own child、最多0.5秒 wait 并检查 poll 的实际整数退出状态，独立关闭两根 pipe；未知退出/清理失败使基线失败，不使用无界 communicate 或全局终止。

该基线没有 rtnetlink IPv4全表/address/policy dump；公开 `ipv4_all_tables_verified=false`，不能称“所有IPv4表恢复”。接口/进程/STA等比较亦只是当次取样，不证明驱动内部缓冲池、P2P接口绑定或未来运行能力。

远端结果仅固定布尔/计数/stage/class/errno，未知异常不公开自由文本；errno只1..4095整数，未记录为0。优先使用固定 zlib/base64 命令，只有完整命令长度≤3500才无 stdin 传输；超长则保留 stdin。派生解析仅允许剥离**与本次实际传入完整源码逐字匹配**的 PTY echo 前缀（只归一化 CRCRLF/CRLF）；没有 echo 也合法，截断/修改/未知前缀/重复 echo 不合法。其后仍只接受 RESULT、MTA_REMOTE_OK、MTA_REMOTE_EXIT=0 三行固定顺序与空行，额外文本/非法或重复标记失败。地址、名字、端口、FD及报文只在私有运行上下文，原 ADB stdout/stderr、host exit和remote exit分别原样留在 `private-raw`，不在 raw 中删除回显。ZIP只收入 `result.json` + `README.txt`。独立基线差异或未解析成功只报告不相等/未知，不诊断损坏。

首个旧 checker `1055e928…2917` 的 ROOT 实机记录 `logs/MtaP011-UdpLoopback-20261001-072329-0cfa2813` 保留 FAIL：UDP未调用，两个 baseline 的远端实际 exit0，但严格 parser 拒绝正常 PTY stdin echo。此为传输/派生解析证据，不证明原厂改变；本修订未重写该日志。PC按实际完整包装测得 baseline/UDP 源码输入7715/11299 bytes、完整压缩命令3982/5366字符，均超过3500；当前两份实际源码仍需精确 echo 分支，不能声称已通过改成压缩避免实机回显。短源码压缩路径与长源码完整 echo 路径仅由 HOST fake 验证；新实际入口验证仍由 ROOT 独立执行。

环回成功也不等于 DHCP、真实 UDP ingress/L2 server归属、P2P关联/接口 IP lease、ARP冲突或手机端点/互传验收；这些公开保持 NOT_TESTED。本轮 HOST fake 包含 socket/API/时间/FD/错误及 Adb 合约，不冒充 Linux/P011 实际数据报证据。

专项入口：在项目目录运行 `python -m unittest discover -s tests -p test_device_udp_loopback.py -v`。最终实际次数/工具退出/SHA由完成回报记录；无预填实机 PASS。
