# 原 WPA STATUS 命名空间认证：最小下一实施方案

状态：设计待审；本轮仅源码研究，未运行 OS/socket/CLI/ADB/RF，未改稳定 collector。回复来源认证不等于网络恢复、CLIENT 并发或 RF 准入。

## 已核实的协议与内核边界

本地官方 `native/private-p2p-candidate-20261001-v2/source/wpa_supplicant-2.12.tar.gz` SHA `08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6`；不是原厂 daemon 版本证明。[发布包](https://w1.fi/releases/wpa_supplicant-2.12.tar.gz)

- `src/common/wpa_ctrl.c:94..151,208..244,476..588`：UNIX DGRAM bind/connect/send/recv；`recv` 不提供 ancillary，不能原样用于认证。
- `wpa_supplicant/ctrl_iface_unix.c:129..236` 用同 socket `recvfrom`→处理→`sendto`；`ctrl_iface.c:13578..13580` 调 STATUS。独立命令连接不 ATTACH、不登记 monitor。[控制说明](https://w1.fi/wpa_supplicant/devel/ctrl_iface_page.html)
- Linux v4.14 `af_unix.c:1484..1504,1709,2037..2052`：接收端 PASSCRED 足以给普通 sendto 附发送任务 TGID/real UID/GID；无需修改 daemon。[发送凭据](https://github.com/torvalds/linux/blob/v4.14/net/unix/af_unix.c#L1484-L1504)、[接收凭据](https://github.com/torvalds/linux/blob/v4.14/include/net/scm.h#L102-L128)
- SOL_SOCKET=1、SO_PASSCRED=16；ucred=三个32-bit字段，目标 ABI 仍须核验。DGRAM peer 限实际 socket，不用 stream SO_PEERCRED 代替逐报文身份。[UAPI](https://github.com/torvalds/linux/blob/v4.14/include/uapi/asm-generic/socket.h#L7-L32)
- 特权 root 可按 CAP_SYS_ADMIN/SETUID/SETGID 指定凭据；本方案不抵御受控 root。[权限链](https://github.com/torvalds/linux/blob/v4.14/net/core/scm.c#L44-L60)

## 最短可编码组件与一次操作

建议新增 `runtime/mta_client_wpa_status.py`、Fake 专项/review；collector 接线另授权。纯 ctor，内部固定 manifest/daemon/endpoint producer；UI/HTTP 无命令/路径/Actor/布尔准入。`read_status(deadline)`仅发送 **`b'STATUS'` 一次**，无 Popen/ATTACH/PING/SCAN/重传/重连。

1. 单线程 F；创建前登记 socket/anchor/read ticket。原 daemon actual Actor（PID/start/exe/argv/全 tasks/boot）及实际 `/proc/<pid>/exe` 完整 SHA/inode/metadata 必须匹配固定 manifest；另读 real UID/GID、同 PID/user/net namespace。缺 pin/身份拒绝。
2. 只用已证明的固定 interface endpoint。官方 `/var/run/wpa_supplicant` 默认与旧 probe `/run/wpa_supplicant` 均非当前证据。canonical root-owner/非信任不可写/无 symlink 父链和 socket entry 类型/dev/ino/uid/gid/mode 前后一致；socket 本身可有已审 group 写权限，不当 regular file 打开。
3. 需要 FD归属时：`/proc/net/unix` pathname→kernel inode→exact daemon `fd/socket:[inode]` fresh 对照；**lstat pathname inode不等于sockfs inode**；仍需回复凭据。
4. 优先显式唯一 abstract local（项目前缀+私有 token）bind/getsockname 一次；上游 sockaddr/fromlen 可表达，原厂兼容性待实测。不建/unlink文件、不 autobind、不 fallback。立即留 exact socket ref、不可继承/PASSCRED=1 readback；connect固定server一次；共享≤3s单调预算非硬抢占；发送恰6B。
5. recvmsg 上限16KiB+1、bounded ancillary；新 socket只一 command（协议无事务ID）。每条恰一12B SCM_CREDENTIALS，pid/real uid/gid匹配实际 daemon；source固定；TRUNC/CTRUNC、未知/重复 ancillary、event/FAIL/坏STATUS均拒绝，不跳过。
6. SCM_RIGHTS可能安装FD：receive前creator登记、完整返回先留存、MSG_CMSG_CLOEXEC；实际返回每个 rights FD登记独立once-close，不漏掉“被拒包”的FD、不猜数字归属。最多253；未知/截断安装sticky pending，正常官方sendto无rights。[FD安装](https://github.com/torvalds/linux/blob/v4.14/net/core/scm.c#L241-L310)
7. 只产私有完整STATUS/digest/frequency/COMPLETED；末次 daemon Actor/映像/real uidgid/endpoint/anchors fresh一致才接受，非原子快照。所有已知original独立once-close，wrapper失效+原FD EBADF；unknown/foreign不重close，exact refs保留、禁二次read。abstract随实际关闭释放；不签原server恢复。

## ROOT 下一次只读收集需取得的事实

| 缺口 | 所需真实 observation；本轮不执行 |
| --- | --- |
| 目标可达 | 唯一P011、当前boot，不能用历史连接 |
| 原 endpoint | canonical目录/socket metadata、原配置或exact argv/FD关联；缺wlan0/endpoint拒绝 |
| 原 daemon | actual全Actor/image SHA/metadata/real uidgid/namespace；多supplicant不凭comm选 |
| 固定源 | reader+依赖source pins、actual原daemon pin；不能用私有e069或官方包SHA代替 |
| 目标 ABI | recvmsg/CMSG_SPACE/CMSG_CLOEXEC/PASSCRED readback/12B cred、abstract有限UNIX专项，尚未验证 |

已读 `logs/MtaP011-WpaCliFileOnly-20261001-172839-376481/result.json`：目标选择失败/未发设备命令/CLI SHA=null；旧caps的wlan0缺席不能当当前状态。先ROOT只读取得identity/endpoint，再HOST Fake组件，最后ROOT一次STATUS-only验收；不自动开网/修复/重启。

公开只fixed stage/reason/count/bool；身份/路径/STATUS/ancillary/raw私有。source_authenticated只表示本地回复来源，不签控制生命周期/恢复授权。Store/Provider及生产send/receive仍关闭。
