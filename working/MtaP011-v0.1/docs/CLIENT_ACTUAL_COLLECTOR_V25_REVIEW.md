# v25 actual collector / authenticated STATUS 的最小 HOST 覆盖

本切片只新增 `tests/test_client_actual_collector_v25.py` 与本说明，target 源码 0 件改动。旧 v24 SOURCE 包、manifest、来源、测试方法及历史不改。新方法不是完整 INIT→DORA→恢复，不是 P011/小米 15 Ultra、RF、真实时间或 heap 验收；目标仍 active，Formal F 仍旧 24-source 图。

## 固定输入与真实算法

新 test SHA256 `d3285398a5a6eb6f0b48826dbcfce0281ad97be41a7a1723d7bb0060b346f657`，331 行 /19057 B。它逐源核 v24 manifest `dcfab972fed81b1a63bafe1a8cae6a2681d2c83d3e666bf10a827c2c7b36f70e` 的 29 个原 SHA/bytes，按固定顺序建立私有同域；Python3.5 AST 与 target 禁 assert 检查在该新方法内执行。未通过可变 runtime 兜底实际目标模块。

只复用已 pin 的 full-v24 fixture 定义（`95ab61699cdf0e5efcd2a057d7c3d6d6a36d3843ee2fd45a9c27d3fea217119e`）及 baseline fixture 的只读包编码/假 socket 定义（`f80965117e0b4c4f3471ab5c109fc5034b6342c58e62ffb10d65cbbcfc4b4f80`）；没有调用任何旧 TestCase 方法。纯构造 full fixture 后，其尚未调用的 SnapshotAssumption 工厂替换回实际默认 `_AuthenticatedCollector`；STATUS 工厂仍是同域实际 `AuthenticatedStatusReader`，有 exact type 断言。

三 stock 输入来自 PC 备份 `D:\project\P011\06_Firmware\backups\v2.4.0-20260923-162730\files`，读取 bytes 后真实 hashlib SHA 与 actual core.STOCK_PINS 比较，无 patch hashlib：

| 文件 | bytes | actual core 固定 SHA256 |
| --- | ---: | --- |
| Z03 | 4103844 | `cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a` |
| control_engine | 163184 | `364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d` |
| zyb_z03_launch.sh | 1913 | `7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b` |

这是该候选固定 stock 字节输入，不改写项目交接的另一原始 Z03 pin，不替换设备文件。CLI、原 endpoint daemon image、CONFIG、`/proc` 进程/namespace/FD、netlink 回包、STATUS text/credentials 都是明确 HOST 合成前提；CLI/daemon/config 用实际 SHA 写入此 fixture 的私有 manifest，未称它们是 P011 真实 pin。

## 这一个新方法实际覆盖什么

从纯构造开始实际 Store.acquire 原锁；实际 DirectChildOwner.register→launch→release→resolve 发出 exact controller ChildTicket。fork、exec 字节与进程存在是 FakeKernel 假设；release 的 PersistReceipt callback 明确为合成持久回执 seam，不是已写 ready Journal。没有 lease.start、CREATE/CONNECT、手工 Journal/Handle 或直接 ProcObservation/许可 Actor 注入。实际 parent、preexec、postexec Actor 都由同域 ProcReader 从合成 `/proc` 重新解析。

Proc FakeFs 的 open/read/fstat/close 与 baseline/STATUS 共用 io.handles 的一个 FD 发行空间；FakeKernel 原件使用不相交高号段，并进入同一 current fstat 门与碰撞检查。不通过不同低 FD 私有表把当前复用错当 EBADF。实际 `_ObservationIo` 不替换：原 provider `_private_pids()` 消费 owner 的 exact issued child/spec/hash/fresh actor，才能从 `/proc` 枚举排除私有 controller。原 endpoint daemon 同时存在，仍由 actual source 的 comm/image/argv/UID/GID/namespace/config/unix-inode/daemon-FD/credential 链认证。

实际 Provider.executor 与 default Provider.snapshot 完成 actual collector 的双 round、四 manifest 首读/末 rehash、两个 stock live image 重读/每次 fresh actor、netlink family/interface 与完整 IPv4 addresses/routes/rules、IPv6 files。两 round 各一次 actual STATUS，共两次 STATUS；每 STATUS 前/后各一次 actual LinuxStatusSource，两个原 observation 不是同 dict 且原认证 key 相等；每 source 两轮共八个 actual actor call，均同一个已绑定原 ProcReader，保留八个独立 history generation。每 STATUS 只发一次固定 STATUS/收一个认证回包，socket close-once；没有 CLI/Popen/select fallback。

断言包括：两 Snapshot key 一致、原 daemon 仍在 stock actor 结果、exact 私有 controller 不在结果；所有 source 原 CloseProof complete、collector 每原 ticket attempted/closed/known、所有已 bound ProcReader history_closed；最终实际 wait/reap/fresh absence、Owner.close_inventory 和 Store.close 清空 shared IO/FakeKernel FD，broker active_producers=0。这是组件资源关闭，不签 restoration 或 Formal F 自动纳 DORA。

## 实际三次执行历史（同一个新方法）

命令均为 `python -B -m unittest -v test_client_actual_collector_v25.ActualCollectorV25Tests.test_actual_two_round_collector_and_authenticated_status_with_issued_private_controller`，cwd 为本候选 `tests`。未执行旧方法或负向期限方法。

| 回执 | 实际 HOST 结果 | 首因 / 窄修 |
| --- | --- | --- |
| `fa1eb5` | 1 /0.374 s /exit 1 ERROR，tool wall 0.691460 s | fixture 构造把冻结 tuple status_manifest 按 dict 索引；尚未 acquire/collector。仅转 dict 读取。 |
| `446087` | 同方法 /0.366 s /exit 1 ERROR，tool wall 0.6724652 s | fixture 构造复用 codec snapshot 的非 ASCII actor 生成 comm 失败；尚未 acquire/collector。仅独立生成明确合成 proc 树，不导入 ready/Observation。 |
| `814554` | 同方法 /0.451 s /OK /HOST exit 0，tool wall 0.763190 s | 两处 fixture 修正后的唯一受影响复测，完整正向及上述关闭断言通过。该通过方法不再重复执行。 |

exec_command 回执是合并输出，未独立留 stdout/stderr 文件；不报告空 stderr、remote exit、P011 raw 或物理结果。首错误不删除、不称三个不同方法或整个项目回归。

## 确定尚未证明的门与下一步

本方法 clock 固定合成值，0.451 s 是 PC unittest 时间，不是 device fresh≤5 s、trial≤20 s 或 restore≤60 s 证明。独审发现 actual 复用 ProcReader 每 operation 的 `_begin` 仍按 now+constructor timeout 建新局部期；Baseline._proc / LinuxStatusSource._actor 只有 outer 前后检查，后轮 remaining 缩小时内部 IO 仍可能越过 outer deadline 后才拒。这不是成功续租；必须由另一个推进 clock 的新 repro 记录每 open/read 时间，保首 FAIL，由 ROOT 决定隔离绝对期接点窄修。本固定 v24 输入 test 不抢改该 target。

未执行 wrong-privatechild/credential/namespace 等新增负向，未验证设备进程真实性、实际 syscall/wall 上界或完整 retained heap。本子图实际算法正向填补 v24 SnapshotAssumption 的 collector/STATUS 缺口，但没有把它换入新 full lifecycle，未重接 F/Parent/watchdog 未 bound direct reader 或 DORA inventory。下一切片应先验证原单绝对期传播与到期后无新 IO，再新增受影响完整 lifecycle 方法；不靠扩大 TTL、跳过 fresh、伪 ready 或扩大 quota 求绿。本轮没有设备/网络/RF/真实 INIT、staging、服务/原厂/启动项变更、清理或重启。
