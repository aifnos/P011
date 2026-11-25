# 最新 State smoke 前置只读入口（拆分第一阶段）

本次只新增 `host/device_state_smoke_readonly.py`、其 HOST tests 与本文档。没有执行 ADB、设备、staging、freeze、页面、ZIP、全套或网络操作；旧 8 文件保持冻结。

## 明确不是最新 State / UI 运行验收

- 完整同对象 State/HTTP 历史 actor observer 与全 IPv4/规则/租约原厂基线的实现较大，依据 ROOT 授权先拆为只读前置观察；不复用 archived START，不构造 State，也不以旧 UI/TLS/TTY PASS 填新结果。
- 两个 CLI 模式互斥且必须显式指定：`--validate-host` 只检查载荷 Python 3.5 AST、短 argv 预算与 8 个 reviewed 源 SHA；`--check-readonly` 留给 ROOT 后续唯一审核后只读观察。本轮没有调用后一模式。
- 没有 staging/run API。公开 `staging_allowed=False`、`run_allowed=False` 恒定；`latest_state_run/ui_pages/saved_worker_closed/transport_closed=NOT_IMPLEMENTED`。即便全部已知阻塞消失，也不能自动进入下一阶段。

## 固定目标载荷与阻塞

- 一个固定压缩 inline argv，强制 `<3500` 字节；不允许 Adb.python 进入长源码 stdin fallback。源码上限 12288 字节、单行 2048。只 import os/stat/hashlib/time，不导入候选模块、json、State/helper，不创建 socket/线程/远端子进程。
- `/tmp/p011-mta-p2p-device.pending` 只 `lstat` 存在性；任何对象存在都阻塞，不读取 journal 内容、密码、私钥、owner 文件或用户文件。当前 V9 pending 未清，实际前置观察仍必须阻塞。
- STA 固定 `/mnt/data/p011-toolbox/sessions/mta-network`：逐层目录归属/非链接检查，精确 0700，最多 16 个名称。任意条目阻塞，无“忽略未知文件”或判断旧租约已恢复；父目录不安全即停止，不跟随读取目录。
- UI/native 锁、临时 menu 任意对象存在即阻塞。P2P lock 仅核查固定文件元数据；不尝试 flock，不宣称观察到未持锁或清理成功。
- `/proc` 两次有界最多 512 PID、4096 名称、每个 cmdline/stat 4096 字节，最多 32 次 ENOENT/ESRCH 瞬时竞态，其它读取失败使快照不完整。候选路径参数/exe、两个旧 readonly marker 的任意 argv 形态均计数；匹配进程须精确 cmdline/exe/PID/starttime/parent 重读一致。
- empty cmdline 不进入分类，至多 32 次瞬时消失被容忍；所以 blocker-clear 仅指“本轮已观察的 known blockers 为零”，不是全 actor 缺席，更不是实际 smoke 或 staging 授权。未来完整 runner 必须独立证明其全部 exact owner/历史 actor 闭合。
- 仅固定原厂文件全 SHA + FD/lstat 元数据读回、Z03/control_engine/weston 数量与 exe、tracked 网络进程身份、boot、sysfs 接口名/ifindex，以及三个 proc 网络文件私有 hash 双快照。project mta/p2p 接口存在阻塞。所有身份/路径/argv/IP/原始 hash 仅留目标内存，不进入公共结果。
- 此 proc 网络 hash **不是**完整 IPv4 地址/全 tables routes/rules、Wi-Fi COMPLETED、P2P association、durable receipt 或锁持有证明。`full_ipv4_baseline/prior_receipts=NOT_ASSESSED`；未识别 actor/所有资源缺席仍 `NOT_PROVEN`。

## 结果与失败边界

- `pass/check_complete` 只表示两次观察完整且一致；`observed_blockers_clear` 另外严格要求 pins/已知原厂/网络一致、pending/锁/已知 actor/接口/journal 数量为零。前置观察 PASS 可以同时 blocker-clear False。
- 缺字段、额外私有字段、bool 当 int、truthy bool、计数越界、计数与一致性矛盾均拒收。未知异常只输出固定 host_or_parse_error，不公开异常文本。
- readonly 目标检查在 deadline 门槛间检查时间；OS read/close 本身不可硬抢占，不能承诺 kernel syscall 的硬超时。外层固定等待 25 秒，超时保留私有 raw；不发 signal、kill、restore 或重试。
- HOST reviewed 8 pins 在任何 ADB/输出目录前核对；不复制/改权限/运行已有 candidate。公开仅 result.json/README.txt，本入口不打包、不输出截图。
- 实际 State smoke 下一 capsule 须另审完整 import closure、fresh candidate 全 FD/pin 门槛、固定最小页面 whitelist、同 exact State/Session/saved worker/finalizer/probe actor/HTTP request history/Qt child 持有及真实 closure readback；完整闭合前保留占用锁与 journal。
- 下一 capsule 的最小页面白名单仅：主页面、合成 16 B 文件选择页、选择摘要、键盘输入后取消、空接收列表（5 图）；全 800×268。GET 只 status/合成 files/received，POST 只 cancel 与显式合成 rename；禁止 discover/scan/receive/connect/recover/LAN/audio。这是待审方案，本入口没有页面载荷或执行按钮。
- 现有 ADB helper 是 `host/device_probe.py`，本轮只读 SHA 为 `e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348`。本入口 8-pin 检查并非完整部署 import closure；后续 actual 审核须将该 helper 与新 checker 一并固定，不仅看 State pins。

## 验证记录

- 唯一 focused HOST：`python -B -m unittest discover -s tests -p test_device_state_smoke_readonly.py -v`，20 run / 20 PASS / 0 skip / 0 failure / 0 error；没有之前失败后降断言。
- `--validate-host` 仅本机执行：当前 8 pins 一致，Python 3.5 AST 通过，源载荷 7010 B，固定压缩命令 3489 B（小于 3500），没有 ADB。
- HOST 目标环境全为 fake os/proc/FD/metadata；其 stock 数据和 digest 明确 SYNTHETIC。未创建真实设备 FD、socket、线程或远端子进程，测试不能升级为 P011 实际读回。
- 测试覆盖存在 pending/三类占用、STA 条目、unsafe parent 不跟随、project/旧 marker actor、接口/进程身份变化、stock inode/owner/link/hash/close 故障、不完整/超限快照、固定 schema 与私有字段拒收；无 staged candidate 或 ZIP。
- 最新 State/页面/生产 worker/传输/手机互传仍未测，当前 V9 残留与旧 FAIL 没有被清理或改写。
