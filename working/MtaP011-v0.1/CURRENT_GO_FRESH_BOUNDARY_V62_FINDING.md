# GO 中间步骤新快照 v62

## 后继64实际：新单轮已通过reserve，channel仍局部超时

后继64唯一实机 `c90e47` 整体FAIL：初始双轮及reserve/watchdog已走过，observe_channel原10秒内的新单轮在stock STATUS读文件超时；RESTORE另遇Proc pid_identity_changed原采样拒绝并留下pending。没有CREATE/GROUP_ADD，after只读因pending_exists不采集完整轮。不能把HOST否定补测或reserve走过当GO/完整恢复通过。ROOT `9df444`原件审计通过不改变该判定；详情见 [64实际与恢复边界](CURRENT_GO_ACTIVE_BUDGET_V64_FINDING.md)。62设备入口仍未运行。

## 最新：63-r2 两个受影响模型否定域通过

ROOT `2aeefe` 唯一执行新63-r2方法：HOST0 / 无超时 / 0.906秒；仅 interface_extra、close_unknown 两域，两次实际模型 Bootstrap.run。严格 marker `2/2/2/1/1/0` 与 Ran1/OK相符；不重放原十域或正常路径，不把原63整体FAIL改成十二域PASS。结果 `results/go-fresh-boundary-v63-r2-host-model-20261002-213131-c40f5696`。

ROOT `f5d9f5` 和独立原件审计通过：28私有输入副本逐字匹配，stdout141 / stderr100 B及报告hash一致，四成员ZIP6680 B，SHA `df2f47f9e5a774e4072ecbfdfd5cf56fe756232665572d26210b1b899f4b5abd`，成员原字节/长度/CRC一致。ROOT两个临时审计夹具分别漏了checker初始输入、用错私有副本嵌套路径，已按原checker修正；没有重跑模型方法或修改原失败记录。设备、物理RF、完整Native恢复、手机和收发可用性仍未通过。v64唯一实机试验正在运行，尚无终态。

## 最新：HOST63 首次整体 FAIL，两处夹具问题；v62 未实机运行

ROOT `149c48` 唯一新 HOST63 方法执行，HOST1 / 无超时 / 7.563 秒，结果 `results/go-fresh-boundary-v63-host-model-20261002-212107-e8bb57ca`。12域中的10域走完后验；interface_extra 在目标 interface_current 之前的 channel_current 已注入额外接口，因原 caps topology 拒绝，未测到目标；close_unknown 已核原EIO/一次物理模型关闭/closedFalse/pending/no retry，随后强求 best-effort 日志非空而失败。原方法整体仍 FAIL，计数 marker未输出，不能与后续重测拼称整批PASS。

ROOT `b3fa61` 与独立实际原件审计通过：28私有输入与冻结源、raw及ZIP一致。stdout0；stderr3017 B SHA `af8d3d4062355256ca56f8afbefec6b2b2924da5fd8e83c80b22e9b70d07c211`；两成员失败ZIP6783 B SHA `dd23aea2018e594fe2a8479dd0a4481210382610ddddcaaff583e01f1262521f`。10域仅有限已完成模型证据，不重跑；新63-r2只补两个受影响域，制作中未执行。原63源码与结果不改。

v62 未进行设备试验。后续 [v64](CURRENT_GO_ACTIVE_BUDGET_V64_FINDING.md) 保留同一 Native62 与固定图，仅将父原一次 active准备预算75及remaining165分配；SOURCE与纯prefix通过不签性能。实际GO、恢复、IP/DHCP及手机互通仍未通过。

## 制作阶段：SOURCE 通过，HOST 当时未运行

基于 GO60 唯一实机原件：首次两轮完整基线约 4.284363 / 5.067999 秒；随后 Store.reserve 的原 10 秒范围重新采集双轮时到达 deadline。GO60 整轮 FAIL、resource_pending=true 和完整 Native 恢复未验证保持。ROOT 与独立离线原件审计通过只确认原件，不替代成功互传。

v62 唯一业务变更：baseline_current、interface_current、origin_current、_group_status 四处 active 消费时各自重新采集一次完整 Snapshot，与原基线或 outside-key 比较。不是快照缓存，也不重新签发 baseline/grant。helper 只有 exact `_scope_cleanup is False` 才走单轮；cleanup 或其他形状走原双轮。快照先保留，再进行原截止/取消检查。

初次 observe_baseline、delete_interface 前后、observe_restore、restore_current 的原双轮不变。wait_group 的两次真实 GROUP STATUS 及频率、BSSID、内核 Origin 核验不变；ProcReader 自身双 pass、镜像/元数据、原身份、FD、WPA、IPv4/IPv6、ACK/ECHO、durable intent 和 once restore 不变。原 baseline15 / reserve10 / active45 / cleanup60 等时限不增加。

这是明确的语义取舍，不是等效改写：中间消费原来以 B、C 两个新快照相等并核对 A；现在只以一个新 B 核对 A。若改变发生在 B 之后、原 C 之前，旧实现可能本次拒绝，新实现只能由后续实际读回发现。两种方式都不是原子快照，不能防止最后一次读取之后的全部竞态。

源码正常路径计数从 32 个完整 Snapshot 减为 21 个，其中初次 2、中间 11、恢复 8。此为源码路径计数，不是笔端耗时、45 秒完成或硬件可用证明。新 HOST63 专项及 v62 唯一实机试验均尚未执行；已有 HOST59/61 和旧实机不重跑。

生产 send/receive、GO ready、IP/DHCP、State、文件中心和小米 15 Ultra 原厂双向互通仍未验收，目标 active，尚非仅剩人工。

## 新件与电脑来源证据

ROOT `354264` 首次 PC 检查通过：四新件尺寸/hash、52 实际目标源 Python3.5 AST、17 map 仅 Native 一项差异、Native 去除 exact helper/doc/four-callsite 后整体 AST 与 GO60 相同。4415968 B 零 token 完整 payload，SHA `297022ca866d4c06df8095e785859c91e2ca14d26d18a5abfde54afcfc6161b8`；52 源及三 blob base64 往返逐字一致，target body 保持。不导入目标模块、不调用 ADB、不写文件。PC SOURCE 一键已制作但未点击，不为补日志重跑。

- Native：99675 B / `c6d503ec282786db3839751f2109ded12366e4505c77ab720e5db858528861cf`。
- map：3955 B / `b959ae92e6ef048b3724e716e09503a7607f0b07e6eef5f4e14be71bd545e842`。
- preparer：50876 B / `6bac66b1a8e3d7523e51e8ba419016ccabe578980f13d4f0b8a9e8699b8a4d5e`。
- HOST：34871 B / `2d180e959c43e70c1e9441e59b88233f4d38dd1045a99d449c4a742543907d7c`。

未改变 F60 / Store56 / Bootstrap58 / readonly51 或旧候选。Native 及三机械绑定件的独立 SOURCE 审查均已封口，无确定阻断；完整窄 diff、52 实盘来源及 marker 切片同宽匹配。HOST63 尚未执行，不签实际快照计数、恢复或性能。
