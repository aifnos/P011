# 正式 GO bootstrap v42-r2 首次设备试验：FAIL

2026-10-02 唯一实机入口 `host/go_bootstrap_device_v42_r2_p011.py`，HOST ADB exit0、remote exit1、无超时，37.188 秒。正式子入口真实启动并以 exit1 退出，两轮 absence 与父端 EOF 已观察；子入口 stdout／stderr／exec-error 均 0B，未提供内部失败原因。

新 EXCL run 的 20 固定文件已准备，旧 GO 根 1 条目保持。未生成 `go-journal.json`，没有观察到 RF 创建意图，`journal_reconciled_verified=false`、`resource_pending=true`，整轮 FAIL。不将“已请求 RF 试验”当实际 RF 已发生，也不把资源待核实字段当已证明物理 FD 泄漏。前后独立原厂／网络基线一致、global pending 缺席；这不是完整原生恢复证明。

ROOT 离线审计（`faad56`）核对当前与私有复制的 35＋17 源映射、完整生成 payload 中 52 源及三个 blob 字节、reviewed driver／runtime／leaf、实际 stdout 的完整 echo 前缀及私有 JSON、原 HOST／remote 回执。父端已观察 FD、writer 库存与 Proc reader 均闭合；未导出子入口 Native 库存，不能扩展到所有子资源。没有重测设备、修改原日志或自动修复无线。

来源 SHA-256：

- HOST driver：`f255e7192f92f8e40fccee0ad9800e9874c77a4ae60bff66097d51ec49417fff`
- runtime preparer：`d38e282fc30dfad0c6498478f491db32d4111ec27015c20a3eee3477c26a8ce6`
- GO17 映射：`491b08d4754fcbf5d3dc203c48cf73a5d274bf5fc4da7d46fbb41a3af55ea296`

[脱敏失败 ZIP](results/go-bootstrap-device-v42-r2-20261002-145313-0cc03cee/public-result.zip)，1587B、两成员，CRC 与外部字节一致，SHA-256 `b3fc1d15f06c1ed3ec036e79556b8fc00c452cc4fa92903b6bf9f9731370993d`。私有 raw 仅在同目录 `private-raw`，含设备标识，不纳入公开包。

旧 v42 未执行；r2 仅修独立 journal 检查中的瞬时线程状态比较，仍保留 live／PID／start-time 等完整身份门。r2 失败原判保持。下一制作独立 v44：仅给原 F.main 异常增加限长私有 stderr，保留 Native／Store／Loader／期限／恢复逻辑；不是盲重试或可用互传发布。typed GO-IP／DHCP v43 同时仍为 SOURCE 草案。IP／DHCP／收发／手机／生产准入均 false，目标 active，验收手机小米15 Ultra。
