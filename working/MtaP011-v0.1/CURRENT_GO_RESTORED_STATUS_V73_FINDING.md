# 恢复状态显示：v73 最窄修正与主机证据

2026-10-03。v73 是独立、未部署的状态显示候选，不改变恢复动作，不授予收发权限，也未替换进 v72 固定来源图。

## 缺陷与修正

v72 在 `finish_restore()` 返回后还检查原 canonical 及 Store／Native closed facts。末门失败会留下 `restore_failure` 和 `phase=restore_pending`，Store 的 logical 标记却可能已为 True；旧 `status()['restored']` 直接使用该标记，可能误报恢复。默认 `run()` 成功门已经严格拒绝此情况，问题只在公开状态投影。

新投影要求：已尝试恢复、阶段为 restored、无 restore_failure、Store logical 标记是 exact True。它不检查活动业务 failure，因为业务失败后仍可能正确恢复。不增加 IO、重新读取库存、恢复重试、期限续期或 readiness。整模块 AST 逆换 status 和文档版本后等于 v72，其他定义不改；原 v72、HOST72 结果和来源映射保持原件。

| 冻结件 | 字节数 | SHA-256 |
| --- | ---: | --- |
| candidate/go-restored-status-v73/runtime/mta_go_bootstrap.py | 22837 | f52141612f6f25e0c049ed74dd3177d6ab250dba370ffe291709869a475be318 |
| host/go_restored_status_v73_check.py | 9629 | 6d79a30e89a28f420f2a4cf70d3d5b4a2eb8c99d50af21e20ae27543f411b84d |
| HOST_MTA_GO_RESTORED_STATUS_V73_CHECK.cmd | 181 | e1a18922d0eda605828434a2bb782b5154c85422cd965569b1ef7c912cccac1f |

CMD 仅 SOURCE 核对，未点击；ROOT 直接运行固定 checker。

## 实际检查范围

ROOT `3895ed` 唯一首测 HOST 0，9 个新增受影响向量全部通过；不是 child/unittest 生命周期测试。只提取并执行候选实际 status 函数，输入是明确惰性的字段模型，不执行模块构造、Bootstrap 生命周期或完整依赖图，旧 HOST72 方法 0。每个向量要求平台 IO tripwire 为 0，所有可用性和 device／phone 字段保持 False。

覆盖无恢复、仅 logical 标记、pending 末门失败、pending stale logical、restored 但有恢复错误、logical False、logical 非布尔 1，以及业务失败但恢复完成／正常恢复完成。前七项 restored=False，后两项 True；模型中的 True 仍不等于物理恢复证明。

[实际 result.json](results/go-restored-status-v73-host-20261003-023730-dba68418/result.json)；[四成员脱敏 ZIP](results/go-restored-status-v73-host-20261003-023730-dba68418/public-result.zip)：1600 B，SHA `adde45119f747abb9d7879c6ddfc6b33057b0042004bde481bcd55edce020ff8`。

ROOT `3b16ac` 与独立 final_cap_review 只读审计均核对 4 件快照／当前字节／SHA／大小、9 项向量、exact model.raw 以及 ZIP 四成员逐字／大小／CRC／完整读回。model.raw 97 B，SHA `13a02eaa36c32996a9930a91fc7f7be5157f3e4d3bb13a6d8914281d2f3feea9`；记录的 PC 检查耗时约 0.031 秒，不是启动、恢复或设备性能。未重放方法或 checker。

checker 的错误留存限制：最后核来源是否未变时若源文件恰好消失，会异常退出、没有结果 ZIP；不会误报通过。这一限制尚未另改或测试。

## 下一步与边界

需把此最窄来源修正纳入后续正式固定图，不能说已在笔上生效。[v72 编排结果](CURRENT_GO_TYPED_LIVE_V72_FINDING.md) 只签主机模型；准备／服务成本、真实 Sender provider、接收准入和正式 UI／文件中心接线仍待。当前无设备操作或部署，旧 GO64 FAIL／pending 和完整恢复未证保持。目标 active，尚非仅剩手机人工验收。
