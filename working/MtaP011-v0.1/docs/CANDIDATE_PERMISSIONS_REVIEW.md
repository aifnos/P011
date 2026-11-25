# 固定 V5/V6 候选权限：证据与窄范围修正方案

本文件区分已经观察到的权限事实、HOST 实现与尚未执行的权限写入。它不修改旧日志、候选字节、manifest、harness 或只读检查器。

## 已有实机事实

- V6diag 唯一执行 `logs/MtaP011-DeviceP2pV6Diag-20261001-053019-ffaa543c/result.json` 在 prior 阶段停止，`rf_trial_invoked=false`；没有进入 GO 或 IPv4 创建。缺 before snapshot 导致比较标志 false，不能据此诊断原厂损坏。
- 独立只读诊断 `logs/MtaP011-PriorJournalReadOnly-20261001-054328-59c5c157/result.json` 把匿名记录 6/version3 的拒绝定位到 `prior_context/historical_manifest_permissions`。当时尚不能区分文件类型、属主或其他用户写权限。
- 主线程随后唯一只读检查 `logs/MtaP011-CandidatePermissionsReadOnly-20261001-055734-dd922b01/result.json` 确认两个候选共 16 文件的完整 SHA、尺寸、普通文件、非符号链接、属主匹配 euid 全部通过。两份 manifest 和各五份 runtime 为 `0666`（数字 438），各两份 native 为 `0700`（数字 448）。完整原厂、STA、进程、接口、boot、IPv4 地址/全部表路由/规则与 IPv6 基线不变；没有 RF/IP 或权限写入。

由此可确认该次 prior 拒绝的“其他用户可写”条件成立。不能把这一结果当成 carrier、驱动或 IPv4 创建问题的证据。Windows ADB push 是可能的来源，但本阶段没有证明具体成因。

## 唯一允许的修正范围

新入口 `host/device_candidate_permissions_normalize.py` 的导入及测试不构造 ADB。无参数运行被拒绝，唯一明确动作是 `--normalize-reviewed`；只能由主线程完整审查后执行。没有任意 candidate、路径、mode、shell 或函数参数。

固定别名：

| 别名 | candidate identity | 完整 manifest SHA-256 |
| --- | --- | --- |
| v5 | 0f2a45489fd3e03b | 0f2a45489fd3e03b0b56b9bb083cf2d978f005d8260e9148339616d7856591b8 |
| v6 | 916a02d44aeeaf0d | 916a02d44aeeaf0dcb24a3eaa57b7762fad5f503e3dabac83bed34df10780daf |

每个别名仅处理 `SOURCE.sha256`、固定五份 runtime 和固定两份 native，完整 pins/尺寸沿用已审只读检查器 `ca2ab521dd6acc12a5f9e0ff30914917c36b2992b31393d09178768f60d1c1fa`。该检查器又锁定 `3e8192…` 和 `97f00c…` 及原冻结候选。旧来源完全不修改。

- manifest/runtime 目标权限：`0400`；只接受原 `0666` 或已目标 `0400`。
- native 目标权限：`0500`；只接受原 `0700` 或已目标 `0500`。
- 拒绝特殊权限位、其他未知模式、foreign owner、符号链接/非普通文件、`nlink!=1`、重复 dev/inode、额外文件、尺寸/哈希不一致与不安全目录。
- 不修改 UID/GID，不调用路径 chmod/chown，不使用 glob/全局清理，不重写文件内容、manifest 或旧 journal，不停止任何服务。

## 写前与写后责任链

1. 分别读取完整原厂及双栈网络 before 基线。不是简单复用旧 PASS 或主 IPv4 route 摘要。
2. 以固定 canonical/private/no-symlink 目录为边界，打开全部 16 个 `O_RDONLY|O_NOFOLLOW` 描述符。校验 euid owner、普通文件、nlink=1、允许模式、尺寸、完整 SHA；比较 `lstat/fstat` 的 dev/inode/mode/uid/gid/nlink/size/mtime_ns/ctime_ns，并验证精确文件集合。
3. 全部描述符成功验证之前，绝不调用 fchmod。持有的描述符分别对应精确已验证文件，不能换成路径 chmod。
4. 每项写前再核验完整 descriptor/path 身份。已目标模式直接进入读回，不重复写。其他允许旧模式仅调用一次 `fchmod(fd, 固定目标)`。
5. 写后核验精确目标模式、同 dev/inode/nlink/uid/gid/size/mtime/type；ctime/mode 允许因这一次权限写入变化。重新读取完整字节 SHA，并验证最终 `fstat/lstat` 身份一致。
6. 每个已打开 FD 都有独立关闭尝试；一个关闭失败不能跳过其余 FD。源程序正常处理预算为 25 秒，主机单程序等待 50 秒。失败后的有限描述符观察与关闭不因预算耗尽而跳过。
7. 独立读取 after 全基线。任何原厂、STA、进程、接口、boot、完整 IPv4 或 IPv6 变化，都不能把权限修正判为成功。

这些连续读取不是对并发不可信修改的原子事务；每次元数据/字节变化都保守失败。主线程应继续串行执行，不在候选正在运行或其他写入者活动时进行修正。

## 失败、部分完成与公开范围

没有自动回退或自动重试。第一失败阶段/固定别名/固定相对文件、固定原因/异常类别/errno 不会被后续关闭错误覆盖。每项保留 old/new `0777` 数字模式、写入尝试、已观察变更、身份/哈希及读回布尔；汇总保留已验证、尝试、部分变更、读回、FD 开启/关闭/失败计数。

fchmod 抛错也会尝试观察 descriptor 当前模式，不能直接声称“没有修改”。若观察不可用，`mode_observed=false`、`change_count_complete=false`，部分变更计数不能当成精确总数。主机/传输失败而未取得远端完整结果时，也不能声称权限未变；保留 private raw/exit，停止等待主线程审查。

public ZIP 只含 `result.json/README.txt`，不含原始 stdout/stderr、host/remote exit 文件、候选、journal、UID/GID/inode、绝对设备路径或私有标识。权限写请求和实际程序调用有明确字段，绝不冒充只读。PASS 仅表示权限全部读回且完整原基线未变，不等于 prior admission、GO、IP、DHCP、手机或完整互传 PASS；后续试验仍需单独审查。

## 本轮 HOST 边界

专项命令：在 `working/MtaP011-v0.1` 运行 `python -m unittest tests.test_device_candidate_permissions_normalize -v`。12 项 HOST 测试通过，覆盖首次全验证后写入、幂等不写、中途 fchmod 失败及“已应用后抛错”、未知失败后模式、身份变化、foreign/link/nlink/哈希/短读/额外文件/未知模式/特殊权限位、预算耗尽与所有 FD 关闭、关闭错误继续其余项、原基线变化和唯一固定入口。

本作者未调用 ADB、未改设备或主机原候选权限、未执行完整项目回归，未生成实际结果或实际 ZIP。测试使用内存模拟 fchmod 与临时主机目录；真实权限修正由主线程完成审查后单次执行并另存日志。

## 主线程实际执行（后续独立记录）

root完整阅读工具8155e2eb…、12项tests及本文并复核精确SHA后，单次执行`--normalize-reviewed`。记录为 `logs/MtaP011-CandidatePermissionsNormalize-20261001-060853-204a0e0a`：三次host/remote exit均0；16预验证、16fchmod、16目标权限/身份/全SHA读回、16FD关闭，0关闭失败。manifest/runtime0400、native0500；完整原厂、STA、全IPv4地址/所有表路由/规则、IPv6、进程/接口/boot均相同。此轮确实修改项目文件权限，不改内容或属主、历史journal，无RF/IP/recover/retry。

normalization_complete PASS只表示这一步完成；下一轮仍须独立复核prior admission和原网络基线，再取得实际IP创建诊断。原055734事实和053019准入FAIL保留，不覆盖为成功；旧harness/checker/frozen字节保持不变。

061551后续新独立入口已实际复核固定16文件、旧pins、prior准入及完整pre-RF等值，通过后唯一启动TTL20。14项原生事件均0，但ip_create/interface_l3拒绝、六bool全true含carrier；无成功安装收据。原厂、STA、全IPv4/IPv6与资源恢复独立通过。这是独立设备FAIL，不改变权限规范PASS，也不把权限修正等同于IP/手机完成；下一步只补IPv6地址/路由子诊断。
