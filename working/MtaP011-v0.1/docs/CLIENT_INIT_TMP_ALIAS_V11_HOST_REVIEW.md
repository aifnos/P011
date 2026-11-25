# CLIENT tmp-alias v11 HOST 来源与边界

本候选是 SOURCE/HOST 层，不是已验收互传版本。旧 v10 host `cb50e2a92b669b64061f9872bcbb27265d3b3818517cc95cfabeaef3f8e714df` 完整保留；其实际首失败和补采路径 raw 不覆盖。

## 唯一新入口与来源图

`host/client_init_tmp_alias_v11_p011.py` 读取并核 whole SHA 的冻结 v10 HOST 基础代码，只显式替换 candidate kind/log tag 并去掉旧 main footer后 module-exec。`__file__` 保持新入口，source_check/execute 的 driver SHA 指向新入口，不指向旧基础文件。

新图 20 项：common `mta_client_tmp_alias` 紧随 `mta_ip`，其余 19 名称与顺序不变。五项新 SOURCE 为 common/Coordination/Files/F/Provider；Pending、phase v10、Store v8、core v7、baseline v6、Owner nlink2 等仍使用已冻结旧 pins。共 11 个 candidate 映射及 9 个原 runtime。

五项 pins 全齐之前 source_check 返回 unavailable，execute 无法准入；全齐之后仍默认仅 source-only。需要 ROOT 独立审源码并明确 `--execute-reviewed` 和匹配入口 SHA 才进入唯一实际调用；无自动试验、重试或超时 kill。

## staging 原资源接线

TARGET 保存 StageOwner，root 原 FD 先登记、打开并认证；common 先持原 `/var`、`/var/volatile` 两额外 prefix tickets，再由 caller 打开目标 tmp 原 FD 并 bind/authenticate exact owner/root。只接受固定 `/tmp -> /var/tmp -> /var/volatile/tmp` profile，非泛化 namei，不修改系统 link、权限或挂载。

root/tmp/prefix/private 目录全部持原 FD。目录 identity 比较 dev/ino/mode/uid/gid，要求 nlink>=1，但不把创建子目录引起的合法 nlink/size/time 变化误判为替换。private root/run/runtime/native/ctrl 必须 root:root 0700。

mkdir、open、文件发布均 relative exact parent FD。目录 open 为 DIRECTORY|NOFOLLOW|CLOEXEC；文件 open 为 EXCL|NOFOLLOW|CLOEXEC、初始 0600，逐 chunk 写入后 fstat 验 identity，完整原 FD 字节读回、fsync，再将本候选自建文件设为源/manifest 0400、native 0500。nlink1 和 full file metadata 不豁免。目录也用原 FD fsync、entry readback及 exact layout；既有非空 ROOT 保守拒绝，绝不自动删除。

每次实际 open 前已登记 ticket；未知和部分返回留存。文件、全部目录与两个额外 prefix 原 FD 都关闭一次，fstat + EBADF 验证；失败不重试。完整 stage_inventory/stage_mutations 在 private raw，公开 ZIP 仍只有 result.json/README.txt，不含 raw/身份/ELF。

Staging 成功或异常均走同一次 StageOwner.close；关闭未知则不得到 DeploymentLoader/RF。完成后仍执行原 DeploymentLoader 来源重读/哈希/authenticate、candidate 重读、fresh baseline/pending/关闭证明与 RF 余量准入。native 计划值使用验证 profile 的物理 WPA 路径；executor/cfg/ctrl 仍为逻辑路径，F/Provider 对应候选负责同 entry 来源证明。

Staged 文件保留在独占目录；FD 关闭不是删除目录、恢复其权限或全网恢复。旧 SOURCE/actual 首错误不因新候选而失效。

ROOT 唯一只读能力补采 `47e845`（作者不重采）已由 `32cedc` 独立核已有 raw：严格三帧、host0/remote0/空stderr、Python3.5.5；dir_fd open/stat/readlink/mkdir、fd listdir/stat、follow_stat 全为 exact True，NOFOLLOW/DIRECTORY/CLOEXEC 为 32768/16384/524288。stdout 297B，SHA `2170b032cec38ec9507c0163633e12452e5029f6aa328cf1e04525107ba8bfdf`。这是支持表观察，不是 StageOwner 实际调用成功或性能验证；无需新增 fallback。

## 未改的预算与成功层次

入口 195、外 transport 225、就绪窗口 52、RF 前余量 155、Parent.finish 90、INIT trial TTL 20 秒全部保持 v10；同 F 恢复 60 秒由新 Provider/F 沿用。同步 OS 调用仍非硬抢占，余量不足不 start。

Parent 实际 done 仍要求曾观察 client_init_ready；因此理论 TARGET 的 init_not_ready 分支不能声称 actual 可达。未 ready 时保守 pending，未放宽 Parent 或公开 PASS。没有 CLIENT connect、DHCP/IP、手机或文件验收，send_available/receive_available/phone_tested 仍 false。

## 新专项及停止条件

只运行本新增模块的新方法一次；只有真实首 FAIL/ERROR 涉及的方法允许精准修复重跑，不重跑旧 suite。新 TARGET 使用实际 common 类与内存 Fake OS 原 FD 树；其 baseline/Parent 等是 HOST 假夹具，不是实际恢复或 RF 证据。唯一新 20 图 PC source_check/纯 module loader 验证不构造默认 OS/网络对象。

首批工具 `f09883`，唯一新增模块 8 方法：`Ran 8 tests in 0.688s / OK`，exit 0，无首 FAIL/ERROR。这批实际 20 图用的是作者当时宣布停写的 Provider `308a0901cc5c385db41f7a9e52fb51ad22cb69721f0da17ac6a7803c152be949`；只有 actual PC 来源/纯 loader 方法检查真实图，其余 TARGET 运行是 HOST Fake，不是设备操作。

ROOT 暂停通知在这批完成之后到达，独立审指出该 Provider `_alias_fd` 的 nlink 比较需要窄修。本批保留；旧图的 8 PASS 不用于签新图或宣称实际操作可用。

Provider 最终 `4f4cec03ddec5ec8e91f9f04ccdc91beb7e54a725a1481ba73c7045338883df6` 经 ROOT 全文限定审查授权后，HOST 唯一后续源码差异是该 pin 替换。工具 `bce6fd` 只补测精准受影响的 `test_frozen_twenty_graph_actual_pc_loader_is_coherent_without_default_io`：`Ran 1 test in 0.394s / OK`，exit 0，另 7 方法不重复。两批是首 8 旧图 + 补 1 新图，不合并声称 9 方法一整批，也不是实际 INIT/restore 通过。

作者三文件至此停写，最终 whole SHA 交 ROOT 与 Protocol 独立审，不由作者自签验收。不执行设备、旧 START、旧目录 cleanup、实际 RF 或打包。
