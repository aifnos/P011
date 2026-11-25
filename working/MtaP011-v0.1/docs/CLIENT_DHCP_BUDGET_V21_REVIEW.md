# v21 CLIENT DHCP 分离预算候选（仅 HOST）

原 `runtime/mta_dhcp_client.py` 整字节 SHA 为 `d8b44be21cd60e6d897943b4e13c0b9267ab216def429ad6a16b7ba6b50d1814`。全文读原 adapter、`tests/test_dhcp_client.py` 与 `CLIENT_DORA_NEXT_20261002.md` 后，将 adapter 隔离复制到 `candidate/client-dhcp-v21/runtime/mta_dhcp_client.py`。原源码、核心、旧测试与历史日志保持。

## 精确范围

仅改变 `DhcpSocketClient.__init__ / _guard / confirm_runner_closed` 三个方法。原 constructor 新增 trusted internal 参数 `proof_seconds` 和 `lock_seconds`；默认均为原 `PROOF_SECONDS=.2`。两值只接受 exact int/float 和 finite 范围，proof 为 `.2..10`，lock 为 `.001...2`；非法值沿用固定 `invalid_time`，没有 UI 配置、泛化 factory 或新公开 schema。UDP `POLL_SECONDS=.2` 不变且没有新增 poll 参数。

`_guard` 在 owner acquire 前后调用原 `_basic`，锁等待取 `min(lock_seconds, context.deadline - lock_start)`。成功取到原真实 RLock 后，fresh callback 和 actual ifindex reader 同在锁内，完整两者耗时取 `min(proof_seconds, context.deadline - start)`。原 exact AssociationProof/context/boot/epoch/native/interface/iftype、全部严格 True 旗标及 actual index 门槛保持，后置 cancellation/expiry/generation 与 yield 后 `_basic` 保持；没有缓存、续期或借用上次 proof。

`confirm_runner_closed` 只证明关闭，不授予网络能力；它不能受 association 到期约束，否则正常 TTL 结束后的 dead runner 也无法解除 pending。新末尾可选参数 `recovery_deadline=None` 由可信 owner 内部传入明确绝对恢复期限。显式值严格 finite、`now < recovery_deadline` 且剩余不超过 60 秒，锁等待和 closure producer 只取该独立恢复期剩余最小值；非法/到期不调用 producer，执行中到期仍拒绝解除 ticket。不传入时只沿 constructor 配置的有限锁/proof 预算，保留 association 超期后可以核真实闭合的原语义，不创建或更新 association deadline。

原关闭状态、exact ticket/client/context/creator/current generation、实际 dead thread、all_producers_stopped exact True 及终末原 ticket 复核保持。成功仅解除精确已退出 runner 的 ticket，不能清 factory unknown、未知 FD 或其他 producer。恢复期限不可来自 UI 或被用作新的网络租约，pending 不因超时自行清除。

原核心 SHA `13c03d181139fd9ead7ff3bf2bcbb4930669f1e795b17360da85834dc345e9fa` 不改。原 `run` 的 finally/close/core.cancel、socket 选项与广播、poll、candidate、FD dispose、actor/factory unknown 和公开 inventory/status 不改。此候选仍没有 IP 写入、持久 IP、可信 MTA endpoint 或 production send/receive。

## HOST 验证边界

新方法只使用合成时钟、原算法与 FakeSocket；原测试模块只作为未运行的 fixture 定义复用。真实 Python RLock 在当前 HOST 主线程同步持有，不启动线程；proof 和 index 同锁断言有覆盖。锁耗时通过前/后 clock 序列合成，不能称真实锁竞争、OS proof、STATUS/kernel/fresh producer 或 P011 DORA 测试。

覆盖完整源码逆向/仅三方法变化、默认拒绝 4.17 秒 fresh、显式 5 秒接受合成 fresh 与当前 allocation 到期拒用、deadline 剩余 clamp、index 累计成本、非法预算、锁前后成本与取消/变代/严格原字段、closure proof 全身份/dead-thread、factory/FD 未知强引用与原关闭门禁。socket、OS/进程操作、Thread.start 与 sleep 均有 tripwire。

首轮工具 `31ea49` 的新专项实际 8 方法 / 0.029 秒 / OK / HOST exit 0，针对 ROOT 最初要求的 association deadline closure clamp。当时 adapter SHA 为 `96d9423642759dfb2e2f60c6ff08fbfc753d70d880f15642a56fa3db1ceed26a`，tests SHA 为 `5e6f58e14bdf456e1e76d4e6f343cda1ad97c86fd16c6742c01d0f54a135dd07`。随后 ROOT 审查定位该要求会使正常 TTL 后闭合永远被拒，明确要求改用独立恢复期；首轮不改写为修订后结果。

仅修订 closure budget、两个包含其 clamp/expiry 假设的方法，并新增 association expired + 独立恢复期方法。完整源码边界也受此次源码变更影响；修订后工具 `e9990d` 仅定向跑这三个受影响方法及一个新增方法，实际 4 方法 / 0.026 秒 / OK / HOST exit 0。其余五个已过方法与原套测不重跑。首次没有失败、错误或跳过；修订源于 ROOT 纠正设计要求，不伪称修测试失败。累计 12 次方法执行、9 个不同新方法的分批证据，不是一次全部 9 PASS 或 12 个不同方法。

最终完整 `git diff --no-index`（工具 `3c65c0`，exit 1 表示发现预期差异）仅显示三方法和末尾 optional recovery 参数。新专项内还将这三方法替回原定义，完整逆向等于原全文，并逐项核原 `_basic/open/poll/_send/candidate/run/close/_dispose/status` AST 及 closure/AssociationProof 原谓词。

最终 adapter 与 tests 冻结并停写：

- Adapter：`794421678866d04a10ca46fa9eb7e17174f24c4d9e705cf59016b457702003a0`，418 行 / 24670 B。
- Tests：`076908e4868deb2107d876c0087bc1cc8f6d23e92bc7b703a8ef4098920b26e7`，302 行 / 20822 B。

本文 SHA 在交付 ROOT 时单独给出，不形成自身摘要循环。三新件交 ROOT 以最终三 SHA 全文复核；不需要重跑其余已过方法。

## 当前未完成

文档提到约 4.17 秒实际 collector 来自 ROOT 的当前证据；本次只以该耗时驱动合成 fixture，没有实际 producer。trusted caller 选择 5 秒也不能形成 fresh 授权；仍必须由真实同原 context/owner/issued receipt producer 证明全部旗标。

fresh/DORA proof producer、coordinator、formal 长租约、CLIENT ACK 动态 IP/持久 owned delta/恢复、可信 endpoint、GO/State/文件中心和小米15 Ultra双向验收仍是独立欠账。原 `run` 的历史返回值不可直接安装 IP。不自动部署、设备执行或无线重试，不称可互传。
