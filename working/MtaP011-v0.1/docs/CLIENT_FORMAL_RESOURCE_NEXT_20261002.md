# CLIENT 正式操作的资源生命周期欠账

这是 v21 新 HOST 阻断之后的源码执行边界，不是资源层已修好或 P011 已通过。原 v19/v18/FILES 来源和旧失败记录保持。小米15 Ultra 仍未做原厂互传验收。

## 当前确定的首个瓶颈

作者的唯一受影响重测 `8b7fbe`（2 方法 / 7.494 秒 / HOST exit 0）中，完整 DORA 容量方法按预期拒绝：原 producer 返回 `('files', 'resource_budget')`，外层转换为固定 `proof_failed`。当时原 kernel/caps/association receipt/FILES 库存数是 `4 / 4 / 2 / 256`，发生在 `open` 的第二次 fresh，尚未发送 DISCOVER。该方法验证“额度不足不继续操作”，不是 DORA 成功。

HOST 使用 actual v19 私有定义、Store/current/CAS/reader 算法及 FakeIO，ready/原厂 baseline/actor/P2P 事件是合成前置；未执行完整实际 INIT 或设备系统调用。源代码的真实 INIT 在 CONNECT 前还调用 caps 两次，所以不能把此 fixture 的首个失败时点直接说成 P011 实际失败时点。

## 不能仅改一个常量

| 当前来源 | 有限门槛 | 必须保留的事实 |
| --- | --- | --- |
| FILES | 256 个尝试票据 | 打开前登记、未知返回、close-once、即时闭合证据、原 CanonicalRecord issuer |
| Provider | 8 个 kernel reader、8 个 caps reader、8 个 association receipt | 原件和代次、资源未知、角色/MAC/BSSID/频率、当前 receipt 撤权 |
| Provider | 32 个 collector、512 个 proc call、64 个 ledger row、32768 个 FD receipt | 实际组合库存、FD 合法复用与外来复用分开 |
| Provider close proof | 最多 128 个逻辑事实 | 逻辑 owner 内的每个真实 FD 单独闭合核验，不能拿数量代替闭合 |
| 当前 F / Lease / watchdog | 20 秒 trial、独立最多 60 秒恢复 | 同一原 owner/OFD、绝对期限、恢复 gate 与终末 marker 最后清除 |

`Store.current` 会产生新的 actual CanonicalRecord，但 Lease 保持原 Journal/baseline 原件；v21 只在精确 issuer/current/CAS/代次/字节/metadata/hash 和双轮实际读回全部符合后 advance canonical。它不合并或删除 FILES 票据，不补造缓存 proof。

## 下一实现顺序

1. 以一次完整 INIT→CONNECT→DORA→动态 IP→传输→恢复的原调用图，量出每阶段的实际发行/保留成本。HOST 数量、实际 producer 耗时、P011 内存/时延必须分开。4.17 秒是一次只读 collector，不是双轮 fresh 总耗时；v21 的 5 秒是上限，不是时间保证。
2. 隔离制作正式资源 profile/生命周期。对重复的已闭合来源可设计受原 issuer 验证的有限组合 owner，但必须保留原强引用与逐 FD 证据；未知、活跃、晚返回不能退休。若采用更大的额度，也须按完整图的有限次数和内存成本定义并验证，不能只改 256 或 8 来令旧测试变绿。
3. 同步核全部后续门槛：FILES、CanonicalRecord registry、Provider readers/receipts/proc/collectors、ledger、CloseProof 和原事件/报文总数。保持源身份及复用规则，并为取消、到期、未知与超额预留真实恢复容量。
4. 正式操作绝对期必须贯通 Journal schema、Loader/argv、F、Lease、Provider、watchdog、Parent、State 和传输；不得把旧 20 秒 trial 在局部变成 300 秒，也不滚动续期。闭合证明使用可信 owner 的独立恢复期，不续网络权限。
5. 再接仍活跃的 ACK 动态 IP、持久 intent/owned delta 和可信应用端点。不得安装 `run` 已关闭后的历史返回值；所有 IP 写入前须在同 owner 下重新核当前 allocation，随后纳入原恢复库存。

v21 新 coordinator 尚未纳入冻结 F 的正式 factory/资源 inventory，F 仍是原 24 模块。新增 28 定义图只表示 24 原模块加 4 个隔离扩展，不代表可发布的平台。GO 九方法、State/文件中心、笔端原网恢复与手机双向仍在完整目标中；目标保持 active。
