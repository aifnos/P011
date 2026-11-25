# HOST Linux 隔离 Durable Store B 组合入口

状态：新入口/专项已稳定，待 ROOT 全文审阅及明确来源后唯一实际 Linux 执行。本作者只运行 FakeIO/source 检查，没有实际 OS 文件/锁、WSL、P011、RF 或手机试验。旧 checker 和 B/clear 来源均未修改。

## 执行与固定来源

`host/client_durable_store_linux_check.py` 自包含加载，未 import 旧 transaction checker。固定 9 个 runtime SHA（ip、p011_json、CLIENT core、proc、codec、Coord A+B、FILES、Pending clear、Store B）及 B test/review 两个参考 SHA。任何来源变化、额外项目导入、未知顺序或 checker SHA 不符都在 fixture 前拒绝。

默认仅来源/AST，无创建/执行：

```text
python3 -B host/client_durable_store_linux_check.py --source-check-only
```

实际模式仅在 ROOT 审查最终 SHA 后允许：

```text
python3 -B host/client_durable_store_linux_check.py --execute-reviewed --expected-checker-sha256 <exact-reviewed-source-sha256>
```

两模式互斥，无任意 fixture/root/path/候选参数；同进程登记实际 owner 后最多执行一次。不自动重试、恢复、清理或删除 fixture，不改变生产可用性。

## 明确的真实与合成边界

实际模式限 root Linux：独占创建新的私有 `/tmp` fixture；三 default Linux io **仅逐实例 open_root 映射到该 fixture**，其余 write/fsync/rename/flock/unlink/fstat/close 仍实际系统调用。真实 `/tmp` 只承载 fixture，不读取或修改真实全局 pending；设备锁/marker 同名但都在隔离目录内。

`actual ProcReader.read_self` 两轮有限读取当前进程/boot，仅接受单 task、live actor、文件确闭合、前后身份一致。没有进程创建、信号、网络、真实 CLIENT 接口或 Provider。

stock/network/baseline、interface intent/owned、controller/watchdog 票据与 Actor **全部 synthetic**，只用于严格 schema 各阶段真实文件 CAS。restore producer 是明确 synthetic registry，每次新发行 Snapshot/CloseProof 并 exact 认证；这些对象不证明网络或进程恢复。默认 Store producers、production F/Executor/manifest 仍未装配。

公开报告固定声明：`production_provider=False`、`p011_tested=False`、`phone_tested=False`、`rf=False`、`global_device_namespace_touched=False`、`network_baseline_authenticated=False`，同时 `synthetic_stock_network_baseline=True`、`synthetic_restore_producer=True`。不靠 sleep 触发 RF TTL；`rf_ttl_expiry_actual_tested=False`，超 TTL 保存只由之前 FakeIO 专项证明。

## 组合检查与原资源

实际空 journal → prepared 完整 CAS 与 own-marker → watchdog/interface/controller 多个 intent/saved → synthetic ready → 每次实际新 inode 与 fresh bytes → active_return 原 journal close → 一次 reacquire 同原 device、第 7 票据与实际新 journal flock → fresh current → cleanup_intent/verified → finish reconcile 持久化 → exact own-marker unlink/目录 fsync/独立 ENOENT → 终末 journal bytes/完整 metadata 独立读回。

三 io.close 的唯一补充是被动记录：先登记 exact 当次 original ticket，然后调用原 close，返回值/资源逻辑不改。observer 自身异常仍调用真实 close，但保持 close-observation unknown、报告失败。按每个原票据检查一次 close 及实际 EBADF，不用相同数字 FD 跨 epoch 冒充；完整组件最后一条 close 必须是原 device ticket。

setup 自己的原 FD 单独逐个 close/EBADF、未知强引用保留，不和 component 逻辑两槽 CloseProof 混计；result writer FD 不属这两个证明，也不是“当前进程全 FD 清空”。fixture/journal 始终保留；成功 own-marker 在 fixture 内清除，非任何历史 GO marker。未知 controller/继承/OFD 不因此获得授权。

结果保存在不可重名的新 `results/client-durable-store-linux-host-...`；public 仅 result/README，fixture/boot/Actor/traceback/合成完整 journal 只在私有 observations。独占 xb 保留原 FAIL，不复制历史结果冒充本次。

## 首次 HOST 专项与窄修

开发 PC Python 3.12.0、`-B`；实际 os.open/mkdir/read/write/fsync/close 等、ctypes、socket、mkdtemp 均 tripwire 禁止。source 只读检查允许，组件使用固定来源加载的真实代码，IO 为 Fake。

- `461ff6`：**20** 新方法，0.932s，wall 1.3504914s，exit1；16 PASS、4 FAIL、0 ERROR。未执行真实 Linux。
- 4 FAIL 由共用旧 FakeIo 的 `len(nodes)+100` inode 分配触发：temp rename 后数量不变，连续新 temp 与仍存在的 current 获得相同 inode。严格新 inode 门槛正确拦截在 stages；源检查器未放宽。
- 仅新 test 增加单调 DistinctInodeIo；将“最后 process 身份变化”的 fixture 推迟到独立 terminal 读回后，避免 Pending 正确在首次 marker 读取就拒绝而遮蔽该指定场景。
- `f9b9b4`：仅上述 4 失败方法重跑，1.337s，wall 1.7659918s，exit0，4 PASS。原16 PASS不重复；不是“24 unique”或项目全套。Python3.5 AST/source 检查在首批指定方法通过，最终 test AST 另静态核验。

覆盖来源失败在 I/O 前拒绝、默认 source-only、精确 CLI/SHA、纯 ctor、全阶段/CAS/handoff/clear、私有输出、Proc未知/多 task/变化、marker/terminal 独立读回失败、observer 异常不跳 close、setup/组件关闭失败及 once/unknown 强引用。其余真实 libc/OFD/rename/unlink/fsync 结果必须等待 ROOT 实際运行，不能以这 20 个 Fake 方法代替。
