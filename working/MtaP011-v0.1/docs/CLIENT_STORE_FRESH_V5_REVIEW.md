# CLIENT Store fresh-baseline v5 — SOURCE / HOST only

范围：隔离 `candidate/client-store-fresh-v5/runtime/mta_client_store.py`，基点是原 Store `c6d4c8b7fda8370be83efafe61bfad4a4680ef7a8edba51a89f539c6868594cd`。原 runtime、core、codec、Provider、Owner、F、旧候选和生产门禁均未改；无 HOST 实际锁/文件系统集成、WSL、ADB、设备、网络或 RF 调用。

## 唯一变化

- 新增 `_same_live_baseline(left, right)`：两边必须 exact `core.Snapshot`，完整 `Snapshot.key()` 相等，双方所有原厂 Actor 必须 exact `core.Actor` 且 `live() is True`。
- `Snapshot.key()` 保留 boot、映像 hash、Actor PID/start/exe/argv、完整 TID/start 集合、原 STA 状态指纹/频率、接口、全部 IPv4 地址/所有表路由/rules、IPv6 地址/路由；只有 Actor 的瞬时 task state 不在稳定 key 中。
- 仅 `DurableClientInitStore.prior_clear` 和 `_fresh_restore` 的实际 fresh-producer 比较改用此函数。原读回对象直接保留，不重写、归一化或伪造 R/S 状态。
- 原 `_same_baseline`、`_transition`、`core._same_journal`、canonical bytes、generation、元数据/CAS、鉴权、CloseProof、reuse 检查和所有预算均不变。

这是 fresh observation 与持久记录的不同用途，不是新身份授权。R/S 改变但稳定身份相同且双方 live 可进入原 producer 鉴权；身份、网络或 boot 改变仍拒绝。Journal 阶段转换和实际当前文件 CAS 的 raw task state 改变仍拒绝。

## 首次且唯一专项证据

命令：`python -B -m unittest discover -s tests -p test_client_store_fresh_v5.py -v`

工具 `975904`：12 个新方法，1.318 秒，0 FAIL / 0 ERROR，`OK`，host exit 0；外层 wall 1.7971621 秒。无第二批，不累计旧测试或项目套测。该批包含新候选与测试的 Python 3.5 AST 检查、原 Store SHA 与完整精确生成差异校验。

测试真实调用新 Store、coordination、FILES、Pending/marker 方法；仅 OS 文件/锁、进程和 prior/restore 来源为显式 FakeIO / synthetic producer，所有默认实际 OS、socket、Popen、ctypes 和 proc 入口设有 tripwire。测试隔离部署把 Pending 的 exact Store import 指向该候选，没有以 mock `True` / `None` 替代生产鉴权或 clear 门槛。

覆盖：

- prior 的 R→S 鲜读通过、原/新 raw 对象任务状态均原样保留。
- 三次 fresh restore 发行独立 snapshot/CloseProof、逐次 exact registry 鉴权；终末 Journal/codec 的原 raw baseline 不改。
- Actor argv/PID-start/线程启动值/线程增删；boot、STA 指纹/频率、完整 IPv4 cacheinfo、IPv6 地址/路由改变均拒绝。
- Z/X 非 live、Snapshot 子类/形状对象拒绝；构造器本来拒绝非 live，本项通过只在 HOST 的对象损坏注入独立验证 gate。
- prior/restore 鉴权 boolean 或未发行结果、restore tuple/snapshot/CloseProof 复用仍拒绝。
- 默认缺来源保持 unavailable；persist transition rawstate 改变零写拒绝；实际当前文件 rawstate 改变不 rebase，并保留 pending。

## 未验与接入边界

ROOT 已报告的 P011 性能轮次发现同一 live Actor/TID-start 的 R→S，是本候选针对的问题来源，不是本专项的设备验证。该候选尚未部署或验证任何 P011 fresh producer / prior / restore；没有手机、CLIENT 关联、DHCP、传输、真实恢复或互传成功证据。

候选需 ROOT 完整 source/diff 审定后才可进入独立固定来源图；旧日志/历史 FAIL 不改，`send_available` / `receive_available` 不开放。
