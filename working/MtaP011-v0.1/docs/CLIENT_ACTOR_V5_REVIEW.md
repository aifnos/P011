# CLIENT Actor v5：仅两个 fresh 身份比较

## 来源与实际问题边界

候选仅新增 `candidate/client-actor-v5/runtime/mta_client_baseline.py`，从固定 v3 `ed41639b1f74c096132a04f9a9a137f2ccc48ddc274c4d3786fe43d718d6c51a` 逐字复制后改两个 fresh predicate；没有新 host 或设备动作。
ROOT 的 `938739 / 92e5f1 / 23b40d` 只读证据定位 `actor_image`：两次 actual Actor 稳定 key、live 和 TID/start 相同，原始任务状态为 R→S。
该失败 collect 的已观察耗时 1.406888s，未进入 STATUS、未形成 round；不是完整基线成功耗时。旧 deadline 问题没有因此被证明解决，也不重判旧结果。

## 精确源码差异

- `_actor_image` 第 251 行：从 `key + raw tasks` 全等改为完整 `Actor.key()` 全等且双方 `live()`。
- `collect` 第 519–521 行：两个已采样 snapshot 的原 actors 比较稳定 key 且双方 live；其前的完整 `Snapshot.key()` 比较原样保留。

完整 PID/start/exe/argv SHA 和任务 TID/start 仍是 Actor.key；原始任务状态没有修改、归一化、丢弃或从输出排除。
原 ProcReader 的两 pass、全部线程集合/启动时间、Z/X 非活跃及 P 不支持状态门禁不变。原 boot、映像 SHA/metadata、全网络、原 pins、clock/budget/default 5s、原资源闭合库存均未改。
`core._same_journal` / codec / Store 持久 CAS 仍比较完整原值，包括 raw task states；新鲜身份相同不意味着持久记录相同。
v3 的路由重复行完整保留行为仍原样，没有改 IPv4、IPv6 其他格式或记录顺序。

## 唯一新 HOST/Fake 批次

工具 `eb16cc`：

```text
python -B -m unittest discover -s tests -p test_client_actor_v5.py -v
Ran 7 tests in 0.125s
OK
host exit 0; wall 0.7167523s
```

7 个新方法，参数 subtests 不另算方法；没有重跑原已通过测试。首次全通过，没有隐藏或覆盖的首失败。中断发生在首次运行之前，不是 SOURCE/测试失败。
真实 `Baseline.collect` 与原 `ProcReader` 运行于既有 FakeIO/FakeFS。测试在读取前构造合成 stat 字节，随后保留真实 reader 返回的 raw/Actor；没有手工伪造 live P Actor。
覆盖 image R→S、round S→R、两门槛的 TID/task-start/leader-start/argv/exe 变化拒绝、原 ProcReader 对 Z/X/P 的 opaque 拒绝、完整 raw states、journal codec/CAS 状态敏感、两个替换逆向逐字恢复与 Python 3.5 AST。
文件库存仅为 Fake 闭合及 EBADF 读回，不是实际 Linux/P011 FD 证明；合成映像由既有明确 Fake hash seam 提供，不能签发原厂映像验收。

## 最终固定来源

- 候选：`3e1575d94020bf9e1e54a9fca2ca35876efbcb1385a15dd0bc0bfdf8ac8736ea`，539 行 / 29268 B。
- 专项 `tests/test_client_actor_v5.py`：`22ffd9e8d1ba54bd8d84210c9d6d7ea5213d5095cb15b7708ad221a7fb440482`，195 行 / 11059 B。
- 原 v3 ed416、core ec2d927、ProcReader 2f0ef523、Store c6d4c8b7 全 SHA 读回未变。

本轮仅 SOURCE/Fake；没有实际 P011、STATUS、完整基线通过、恢复、关联、RF、手机互通或性能验收。生产门禁保持原样，三文件停写交 ROOT 审阅。
