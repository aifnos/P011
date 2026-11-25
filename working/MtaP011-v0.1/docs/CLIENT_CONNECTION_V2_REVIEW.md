# CLIENT connection v2：观察尾部断开撤销

## 固定来源与最小差异

本轮仅新增隔离候选与专项，没有修改原 A+B、RESTORE-only v4 或生产 runtime。

- 原 connection：`candidate/client-connection/runtime/mta_client_connection.py`，SHA `584a8007b076cb1df41697c690268e0d31dc0148b1eaeff43591403de00d10a4`。
- 新 connection：`candidate/client-connection-v2/runtime/mta_client_connection.py`，SHA `84ce100a1449a92562eec9e76b1b5d0bc28a490960fd381e701d29169e081ba3`，232 行 / 13078 B。
- 新候选 Provider：同目录 `mta_client_linux_provider.py`，逐字复制原 SHA `41459a480e9d78924a792bd881d25cd0696d64f0637a9d4b9be06083af09d25b`，1348 行 / 81990 B。其 import/exact-type 绑定新 connection；没有混入 v4 restore 改动。
- 专项：`tests/test_client_connection_v2.py`，SHA `d1b30241561ac02fa5101ca89ccf1da40bab625ca5a0b15f32623f96f6663907`，143 行 / 6856 B。

connection 只增加 `_drain` 中两行：已保存 `group` 且非 `disconnecting` 时，规范化事件为 `CTRL-EVENT-DISCONNECTED ` 就按既有固定 `event_removed` 拒绝。
事件仍先经原限长/ASCII/IFNAME/优先级校验和同 Provider 实际回复认证链；原始私有事件保留，不进入公开输出。
`_event` 和收到 group 之前的协商信息分类未变。主动 `disconnecting=True` 仍允许预期的断开事件；不构造关联、地址、端点或恢复证明。

## 失败/资源语义

首次 run 的最后 drain 若收到断开，原异常路径设置 `failed=True`，不发行连接观察。
readback 的最后 drain 若收到断开，原异常路径撤销当前操作；旧观察仅保留为历史私有对象，之后 readback 拒绝 `not_connected`，不会刷新发行。
现有 `last_connection_observed` 字段表示曾取得观察，不是当前关联/实际连接证明；必须同时看 failed/disconnect 状态。
本次不关闭底层资源、不替恢复流程清除 marker、不延长 TTL，不改变 journal/Store/原锁域或原网络基线门槛。

## 唯一专项实际结果

工具 `8dbf6c`：

```text
python -B -m unittest discover -s tests -p test_client_connection_v2.py -v
Ran 6 tests in 6.594s
OK
host exit 0; wall 7.2756895s
```

这是 5 个新方法（含 source reverse/Provider 原字节/Python 3.5 AST）和 1 个直接受影响旧 disconnect 方法在新模块私有 globals 下的精准重跑；未重跑原整批。
覆盖 run/readback 第二次 COMPLETED STATUS 后的 final drain、协商前信息仍可处理、主动断开含实际 Fake 事件仍成功、旧 disconnect 语义保持。
测试调用真实候选 run/readback、Provider 与 Store 方法，但 IO、已保存 Actor/关联事件和网络基线是明确合成 Fake；OS/socket/Popen/kill/wait/root-open 有 tripwire。
首批全通过，没有被隐藏或重判的失败。原 584a、41459、v4 a8ca 哈希读回未变。

## 未验证层

没有实际 P011、手机、socket、RF、关联、DHCP、数据传输或完整恢复验收。send/receive/production 能力仍关闭；源码停写后交 ROOT 审阅。
