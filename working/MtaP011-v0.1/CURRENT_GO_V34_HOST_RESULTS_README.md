# GO v34 当前结果：仅 HOST 算法模型

本阶段 ROOT 已首次执行 r4 唯一方法并通过；本文仅读取既有结果与 raw，不重复测试，新增 CMD 也未执行。旧三轮失败与输入、源码、raw、ZIP 均保留，不能改写为 PASS。

## 首次回执

| 版本 | 结果 / child exit | 原始 unittest 耗时 | HOST 包装器耗时 | 固定输入 / 公开成员 |
| --- | --- | --- | --- | --- |
| v34 | FAIL / 1，无超时 | 1.252 s | 1.438 s | 25 / 2 |
| v34-r2 | FAIL / 1，无超时 | 1.249 s | 1.422 s | 25 / 2 |
| v34-r3 | FAIL / 1，无超时 | 17.813 s | 18.079 s | 25 / 2 |
| v34-r4 | PASS / 0，无超时 | 18.080 s | 18.485 s | 25 / 4 |

v34 的共同早期失败被后续断言遮住；r2 只补安全原异常诊断，确认首因是 `invalid_snapshot`。模型地址回复缺少 Linux `IFA_CACHEINFO`，与实际 Core 的永久寿命要求不符。r3 仅补这一模型属性，没有放宽生产快照检查；其余十个模型流程完成，剩余 `unlink_unknown` 用例错误地要求所有接口清理都停下。

r4 仅修该观察并加强证据：有已确认 ACK/ECHO 原件、实际 durable restore intent、原 child 退出、fresh 同一接口与基线证明时，原生算法可清理那个已知接口；本地路径 unlink 的返回仍未知，所以整体资源恢复继续挂起。用例必须保持一次 raw close、一次不重试的 unlink、`native_resource_pending`、无 restored 原件、未签 reconciled、pending marker 与 logical restored=False。已知接口的 DEL=1 不等于全部恢复成功。其它失败用例仍要求 DEL=0。

## 通过范围与未测试范围

- 实际固定 17 源定义运行 Loader、F Entry、原生 ProcReader/ResourceBudget 与中性 Store 构造、GO durable Store/CAS/readback、ProcessOwner 父分支、Native netlink/Unix 解析、Bootstrap 同 8→9→8→删除及单次恢复算法；没有替换 native producer、grant、canonical 或 restored 布尔值。
- 唯一方法包含十一条独立模型流程：正向、缺 ACK、首 child 停止失败、首次 unlink 前检查失败、unlink 返回未知、foreign endpoint，以及五种 publication unknown / child 原件拒绝。原期限、预算、阶段门和 unknown 库存不续期、不扩容、不退款、不清掉。
- Linux 文件系统、FD/OFD、Proc、kernel/netlink、Unix credentials、时钟、fork/exec/signal/wait/EBADF 为明确 HOST 模型。模型 fork 只走父分支；gate write 模拟子进程 exec 与控制 socket 准备。
- 实际 child 分支、FD3、watchdog 循环、真实 EOF/R 通知、child inherited OFD、物理锁、Linux syscall wall bound 和 physical close **均未验证**。不能据此签 P011 恢复、驱动/RF、手机互传或 GO 服务可用。
- PC 固定源码、已归档 WPA/stock-three 文件字节与 ZIP 回读是实际 PC 证据；Python/CLI 是合法 ARM ELF/CLI 形状的合成 fixture，不是学习笔真实身份，其 pin 禁止进入设备 preparer。
- 结果保留 `device_accessed=false`、`rf_requested=false`、`phone_tested=false`、`actual_p011_restore_verified=false`、`state_production_receive_gate_enabled=false`、`p011_go_service_available=false`。IP、DHCP、TLS 与手机传输也没有被这个 GO bootstrap 方法实现或验收。

## 固定成功身份

唯一方法：`GoBootstrapNativeV34R4Tests.test_actual_go17_known_interface_cleanup_keeps_unknown_endpoint_pending_and_original_restore`。

| 文件 | SHA-256 |
| --- | --- |
| `tests/test_go_bootstrap_native_v34_r4.py` | `3574ad5f729162ef6a26e8f4f133210bcec6bcc8e2f74c99d1355b67974cd8ef` |
| `tests/go_bootstrap_host_model_v34_r3.py` | `d8c07c9aa2e5e7c7c009f9411d7cb6ad3f820b12273639aad96526738dc6358f` |
| `host/go_bootstrap_native_v34_source_manifest.json` | `491b08d4754fcbf5d3dc203c48cf73a5d274bf5fc4da7d46fbb41a3af55ea296` |
| `host/go_bootstrap_native_v34_r4_check.py` | `3cb1a28d0a14ea3d6034b30ec3e589af68765b28ad94bef5c3ce02492e4d4393` |

## 已保留公开 ZIP

以下目录均在 `results/`，ZIP 文件名为 `public-result.zip`。成功含 `result.json`、`README.txt`、`stdout.raw`、`stderr.raw`；失败仅前两项，失败 raw 与固定输入保持私有。

| 结果目录 | ZIP SHA-256 |
| --- | --- |
| `go-bootstrap-native-v34-model-20261002-130219-41ee3863` | `22dec80acff1fbb542823f0c7131759b3636a5be24a2ff08a169a21510936b38` |
| `go-bootstrap-native-v34-r2-model-20261002-130727-f7a7fbee` | `e7d182f2e4c2c92d0dcb29086e5e5b9f4d827df8fb8060646d04aa406a23509b` |
| `go-bootstrap-native-v34-r3-model-20261002-131307-15bd8bb0` | `15f0314c845f800f2644b3c8fd0f0a1a72b877f3edb13c28f78ee281679adf31` |
| `go-bootstrap-native-v34-r4-model-20261002-132019-93dc7917` | `2526f82e9b84a5494a65217b7d8b471ce73022cf787f1166ae7d40339cc768d6` |

r4 原 stdout marker 为 `GO17_FULL_HOST_MODEL_R4_OK`，stdout SHA 为 `e65ae5aa67a95122746e669b972661d33964b8fab698c9dbc0ddad5c44fe2804`；stderr SHA 为 `5fd5588e891e72fbd2f7d859cb2f335801c10791fcd7dc3f53d6343940502ca7`。ROOT 已核对 25 项 current/private snapshot、4 成员 ZIP CRC、外部原 bytes 与 raw SHA。

## PC-only 手动入口

`HOST_MTA_GO_BOOTSTRAP_V34_R4_CHECK.cmd` 只运行上述固定唯一 HOST 模型方法。包装器保留 `-I -B` 私有快照、原 120 秒 HOST 上限、严格 stdout/stderr、一次调用、成员 bytes/CRC 回读，不调用 ADB、不启动设备、不自动重试或修复。已存在 PASS，无需为补日志或打包重跑；仅有确切新的验证需要时手工启动，结果进入独立新目录，旧回执不被覆盖。
