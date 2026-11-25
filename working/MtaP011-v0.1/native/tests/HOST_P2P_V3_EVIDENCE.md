# private P2P V3 HOST 证据 — 2026-10-01

范围仅为新 runtime 的 HOST mock／安全诊断 QA。没有 ADB／RF、实际 GO／IP、DHCP、手机连接或文件传输。V2 FAIL 与恢复证据不被改写。

## 身份

| 文件 | SHA-256 |
| --- | --- |
| V3 独立 candidate/runtime/mta_send_wifi.py | `eacc3a3a602f2ce047106920adaaa6c45a647e1de13a9ba4e90b5858303aff12` |
| 主／V2 runtime（未改） | `e7222f0ed14589789faf0fc7d6857269a664264ade9ccf0b46d2c991e9b8b3c6` |
| test_send_wifi_v3.py | `c514ad91b9841cdc5c36a618c1ece3689a910e263aca66c05cddeccdf1da8c66` |
| V2 WPA（未改） | `e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301` |
| V2 caps（未改） | `9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6` |

V3 未创建主生产 runtime 副本。独立 candidate 为 `native/private-p2p-runtime-candidate-20261001-v3`；新 harness 必须精确冻结这个路径，不能拿主 runtime 冒充 V3。

## 执行结果

容器 `p011-bili-build-20260923`，新 HOST 目录 `/work/mta-v3-host-20261001`。该目录的 runtime 是 V3，历史 test modules 同样针对 V3 导入，验证原有生命周期门槛不退化；新测试独立加载 V3 候选。

```text
docker exec p011-bili-build-20260923 python3 -B -m unittest discover -v -s /work/mta-v3-host-20261001/native/tests -p test_send_wifi*.py
Ran 57 tests in 0.465s
OK
```

host command exit=0。41 个既有 V1／V2 lifecycle／flock／pending／diagnostic 回归＋16 个 V3 检查全部 PASS。新增范围：

- NEW_INTERFACE 模拟 EBUSY／EOPNOTSUPP 的 exact phase／errno／command。
- watchdog 模拟 fork EAGAIN 在 create 前停止、不执行 create、不留假 pending。
- snapshot／capability／existing-interface 查询的独立阶段。
- interface 记录写盘 ENOSPC 区别于 kernel create failure，仍只撤自身资源。
- cleanup EIO 不覆盖原来的 NEW_INTERFACE errno 与阶段，pending 不错误清掉。
- ready 返回值／version2 journal／RF 操作接口不变；进程内 phase 不进入 journal。
- kernel extack 含模拟秘密时不导出；send／recv OSError 保留安全数字和 command。
- timeout／负数／bool／字符串／超范围 errno 不猜，统一未知 0；未知或非字符串枚举不导出。
- constructor 失败与 main create 失败输出固定 JSON schema，不输出 exception args／strerror／filename／自由 traceback。

HOST Python3.5 AST 语法检查 PASS（exit 0）。不是 P011 解释器导入或实际 fork／netlink 成功证据。无需重建 native；其 V2 pins 没变。

## 尚未验证

- V3 的实际失败 phase／errno；当前设备错误仍是 V2 的未归因 OSError。
- GO-ready、私有 WPA 初始化、原厂并发稳定性及新的独立恢复。
- IP／DHCP／bound-device socket／手机互操作及真正双向互传。

RF gate 仍关闭，TTL20、send.available=false、无 DHCP／IP／BLE。只能 root 审阅＋冻结＋串行有限试验，不能因 HOST PASS 自动启动。
