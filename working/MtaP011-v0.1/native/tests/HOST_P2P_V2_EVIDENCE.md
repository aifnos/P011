# private P2P V2 HOST 证据 — 2026-10-01

本页范围是第二版 **HOST / SDK 构建与 mock QA**。作者未触设备 / RF；不证明 GO 建组、DHCP、手机互操作或完整互传成功。第一版 immutable 候选及 FAIL 日志未修改。

## 最终候选身份

目录：`native/private-p2p-candidate-20261001-v2`。

| 文件 | SHA-256 |
| --- | --- |
| mta-wpa-supplicant | `e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301` |
| mta-wpa-cli | `d57101bc097ff7aaf41631d9ddcae82bd1dec3e365c1f0a18d81f2d0446aac15` |
| mta-wifi-caps | `9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6` |
| runtime/mta_send_wifi.py | `e7222f0ed14589789faf0fc7d6857269a664264ade9ccf0b46d2c991e9b8b3c6` |
| source/prepare_wpa_v2.py | `fa7f0cc2b454180cc0131a96faa84cf866a7bd852db1f5a8297ff061568749a6` |
| source/build_p2p_private_v2.sh | `60d2e659971ccaa54ea595615848b41ba0a62a1f840e0826758fac15dc46bb81` |
| source/p2p-private-v2.config | `1c46fae858e3c7d61213e1f28f9cf5ada2c55246a1c25eef211ffc342452f3bd` |
| source/project-v2-supplicant.patch | `bad24af1dcef004ab28cc0a6ab9c9e025cc18b2545587f709ec1118dd35a18c7` |

主 `runtime/mta_send_wifi.py` 与候选 runtime 副本应保持此相同身份。root 的旧 `host/device_p2p.py` V1 pin / journal schema 不可直接作为 V2 harness；新冻结应审计此候选及 version=2 的完整 baseline / device pending / numeric diagnostics。

## SDK 构建

最终 build root `/work/mta-p2p-build-20261001-v2d`，容器 `p011-bili-build-20260923`，旧 P011 SDK `arm-buildroot-linux-gnueabihf-gcc`。

- 官方固定 WPA 2.12 / libnl 3.11 source tar SHA 与 V1 一致，版本源码 / 两阶段 patch / config / build script / 原许可均打包。
- 应用 object tar 与 static libnl archives 一并提供对应源和重链接素材，无 vendor SDK 库被打包。
- SDK 编译链接 PASS；最终新增代码没有编译警告。`NEEDED` 只有 libc.so.6 / librt.so.1 / ld-linux-armhf.so.3；最高 GLIBC 需求 2.15，不依赖 vendor OpenSSL ABI。
- 首次上游重新下载遭 TLS EOF，改用已固定哈希的官方归档 cache 继续。v2a source transform 发现不唯一锚点而 fail-closed；v2b 验证完功能后移除新增 write-return 警告；v2c 补齐初始化后半阶段之前为 intermediate；**v2d 才是最终诊断完整候选**，旧构建目录保留，不覆盖第一版。

## HOST QA

最终 runtime 的 Linux HOST 命令：

```text
docker exec p011-bili-build-20260923 python3 -B -m unittest discover -v -s /work/mta-go-v2-host-20261001/native/tests -p test_send_wifi*.py
```

初次 V2 review 为 runtime `80100d62…`，**37 tests PASS**。随后 protocol review 找到诊断管道尾部未完整帧门槛缺口；root 仅把 `PrivateDiagnostics.report()` 的报告值改为 `self.invalid or bool(self.buffer)`，并同步主 runtime／候选副本。最终 runtime `e7222f0e…` 重跑 **41 tests PASS**（0.403 秒、exit 0），包括 V1 16 个生命周期检查＋V2 25 个新增检查。没有改动 WPA／probe binary 或 RF 控制流。主要覆盖：

- 精确 origin / PID durable-before-exec、iface / PID 重用拒绝、未知 create ownership 保留、秘密不进 journal。
- STA 状态只在原厂 baseline 完全不变、controller 已退出、模拟 quiescent / no-data-address 通过时允许同一 origin 回收；错误 WDEV、data IP / active、基线变化均拒绝。
- reconciled 不盲返旧 PASS，独立读回 original baseline / interface absent / process gone；新异常再次持久 pending。
- TTL 到达 / watchdog 先清理时不再执行 create；watchdog setup 失败不会留下假 admission。
- 实际 Linux flock HOST fork 验证同 open-file-description：parent 关闭自己的引用后，child 仍阻止另一 open 抢锁；child 释放后新 holder 才能 acquire。
- pending 精确 journal / boot / candidate 身份，partial / symlink / 不同 run 拒绝，防随机新目录绕过前次未清理。
- 私有诊断 incremental / pipe / bounds，原始 PSK / SSID 字符串与未知字段不会进入报告，事件白名单＋数值 code。
- 未换行的数值帧、完整事件后的私有尾部、pipe EOF 半行均报告 diagnostic_invalid，buffer 从不导出；半行仅为 transient，不污染持久 invalid，后续补齐同一合法帧则恢复有效；真正不合法帧仍保持 invalid。

Python 3.5 AST 语法 PASS；这里没有声称目标解释器导入、fork / FD3 或 route parser 的 P011 实机验收。既有 DHCP 29 HOST PASS 保持独立，未接入 V2。

## RF 门控仍关闭

20 秒实验 lease / `send.available=false` / `local_ip=None` 保持。没有 DHCP、IP / route writes、BLE、配对、手机传输或自动重试。只能由 root 在原厂 fresh baseline / 完整候选审查 / 新不可变冻结后串行执行下一轮有限 RF 试验。
