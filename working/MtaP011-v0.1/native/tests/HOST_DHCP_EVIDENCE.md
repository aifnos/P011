# DHCP HOST 证据 — 2026-09-30

范围：`runtime/mta_dhcp.py`、`native/tests/test_dhcp.py`。本报告不代表 P011 RF / DHCP / 手机 / 文件传输通过。

冻结本轮成功测试源码 SHA-256：

- `mta_dhcp.py`: `631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176`
- GO 首阶段源码 `mta_send_wifi.py` 仍为 `f8675ec9cdce01e518700b1f97db91a47d20ef076b7510dbdecc588c570b540e`，本轮没有改动。

验证结果：

- Windows HOST `python -B working\MtaP011-v0.1\native\tests\test_dhcp.py -v`：**29 tests PASS**。
- Linux HOST container `p011-bili-build-20260923` 执行同源码的 `/work/mta-dhcp-host-20260930/native/tests/test_dhcp.py -v`：**29 tests PASS**。
- 每次测试含 20,000 个固定 seed 恶意/随机封包 fuzz；只允许 bounded decode 返回或 symbolic DhcpError，不输出原始 payload。
- DORA mock 验证 actual remaining lease、xid/chaddr/client-id/server/subnet/ACK 地址匹配、单客户端、decline/释放、无 router/DNS、截止时不提供成功配置。
- mock 中禁止 `socket.socket`，正常 DORA 仍完成，确认本组件没有网络 / 系统配置副作用。

首轮 Windows 测试曾发现 IPv4 `$` 正则接受末尾换行；已改成严格 `\Z` 并加入对应边界覆盖，上述为修正后的完整重测。

未执行：P011 导入 / 实机 DHCP、UDP socket、地址或路由写入、无线操作、手机互操作。本核心 Python 3.5 语法兼容，不将较新 HOST Python 测试当目标解释器通过。
