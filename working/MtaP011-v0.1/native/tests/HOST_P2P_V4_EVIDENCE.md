# V4 配置兼容候选：PC HOST 专项证据

日期：2026-10-01。此文仅记录本子任务实际执行，旧 V3 **57 Linux HOST** 仍是历史 V3 证据，不升为 V4 Linux/实机结论。

## 变化与稳定身份

独立 `native/private-p2p-runtime-candidate-20261001-v4/runtime/mta_send_wifi.py` 为 V3 完整字节复制，唯一变化是删除生成配置中的 `\nupdate_config=0`（17字节）。没有额外诊断/行为/注释变化。

- V3：55336字节，SHA `eacc3a3a602f2ce047106920adaaa6c45a647e1de13a9ba4e90b5858303aff12`。
- V4：55319字节，SHA `ef2f087444c149a988b5b3895225960e85c03d702aa5a084cef62e6222ccf334`。
- 固定 WPA e069…及caps9ea…、main/V2/V3源码和旧候选均未改。

源码已稳定，harness README 为 **V4 single-config-line compatibility fix**。最终 harness SHA `55d715ff1282011f95040aa21afeb3f48da12b449d5aa89acf4dcbf1934cf25c`。

## 实际测试

Windows Python3.12 开发机执行：

```powershell
python -B -m unittest discover -s tests -p test_device_p2p_v4.py -v
python -B -m unittest discover -s native/tests -p test_send_wifi_v4.py -v
```

最终 **24/24 harness + 7/7 native配置 = 31 PC HOST PASS、0 SKIP**。

生成配置测试调用真实 writer，但 `os.pipe` 和 `os.fork` 明确 mocked，写完合成临时private.conf后在fork前停止。Windows无fork，使用create mock；没有实际子进程/exec/WPA/RF。

覆盖唯一字节变化、其余六配置项、非法原wlan0拒绝、固定tar parser/build flag、诊断/未知errno/nativepin/锁/pending保持、sendfalse、独立V4sourcepin、旧V2/V3拒绝、strictschema/terminal顺序/early/invalid、pending/actor/接口及完整IPv6独立门槛、超时仅一次提交且不recover、ZIP白名单。freeze测试只使用临时假ELF/假Python fixture，销毁后不留真实candidate。

新harness/test/native-test/runtime的Python3.5 AST，以及三类远端只读source AST PASS。这里没有声称目标Python导入、fork、FD3或GO运行。

## 独立设备证据与未测层

主任务的 `logs/MtaP011-WpaConfigNoRf-20261001-025636-5a66dea7/result.json` 是 **P011_WPA_CONFIG_PARSE_ONLY PASS**：同native e069，原conf exit255，唯一删除后exit0，stock/network独立baseline相同。该结果不是本子任务执行，也不是V4 GO PASS。

本子任务 **未生成真实V4 frozen manifest身份、未ADB/RF/重启、未最终设备测试**；root后续freeze/review/一次GO另建记录。V4 GO NOT_RUN、PHONE NOT_TESTED；正式send仍false。

详细入口/边界见 `docs/P2P_TRIAL_V4_PLAN.md`。不编造候选ID，不覆盖任何历史FAIL。
