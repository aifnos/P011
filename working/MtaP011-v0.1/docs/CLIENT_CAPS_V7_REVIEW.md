# CLIENT caps v7 SOURCE / Fake review

仅独立候选 `candidate/client-caps-v7/runtime/`，不覆盖旧 Provider/core、decoder、host 或已归档结果。
目标是 CLIENT init-only 的能力表达修正，不是 GO、关联、DHCP、互传或恢复验收。

## 固定来源与边界

- Provider：owned-origin-v4，`a8ca35f57841bf75b9ea53120404a395e2ad446cb2859a16a6c5c225efbb5491`。
- core：route-v3，`f5ebf037743f9fc910a7107425119576acdea649e16cf9e0660c0e9e257a607e`；IPv6 route 重复行、原顺序/数量、原完整 CAS 保持。
- decoder 保持 `c1792c2294fed5da16ec4a676423fbcbe53d44e9bc4ddadc1bc26fd45afe046c`。
- 新 Provider 只改变 `_caps_core`；新 core 只改变 `client_combo`。原 v4 六行 Origin 认证/替换与 DELETE/ACK/fresh absence/恢复/闭合流程保持。
- 构造/import 无新增系统动作。未 ADB、RF、socket、WSL、实际 interface CREATE/DELETE 或完整项目测试。

## 具体改动

1. Linux v4.14 supported-command 编码广告 `add_virtual_intf -> NEW_INTERFACE(7)`，不广告 DEL_INTERFACE(8)。本候选只要求 7，不把广告解释为删除必然成功。
2. Provider 保留 DecodedCaps 的完整 limits/max/channels/radar/beacon 值；新增明确 `bi_policy`/`bi_min_gcd`，未把缺失 BI_MIN_GCD 改成 1。
3. 新 core schema 严格接受 `all_beacons_identical` + None，或 `minimum_gcd` + exact int 1。未知、较大值、bool/float、字段不全全部拒绝。
4. identical-beacon 分支要求当前同 phy 恰好一个原 STA(2)，由本函数加入待创建 CLIENT(8)；AP/GO/IBSS/mesh/DEVICE/其他现存角色均拒绝。
5. 共享 limit、总数、types coverage、software/radar/beacon、正整数 channel 约束保持。空 CLIENT 无已分配 operating channel；不宣称已建立两信道关联。
6. 旧六字段 combo schema 保持原分支行为。此 API 始终用于 init-only，不可拿其 True 开放 GO 或关联。

## 主来源

- [Linux v4.14 nl80211.c 1258–1343](https://github.com/torvalds/linux/blob/v4.14/net/wireless/nl80211.c#L1258-L1343)：广告构造；2836–2853 是独立 DEL handler。
- [nl80211.c 969–1025](https://github.com/torvalds/linux/blob/v4.14/net/wireless/nl80211.c#L969-L1025)：BI_MIN_GCD 非零才发送。
- [UAPI 4405–4407](https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/nl80211.h#L4405-L4407)：缺失为所有发信标接口 BI 相同。
- [cfg80211.h 3842–3843](https://github.com/torvalds/linux/blob/v4.14/include/net/cfg80211.h#L3842-L3843)、[util.c 1494–1626](https://github.com/torvalds/linux/blob/v4.14/net/wireless/util.c#L1494-L1626)：本地发信标字段与实际组合检查。
- [core.c 369](https://github.com/torvalds/linux/blob/v4.14/net/wireless/core.c#L369)：add 无 del 只 WARN_ON，不是删除保证。

## 专项证据

唯一首次批次：工具 `f5b36c`，`py -B -m unittest discover -s tests -p test_client_caps_v7.py -v`。
11 个新方法，unittest 0.160s / OK，host exit 0；执行器 wall 0.5919514s。没有首 FAIL/ERROR，没有重跑旧整批。
覆盖实际公开 17-command 形状（不是实机 socket）、缺 8/缺 BI、显式 int1、unknown/bool/较大 BI、共享 limits/max/types/channel scalar、其他现存 role、旧 schema、其余 AST/route-v3/CAS/Origin 不变和 Python3.5 AST/纯构造 tripwire。
这些结果仅 SOURCE/Fake，不是 P011 CLIENT/DELETE/关联/恢复 PASS。原 actual caps read 是只读证据，未执行 v7 设备候选、未开放生产 send/receive。

## 最终停止写入身份

- Provider：`a49ce9bc6766d6b0182b45c833a3edaad307e4c27c45069871042ae49282f7c6`，1230 行 / 74662B。
- core：`bb22e43ec191c04624e009539f954a9bcbb7b98520fb32adf6fd4f18f4e8139a`，1027 行 / 61503B。
- tests：`0b3216c934791268c9a8172fad9fdf822d1e2ae0f0d4d727506be9415bbdbe34`，214 行 / 10359B。
- 精确公开 diff 工具 `a3515c`：只 `_caps_core` 与 `client_combo` 改动；没有其他模块接线/marker/deadline/资源恢复变更。
