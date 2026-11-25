# CLIENT raw caps decoder：字节层审阅

## 范围与证据层级

新组件仅 `runtime/mta_client_caps.py`、专项 `tests/test_client_caps.py` 与本文。
Python 3.5 语法、无 stdlib json；import 与构造纯，无 socket、文件／进程／编译／网络动作。
本轮不修改 CLIENT owner/core、旧 native/probe、runtime provider、冻结候选或历史结果。
HOST fixture 不证明 P011 原始 dump、关联、CLIENT 实机能力或手机互传；能力保持未开放。

## 输入与输出合同

`decode_wiphy_projection(fragments)` 接受 exact tuple[bytes]，每项是一个 NEW_WIPHY 响应的
**投影属性流**，不是完整 netlink/genl message。投影只准 WIPHY(1)、SUPPORTED_IFTYPES(32)、
SUPPORTED_COMMANDS(50)、INTERFACE_COMBINATIONS(120)、SOFTWARE_IFTYPES(121)。其它投影字段拒绝。
未来 trusted provider 需先保留完整 raw dump，再按已审 UAPI 政策投影；不能任意丢未知潜在约束。
组件没有 `complete`／`split` 参数，不认证 kernel，不签 dump complete，不能直接作为 mutation admission。
返回不可变 DecodedCaps→Phy→Combination→Limit tuples；每个 optional 字段有 presence 与真实值。
missing radar 值为 None，software missing 与已记录的空集以 presence 区分，不能归零推断。

每片恰一个 WIPHY；不同片重复该身份合法。同 PHY 其它投影 singleton 跨片也不得重复；不做 set 合并。
组合／limit 数组序号正整数、唯一连续；未知组合／limit constraint 固定错误拒绝，不吞成空 unknown。
iftype 只支持官方 4.14 的 1..12、empty flag payload、无重复；limit coverage 不重叠且不得超出 advertised。
宽度 bitmap 仅 4.14 的 0..7 bits、地区仅 0..3 bits；未知位拒绝，已知非零值忠实保留。
预算固定：总 262144B、64片、8 PHY、4096 attr、16组合／16 limits、256 commands；不接受 caller 放宽。
属性长度、完整 alignment、零 padding、flags 全部验证；嵌套允许 0 或 NLA_F_NESTED，scalar/flag只允许0。

## 兼容当前 core 的受限 schema

`decoded_client_schema(fragments)` 每次重新严格 decode，只返回 `{'phys': tuple}`，**刻意没有 complete**。
它保留 core 支持的 software、radar、beacon 值与完整 counts/limits；core 仍可能拒绝该 schema。
当前 `mta_p2p_client_init.client_combo()` 不支持 BI_MIN_GCD。absence 表示 BI 默认一致约束，非零为最小 GCD；
两者均不能悄悄删除。唯一可无损省略的值是显式 BI_MIN_GCD=1（正整数 BI 的 GCD 不可能小于1）。
其它 BI 值／默认 absence 固定 `unrepresented_bi_constraint`；任一 radar absence 固定拒绝，不推断为0。
未记录 supported/software/combinations 或无组合，拒绝兼容 schema；保留丰富 decode 结果供未来 provider 审阅。
没有按 STA/CLIENT 虚构“BI不适用”，也没有删除拒绝的组合去碰巧找到一项通过；实际 role/count 判断另审。
纯解码中的 `unknown_constraints=()` 只出现在已拒绝未知字段的窄 schema 中，不是 kernel 无未知约束证明。

## 主来源与完整性缺口

- [Linux 4.14 nl80211 UAPI](https://raw.githubusercontent.com/torvalds/linux/v4.14/include/uapi/linux/nl80211.h)：
  combination attrs 1..7；SUPPORTED_IFTYPES 不是并发支持；软件接口也有语义限制。
- 顶层数字亦与固定历史 `native/tests/private-wifi-readonly-20260930c/01-wifi-caps-readonly.stdout.raw:1`
  的 --ids 记录一致（不是新设备证据）。
- [Linux 4.14 nl80211 输出](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/wireless/nl80211.c)：
  `nl80211_put_iface_combinations` 仅 large/split 输出 radar；`nl80211_dump_wiphy` 同PHY跨多消息；
  非 split／第一片即使 schema 合法也不能代表完整约束。
- [Linux 4.14 属性 helper](https://raw.githubusercontent.com/torvalds/linux/v4.14/include/net/netlink.h)：
  `nla_nest_start` 当时不自动加 NLA_F_NESTED；只允许 flagged nested 会误拒原厂合法编码。
- [Linux 4.14 BI 判定](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/wireless/util.c)：
  非零 min GCD 与默认不同-BI 拒绝是不同分支；本组件保存区别，不复制内核实现。

future provider 必须验证 actual split 请求、同 socket/seq/target PHY、kernel peer0、全部 multipart/DONE、
无 ERROR/DUMP_INTR/截断／预算溢出，并保留 exact 原始属性。不接受旧 probe JSON 的省字段等于 known-false。
这里没有提供通用 True／complete callback 或 typed token，自造一个 byte-only对象不产生 trusted transport。

## HOST 验证记录

专项命令：`python -B -m unittest discover -s tests -p test_client_caps.py -v`。
首次实际执行（02d58d）：43项，41 PASS、1 FAIL、1 ERROR、exit1，0.016s；保留失败，不改写成初次全过。
两项均为新 HOST 夹具错误：reject辅助函数把None输入误包装为tuple；core Snapshot缺原厂actor/default-rules。
runtime源码未为这两项改变；只修夹具，依约不重跑已过的41项。
受影响项目分别 `-k invalid_input_types_and_empty_fragments_reject`（d1d200）、
`-k projection_is_exact_current_schema_but_not_complete_proof`（d21a77）实际各1 PASS、exit0。
当前43项已有相应通过证据（41首次+2修后专项），**不是修改后整批43重新执行的PASS记录**。
其中 runtime Python3.5 AST及禁止open/socket/Popen下import+decode验证通过；PC Python3.12执行。
没有 P011 import、真实原始caps dump或CLIENT实机试验，也没有Linux新容器／套测／冻结／打包。
测试包含当前 core HOST-only complete fixture；它专门证明裸 schema 不能通过完整性入口，
不将该 fixture 当真实 transport 或生产可用证明。
