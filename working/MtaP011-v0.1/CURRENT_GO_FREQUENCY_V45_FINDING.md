# GO v45 首因定位：接口频率属性可缺席，尚未修复验收

## 实际设备结果

唯一v45诊断 `results/go-bootstrap-diagnostic-v45-20261002-152643-ccf334c5`：HOST ADB0／remote1、无超时、35.859秒；真实F exit1，577B原私有stderr。PRIMARY原trace为 `GoBootstrap.run → Native.observe_baseline → _stable_snapshot → _snapshot_once → native_station_channel_changed`；RESTORE为`reservation_or_publication_pending`。本次首次异常在`store.reserve`之前的baseline阶段，尚未执行创建接口／GROUP_ADD。journal缺席，整轮仍FAIL，不签完整原生恢复。

前后两轮独立原厂／网络完整baseline一致、global pending缺席，父端FD／writer／Proc reader及readonly已观察资源闭合。ROOT `dcf280` 核当前／复制52源与3blob实际payload、raw echo／私有JSON、577B原子stderr关联、原exit／两成员ZIP外部字节与CRC，没有重跑或改判失败。

[脱敏失败ZIP](results/go-bootstrap-diagnostic-v45-20261002-152643-ccf334c5/public-result.zip)：1703B，两成员，SHA-256 `01b18154ac08416bde23e5ad36006d4d254f5703afc429af0dfbfceb2526186a`。原trace仅在private-raw，未进公开ZIP。

实际运行来源：F `377bc1bf9376885213412805a121cc2774998992f532c257a536de9f9186b711`；17map `1e1e76b34443872cc3ec5281a6f6e0c8a39594b4486665965fbb1b43f69b0103`；preparer `5eea6109589da58dcabeb67b24500043d841745987367db25a3873936f6529e5`；HOST `14801c1b6d98430d3867c4244e4e4306cacef57b7acc83802946aeac62cf1814`。原HOST282c草稿未执行；ROOT仅修两条README文案后复审、PC默认检查／Python3.5 AST及生成包往返通过，再唯一设备调用。

## 已证实的兼容假设错误

ROOT `95a843` 离线解析独立只读原raw（151615-63f7b8b3）：两次wlan0 GET_INTERFACE回复都只有属性1／3／4／5／6／46／52／153，均缺属性38（WIPHY_FREQ）；同次实际COMPLETED STATUS频率2412MHz。Native `_origin`已正确把缺属性解成None，但`_snapshot_once`无条件做None与STATUS频率比较，所以确定拒绝。

上游[Linux v4.14 nl80211_send_iface](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/wireless/nl80211.c)仅在get_channel回调存在且成功时发送频道属性（2432–2440），说明该字段不是每个合法回复必有。不能由P011当前reply缺字段推断vendor具体回调缺失／失败，更不能归因无线硬件损坏。

独立SOURCE审查另发现 `_channel_read` 和 `_group_status`同类假设；修第一处而不同步其他两处仍会再次拒绝。下一隔离v46仅将kernel频道做可选交叉核：

- STA频率仍来自真实原STATUS；RF准入仍须实际GET_SCAN中的唯一同BSSID／频率／ASSOCIATED BSS、有效BI、caps／no-IR／组合及原身份稳定证据。
- GO频率须真实凭据认证的GROUP_STARTED事件＋当前AP STATUS；两者匹配原measured频道，并保原if9／MAC／BSSID／外围baseline。请求的GROUP_ADD freq不是证明。
- 属性存在但冲突继续拒；空BSS、缓存未关联、缺BI、事件／STATUS缺失或冲突不能放行。不改原期限／额度／ACK／ECHO／持久化或恢复门。

先做新的只读GET_SCAN前置，绝不TRIGGER_SCAN或主动扫描来补资料；然后因果定向HOST新成功flow及受影响窄反例，不重复旧11flow，不启动新RF。

v46 SOURCE已经冻结并经ROOT完整窄diff／独立只读复审：Native `candidate/go-frequency-v46/runtime/mta_go_native.py`，87772B，SHA-256 `78e08414233e06f4100ebc318bb4d0d1996bd072caa77b2018a7035ec21b579a`；新17图 `host/go_frequency_v46_source_manifest.json`，3950B，SHA-256 `090392942b3472e45b1eb5f3ccf8b06a236b273255ce510fe52efc0fd20bcc7e`。相对v45仅Native一行替换／schema，另16源与F45诊断不变。ROOT `e2d2d7` 完成17固定源字节核与Python3.5 AST，没有import runtime／执行HOST模型／ADB。缺频道baseline分支实际增加一原genl socket／family query／只读BSS dump；原期限／额度不增，成本仍待因果测试，不称设备修复通过。

新的只读probe采用原两STATUS夹两个GET_SCAN：STATUS1→DUMP1；DUMP2（匹配同原STATUS1／Origin）→STATUS2，最后两STATUS raw／BSSID／频率、两完整baseline及两唯一ASSOCIATED BSS身份／BI均稳定。只新增两次原wireless socket的缓存dump，不额外启动STATUS进程或增加FD，保原10／30／45秒和32-record等上限；SOURCE正在制作，尚未执行。

## GO-IP／DHCP v43的独立SOURCE状态

已收到联合冻结20源图 `host/go_ip_dhcp_v43_source_manifest.json`，SHA-256 `ffc8253716ec87bb2f190db606e0ff7a6f7b9a3e8b6762834d8ef40b50f07635`。新增严格IP/DHCP record、原if9精确NEWADDR／DELADDR与UDP闭合顺序、实际STA准入、服务期限及20源Loader；发布21≤原26、retained-open源码推导215≤原216。数字为源码推导，不是实测。ROOT尚待全文／AST／HOST审核。

v43保留上述频率前置阻点，未暗中修旧图；它不是设备可用版。生产收发／手机通过仍false；目标active，小米15 Ultra真实互传验收待后续。
