# CLIENT v16：本地MAC前置观察（SOURCE/Fake）

仅四个新文件；旧v15、Provider、F、core、Store与既有结果不改。不是实际关联/DORA/手机验收，没有设备GET/RF/网络操作。
不发行AssociationProof，不创建持久关联收据，不授予DHCP/IP/endpoint或生产发送/接收权限。

## 固定来源 / 官方ABI

- v15 reader原件：f16af6f1db74c9e6d74d2e56e6b469cf1ed589f27d3a1d5b4f897220cdeeb334。
- v15 connection原件：4a561d8d385fc71870c6d46653b7855b304c854ca10f102f31d174096fd7f2d1。
- [Linux v4.14 UAPI nl80211.h](https://raw.githubusercontent.com/torvalds/linux/v4.14/include/uapi/linux/nl80211.h) 2124–2132：枚举起点及MAC顺序确认NL80211_ATTR_MAC=6。
- [Linux v4.14 nl80211.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/wireless/nl80211.c) 2422–2429：interface消息以ETH_ALEN输出wdev_address；这里不是GET_STATION的peer地址。
- 原GET_INTERFACE请求/回复身份链、ifindex/Origin/Actor/boot、期限与raw/关闭库存保持，没有新增请求。

## 最小行为差异

- `_interface`消费attr6：flags必须0、exact bytes6、非全0且unicast；畸形固定attribute_format，旧重复属性仍拒。
- 缺字段返回None，不从STATUS/BSSID/go_dev_addr/BLE填值；新私有字段名`local_mac`。
- 每个reader原三次GET_INTERFACE的MAC必须全等，含缺失/出现变化；不同固定interface_changed。
- KernelObservation私有保存实际MAC，immutable；public仅新增local_mac_observed布尔，不含地址值。
- attr6原encoded仍保留在extra/unassessed/raw库存；新增消费不表示其余未知metadata已解释。
- Connection同轮MAC必须非None且等于已认证COMPLETED STATUS的private `address`；不能从`bssid`、BLE/go地址替代或填补本机MAC。
- 本机MAC加入既有两轮kernel稳定key；原双STATUS全字段一致判据仍在，所以双STATUS本机地址改变可先触发status_mismatch。
- readback原exact当前op.result/owned observation准入保留；新结果发行后、赋op.result之前只比较新旧actual本机MAC。
- 跨readback MAC变：固定kernel_mismatch、op.failed=True、仅该新分支op.reason=kernel_mismatch；旧结果和新observation/readers/raw库存都保留。
- 原station/BSSID跨readback契约不顺带改变，原finally/取消/checkpoint/absoluteTTL/资源证明与恢复所有权保持。

## 实际新增测试 / 边界

- e75106：唯一首批10方法，5.896s，OK，exit0；没有首FAIL/ERROR。
- 首批包含实际新reader over FakeIO与实际新Connection.run/readback；Provider是冻结v15文件在同域private loader加载，不是自写stub issuer。
- 覆盖合法MAC与不同BSSID/BLE、None、短/长/空/零/multicast/flagged/重复attr、三GET变化、STATUS mismatch、双round变化及readback新MAC。
- 原socket/文件/native/进程/OS入口有tripwire；成功/失败核原库存关闭，不将Fake当P011。
- 首批exact逆向替换完整恢复两个旧v15源SHA，Python3.5 AST通过；未跑v15旧suite。
- ROOT允许仅新readback拒绝分支补fixed reason后：ef2639只该受影响原新方法1，1.342s，OK，exit0；新增reason断言、逆向模板同步。
- 10不同方法，首10+精准1不是新11个；未重复首批或最后逆向方法，不用前pin证明后pin未跑分支。最终hash另读回。

## 停写身份

- reader：4ebfedf198673e3bad2f64a4bd72c581e5d6af24cef83e589b4456d2a38f8ede（413行/23702B）。
- connection：1eaf385b0921748b84414361b7bd1df06ffcb2489ea8ba567a1428b8b29daa2e（281行/16118B）。
- test：255cb4cb604821aa38e9366db845cb3d738943b13e93ad9a890387c34c68a4fc（161行/12031B）。
- 没有graph发布/正式freeze/实际INIT/ZIP；当前仍缺持久关联票据、CLIENT地址子租约与可信DHCP producer接线，不能以本节观察代替。
