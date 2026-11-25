# CLIENT caps transport：只读 split dump

## 边界

仅新增 `runtime/mta_client_caps_transport.py`、`tests/test_client_caps_transport.py` 与本文。
import／constructor不做I/O；显式 `ClientCapsReader(phy).read()` 在Linux打开一个私有
AF_NETLINK／SOCK_RAW／NETLINK_GENERIC socket，完成三项固定只读请求后finally关一次。
没有线程、重试、scan、RF／IP写、外部进程、通用command、UI参数或 capability 开放。
测试注入的factory／clock是可信内部HOST依赖，绝不是byte→kernel证明或生产可用开关。
不改旧decoder、CLIENT owner/core、native、现有probe或任何冻结候选；部署须由ROOT固定完整依赖图。

## 主来源与消息合同

- [Linux v4.14 nl80211 UAPI](https://raw.githubusercontent.com/torvalds/linux/v4.14/include/uapi/linux/nl80211.h)：
  GET_WIPHY=1、NEW_WIPHY=3、GET_PROTOCOL_FEATURES=95、PROTOCOL_FEATURES=173、SPLIT_WIPHY_DUMP=174；
  SPLIT_FEATURE=1包括按WIPHY过滤。数值由官方enum顺序核实，不复用省字段probe JSON。
- [v4.14 nl80211.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/wireless/nl80211.c)：
  family version1/hdrsize0；feature reply command95；split send_wiphy每片重复WIPHY/name/generation。
- [v4.14 genetlink.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/netlink/genetlink.c)：
  ctrl family version2、GETFAMILY3→NEWFAMILY1；响应头port取snd_portid（实际请求socket port）。
- [v4.14 af_netlink.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/netlink/af_netlink.c) 与
  [netlink.h](https://raw.githubusercontent.com/torvalds/linux/v4.14/include/net/netlink.h)：
  recvmsg peer来自NETLINK_CB而非nlmsg_pid；dump DONE为MULTI并含4B返回码。两者不能混为kernel headerpid0。

socket bind(0,0)后要求实际正整数port、group0、non-inheritable读回False。
三次sequence严格1/2/3、请求headerport实际值；CTRL和nl80211版本分别2/1，reserved0。
family response只known ctrl attrs1..7；scalar/嵌套索引/长度/flags/重复字段严格检查。
固定family name、dynamic ID19..1023、nl version1/hdrsize0、maxattr有界，feature仅值1接受。
split请求固定WIPHY+空flag174、REQUEST|DUMP、不请求ACK。收到kernel peer恰(0,0)，headerseq和port须匹配。
单项reply flags0；dump每个message/DONE恰MULTI。ERROR（包括success ACK）／OVERRUN／DUMP_INTR／
未知flags／TRUNC／CTRUNC／任意ancillary／截断／非零padding／不匹配family-command-version均拒绝。
DONE必须匹配当前dump、已有data、body恰int0；第一个fragment或ACK都不完成dump。terminal后同packet还有消息拒绝。

## 完整raw与未评价字段

返回既有rich `DecodedCaps`，不生成旧complete dict／mutation admission，也不消除BI或radar presence。
每片WIPHY/name/generation恰1且所有片一致；只允许固定send_wiphy及其helpers已审顶层名单，不用编号范围。
五cap字段投影后复用严格decoder；未知top或未知组合／limit字段拒绝。组合、software、commands等required字段缺失拒绝。
已知u8/u16/u32／flag／binary／nested top做形状验证；非投影嵌套仅检查已观察的属性framing/flags，**不声称语义完整解析**。
bands／信道／监管、FEATURE_FLAGS／EXT_FEATURES、DEVICE_AP_SME、WoWLAN及vendor等在exact raw保留，
不能称已审metadata可忽略或已判无约束；未来provider必须按operation评审，reader成功不授权RF。
`raw_datagrams`、`raw_wiphy_messages`、`raw_requests`、`unprojected_attributes`仅私有证据，错误时仍保留。
公开status只有固定reason、bool和计数；`has_unassessed_fields`明确存在未评价内容，绝非unknown_constraints空集证明。
对象绑定本次实际socket、port、family与seq，不接受caller raw bytes或complete bool自签kernel来源。

## 预算及关闭

timeout先type/range后finite检查（0.1..10秒），一次共享deadline且clock回退拒绝。
send／receive前settimeout并精确核对CPython整数纳秒量化后的gettimeout读回（见末节），收到消息和decode后再检deadline；不硬抢占任意OS/factory调用。
receive MAX+1=65537B探测超限，ancillary buffer256；单packet65536B、总1MiB／128packet／256message／64片／4096top attrs上限。
exact收到的数据在检查前保留；预算边界最多多保留刚收到一片，不无界复制或重试。
finally保留强引用exact socket，调用close一次并读回actual fileno==-1才可返回成功。
factory抛错／未知创建、close抛错或fd未关闭：保留creator/socket引用与pending，未提供通用True清除。
read中KeyboardInterrupt／SystemExit也记录固定interrupted并finally关闭，不因close成功误报读取成功；close被中断仍pending。
同步read不创建后台线程；调用者若在非Main线程运行，应由外层owner独立记录其真实线程寿命，method return不是thread exit。
HOST fake socket只证明上述解析／资源协议；没有P011实际split dump、CLIENT创建／关联或手机兼容证据。

## HOST专项

首次且唯一整批命令：`python -B -m unittest discover -s tests -p test_client_caps_transport.py -v`。
实际a9e274：42项全部PASS、0FAIL／0ERROR、exit0、0.022s，PC Python3.12；包含runtime Python3.5 AST。
后续静审发现read中BaseException可能错误更新status，窄修固定interrupted并新增2项，不重跑原整批42项。
受影响命令：上述命令加 `-k base_exception -k close_exception -k python35`。
实际429f9b：4项PASS、exit0、0.005s（新增中断2项＋受影响close旧项＋AST）。
当前44项有对应通过证据（42首次＋新增2项；另外旧close/AST复核），**不是最终整批44重新运行的记录**。
首次无失败；保留42→窄修→4的实际证据层，不改写成一轮44。测试全程blanket禁止真实socket.socket。
Fake OS覆盖kernel peer/headerport/seq/genl ABI、DONE vs ACK、截断／budget／unknown字段、raw保留、single close与pending。
没有实际Linux／P011 split dump、ADB、RF、Docker、编译、套测、freeze、package、CLIENT关联或手机验收。

## 纳秒超时读回窄修

独立只读审查发现上一版runtime SHA `676f1780a4b10bcbf296153ecb4d9a490ee7b7c1a2f2e5413e7b85cc92c1521c`
在settimeout后逐位比较原始remaining浮点值，这可能在正常真实socket的首次send前误报timeout_readback。
旧HOST FakeSocket原样保存浮点、时钟固定，未观察该差异；上文a9e274／429f9b仍是原版本HOST证据，不能升级为真实Linux通过。

主来源：[CPython v3.5.5 socketmodule.c](https://raw.githubusercontent.com/python/cpython/v3.5.5/Modules/socketmodule.c)
2198–2273明确settimeout用`_PyTime_FromSecondsObject(...ROUND_CEILING)`存整数纳秒、gettimeout用`_PyTime_AsSecondsDouble`还原；
[pytime.c](https://raw.githubusercontent.com/python/cpython/v3.5.5/Python/pytime.c)208–272明确浮点秒乘1e9后ceil，读回为整数秒加余下纳秒乘1e-9。
因此本版计算`ceil(remaining*1e9)`，以`sec + ns*1e-9`核验exact float读回，不采用一般误差容限。
None／bool／int／float子类／非有限／非正／巨大值，以及比准确量化值仅差1ns的读回都拒绝。
没有重设共享deadline、补时、重试或修改收包／decode后的截止检查；CPython自身的纳秒向上量化不构成新的总预算。

FakeSocket新增显式纳秒量化模式，新增4项分别覆盖非整纳秒递减clock完整通过、异常读回类型和值、
原始未量化及相邻纳秒读回拒绝、量化模式的late DONE仍deadline失败。没有真实socket创建。
本次唯一新增／受影响命名批工具`154fef`：`python -B -m unittest -v <12 named tests>`，
**12 tests／0.007s／OK／host exit0**（4新增＋8受影响，含Python3.5 AST、请求／结果、deadline、BaseException关闭）。
测试文件现48个独立方法；不称本版48全批重跑，也不改写42→4→12的历史层级。
仅修改本节列出的runtime／tests／本文；无设备、实际socket、网络、Docker、全套或harness pin变更。
当前三SHA由交付消息记录，仍不是mutation admission或P011实际split dump证据。
