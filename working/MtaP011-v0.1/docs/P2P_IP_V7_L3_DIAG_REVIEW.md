# V7 L3 同次观察诊断候选

状态：独立源候选，仅 PC HOST；尚无冻结 manifest、P011 执行或手机互通证据。
不得执行旧 START、旧 harness 或修改其全局常量来绕过固定源验证。

## 已知事实与仍未知的原因

- ROOT 的 `logs/MtaP011-DeviceP2pV6DiagPermissions-20261001-061551-48fbed57/result.json`
  保持 FAIL：RF 已进入，14 个 native stage code=0，`ip_create/interface_l3` 拒绝。
- 六项已观察的 identity/carrier 布尔值均 true；本轮不是 carrier 门禁拒绝。
- 失败内层 cleanup 完成，独立原厂、STA、完整 IPv4/IPv6、接口和进程核验恢复；
  journal 为 reconciled、IP stage none、pending clear。最终 none 不反推首次未写 IP。
- 现有结果不能分辨地址检查或路由检查，更不能证明某个 `/128` 是本机原因。

Linux 4.14 primary source 给出的可能兼容边界：

- [addrconf.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/ipv6/addrconf.c)
  L2880–2899 自动建 link-local `/64` 和前缀路由；L958 调用 local dst 分配，
  L5195–5211 在地址通知时插入该 host route。
- [route.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/ipv6/route.c)
  `addrconf_dst_alloc` 创建 local `/128`。这是上游语义，不是 P011 的现场路由证据。
- [ip6_fib.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/ipv6/ip6_fib.c)
  L1995–2013 的 proc 输出仅在 RTF_GATEWAY 时显示内部 gateway；否则输出零。
  不能把内部 self-address gateway 误判成 proc 的非零 gateway。

## 最小实现与不变项

- 新源：`native/private-p2p-runtime-candidate-20261001-v7l3diag/runtime/mta_send_wifi.py`。
- 新测试：`native/tests/test_send_wifi_v7l3diag.py`；其余实现、旧测试/日志均不改。
- marker：`p011-go-ip-only-v7l3diag-1`；journal version=3、kind=go_ip_only，
  identity 仍为原六字段，仅 runtime_marker 改变。旧 V6 journal 不被新 recover 接管。
- 保留原 `_only_link_local`、`_owned_routes_safe` 和全部 restore/cleanup 函数。
  creation-only twins 按原字段顺序与短路判定，仅记录此次实际访问的拒绝分支。
- creation 仍只进行一次 `_address_dump`；地址拒绝则不打开 route 文件。
  route 函数仍只打开一次 IPv6 proc 文件，第一次拒绝后不读后续行。
- 不放宽 prefix、scope、link-local、source、gateway、carrier、原网络、归属、TTL、
  CREATE|EXCL、ACK、durable receipt 或任何删除条件。shared helper/core/WPA 不改。
- 无新增地址/接口原始载荷落盘；进程内诊断不写入 journal/pending。
  公开不含地址、接口名、MAC、SSID、PID、路径、异常文本或任意键。
- 收集首个 L3 拒绝并在 cleanup 前复制；restore 不收集或覆盖 creation 诊断。
  诊断自身异常 fail closed，不可授权地址写入；实际 L3 读异常保持原传播/拒绝路径。

## 公开 schema

ready、failed、最终 cleanup/recovery 事件增加顶层 `ip_creation_l3`；原事件字段不变。
对象精确四键：`reason`、`stage`、`counts`、`observations`。

`reason` 固定枚举：

```
not_recorded accepted address_family address_prefix address_scope address_length
address_not_link_local route_shape route_prefix route_destination route_source
route_source_prefix route_gateway route_hex_invalid unexpected_l3_read
```

`stage` 固定枚举：

```
not_recorded address_dump address_fields ipv6_routes route_shape route_destination
route_prefix route_source route_source_prefix route_gateway done
```

`counts` 仅：`ipv6_address_rows`、`ipv6_address_rows_examined`、
`ipv6_route_rows_examined`。值必须 int 非 bool，范围 0..4095。
地址 rows 是原 dump 返回的属性行，不能解释成唯一地址数量。
examined 只计已检查的行；不为了求总数越过原短路。
超过上限饱和且 `count_saturated=true`，此时数值仅是下界，不是精确总量。

`observations` 仅 strict bool：`address_dump_complete`、`addresses_accepted`、
`routes_accepted`、`route_prefix_is_128`、`count_saturated`。
未访问项缺失，不填 false。`route_prefix_is_128` 仅属于当前实际解析的 owned 行；
下一行未能解析时清除旧行该字段。accepted 只表示本次 L3 检查通过，不表示 IP/互传完成。

## HOST 验收与下阶段门槛

命令（项目工作目录）：

```
python -m unittest discover -s native/tests -p test_send_wifi_v7l3diag.py -v
```

45 项 PC HOST PASS；fake kernel/journal/lock/sysfs，没有真实 socket、flock、fork watchdog、
RF、ADB 或 P011/PHONE 试验。包含 Python 3.5 AST，无 assert 副作用。
对照 V6 验证相同布尔判定、读取次数及顺序，逐字段短路、计数饱和、公开白名单、
异常 fail-closed、创建拒绝不写地址、cleanup 前快照及诊断不进入 journal。
AST 对照验证其他全部既有函数不变；helper/core/旧 V6 固定 hash 未变。

ROOT 审查后才决定新独立 harness/entry、七文件 manifest 和最多一次 TTL20 试验。
不得改旧 run/globals；新 parser 严格验证新增对象，原事件副本去除新键才复用旧纯 parser。
prior admission 只能读取已核实旧候选，不能迁移其恢复归属；新 staging 必须先私有目录，
每个 FD 核验 pin/size/owner/nlink，再设 runtime/manifest0400、native0500并全量复核。
本候选不是 prefix/gateway 修复，也不是 IP、DHCP、完整发送或手机互通成功。
