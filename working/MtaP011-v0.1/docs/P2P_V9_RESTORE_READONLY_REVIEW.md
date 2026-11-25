# 固定 V9 清理失败：当前恢复前提只读观察

新增三文件仅 HOST 实现与 fake 专项，未 ADB/RF/实际运行 probe、未修改任何已 pin 入口/runtime/helper、未执行恢复或整套测试。ROOT 的 `084811-e064eae6` 功能试验为 FAIL，GO/IP_READY 是真实阶段证据，但 cleanup、完整 IPv4 和 pending 尚未恢复；不能改为完成。

## 已知事实与因果边界

固定 runtime `cfe24fba81332082d4033e148578ac088e07e7efce0ab037f499a40e887901fb`；helper `39373dba355557ee73cfac354bdbaa95eaf0ddde4e27313450edf0e74742f12c` 均未改。

原 helper `restore()` L334–357 在两次 `_gate()`、snapshot、receipt/基线检查之后才进入 `delete_intent`。本轮 cleanup 仍 `confirmed`，可把正常代码路径收窄到该赋值之前。V9 `_stop_locked()` L1402–1403 吞掉恢复异常，只记录 `ip_ok=False`，因此不能确定是恢复身份/L3、5 秒预算、地址/route delta、原网状态还是其它读异常。

离线读取原 actual after RESULT：自有 IPv4 地址一条 /24 PERMANENT scope0；自有 route 仅一条 /32 table255 proto2 scope254 type2 flags0。旧 `without_owned()` L267–274 要求四条 expected routes 全部存在；当前单条 local route 不能满足旧门槛。WPA 停止发生在 IP 清理失败之后（V9 L1405），故现存子集不能倒推第一次 stop 时的路由状态或失败原因。

## 固定入口与不变边界

```powershell
python -B host/device_p2p_v9restore_readonly.py --check-readonly
```

- 只固定正式候选 `1d695a9e8056e11f`、完整 manifest `1d695a9e8056e11f20039cd3f5b3f6982645a61993f7013fbd76d81064df8c06` 和唯一失败 run `084811-e064eae6`。不提供候选/run/command/output/TTL/recover 输入。
- 引用 bounded 入口 `20e816a946ff4a4470db61134ca38f22f342e3cdac55711b8ac2e0dc52b75fea`，复用其固定 V9/旧引用链与 exact old16、V7 eight、V8 eight、current V9 eight 初末 FD/元数据/SHA/0400-0500 检查。候选不 stage/push/chmod、不改旧 globals。
- 所有输入程序与完成 payload ≤256 KiB、单行 UTF-8 ≤2048 B、3.5 AST；继承原 raw 保存、unique RESULT/OK/remote-exit、50 秒 HOST 超时。未知/缺失/重复/截断或超时 FAIL，不能将 HOST timeout 当远端退出。
- 只构造 `LinuxBackend(...allow_rf=False)`；不调用锁/acquire、controller/start/stop/recover、地址 ACK/DELADDR/remove、journal/pending save/clear 或 RF arming。对象 `__new__` 先保留引用，构造失败仍尽力关闭已知资源但不假定未知构造完成。
- 构造成功立即强引用实际 `backend.nl.sock` 与 `backend.ip_transport.socket`。finally 分别关闭所有已知资源，再要求两个 retained 对象真实 `fileno()==-1` 且 `ip_transport.closed is True`；单凭 close 返回或字段变 None 不能报 sockets closed。

## 两次同源当前观察

每次读取固定 journal 严格 schema/current identity、完整 durable receipt、pending exact owner/run/boot、原厂 pins；严格 process_absent 双检，实际接口 name/ifindex/WDEV/phy/type 与 sysfs ifindex/flags/carrier；IPv6 地址和原恢复 route predicate；当次完整 IPv4 地址/所有表 routes/默认规则及原网 baseline。

七个原 baseline 差异组为 boot、original_processes、station_identity、original_interfaces、frequency、station_state、original_ipv6（最后一组包含地址和 route 两个 digest）。私有全字段含 cacheinfo/地址/所有 routes/rules、journal/pending、接口/sysfs/IPv6 原始数据均进行 first/second 相等检查，不只比较公开计数。

actor 扫描至多 512 个 numeric PID、每 PID 检查 deadline；非空 cmdline 必须 NUL 结尾，不接受截断；只有 ENOENT/ESRCH 且严格双检 absent 才跳过。空 cmdline 需实际 stat 的 PF_KTHREAD 标志才视为 kernel thread；opaque/权限错误/未知 live actor 不是 gone。当前 probe 自身只按实际本进程 PID 排除，其他 readonly producer/trial/recover/private WPA 会阻止 observed prerequisites。

carrier 仅观察，不是旧 restore 条件。仅 flags 格式有效且已 DOWN 时，carrier 读取 EINVAL 可作为 private None、公开 `carrier_read_unavailable_down=true / carrier_read_valid=false`，不伪造 carrier=0；UP 上 EINVAL、EACCES、缺文件等仍 FAIL。ROOT 核实的 [Linux4.14 carrier_show](https://raw.githubusercontent.com/torvalds/linux/v4.14/net/core/net-sysfs.c) L171–179 对非 running 接口返回 EINVAL，支持此窄观察契约。

IPv4 公开事实分别保留：exact receipt 地址含全部 cacheinfo 是否存在、同 ifindex 是否恰一地址、owned route 数量/四条 exact expected 存在数、无 duplicate、是否 exact expected 子集、current==baseline、旧 without_owned==baseline、减去 exact 地址与**实际** expected subset 后全 IPv4 是否等 baseline。未知/重复/flag 改变/其它地址或规则不可认领；纯观察不导入尚在制作的新 recovery core，不删除任何资源。

`check_complete/PASS` 仅表示两次完整一致、socket 闭合、四组末 metadata 与完整当前 before/after baseline 均未变。`restore_preconditions_observed` 另为旧严格 gate 可观察前提的合取，缺四 route 时保持 false；即使 subset fact 为 true，也不升级旧门槛或 mutation 授权。`authorization_or_lock_held=false`、`network_mutations=false` 永久明确；历史原因 `NOT_PROVEN`。

## HOST 证据及下一步

命令：`python -B -m unittest tests.test_device_p2p_v9restore_readonly -v`。最终 **15/15 HOST PASS，3.376 秒，0 FAIL / 0 ERROR，exit0**（`675ee5`）。测试只执行 fake backend/kernel/ADB 与已有纯 bytes/receipt decoder；不是真实 sockets、P011 或恢复证据。

保留首次 `124d2a`：14 项、1 FAIL，duplicate route 被严格 snapshot decoder 在更早阶段拒绝，原测试错误期待完整负观察；只修正测试期待为 failclosed，不放宽生产 decoder。最终增加 exact fd 闭合、unknown constructor/无效果 close、DOWN EINVAL、opaque/NUL/PF_KTHREAD/512PID fault。

其它覆盖：完整四 route、精确单条 subset、未知 route/flags/cache/其它地址/规则/重复、七组 original 差异、pending/boot/stock/PID/type/sysfs/IPv6、时间/两次状态改变、严格 result bool/int/enum、raw不改、secret不公开、初末元数据/timeout/trunc/after fault、无任意 CLI/变更调用。

ROOT 全文审查后才可唯一执行此只读 probe。真实旧严格前提/新 subset 事实和 producer/stock 当前证据分别审查，再决定唯一精确旧 recover 或另审新的窄恢复方案；不自动 retry，不以任何观察结果直接授权 DELADDR/netdev 删除。
