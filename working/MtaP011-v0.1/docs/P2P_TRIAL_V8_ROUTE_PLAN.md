# V8 同次拒绝路由摘要：独立有限试验入口

状态：仅新入口 HOST 实现；没有本入口的正式冻结、ADB、RF 或 IP 实机验收。
生产 send_available 仍为 false；不配置 DHCP、不创建应用 TCP/UDP/TLS socket、不启动 BLE/UI、不访问手机或用户文件。

## 范围与固定参考

运行候选 `native/private-p2p-runtime-candidate-20261001-v8routediag/runtime/mta_send_wifi.py`，
SHA-256 `83770b7e9264dbcb8887d323e9b49771e3db46e8144a7325fccbaa8be8ba7e89`，90829 字节；
marker `p011-go-ip-only-v8routediag-1`。version3 / kind go_ip_only / core/helper/native 不变。
仅补充原 predicate 拒绝后、同次已分词当前行的 route_details，不再读内核，不授权新路由，
不放宽 carrier、地址、前缀、路由、租约、收据、watchdog、恢复或生产能力。
详见已审 `P2P_IP_V8_ROUTE_DIAG_REVIEW.md`；/8 多播是主源码假说，不是本入口已有 P011 事实。

独立新入口只复用固定 V7 parser/FD 程序及其已审旧参考，不修改任何旧 globals，不调用旧 runner。
HOST 固定 V7 harness SHA `1354a0f3b51a511cdbf3affdedda2ea8aa50bcf24b8221c94475fe60aa068c51`；
V7 tests SHA `0e5ae55fa9d0a4d2c1b1c657fe0e81464b6019e1cb5cd66716a8ad22bc731086`。

PRIOR-only registry 只含确切 V5 `0f2a45489fd3e03b`、V6 `916a02d44aeeaf0d`、V7 `3cbd5bf8e5c718b9`。
V7 固定来源 `logs/MtaP011-P2pV7L3DiagFreeze-20261001-072118-29cffe87/private-candidate`，
完整 manifest SHA `3cbd5bf8e5c718b91443a111d94c4adae297b5d988bb332a820f9f696a1e7c0e`，654 字节。
本轮已只读取得该 SOURCE 的全部七 payload pins/尺寸；V7 runtime 为 fbf39cf…、85568 字节。
每个旧候选 manifest、七 payload 全 SHA、原 marker、process.exe、完整原基线与 PID gone 均独立核实。
已清历史 journal 只用于 admission；不迁移、不改写、不删除、不自动 recover，不接受未来候选。
当前 journal/pending/owned 只按新的 V8 identity；未知身份或读取错误阻断。

## 唯一执行顺序与文件真实性

1. HOST 验证源码参考、固定 V7 原八文件、当前 V8 包；新包为五 runtime＋两个原 native＋654B manifest，总八文件。
2. 明确选择 P011；先保持原 V5/V6 fixed16 readonly 验证，再另做 fixed V7 eight readonly。
   两个报告是实际16和8，不将旧16计数硬改24；每个对应八文件全 pin/size/mode/owner/nlink/metadata。
3. 第一独立完整原厂/STA/IPv4全部表、地址、rules/IPv6/进程/接口/boot 基线。
4. 新候选 fresh-only，所有目录 canonical/noSymlink/root-owner/0700；已有目标即拒绝。
5. push 仅新八文件；不导入候选，先持有八 O_NOFOLLOW FD 全部校验后才 fchmod 新 manifest/runtime0400、native0500。
   全 SHA/size 与同 FD/路径身份读回、全部 close 尝试；独立第二程序完整 reread 后才验证新候选源码。
6. 严格 prior、global pending；创建空的 owned session。RF 前最后验证新八文件、旧16、旧V7八、全部 prior。
   新/旧各自 metadata 指纹相同，最后完整原基线须与第一份逐字段一致。
7. 唯一 `--trial --ttl 20` 调用，无自动 retry/recover/reboot 或全局服务动作。
8. finally 用旧独立已验证程序检查完整原厂/STA/双栈原基线；只有新包已验证且 owned session 已创建才读当前 journal。

试验不是纯只读：仍沿原 IP-only 路径，若门禁通过会实际 NEWADDR；公开 ip_trial_requested=true。
失败或 partial fchmod 如实保留阶段/计数，不虚构未改文件；不删除 private candidate/raw，不重写历史 FAIL。

## 派生解析与验收

ip_creation_l3 为旧四键＋必有 route_details；未观察拒绝路由行仅{}，不能补 false 事实。
非空严格 values/observations/invalid_fields 三键：prefix exact int非bool0..128，destination_class 固定四类，
observations 仅已读固定 strict bool，invalid_fields 排序去重固定枚举且与对应值/布尔互斥。
正确形状拒绝行严格分区六字段：每字段完整事实或 invalid；flags 合法必须十位＋other_bits 整组完整。
冻结 runtime 的通用 formatter 虽可拷贝 partial，真实 _route_rejected 不产生 partial，因此入口不接受三键全空对象。
shape 拒绝只能 shape；parsed prefix 与旧 is128 布尔冲突即拒绝。未观察/accepted/地址拒绝不得带路由摘要。
它是“拒绝后同次文本观察”，不表示原 predicate 曾访问或接受 source/gateway/flags，也不授权多播或 local 路由。
仅深拷贝后移除 route_details 交给固定 V7 parser；原 raw 不改，重复键/自由文本/未知字段/额外行仍拒绝。
两个 terminal 事件包括新细节也必须相同；ready/cleanup 不能覆盖任一独立恢复门禁。

PASS 同时要求原完整 IP-ready、当前 durable receipt 恢复、所有新旧文件门禁/metadata、第一最后基线相同，
完整 IPv4/IPv6、stock/STA/boot/进程/接口/pending/journal 恢复。诊断 FAIL＋安全恢复仍是 FAIL，
ip_stage=none 不倒推出从未请求过写；不证明手机、DHCP、传输或驱动命令池完全恢复。
公开只有固定枚举、bool/count和源码/manifest摘要；原地址、SSID、MAC、PID、路径、自由异常文本仅 private raw。
入口不打 ZIP；未来公共包必须精确纳入 root 已审 result/README，排除 raw/source/journal/candidate。

## HOST 与后续操作

专项命令：`python -m unittest tests.test_device_p2p_v8routediag -v`。
2026-10-01 最终实际专项22/22 PASS、25.358秒、exit0；完整工具输出为 ac7958＋1435cd，无套测。
覆盖固定旧V7完整八文件、独立old16/old8、第二次HOST读取变化、所有最终门禁、flags整组/六字段分区、
无未来registry/错误manifest/pins、partial FD/close故障、RF仅一次、恢复成功不覆盖诊断FAIL与原raw保存。
测试仅 FakeADB/FakeOS、原 PC 固定 source pins、TemporaryDirectory 内临时候选；不是正式冻结或设备运行。
不会通过 HOST 临时候选 ID 提供正式 V8 ID。
ROOT 审阅全部三文件后可自行 `--freeze-only`，独立核对实际 manifest/八文件身份，再决定唯一 `--execute-reviewed`。
本子任务不运行这两种工作区/设备命令、不调用 ADB/RF/Docker/套测，旧 source 与历史证据不变。
