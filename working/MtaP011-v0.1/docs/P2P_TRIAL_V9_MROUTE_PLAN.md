# V9 精确内核多播路由兼容：有限 GO-IP 功能试验入口

状态：新入口仅 HOST 实现；本子任务不进行正式冻结、ADB、RF/IP 实机或套测。V9 是 **FUNCTIONAL GO-IP** 候选，不是只读或仅诊断：门禁成功可实际 NEWADDR。生产 send_available 始终 false；无 DHCP、应用 TCP/UDP/TLS、BLE、UI、用户文件或手机验收。

## 固定候选与唯一功能变化

runtime `native/private-p2p-runtime-candidate-20261001-v9mroute/runtime/mta_send_wifi.py`，SHA-256 `cfe24fba81332082d4033e148578ac088e07e7efce0ab037f499a40e887901fb`，92153B；marker `p011-go-ip-only-v9mroute-1`，journal version3/kind go_ip_only。五 runtime/两个原 native 的核心、helper、WPA/caps pins 不变，公共 L3 schema 同 V8。

ROOT 审核的功能变化仅原 creation/restore 两条路径共同支持当前 exact owned name 上最多一条 canonical `ff00::/8`、零源/源前缀/网关、仅 RTF_UP 的内核多播路由；metric/ref/use 是固定十六进制字段形状，不是归属常量。非 exact/重复/其他 flags 不接受。地址、carrier、原网络/进程/epoch、durable receipt、DELADDR 归属、watchdog、恢复条件不由此入口改变。

V8 实际 `logs/MtaP011-DeviceP2pV8RouteDiag-20261001-075353-9ad31b4d/result.json` 仍为 FAIL：拒绝行公开摘要为 prefix8/multicast/onlyUP/零源网关，原厂/STA/完整双栈与清理独立核验全部通过。摘要本身不是任意 multicast 许可，也不证明 V9 功能已成功。

## 固定参考与历史 admission

V8 harness `1000b427c8df75891048b92f584ccf39f49f5f2bd679c2638d8d6f24ce3ac713`；tests `e7608005f0b58f7e9a32058f743af95185e2c8ab2cc3ba7f95b6b62a35690472`；plan `46766784b595085962ddc50d2f89a4fd887060b25942b2a0535e08223e8db02a`。三参考及其 V7/V6 链都在 HOST 验证。仅复用已审纯 parser、文件 FD 程序、独立 baseline/PRIOR/JOURNAL 字符串；不调用旧 run，不修改旧 globals，不导入 frozen runtime，不生成其 bytecode。

PRIOR-only 自有 registry 只包含 fixed V5 `0f2a45489fd3e03b`、V6 `916a02d44aeeaf0d`、V7 `3cbd5bf8e5c718b9`、V8 `7e98dbf4a03abcfa`。各历史候选 full manifest/七 payload pins/原 marker/process.exe/基线/gone 身份仍精确校验。只读取已清 historical journal，不迁移、不修改、不恢复；current journal/pending/recover 只按新 V9 identity。

固定 V7 来源沿旧入口的 `logs/MtaP011-P2pV7L3DiagFreeze-20261001-072118-29cffe87/private-candidate`，完整 manifest `3cbd5bf8e5c718b91443a111d94c4adae297b5d988bb332a820f9f696a1e7c0e`。固定 V8 来源 `logs/MtaP011-P2pV8RouteDiagFreeze-20261001-075316-238ce1ff/private-candidate`，完整 manifest `7e98dbf4a03abcfaf2cbd38e5f4d95d51e2de2969166b2a3dc5557d606d03c29`/654B，runtime `83770b7e9264dbcb8887d323e9b49771e3db46e8144a7325fccbaa8be8ba7e89`/90829B；其余六 pins/size 精确相同。额外文件/目录（包括 bytecode）仍严格阻断，不靠忽略 cache 绕过固定身份。

## 执行顺序与写范围

1. HOST 校验全部固定参考、历史 V7/V8 原八文件、新 V9 七 payload＋654B manifest；expected candidate 与完整内容相符。不接受未来 registry。
2. 显式选择 P011；分别进行 old V5/V6 fixed16、fixed V7 eight、fixed V8 eight 的初次 readonly mode/owner/nlink/pin/metadata 核验。三个实际报告不偷用同一 fingerprint，不将 16 硬改成 32。
3. 获取第一份实际完整原厂/STA/boot/进程/接口、所有 IPv4 地址/所有表 routes/default rules、IPv6 地址与路由 baseline。
4. 新候选 fresh-only canonical/root-owner/type/no-symlink/0700 目录；只 push 新八文件。已存在目录拒绝。全部八 O_NOFOLLOW FD owner/type/nlink/size/SHA 验证完成后才 fchmod 新 manifest/runtime0400、native0500；全 FD/路径读回、每个 close 都核实，另独立完整重读后才 import/RF。partial open/fchmod/close 失败如实保留，不虚构未写。
5. strict prior/pending，创建 owned 空 session；RF 前最后分别验证新8、旧16、V7八、V8八与所有 prior。新旧各自 metadata 初末一致。最后完整 fresh baseline 逐字段等于第一份，并作为真正进入 RF 前的 before。
6. 唯一 `--trial --ttl 20` FUNCTIONAL 调用；无自动 retry/recover/reboot，无全局服务变化。候选若创建门禁通过可写 owned IPv4，所以公开 ip_trial_requested=true。
7. finally 保持旧独立核验程序完整读回 stock/STA/全部 IPv4 addr/all-table routes/rules/IPv6/boot/PID/接口/actors/pending。仅新文件已验证且 owned session 已创建才读取当前 version3 journal/地址收据；失败不自动删资源或接管其他候选。

## 解析与 PASS 门槛

V9 固定公共 schema 同 V8，直接复用固定 V8 parser：strict enums/counts/bools/prefix、完整 rejected-row facts 分区、unknown/duplicate keys/额外行/事件冲突拒绝。原 stdout/stderr/exits/raw 保持，只有派生对象进入公开 result；路由摘要不被入口用来授权地址写。

PASS 同时需要真实 ready、原 cleanup、IP durable receipt 已恢复、完整 current journal/pending 与独立 stock/STA/双栈恢复；再合取新旧每项文件核验/metadata/prior/第一最后完整 baseline 相等。ready 与成功 cleanup 不能覆盖任一恢复失败；诊断/功能失败而安全恢复仍是 FAIL；ip_stage none 不推断从未请求写。不存在新的 send/phone 解锁。

公开仅固定阶段/枚举/bool/count、源码和 manifest 摘要。SSID/MAC/IP/PID/自由错误/原 journal 只在 private raw；不生成 ZIP，不打包 frozen source/raw/密钥。新入口仅在 ROOT 全文审核与正式冻结后，由 ROOT 决定是否一次执行。

## HOST 入口与证据

专项：`python -B -m unittest tests.test_device_p2p_v9mroute -v`，FakeADB/FakeOS＋TemporaryDirectory 临时源 fixture，不是正式工作区冻结，也不运行 ADB/RF。覆盖 V8 新历史身份/独立 metadata、所有 pre-RF 故障、future/错误 manifest/pin 拒绝、raw 保持、一次调用与完整恢复门槛。

首次输出 `678902` 留存：6 项运行，1 fixture FAIL 与 setUp ERROR；后者由固定 V8 本地 frozen 目录存在额外 __pycache__ 引发原门禁，未删除/忽略/放宽。fixture 起初将本来已 False 的值再次设 False，没有真的制造 terminal 差异；只改 deepcopy 后的六项输出 `8c53ba` 仍 FAIL，进一步核对旧 fixture 默认值才修为 True。早先 alias 解释只是初判，实际原因是未改变值。六项 parser/FD 测试随后 `f3bdbf` PASS，仍不是完整入口验收。

ROOT 单独核实唯一生成 pyc 与原八文件 pins 后，将 cache recoverable 移到独立私有 HOST 隔离目录；生成进程未知，不作因果归属。原七 payload/full manifest 未改，旧 strict V8 verify_frozen `0c82c5` 恢复通过，不放宽 validator。本子任务未 import frozen runtime，也未改/删除旧 artifact。

随后 -B 完整专项 17 项/49.398 秒输出 `916f5b` 至 `ca5514` 有 1 FAIL：FakeADB 父 fixture 在 Timeout 前记录旧 V8 label，子 fixture 仅正常返回时映射 V9 label，导致一次调用计数错误为零。只修新测试的 finally 标签记录，不改 entry 或原 fixture；历史失败保留。

最终 -B 完整专项 **17/17 HOST PASS，48.912 秒，exit0，0 failure/0 error**，连续工具输出 `2e1b8b`、`9523c1`、`dbb49c`。全部是 HOST/FakeADB/内存 FD 故障注入与临时候选；不是 P011 import、RF、IP 创建/恢复、watchdog 父死或手机互传验收。尚无正式 V9 candidate ID，不用临时 fixture 身份冒充正式冻结；ROOT 待三文件最终审核后才自行决定正式 freeze-only 和唯一有限试验。
