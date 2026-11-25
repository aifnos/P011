# V9 bounded：只改变 HOST 传送形状，复用已部署候选

本轮只有 HOST 实现与 fake-device 专项。未 freeze、未执行 ADB/RF、未重启/恢复设备、未修改旧文件或全量测试。旧 V9 `082419-8c70df17` 的 preRF FAIL 永久保留，不能据此文档改为 PASS。

## 固定身份与边界

- 唯一候选：`1d695a9e8056e11f`；完整 manifest：`1d695a9e8056e11f20039cd3f5b3f6982645a61993f7013fbd76d81064df8c06`，654 B、七 payload。
- 使用 ROOT 已冻结、已部署且规范化为 runtime/manifest 0400、native 0500 的原候选，不生成候选目录、不 push、不 fchmod、不 freeze、不调用旧 runner、不修改旧 module globals。
- V9 runtime SHA：`cfe24fba81332082d4033e148578ac088e07e7efce0ab037f499a40e887901fb`，92153 B，marker `p011-go-ip-only-v9mroute-1`，实际 journal 只接受它的 v3 identity。
- 新入口固定校验旧 V9 三个引用 SHA：harness `314d7c1db02cd6591d4b4ace5197923e21145df2d3226eee749e30d90c2b8ae6`，tests `da66ddb073e0dcd81d889084fd2dd78f8b61433ecda48bb3b91843ee69cb9ffe`，plan `2be9633f8ae7631f29b342238c0224d9ed20d9c1e39cd372ec3d0daa608b1bc5`；随后复用它们已审的固定引用链和全 manifest/payload 校验。
- 历史 PRIOR 仍恰为固定 V5/V6/V7/V8 四项，完整 manifest、七 pins、marker/identity/exe 路径原样；只读 admission，不迁移、不 recover、不接受 future 候选。

## 传送修正与可证明的等价

`bounded_program()` 仅把已审顶层 `PRIOR_CANDIDATES` 与 `CANDIDATES` 的纯字面量赋值展开多行，保留字典与序列顺序；其它代码不改。每个新 literal 必须 `ast.literal_eval()` 与原值相同，整段新旧程序的 AST（仅忽略位置）必须完全一致。

所有实际传入 `stdin.read(N)` 的程序，包括追加的 `MTA_READONLY_OK` 语句，都进行 UTF-8 单行 ≤2048 B、总量 ≤256 KiB、Python 3.5 AST、无 `assert` 检查。未知长行、非纯字面量/非字符串 key、浮点/集合、超深/超长、AST 不等都在设备调用前拒绝，不截断源码。

旧 fixed16 程序的 `CANDIDATES` 单行 2269 B 也需展开，不能只修 prior 后声称所有行都有界。旧 prior 完整 payload 32270 B，最大行 4500 B；HOST canonical-4095 模型丢失恰 405 B，新 payload 在该模型中完整且值/AST不变。该模型不是设备 TTY 或修复成功证明。

复用固定 remote helper，不改 50 秒 HOST 超时、raw 保存、严格 UTF-8 派生与唯一 `RESULT`/`MTA_READONLY_OK`/`MTA_REMOTE_EXIT` 校验。源码回显不当实际返回；超时/缺失/重复/未知 marker 均 FAIL，原 stdout/stderr/host-exit 保留，不推断远端 producer 退出。

## 两个互斥入口

ROOT 在任何入口前先独立核实旧 `mta-prior-readonly` producer 已退出和实际 TTY 状态；旧 trial-actor gate 不足以证明该 producer 消失。未知活 actor 不得继续。此 HOST 入口不能以自身 no-RF PASS 代替这项外部前置证据。

```powershell
python -B host/device_p2p_v9bounded.py --readonly-preflight
python -B host/device_p2p_v9bounded.py --execute-reviewed
```

- `--readonly-preflight`：initial old16、V7 eight、V8 eight、current V9 eight 各独立 FD/元数据/SHA/0400-0500 门槛；first 当次完整 baseline；一次 bounded PRIOR；last 四组各自元数据一致；last 完整 baseline 等于 first；finally 独立 full after。没有 run directory、trial command、journal/import trial、RF/IP 创建。公开 `readonly_only=true`、`rf_trial_invoked=false`、`ip_trial_requested=false`、`go_ip_ready_event=false`；`pass` 只表示完整只读前置检查。
- `--execute-reviewed`：上述 initial/first/prior 之后才创建唯一新 0700 owned run；last 四组各自指纹及第二次 prior；最后真实完整 baseline 与 first 完全相同；唯一 TTL20 功能试验；finally 独立 after 和 owned journal。源码不改 TTL、IP receipt、watchdog、create/restore 门槛或旧 ff00 profile。
- 四组身份不合并为一个指纹、不把旧16计数偷偷扩展；current/V7/V8 各八项单独读回。全 IPv4 地址/所有表 routes/rules、完整 IPv6 raw、原厂 hash/PID/starttime、STA fullstate/boot/接口/进程/pending 全门槛合取；ready/主 phase 不能掩盖恢复、收据、socket/journal 错误。
- 任意 first/last 文件、prior、baseline、run、解析或恢复异常都 FAIL；finally 尽力保留独立 after。无自动重试/recover/reboot/DHCP/BLE/TCP/UI/用户文件/phone，没有能力解锁，send=false。
- CLI 不接受 frozen/candidate/device/destination/output/TTL/command 参数；测试 `_output` 仅临时私有 HOST fixture。公开结果只有固定字段/符号/pins，原始标识只在 private raw；本入口不创建 ZIP。

## 本轮专项证据

实际命令：`python -B -m unittest tests.test_device_p2p_v9bounded -v`。

首次专项 **15/15 HOST PASS，22.357 秒，0 FAIL / 0 ERROR，exit 0**。工具 stdout 可追溯 `dceccc` → `eb914f`；未伪造新的 P011/PHONE 或物理恢复证据。此 15 项包含多个 fault 子用例，不将子用例数量冒充 unittest count。

覆盖：旧405 B缺失模型/新完整及 AST 等值；全部生成程序与完成 payload line/size/AST；精确八 pins/历史四 registry；旧 globals 不变；未知长行/future/ref/identity/pin 拒绝；只读单 prior零run/RF；功能单次TTL20；全部 first/last 元数据和 baseline fault；timeout/源码回显/missing/duplicate marker；全 IPv4/IPv6/boot/process/pending after 及完整 journal/receipt false 不假成功；raw不改、固定50s、无 secret 公布和任意 CLI。

ROOT 下一步先全文审阅新三文件及固定引用，再唯一执行 no-RF preflight。仅真实 prior 完整返回且全部原状态 unchanged 后，另作是否有限 RF 的决策；只读成功不直接授权或宣称功能 GO/IP/互传成功。
