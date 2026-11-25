# CLIENT retained-stage v12 — SOURCE/Fake 只读检查

当前是待 ROOT 全文审查的新 SOURCE，未执行设备。默认仅开发 PC 本地来源核验；实际必须显式 `--execute-reviewed --expected-driver-sha256 <经审新入口全 SHA>`，单次准入，不自动重试、超时 kill 或清理。

## 范围与来源

固定历史仅 v11 `MtaP011-ClientInitTmpAliasV11-20261001-201536-51704b69`：保存源字节 SHA `b73e750d1cb55fab5c207391fc7112960cc7c77f740b606132d592614b184e6d`，stdout SHA `d39860a1024a3eaf32d101fc0b9ef72127fda5ae9cca4d976314b07460341966`，driver `89a982b0fba22e9720e00a98d95a84547287d38945567f2a53c639e8c5f09248`，candidate `8494abc69a933d72b7f3f85748e92fdb78ff857aa134885b133eb514c4a93298`。CRLF 保存字节和仅用于 echo 比对的 LF 派生文本不混用。

旧源只 AST/literal 数据解析：固定原 20 模块序、每个 encoded/raw/current 全 SHA、native 与 candidate 的 exact 21 文件清单。不执行旧 TARGET、F、Provider、Store，不重装 INIT 20 图。目标端仅执行原哈希保护的六个纯定义：p011_json、mta_ip、mta_client_tmp_alias、mta_p2p_client_init、mta_client_proc、mta_client_journal_codec；LOADER 纯定义字符串与 HOST transport 类从 cb50e2… 冻结入口按 AST 提取，不加载其 TARGET/main。新 transport 仅 225→60 秒，目标观察总期 30 秒；超时不杀进程、不借 PID/FD、不重试。

## 原 FD 只读观察

通过固定 common 两 alias 证明和调用者原 FD 库存打开 root/var/volatile/tmp，再相对 `NOFOLLOW|DIRECTORY|CLOEXEC` 打开当前 private root/run/runtime/native。目录身份 dev/ino/mode/uid/gid，nlink 仅合法下限，不把合法目录 entry 变化当换目录。所有打开先登记票据，原返回即保存，按原 FD 相对 nofollow stat。

21 文件只读取、完整 SHA/全 metadata 前后匹配；native ELF 不进入 result。两个 manifest 持原 FD 到最后再读完整 bytes 与 full metadata。journal/sidecar/global pending 固定名称，regular/root:root/nlink1；权限分别 0600，来源 0400/native0500。`O_NONBLOCK` 防止 pre-stat 后类型切换变 FIFO 造成无界阻塞。每个子项失败保留其它子项，不把无父路径或异常当文件不存在。

每个自有原 FD close 一次，close 前 generation dev/ino/mode/uid/gid，close 后 fresh fstat 必须 EBADF。unknown/异常不补零、不复用 numeric FD、不重试 close。资源表只留私有 raw；公共 `resource_pending` 只表示本检查器原资源未证闭合，不代表旧 F 子进程活跃或历史恢复成功。

## 记录与 Actor

journal 使用固定 codec 的 canonical pure decode，私有 `_document` 留完整字段（含 IPv4），只报告 schema/记录绑定，不签旧 fsync、CAS、FinishReceipt 或当前 interface。sidecar exact schema/canonical/version/kind/stage，绑定当前 candidate/run/原 receipt boot，以及当前 deployment exe/source pins；target ticket 与 journal 相同角色 ticket 若存在则 exact key。保存原 record，不修复。

只有初始两个 manifest 和 21 全文件匹配，且当前 journal 或固定 sidecar exact 绑定，才可查询其中记录 Actor 的 PID/TID。先真实 ProcReader 独立两轮 `read_absence`；不是 known absence 则在前 Reader 原库存闭合可证时，以另一个独立 ProcReader 两轮 `read_actor` 比较 stable key/live/same boot。unknown absence 留存原帧，不变成 absence；独立 LIVE 可保留，但首不完整观察会让 readonly_complete=false。最多四个去重记录 Actor，每次 min(3 秒,总期余量)，不扫描进程、不查询任意 literal、不把无记录当系统零活进程。Reader 原对象存 runtime-only 强引用库存（构造前登记，原返回立即保存），未知持留不重复 close；RESULT 不塞对象。原 fs/fd 库存、files/closed、pending/active/open_attempt 与 fresh EBADF 单独保留。LIVE 仅记录身份观察，不验证当前 Python ELF bytes，不是恢复 authority。

末次独审增量仅收紧 read_complete：每个原观察 kind 必须为 absence/live_actor、恰两轮、boot 绑定且 same_boot=true、pending=false；unknown 即使两轮且 FD 全关也不 complete。OPAQUE 初观察后独立 LIVE 的事实仍保留，但同样不让完整性标志擦掉首 OPAQUE/unknown。资源、查询、预算与恢复门禁不改。既审版本 HOST8ac514…/test022356…/doc0f5182… 保留历史 pin，不覆盖其首批回执。

`GET_INTERFACE` 固定 `NOT_EVALUATED`；journal owned 字段不是当前 interface 事实。`restoration_verified/RF/staging/send/receive/phone` 永远 false。`readonly_complete` 仅是分项观察无错误且本检查器原资源闭合，Actor OPAQUE/不完整帧或 unknown 原资源均不 complete；完整观察到文件 MISMATCH 也不是业务 PASS。缺失 marker 不代表完整恢复。PUBLIC 无 IP、PID、boot、token、路径、argv 或私有 raw；实际新日志若获授权才生成 exact result.json/README.txt 两成员 public ZIP。

v11 历史 private IPv4 的 `{}` 是 generic slots 投影缺口，不能据此签完整 baseline/network。此入口不改历史；未来 INIT/完整网络诊断必须为 exact IpSnapshot/AddressRecord/RouteRecord/RuleRecord 显式私有序列化。本轮不取得完整 after 网络快照。

## 新测试证据

八个新的 SOURCE/Fake 方法：实际六 defs loader 纯构造；21 文件和 marker 缺失；manifest 最后第二读改变/单源错误保留；exact sidecar +实际 ProcReader over FakeFs 两轮 known absence/首 unknown 后独立两轮 LIVE/错误 binding 禁查询；close unknown 一次；alias/预算阻断；Python 3.5 AST 与 no-write/no-init 调用图/transport60 不 kill；默认不执行/显式 SHA/strict echo 三帧/公共隐私。

实际回执按发生次序保留，不能合称一批八项全绿：

- `dd6f7a`：首 loader ERROR / exit1，Windows `os.O_NONBLOCK` 不存在；0 个新方法运行。仅给 Fake 增 Linux constants 并 create=True patch，不涉及设备能力结论。
- `294fe2`：唯一八方法新批 `Ran 8 tests in 0.761s`，5 PASS / 3 FAIL / exit1。两项关联 manifest/actor 失败，一项 AST fixture 把 Actor.start 字段读取误当调用。
- `acdb0a`：只三失败方法 `Ran 3 tests in 0.315s`，AST 项 PASS / 两项 FAIL / exit1。固定非秘密 ReadError.code 留诊断；两项具体 NameError 来自 Fake 独立 TARGET namespace 未提供正式 LOADER 已导出的 base64。
- `e7fa00`：仅上述两项 `Ran 2 tests in 0.491s`，OK / exit0。Fake补正式 loader global；真实六模块 LOADER / TARGET 因果不改。Known ENOENT 的 ABSENT 分项不算 I/O 错误，仍不推全面恢复。
- `65ac23`：独审末增量后只精准 sidecar 方法 `Ran 1 test in 0.493s`，OK / exit0。使用实际 ProcReader over FakeFs 令第三次 PID stat 打开开始 start 变化，真实得到 unknown/两轮/observation_changed/FD全关闭；第二个独立 Reader 得 LIVE/两轮，LIVE 保留但 readonly_complete=false。其他七方法不重跑。

八个不同新方法分批均有通过回执；五项既过方法没有重跑。实际 ProcReader over FakeFs、alias 原 FD over FakeOS 不是实机目录、存活或恢复证据。

没有复跑旧套件、旧 INIT source-check、ADB、设备、RF、锁、cleanup 或打包。首批结果及最终三 SHA 在冻结后交 ROOT，作者不自签硬件或独立 SOURCE 接受。
