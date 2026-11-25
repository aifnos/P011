# Startup 固定别名时钟 v2：隔离源码补丁

来源仍为冻结的 FileCenter-v1 Factory；不是新部署图，没有更改 ROOT、Boot/Owner/Runner pins 或任何旧文件。五个精确替换块及来源/候选 pins 位于 `source-delta.json`，已仅做源码读回与正反逐字节比较；没有执行 AST、SOURCE、HOST、构建、ADB 或设备操作。

v1 独审发现保存的 Owner code 元组可被替换为空，导致 zip 比较跳过。v2 只在同一五块补丁中保存 `_alias_owner_codes_original` 原引用，并在调用原 `_originals(False)`/Owner `_now` 前严格检查 methods/code 元组类型、四项长度及 code 元组引用。旧 v1 原件保留，不作为通过候选。

其余 v1 方案不变：Startup 的 `alias_now` 仅服务固定别名 metadata/readlink 时钟，验证原 Scope、Owner、函数/code、锁、pins、回调和原 prepare 身份；仅允许 reading/importing。按原 Owner `_now` 保持锁/context/Owner/Scope 时间单调性，原 10 秒窗口不续期。ReadOwner rows/raw 必须为空、pending 必须 False；时钟不调用目录 check/fd、不读取文件内容或开启 RF。

真实 `_Files.read` 的完整 scope.now/目录验证、anchors 和别名双样、SHA、Importer 二次 SHA、profile、关闭门及 Publication 字节保持原样。35 源码和 WPA 的别名内层在旧源码中会重复 1656 次完整目录检查、19872 次目录 fstat/stat（算法推导，非设备耗时）。UI6 原 importing 超时证据保留，未测量 v2 节省时间，不能签设备性能、Owner/UI 或无线通过。

新增 HOST 合同只编写不执行，使用真实受影响 AST 方法、模拟 metadata IO 和严格限定 fixture，不能替代完整 Owner、真实基线、设备或手机验收。
