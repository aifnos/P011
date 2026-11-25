# Startup 专用固定别名时钟：隔离源码补丁

仅从冻结的 `formal-receive-filecenter-v1/runtime/mta_client_receive_factory.py` 派生；未接装新 ROOT、Boot/Owner/Runner pins 或生产 manifest，不可作为已部署候选。未运行 AST、SOURCE、HOST、构建、ADB 或设备试验。

本次 UI6 的原诊断在 `startup_readonly` 末尾、私有模块导入完成后的原期限检查失败。父会话仍有时间，但原 `STARTUP_READ_SECONDS = 10.0` 已过约 1.18 秒。没有分阶段耗时记录，不能将全耗时归因于编译。

已定位的重复成本是 Startup 的 `_Files.alias_owner.clock` 原来绑定完整 `scope.now`，固定别名算法每次有 23 次时钟检查，每次间接重新检查 Received 的六节点目录链。仅 35 份源码和 WPA 的前后两次别名检查就涉及 1656 次完整目录检查、19872 次额外目录 `fstat/stat`。这些是按当前算法与固定清单推导的调用量，不是设备耗时测量。私有源码总计 1283171 B；WPA 1351192 B；Importer 再核全部源码 SHA 并实际执行 34 份源码，总计 1165417 B。

## 唯一业务变化

新增 `_StartupReadScope.alias_now`，只供原 `_ReadOwner._fixed_tmp_alias` 的 metadata/readlink 时钟使用。先验证原 Scope、Owner、函数对象/code、固定 pins、锁、回调、原父期限和 prepare 身份；仅允许 reading/importing，按原 Owner `_now` 保持 Owner 与 Scope 单调时间。元数据时钟不调用 `DirectoryBinding.check/fd`，不读取文件内容、不创建或关闭 FD、不发 RF、不签 admission。原 ReadOwner 的 rows/raw 必须为空、pending 必须 False。

真正 `_Files.read` 前后及每个实际读取边界仍用原完整 `scope.now/check_active`，原 anchors 双样、别名双样、源码/native pin、Importer 二次 SHA、profile、关闭证明与 10 秒窗口均不变。Publication 的专用别名时钟及其它业务字节保持原样。

`source-delta.json` 是纯数据：五个精确 before/after/count 替换块，按给定顺序应用；逆序替换逐字节回冻结来源。仅做源码读回、计数、SHA 和正反字节比较，不执行其中代码。下一步原代理独立审读并安排一个受影响 HOST 合同；这不构成设备性能、Owner/UI、无线或手机验收。
