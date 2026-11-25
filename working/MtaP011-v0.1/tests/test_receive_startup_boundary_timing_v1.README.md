# 五边界单项 HOST 合同源码

唯一 selector：`ReceiveStartupBoundaryTimingV1Contract.test_actual_startup_boundaries_preserve_original_call_and_error`。

源码绑定实际 packaged old Factory、新 boundary Factory 与五块纯 DATA 差分的长度/SHA；合同运行时仅 AST 提取实际 `_StartupReadScope.__init__`、`check_active`、`FixedReceiveDeploymentFactory.startup_readonly` 和必要固定常量/数值判断函数，不能执行原模块 imports/main 或旧 suite。三受测函数体不做动态替换。

原定义/context 校验、Owner 时钟、35 文件＋WPA、profile、importer 和 close 均为显式窄 fixture；不签完整 Scope/Owner、真实 IO/SHA/import、设备性能、资源关闭或无线证据。`Files.read` 的 `last` 和 profile 最后时刻由 fixture 模拟，用来检查复制语义，而不是模拟设备耗时。

一个方法对照 old/current：成功、成功但第五点赋值抛错、原 prepare 过期、原过期且第五点赋值抛错、原检查在新时钟前抛错。检查第五点属于最近原 last、成功后的后续检查不覆盖它、原调用次数与 fixture clock/IO 次数不增加、原异常对象/失败列表保持同一对象、测量赋值失败不替代原异常或改变成功结果。保原 10 秒准备表达式。

此合同只编写和读回，尚未 AST、SOURCE、HOST、测试、构建或设备执行。ROOT 后续唯一执行，不重跑旧 alias/graph/Owner 套件；即便 HOST 通过也不等于完整 Owner/P011 UI/手机通过。
