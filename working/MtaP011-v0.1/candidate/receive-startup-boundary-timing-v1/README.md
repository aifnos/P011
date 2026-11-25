# Startup 最近原边界：五个标量源码候选

仅从实际 packaged `formal-receive-startup-alias-clock-v1` Factory（89379 B / 4a1043e3eb3fbcc3e80927b64640d80c350c38d4bd2c6ecf73eeff68bf15c35d）派生。保持该源码既有 ROOT/pins；尚未接装新运行图或 HOST 入口。旧文件保持不变。

`exactsource-delta.json` 为纯 DATA，包含五块按顺序应用的精确 before/after 和各自 count=1。逆序逆替换必须逐字节回到来源。当前仅编辑、读回、哈希及正反源码比较；没有 AST、SOURCE、测试、构建或设备执行。

## 标量含义

- `startup_boundary_init`：原初始化 `check_active()` 已返回的原 `value`。
- `startup_boundary_private_sources`：35 份私有源读取完成后复制原 `scope.last`。
- `startup_boundary_wpa`：原 WPA 读取与长度检查后复制原 `scope.last`。
- `startup_boundary_profile`：原 `_live_profile` 返回后复制原 `scope.last`。
- `startup_boundary_postimport`：原 post-import `scope.check_active()` 单次调用的 finally 中复制原 `scope.last`，成功和异常路径均尝试保留。

四个后续标量在原初始化检查成功后置 None；没有走到某边界时保留 None。初始化本身失败则字段可能尚不存在，应表示不可用而不是造时间值。没有可变记录容器、通用计时器、日志或新模块。

最后调用保留一次、原异常和原流程：finally 内仅属性复制，单独捕获该测量复制的任何异常并忽略；不重调检查、不捕获替换原业务异常、不在 finally 中调用时钟、IO 或校验。若测量赋值失败，字段可能仍是 None。若原 full-check 在采集新时钟前失败，记录的仍可能是上一个原 last；不能据此宣称该调用取得了新时刻。

这些数值是“最近原边界”，不是函数返回的精确 wall-time。profile 最后一笔原时钟位于 return 数据组装和部分尾部哈希之前；`profile→postimport` 差值包含该残差、源行组装、importer 二次 SHA/模块执行、结果校验及原 full-check，不签为纯 import 耗时。没有逐文件或逐模块耗时。

原 10 秒 prepare 和父 cap、函数/code/Scope/Owner 绑定、full IO/check、SHA、Importer、profile、关闭与异常门、Publication、Trial/RF/缓存/Guardian 均不改变；没有新时钟、IO、业务检查或 Item.data 改动。标量仅测量 DATA，不能成为准入或闭合证明。

尚未执行或采集新的实际阶段值；不能宣称性能优化、完整 Owner/UI、恢复、无线或手机验证通过。

## 2026年10月5日 09时50分 执行状态补充

以上“尚未”描述保留为作者冻结阶段历史。随后ROOT执行一个受影响HOST合同方法、严格隔离图SOURCE以及新根core真实暂存／启动／关闭，均通过；原业务源码与五块差分不变。新v2交互仍FAIL，但五个实际最近原时钟边界均取得：总10.304747秒，超过原10秒0.304747秒，四粗段为2.877296／0.149783／5.719892／1.557777秒。末段包括profile尾部残差，非纯import；不是同条件A/B。Owner／资源关闭及有限原厂核对通过，pending=false，无READY／候选UI／截图／FC／凭据／RF／手机或文件互通验收。完整证据与保留的预置失败见[当前状态](../../CURRENT_STATUS.md)，可分享的[脱敏摘要](../../results/receive-startup-boundary-timing-v1-summary-20261005-0950/public-result.zip)不含原始私有日志。
