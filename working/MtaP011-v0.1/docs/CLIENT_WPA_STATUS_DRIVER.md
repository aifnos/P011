# 原厂 STATUS 接口实机驱动

这是已有运行时 `AuthenticatedStatusReader` 的一次固定实机 API 验证，不是新的网络扫描或修复路径。默认运行仅 PC source check，显式 execute 与精确 checker SHA 同时提供时才选唯一 P011、经 ADB 内存载入八个固定模块、发送一次 STATUS。不会写设备源码、ATTACH、扫描、开关无线、连接手机、重启或读取/清理旧 pending。

私有诊断 manifest 来自 ROOT 已独立验证的 2026-10-01 11:42 UTC 原始事实，stdout 原字节 SHA 固定；严格移除相同源 echo 后，使用既有三行 RESULT/REMOTE_OK/EXIT 框架解析。运行时仍重新观察实际 daemon/映像/endpoint/namespace/FD归属与逐报文 credentials，旧事实不会代替当前来源认证。该 manifest 仅限此诊断，不是生产 RF/恢复权限。

八个运行时模块按依赖顺序在内存校验 SHA 后加载，专用 import 只允许已登记且已加载的 mta 模块，不查询设备上的同名源码。标准库由原始 import 加载；设备 Python3.5 不需要 stdlib json。单次 STATUS 的 3 秒预算不是强抢占任意 OS IO；外层 ADB 30 秒有界等待。selector 枚举 raw 沿用原 helper，未独立捕获。

原 stdout/stderr、ADB host exit、remote exit、来源 Actor/SSID/路径和私有错误留在本地 private-raw。公开 result/README 包只允许固定布尔/计数/原因码，不包含这些私有数据。收到调用成功并不证明联网、完整原网恢复或手机互通。

源码验证历史：d43087 首次 source-only FAIL（没有 ADB），原因是新手工 frame 判断把空分隔行当额外行；72e7f8 窄诊断定位该原因，换回既有严格 echo/frame parser 后 af8ee7 source-only PASS，host0。该失败保持，不称实机失败。实机记录另列入最新检查点，不修改本次源码验证历史。

ARM增量驱动99362b8c：只改运行时pin为4f0fa751，并额外保留私有 original_failure 的类型/固定code/errno/traceback，避免公开io_error遮蔽真正原因。公开结果schema和唯一STATUS范围不变；7f0edd仅source-check通过，不代替实机证据。旧dcc188 driver原字节在已冻结17源包中保留，旧实机FAIL保持。

这个部分 SOURCE 包包含依赖、专项源和启动入口，但不含私有事实 raw，因此不是可以在其他工作区独立运行的发布包。原始备份/旧失败和历史 SOURCE 保持不变。

CPython3.5.5 timeout 数值转换已核对原厂 Python 主来源：[pytime.c](https://github.com/python/cpython/blob/v3.5.5/Python/pytime.c#L207-L272)。仅说明所采用的 ceiling/整秒加纳秒读回公式，不证明 P011 socket ABI 已通过。
