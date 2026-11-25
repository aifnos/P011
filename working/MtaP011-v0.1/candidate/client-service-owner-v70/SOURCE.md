# v70：有限 State／loopback 服务 owner（SOURCE-only）

本候选只补固定定义加载后的服务生命周期，不是互传准入。ROOT `46664f` 已全文主审并同意冻结；冻结时尚未执行 HOST 方法、候选入口或 P011 测试，也未部署。

## 冻结来源

- `runtime/mta_client_service_owner.py`：24962 B，SHA-256 `f70046e538db7427dd0af374067f684eb41bafb2f70999a2c3deaf87e8705466`。
- 固定 Boot 为 v69-r3：17973 B，SHA-256 `1c3d05c3bf588aa2b6438e6d940fd5e36e467860c1b183305566a18ed69695aa`。其 22 个固定定义、State32、Factory69-r3、Bridge69、F37 原件均未修改。
- 固定只读能力 helper：BlueZ 65832 B／`179fd01f737acd30c7e903d6925217d9e0467400187614189d06a4cffdc44363`；network 47464 B／`ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6`。

## 实际入口与范围

`FixedStateServiceOwner(loader, original_until, _io=None)` 是纯构造；`start()` 显式消费同域原 Boot loader 与同一固定 factory，调用实际 State／Server 构造并启动有限 loopback 服务。`endpoint()` 只向调用方返回 endpoint／token，`status()` 不输出 token。`close()` 保存单次关闭事实，不声称无线已恢复。

原 `original_until` 必须与 loader 原期限一致，使用真实 `time.monotonic`；Boot 的定义读取局部期限不变成新的服务 TTL。主服务、accepted requests 和线程有强库存，最多保存 4096 个请求。State／Server 对象在原 `__init__` 前登记，线程在原 `start()` 前登记；late／unknown／构造失败不伪装成零资源。

`receive_available`、`send_available`、`scan_available` 都保持 `False`。本轮不构造 Handoff／Parent，不 claim frame、不改 admission，不进入旧扫描 RF 路径；没有旧记录恢复、删除、自动修复或 UI 启动。

默认脚本入口仅输出 SOURCE 说明，不读取资产或启动服务。显式 `--serve --until <原 canonical float 文本>` 需要 fresh process 和已准备的固定私有目录／资产；这只是源码入口，尚未执行，不提供自动部署或 START 脚本。

## 固定路径与关闭边界

生产定义／helper 根为 `/tmp/p011-mta-state-v69`（已知别名对应 `/var/volatile/tmp/p011-mta-state-v69`），目录必须已存在并为 root-owned `0700`。Boot 固定文件为 `runtime/mta_client_receive_boot.py`，helper 在 `native/`；用户目录与 `Received` 必须已按原要求准备。owner 不创建或补装这些资产。

固定路径检查保留已知 `/tmp` 两级别名和虚实目录 inode 核验。文件有原长度／摘要／metadata／一次 close 与 EBADF 读回；所有已返回资源、原异常和失败库存强保留。私有 HOST IO 可显式映射固定路径和 socket metadata，但不替生产 Linux／ARM／root／权限证据。

accepted socket 在线程构造／启动前重新检查原期限，原字节 `recv`／`sendall`／timeout 被薄代理夹到同一服务期限；shutdown／close 是 stop-only。首次 `close()` 固定清理期为 `min(first_close_now + 60, original_until + 60)`，不续期。只有原完成的 State 且无 operation／session 等对象时才调用实际 `State.close()`；其返回值必须是 `True` 才能签服务关闭完成。运行错误即使资源已关闭也不能被 main 的成功退出覆盖。

既有能力 probe 的 `12 + 3` 秒是原 fixed timeout，并非每个系统调用都严格夹在 owner 总期限内；late／unknown 保持失败与库存。本候选没有“抵御并发 root 重写 helper”的声明：摘要读取后的原 State 按固定路径执行依赖私有 `0700` 目录／不可变资产条件。

## 尚未证明

HOST 服务／HTTP／故障用例、P011 ABI／触摸／物理 FD 和线程关闭均未执行。本候选不证明 GO／CLIENT／RF、无线完整恢复、手机收发或生产可用；服务资源关闭与 native restored 是不同事实。后续只能由 ROOT 对受影响方法唯一首测并审查原始结果，不能把本 SOURCE 冻结当运行 PASS。
