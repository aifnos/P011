# Fixed receive factory v69-r3 — SOURCE-only

父候选 v69-r2 `runtime/mta_client_receive_factory.py`（54,133 bytes，SHA `5036e23b6d7f038b3716d4f6740f43c4b81c98be045eb2c8303c02699a893f94`）及原 v69 全部保持原件。本 r3 只有一处生产源变更：`_live_profile` 将 Unix 套接字列表读取路径从 `/proc/net/unix` 改为 `/proc/` + 原 attempt 的实际父 PID + `/net/unix`。不改模块名、固定 root、纯构造、publication 9-tuple、r2 三项库存修正或任何其它接口。

主控本轮真实只读检查确认当前 P011 的 `/proc/net` 是指向 `self/net` 的符号链接；当前 numeric `/proc/PID/net` 为目录，`net/unix` 为普通 proc 文件。旧路径的中间 `/proc/net` 必然被原 `_Files.anchors` 的逐层 no-follow 目录门拒绝，因此它不是可供本 factory 使用的实际 profile 读取路径。本 r3 选择同一原父进程的 numeric 路径，不放宽 symlink 或 anchors 检查。此事实来源为主控本轮设备只读回执；作者没有自行执行设备检查，也没有把该回执当成 Factory 正向或 STATUS 准入证据。

原 `_Files.anchors`、原 attempt PID/worker/clock/cap、内容读取/metadata/一次关闭/EBADF、所有 pending 聚合与失败库存门保持原样。profile 仍仅实时 deployment data；后续实际 F37 的 STATUS/Proc/Provider/Store/Loader 门完全不变，`profile_data_collected` 仍不等于 `status_authenticated`。没有 claim_frame、Parent、RF、receive_available、恢复或手机成功权限。

未来固定 State-side manifest 应指向本 r3 生产源的实际 path/hash/bytes；boot/bridge 的 module/root69 ABI 不需要改动。作者仅 apply_patch、源码读取、diff 和 hash，没有 AST/import/测试/默认入口/ADB/设备动作。r3 尚未执行或验证 Factory 正向。
