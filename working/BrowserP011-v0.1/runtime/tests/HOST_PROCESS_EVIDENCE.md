# HOST Linux 实际进程组及 setsid 后代关闭证据

本项是 **HOST_ONLY**，不是 P011、Qt 页面、真实 Chromium、沙箱或物理画面验收。旧 17 项 mock/静态检查没有重复运行。

源文件为 `host_process_fixture.c` 和 `host_process_integration.py`。新建 Docker 容器使用 `browser685-builder:gcc11`；根文件系统只读、网络 none、cap-drop ALL、pids-limit 64、memory 128 MiB，runtime 只读挂载。C 编译产物在容器私有可执行 tmpfs；日志单独写入本目录的 logs。每个 C 进程有 9 秒自行退出保护，Python 试验 8 秒 alarm，并有仅针对自己夹具身份的 finally 收尾。

最终证据目录为 `logs/host-linux-process-944beccc/`。其中：

- `host-status.json`：docker/主机 exit=0，明确 `device_test=false`。
- `evidence/result.json`：compiler/main/escaped helper/sentinel exit 均为 0，实验 elapsed=0.090033 秒，最终 candidate 私有进程空、全部自建测试进程关闭。
- `evidence/browser.stdout.raw`：真实主进程及 escaped helper 的 READY/EXIT 原始输出。
- `evidence/unrelated-sentinel.stdout.raw`：独立哨兵的 READY/EXIT 原始输出。
- 各自 stderr、compiler 双流、docker 双流均分别保留，没有合并或清洗原件。

实际顺序：编译普通 C 程序并分别命名 `p011-browser-probe`、`QtWebEngineProcess`；主进程建立自己的 session/group 后 fork helper，helper 调用 setsid 并 exec 到第二个组件。`safety.track_descendants()` 在 parent 链仍存在时记录其不可变身份。对主组的 `signal_owned_group(SIGTERM)` 只关闭主进程；已经逃离主组的 helper 仍活着。随后 `signal_owned_pid()` 在 parent 已变为 1 时重新核对 PID/starttime/exe/uid，只关闭该 helper。独立哨兵在这两次浏览器清理之后均仍活着，最后由测试自己的直接 child 收尾单独结束。

结果记录中的 `runtime_safety_sha256`、`fixture_source_sha256`、`test_runner_sha256` 绑定被测试源码，`fixture_sha256` 绑定容器内实际编译的 ELF。它证明 HOST Linux 上这条实际进程 ownership/setsid 清理路径工作，不替代 P011 设备上的 guardian 整体生命周期验证。

历史原件保持：`logs/host-linux-process-bade6690/` 首次在任何编译/启动之前因输出目录被 docker raw 日志占用而拒绝；改用独立 evidence 子目录后 `logs/host-linux-process-afca774c/` 通过，但没有记录 adopted helper 的 waitpid 退出码。最终版本补齐 escaped helper exit=0 及 runner SHA，生成上述 `944beccc` 新轮结果。
