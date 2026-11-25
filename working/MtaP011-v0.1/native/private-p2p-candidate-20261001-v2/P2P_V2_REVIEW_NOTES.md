# private P2P V2 审阅入口

此候选修正 `P2P_FIRST_TRIAL_FAILURE_REVIEW.md` 的 early init2 NULL-param 控制流问题，不改第一版归档。

## WPA 修改边界

`prepare_wpa_v2.py` 在固定官方源码＋V1补丁上执行唯一锚点变换，生成 `project-v2-supplicant.patch`。init2 在任何 mode 选择之前读取仅私有 process 环境的 `MTA_PRIVATE_P2P=1`，要求名称精确 mta＋8小写hex；随后 finish_init 对 nl80211 当前 type 必须是 P2P_CLIENT / GO，再启用 private 标志与隐藏 dedicated P2P_DEVICE 能力。旗标未设置时保持上游入口；旗标设置但名字非法时在 driver-init 前拒绝，因此不会拿 wlan0 尝试 P2P。

private AP / CLI group deinit 保留其 P2P type，不把外部 origin 当 WPA 内部动态接口，也不授予 WPA 删除 netdev 的所有权。最后删接口仍归 runtime 的原始 WDEV 租约。

`CONFIG_NO_STDOUT_DEBUG=y` 关闭原始打印 / hexdump，普通 stdout/stderr 仍重定向 devnull。独立 FD3 只输出 `MTA_P2P_DIAG stage=<整数> code=<有界整数>`，函数没有字符串 / 密钥 / MAC 参数；runtime 只允许16个 stage、code±4095、64事件 / 4096字节。实际 PING/ATTACH ready 后必须见到 initial_type_gate / initial_mode / interface_up / driver_finish / driver_init_result / p2p_init 的成功诊断才可尝试 GO。

## 运行时恢复边界

- `/tmp/p011-mta-p2p-device.lock` 是 root0600、O_NOFOLLOW 的固定 device flock；所有 random run 共用门槛。
- `/tmp/p011-mta-p2p-device.pending` 持久记录 boot / 精确 journal / candidate pin，不含凭据。只有 complete 独立读回后清除；异常 / partial / 错误身份均阻止下次建组。
- watchdog 继承同 open-file-description 锁，关闭原 socket / diagnostics 时 **不关闭 guard fd**；新 backend 显式接管该 guard，不能重新 flock 自锁。parent / child 仅关闭自己的引用，child 到独立恢复结束后释放。
- version2 baseline 增加所有原厂 interface identities、tracked process 的 cmdline digest、IPv6 routes / addresses digest；pre-delete snapshot 只排除 exact owned origin 的接口和自有 link-local IPv6行。
- type2 回收额外要求 exact origin、process truly gone、完整 original pre-baseline、不存在进程 argv 明确引用该 netdev、down OR dormant、仅 /64 scoped link-local IPv6 / 无 IPv4、仅合法 fe80/10–64 自有直连路由。无法验证即拒绝，没有为了方便回收额外 bring-down / flush。
- type8/9 仍须四元 identity，不因名字重用删除。reconciled 读回不相等时再标 recovery_required，不返回历史缓存 PASS。
- cleanupcomplete 保存后仍必须 root 独立核查文件 / 原厂 PID / kernel interfaces / IPv4+IPv6 route / radio state；请求 Stop 或 HOST PASS 都不是实机恢复确认。

## 待 root 与实机验证

候选 hash / HOST 证据见 `tests/HOST_P2P_V2_EVIDENCE.md`。无作者设备/RF操作；20s / sendfalse 不变。原 STA 连接必须保留；下一轮先验证 early gate 是否实际生效和 private GO 创建/退出，失败只读诊断后审查，不能自动改原厂服务 / 升级固件 / 继续 DHCP。
