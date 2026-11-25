# Startup 固定祖先 metadata 时钟候选 v1

本候选只从实际 packaged timing-v1 Factory 派生；唯一业务差分是整个 `_Files.anchors` 单块。来源及候选字节 pin、精确 forward/inverse 存在旁边五键 `exactsource-delta.json`，一块且 count=1。作者交接时未执行；后续ROOT的实际结果见下段，本目录仍不是独立可运行部署图或稳定性能证据。

2026-10-05 10:35 执行记录：ROOT唯一受影响HOST fixture通过，实际七源隔离包与两载体SOURCE通过。先行core真实stage及资源关闭有证据，但原末端prepare拒绝FAIL保留；新独占UI本轮真实Startup／Receiver＋FC／READY1／20秒／关闭通过，五原边界9.152052秒。不是同条件A/B或稳定性证明，不回填core／旧手机失败。只读READY/DRM截图已查看，Files导航／触摸／手机／完整互通仍待；详见[当前状态](../../CURRENT_STATUS.md)。Factory/spec/测试源码仍原冻结字节，不重旧窗口。

仅实际 `_StartupReadScope`、canonical 路径以 `ASSET_PHYSICAL_ROOT + '/'`、`/usr/`、`/proc/` 为固定 prefix、祖先数 d>2 才选新分支。Publication、浅路径和其他路径保原逐祖先 full now。原 `_alias` 算法仍原样执行，不新增路径权限。

新分支 index0 保原 full now，随后本次调用只保留原 bound metadata clock/functions/codes 引用；index>0 的每个 stat 前，先纯核同 Scope/Files、tuple/code 身份和长度、bound self/func、同 alias_owner.clock，以及当前 alias 方法的原 function/code，才调用已有 `alias_now`。成功返回前再原 full now。不存在跨次缓存、旧配置缓存或延长期限。

已有 metadata 时钟仍检验原 Owner/Scope/ReadOwner/lock/pins、阶段和同一父/10秒 prepare cap、单调时间；它不访问 Received 目录。入口/成功出口使用原 full check，Received 完整校验仍在文件真实 IO 边界。所有祖先 stat 次数/顺序、alias/readlink、open、fstat、各 chunk read、SHA/ELF、import、关闭及其他源码保持字节不变。返回 full check 失败不交付 anchors；失败路径不补一次可能掩盖原异常的 finally 时钟。

每个选中 anchors 从 d 次 full now 变成 2 次 full + (d-1) 次 metadata，原 Owner clock 总次数 d→d+1；减少 d-2 次 Received full check，但增加一次 clock。本次双 anchors 文件读相应减少 2(d-2) 次 full check，并增加两次 clock，不宣称实际收益。private 路径原 fixed alias 的 23 次 clock/metadata/readlink及入口 full 不变。

本轮实际旧 timing elapsed=10.304747493 秒、cap=10 秒，超出0.304747493秒。不能使用其他旧轮超时混算。新候选保留原10秒门；HOST fixture通过也不能证明设备能进入UI或性能改善。
