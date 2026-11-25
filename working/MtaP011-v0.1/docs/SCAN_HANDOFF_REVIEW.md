# 私有 scan→send 同 helper 交接组件

2026-10-01，仅新增runtime/mta_scan_handoff.py、test_scan_handoff.py与本文。没有修改State、发送worker、native、provider或生产能力；不启动扫描/GATT/文件/OS/RF动作，不spawn线程/进程，不做cleanup。

## 精确输入与可复用API

- `ScanSession(helper,native_epoch,operation_epoch,started_at,ttl=30,clock=None,cancelled=None)`纯构造，不调用clock/helper。started_at由可信owner在真正scan命令前保存；TTL严格1..60秒，与native以发起命令为起点一致，不因晚ready续期。cancelled为共享exact Event，可默认纯构造Event。
- `native_event(event,exact_helper,native_epoch,operation_epoch)`只接可信reader；错helper/epoch忽略且不更新时间。只能原生`scan/ready`固定事件开扫描记录，Boolean ready不能开门。采样/单调检查/提交全在同一锁内。
- discovered精确5字段：event/peer/cached/name_b64/service_data；非bool peer1..65535，最多32库存，不误设peer≤32。姓名只验证canonical base64/UTF8≤128B，不保存；service_data≤8项、exact uuid/payload_b64、payload≤31B。只ready后的cached=False更新时间；cached快照不创建/刷新可发送peer。
- `claim_intent(deviceId,fileIds,internalTaskId)`只一次，TTL内且发现严格<15秒；返不可变私有SendIntent(handoff,file_ids,cancelled)，handoff真实同helper/两epoch/peer/seen_at/internalTaskId/readback。fileIds保持opaque，不打开或解释用户路径；HTTP未来仍仅deviceId/fileIds，不能传内部proof/ready/task/epoch。
- `readback(exact_handoff,budget)`支持正式SendWorker.ScanHandoff/ScanObservation；equal-copy也不是exact owner。≤0.2秒锁准入/观测预算，不承诺抢占卡死clock或OS调度的硬截止；真实worker仍独立测整个readback调用时限。观察active只反映已接收native扫描事件，不从intent捏造True。
- `note_client_read(exact_handoff,{'cmd':'client_read','peer':N})`纯预登记，同域、fresh、canonical命令且只一次；不发送命令、不证明IO发生/GATT成功。未来可信helper发送协调者须在真实send前调用；本轮没有接State/helper/worker钩子。

## 停止、取消与生命周期

claim后UI立即不可再次选，但扫描actual active保持，满足worker两次pre-read新鲜校验。只有预登记后收到原生own_session_stopped，才报告扫描active=False并保留已claim intent、不置共享取消；readback仍如实False，不能拿交接保留替代扫描active。
实际native合法交接清scan_deadline；组件不在该真实停止之后自行重新合成旧scan TTL事件。任何后续原生lease_expired仍立即失效/取消（包括tick先stop再expire的顺序）。未预登记stop、重复ready、cleanup/错误/closed/stop/client/client_read失败、活跃扫描TTL或时钟异常均sticky失效，并set同一Event；因此已读完GATT的worker也能由共享取消撤销，不依赖下一次freshScan。组件不关闭helper或释放owner。
`status()`只是缓存事实+共享取消观察，固定布尔/计数/原因枚举，无设备ID/姓名/fileIds/task/地址/原event；不采时钟，不是当前内核扫描/平台准入证明。过期将由下次事件/claim/readback发现，不能用缓存status开放能力。

## 固定primary源码链

本地native/mta_bluez_helper.c SHA256 `38a2ce2e7ab967ed2c296d4ccff8ebdfe71331325a65e403df2f4766c48ce289`：448–497真实discovered/32库存/独立递增ID，515–544 StartDiscovery成功才ready且命令起TTL，546–554 stop结果与deadline清零；647–658 client_read先停自身扫描并保留peer表；727–728 tick先own_session_stopped再lease_expired。
native/mta_core.c SHA256 `c9fe71f0e0db4720d2a0a6eca508a3ab292aa38a81357d9b223647b8731a65ed`：scan TTL≤60的原生parser限制。独立protocol agent仅只读核该真实链，未编辑或重测。
SendWorker只复用已实现ScanHandoff/ScanObservation类型；本任务不再次审核或修改其正在修正的实现。

## HOST证据与未做层

新增专项使用Fake helper/clock/native事件、真实HOST线程和Event测试锁内采样顺序；外部OS文件变更/socket/Popen guards拒绝。Python3.5 AST在同一专项。不打开用户文件、不做真实crypto/设备/RF/全套。
唯一首次专项工具`055d6d`：`python -B -m unittest discover -s tests -p test_scan_handoff.py -v`，25方法全部ok，`Ran 25 tests in 0.049s / OK`，HOST exit0，wall0.4424209秒，含Python3.5 AST。没有旧PASS重测或合并假全套。
State动作、同Session交接、实际helper-send note钩子与共享Event尚未接线；没有真实扫描→GATT/GO/IP/DHCP/手机通过，生产send/receive能力不变，platform_available=False。
