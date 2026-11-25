# 2026-10-03：固定只读采样部署器与完整 Parent 通道

本记录交接互传功能的只读采样组件：固定文件部署器和完整数据包 Parent 通道已实现，首次新增 HOST 专项的九个领域通过。它们仍未接入正式收发流程，也没有在 P011 或手机上验证，因此不能据此开启生产发送／接收或宣布网络恢复。

对端为小米 15 Ultra，HyperOS／原厂互传版本尚未知。目标继续 active，生产发送／接收仍 False。本阶段没有 ADB、设备安装、重启、无线操作、旧记录清理或原厂文件修改；正常重启问题的先前许可仍未得到回复。下文的 DATA 仅指文件、采样和进程观察事实，不是开启无线或确认恢复的许可。

## 本轮实际新增

| 文件 | 字节 | SHA-256 |
| --- | ---: | --- |
| `host/go_readonly_observer_v89_asset_sources.json` | 9734 | `b4a3bb3ce6571654b1bf998465e453669b0035a12b510cb4158144158d7ba5eb` |
| `candidate/go-send-observer-stage-v89/runtime/mta_go_readonly_stage.py` | 29281 | `f4c5a008ebf5c7e3ce086cb950c9b675b411c48f5ab23b7f318fd2f4b62ad940` |
| `candidate/go-send-observer-parent-v89/runtime/mta_go_readonly_parent.py` | 41562 | `68a95f868d18c5fc007d711e5f165ee9d564c776119c23edba8c02f83fba47ff` |
| `tests/test_go_readonly_owner_v89.py` | 37468 | `a70126f65e64fc8b5d2ead1483015798f35b9f79f9e35ca9928392f187cb1a07` |
| `host/go_readonly_owner_v89_source_manifest.json` | 10102 | `768824d5a18b4c0c78cb046e7da4d48ea59181339512a5f76e8f210ee09e6f93` |
| `host/go_readonly_owner_v89_check.py` | 11594 | `e51522e2d2cab78523f371dd0d6d0dee79f82960a4d848c2a6285b75c3297bfc` |
| `HOST_MTA_GO_READONLY_OWNER_V89_CHECK.cmd` | 260 | `0548127305de12df40d475e1a124451e93f6fd5363cfd280c758f8768c5e523c` |

旧 39 源表、Packet87、Entry87-r2、Parent86、Owner88 及历史结果保持原件。资产表是在开发电脑上冻结的来源 DATA，不是目标 sidecar、GO 资产 seal 或无线准入。39 源含 Loader 自身；加 Packet／Entry 后固定图为 41 个 `.py`，总 1,347,741 B。

### 文件部署器

`FixedReadonlyObserverStage(original_until).stage(fixed41raws)` 只接受准确的 41 module→bytes；在任何 mutation 前核全图长度与 hash。目标固定为 `/var/volatile/tmp/p011-mta-go-observer-v85/runtime`，不收路径／工厂／IO／时钟参数，不执行所安装的源码。

只创建缺席的新 root/runtime（0700），以 EXCL 0600 创建文件，通过同原 FD 写入和全文读回、fsync、seal 0400、路径 inode／九字段 metadata 核验；保留 6 个目录＋41 个文件的原 FD 与实际 IO 返回。所有已有 root，包括完整 sealed root，均拒绝，不采用、补写、repair、rename 或删除。失败 partial 保留；已知原 FD 关闭一次，须真实 None 返回及 typed EBADF；未知库存不标闭合。

调用方须先发行一次剩余时间在 `(0,120]` 的 staging cap DATA，并传同原 float。它不自行将 600 秒服务 cap 转成新的安装期限，不续期，也不是授权证明。它不安装两个 native helper，不创建 device lock，不读／清 pending，不运行 helper 或无线。

### Parent 完整通道

`ReadonlyDataParent(task_id, native_epoch, operation_epoch, task_until, service_until)` 是独立、固定路径的私有 DATA 组件；尚未接入真实 State／Pub worker 或准入 producer。第一次时钟采样只发行一次 `active=min(now+30,min(task,service)-5)`，保存 `cleanup=min(active+5,task,service)`。cap／任务／epoch 都是调用方原 DATA，不是对服务权限的独立认证。

真实实现固定五定义的本地 pinned import，不写 `sys.modules`；固定六源码（五定义＋named Entry）读回/hash/关闭后才执行纯定义。原 `/usr/bin/python3.5` 自行 NOFOLLOW 全读及完整 metadata／SHA／ARM EABI5 hard-float ELF 校验，允许原厂硬链接 nlink1或2。该 SHA 只代表本次读回，不冒称已经匹配原厂 baseline。保同原 Python FD，通过 `/proc/self/fd/N` exec；Entry 仍是固定物理路径，不能换成 FD script，也不声称防止同权限 root 的并发恶意替换。

原 Popen 一次、固定 argv/env、stdin None；先保原 process/PID 和两个 pipe handles，再做 fd／FIFO／nonblock 检查。独立 Reader 排空完整 packet（最多262144B）及最多16384B stderr，不复用 Bridge8192帧 parser、不先 wait 堵管道。只有真实 stdout/stderr 两 EOF、同原 wait/reap、exit0、完整 packet／六字段绑定、所有原已知 FD once-close＋EBADF 全部成立才返回私有 PacketData。

异常不 kill、不重开、不重新 wait／续排空；原 child 未 reap 或关闭未知继续 pending。保存的 cleanup+5 不是已实现的失败 finalizer 循环。结果始终不签 RF、恢复、State 来源认证或生产准入。

## 首次实际 HOST89 专项

ROOT `a8223e` 首次直接执行新 checker：HOST exit0，tool wall5.080s，WSL child exit0／无超时，child elapsed0.71899999998s；严格 unittest 为 `Ran 1 test in 0.590s / OK`。没有 dry run 或旧方法重放，CMD 已 SOURCE 核对但没有冒称人工双击验收。

唯一方法 `GoReadonlyOwner89Test.test_fixed_stage_and_private_parent`，九个领域、15个独立 owner 夹具（6 Stage＋9 Parent）；九域不等于九个方法：

1. 两组件纯 ctor／默认入口不调用其平台、时钟、FD、process 操作。
2. 实际 Linux HOST 临时树：41源码、47原 FD、EXCL／完整字节读回/hash／0700、0400／85次 fsync／关闭和 EBADF。
3. 旧目录拒绝且旧九字段 metadata／完整内容／目录名保持；错误 pin 在 mutation 前拒绝。
4. readback 故障，partial 文件保留、原业务错误与已知 FD 关闭保持。
5. 实际 returned FD 后模型时钟过期，先保身份，再 close-only；不丢晚返回 FD。
6. 完整 Parent 新算法和实际五定义纯 Packet／SnapshotData 编解码；Python／Popen／pipe／EOF／wait／时钟均明确模型。
7. 四个通过 Parent consumer 的终末拒绝：截断、尾随、绑定不符、非零退出。尾随在 feed 失败，wait0／pending；其他可已 reap 但业务仍失败。
8. 两个模型启动变体：晚返回、缺失 pipe；原返回 process/handle 先留、不重 spawn、不补 wait。
9. 模型 close EIO 保 unknown；重复 close 和过期不抹首错、不重复关闭、不发行新预算。

HOST 文件操作是真实 POSIX，但目标 anchors、aliases、ARM／版本以及时钟是显式投影／模型。Parent 两个五定义域分别用于夹具 encoder 和新 consumer；它们是纯 DATA 算法，不实例化原 Snapshot／Actor／BaselineOwner。固定图的其余源码仅读 bytes，完整 Loader38／Body／native helper 未执行。未运行真实 Parent Popen、原 ARM Python、采样、目标 staging、设备、无线、手机或物理恢复。

测试执行前 SOURCE 审查修正了测试自身 atime 比较和 pipe st_rdev 夹具，以及 Parent 的 nlink1/2、ARM ABI 和未调用工厂的库存分类；没有已运行失败结果被覆盖或重测。本轮只是首次新专项通过，不补签以前的设备失败。

## 原件与一键结果

[HOST-only 一键入口](HOST_MTA_GO_READONLY_OWNER_V89_CHECK.cmd)。它只在电脑运行新 HOST 专项，不自动执行 ADB／archived START。新两 runtime 做 Python3.5 AST 来源检查，执行器是 HOST Python3.13.12，不是笔端3.5.5；旧 target AST和旧 test方法均0。

[脱敏结果 ZIP](results/go-readonly-owner-v89-host-20261003-115314-4b61feaa/public-result.zip)：4902 B，SHA-256 `e7498fc22d60114d978ef9eef6f1e2c8d206432e67b98cb47d4aff84a004ddcb`。四成员为 result.json、README.txt、stdout.raw、stderr.raw。strict safe marker stdout140B、Ran1/OK stderr96B。45来源行＋plan/checker/CMD共48输入快照；ROOT `4cc8a0` 核全部声明、private/current逐bytes/hash、原raw、ZIP逐成员字节／CRC与当前工具一致。

固定 Windows Python312：103192B／`42ac541168e97dedb9aabd8be335539fc41c682e414b9e8d137b164fb68683b0`。WSL kali-linux root、Linux6.6.87.2、Python3.13.12 `/usr/bin/python3.13`：6915048B／`ecf651f545bcef039d29503acf695a38903b7e8e9867a1ce0994ff6924e0274b`，前后身份一致。不是实际 ARM Python 认证。

公开结果16项实际生产／设备／准入否定字段均 False；保留 raw、snapshot、ZIP，不改历史证据。独立实际原件审计 `373c60` 同样 PASS：48份 declared/private/current、strict raw、四成员 ZIP／CRC、固定工具和准确层级一致，未重跑测试、生产导入、AST 或另启 WSL。该审核是证据完整性检查，不是独立重测或硬件验收。

## 仍须制作与实机验证

- 真实调用方部署及 Parent 同 State／Pub worker 接入，先只读采样再发行原 Pub local20，不通过默认 True／caller hash 造准入。
- 出版包含实际新来源的最终 GO／ordinary Boot 资产表和完整 seal；现 Pub 仍 seal=None／硬拒，不能靠现41来源表代替。
- F 在 Store.reserve 前读取新的完整 baseline，与本次原 preflight key 对照；不是从 DATA 重建原 Snapshot／Actor。
- 独立终末完整网络／actor／endpoint／L3与原 FD／子进程恢复确认；旧 pending 还须对应记录的明确处置授权，不因采样、重启或局部关闭自动清除。保留失败 finalizer 缺口。
- 真接收准入、正式工具箱入口、小屏双向流程，以及 P011 与小米 15 Ultra 原厂互传验收。

旧设备 pending／完整恢复未证保持，不能称无线已修或设备已恢复。本阶段仍有自主源码与接线工作，不是仅剩人工手机测试；目标继续 active。
