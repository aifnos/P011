# CLIENT `/proc` 只读身份组件

## 实现边界

仅新增 `runtime/mta_client_proc.py`、`tests/test_client_proc.py` 与本文；不改 CLIENT core/provider、旧candidate或历史结果。
import／constructor不I/O；显式read仅固定Linux `/proc` 下的boot、指定PID与完整task目录，不扫描所有进程。
无spawn／kill／wait／reap／socket／文件锁／RF／设备／OS修复；没有UI路径或任意root参数。
`_fs`与`_clock`是可信内部HOST注入，不能当真实Linux数据证明。默认只允许Linux，真实读取层尚未P011验收。
未来provider／store须由ROOT另行固定完整依赖图，并持同owner序列化本reader及实际调用线程生命周期。

## 当前core合同

读取当前 `mta_p2p_client_init.Actor`：PID/start/exe/argv_sha及全部(tid,start,state)，key不含调度state，live排除Z/X。
只有两次身份相同、完整task集合稳定且每次所有task都非Z/X时才创建Actor；P(parked)不投影给core Actor。
`read_self()`采用实际provider getpid，再同样双观察，不生成ExecutorProof、不签same_ofd_verified。
ExecutorProof的真实role/同OFD与协调锁仍必须由provider证明，单独的/proc身份不能代替。
`read_absence(actor,boot)`只核固定Actor的PID目录、task目录及每个记录TID的独立/proc路径两次均不在，且同boot。
它不返回ExitProof、waited或exit_code；每个结果的reap_complete恒False，不能用于ExitProof.gone或宣称actual wait。
未知／权限失败／路径变化／PID或task复用／某路径仍在都不会报告absence；非空task不能由leader消失推为空。
此观测只覆盖记录的task身份与路径，不证明全系统无新actor或所有FD已关闭。

## 两次观察与私有raw

每次actor pass读boot前后、PID stat前后、exe symlink、完整cmdline、两次task列表以及所有task stat。
要求目录不是symlink、每个task目录身份稳定、leader存在、列表无重复且与num_threads一致。
已退出Z/X可在内核stat里显示num_threads=0，此时仅保留实际非空task观测，不生成Actor或退出证明。
boot或PID/start变化固定拒绝；两pass全部exe／cmdline字节、PID及task stable identity相同，才输出liveActor。
允许已观察的非死调度state在R/S等之间变化；CPU tick不是身份，但comm／flags／ppid变化会拒绝。
cmdline严格MAX+1、非空必须NUL终止且argv0非空；非UTF8与空的后续argv按原始bytes完整SHA-256。
empty用户Z、empty kernel(PF_KTHREAD)、empty unknown分别opaque；非空kernel与executable缺失也opaque，不造Actor／absence。
exe必须绝对canonical且无控制字符／deleted后缀；不读目标binary，不把readlink路径当程序hash证据。
RawRecord保留读到的原始bytes、exe文本、目录条目与元数据（包含私有PID、路径、argv）；repr固定不泄漏。
public_status只有固定kind/reason/stage、strict bool与计数，没有地址／PID／路径／argv／自由异常消息。

## stat与原厂Linux语义来源

- [Linux v4.14 fs/proc/array.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/fs/proc/array.c)：
  do_task_stat输出PID(comm)和50个尾部字段；start_time来自real_start_time转ticks；task与tgid读法不同CPU字段可变化。
  comm可能含空格、括号／换行，不能split整个stat；本实现以最后`) `分隔，验证52字段、数值长度/range及PID一致。
  已知P state保留为private stat但不产生当前core Actor；未知state固定拒绝。
- [v4.14 sched.h](https://raw.githubusercontent.com/torvalds/linux/v4.14/include/linux/sched.h)：PF_KTHREAD=0x00200000。
- [v4.14 fs/proc/base.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/fs/proc/base.c)：
  cmdline读时task不存在为ESRCH，缺mm可返回空；因此空cmdline不能证明死亡、更不能证明reap。

## 预算与资源

每次共享deadline0.1..10秒、每步check且拒绝clock回退／huge int／NaN；不硬抢占任意OS调用。
PID与TID exact int1..2^31-1，start1..2^64-1；task≤128，stat4096B，cmdline32768B，总2MiB／280已打开file。
数字目录名canonical无leading0、重复／未知条目拒绝。listdir数量在返回后校验，不承诺抢占C层目录枚举。
读取flags只O_RDONLY|O_NOFOLLOW|O_CLOEXEC；fd前后fstat须regular/nlink1且元数据一致，不信proc st_size=0代表空文件。
finally每个返回的fd close一次，然后实际fstat仅strict整数EBADF才确认为关闭；close异常或未确认保留exact fs+fd refs/pending。
pending不允许继续read，无泛True清除或重复close；全部已确认关闭后下次read才释放旧内部fd记录。
每个raw文件在失败后也保留部分读取；文件关闭验证不代表child进程退出或实际reap。

## HOST专项

首次实际命令：`python -B -m unittest discover -s tests -p test_client_proc.py -v`。
工具记录 `babddd`：43项，42 PASS／1 ERROR／0 FAIL，exit1，0.057s；历史错误不删除。
ERROR是 expected(start=99) fixture仍带leader task start=100，被真实core Actor构造校验拒绝，非runtime用例失败。
仅修该fixture为一致的leader start=99；受影响命令：
`python -B -m unittest discover -s tests -p test_client_proc.py -k expected_actor_and_pid_reuse_distinguished -v`。
工具记录 `c3d46d`：1项 PASS，exit0，0.003s；累计43个用例已有通过证据，不声称最终全43再次运行。
首次运行内的Python3.5 AST、pure import／constructor、FakeFS边界及禁止实际OS／socket调用测试通过。
全部为PC HOST FakeFS证据，没有真实/proc遍历、P011 import、child wait/reap、provider接线或mutation准入证明。
未运行设备、ADB、Docker、编译、套测或冻结；源码与这三文件交ROOT审阅后停写。

## 独立审查后的资源窄修

上版runtime SHA `58060de46170e72f953d93f9d3d83c93622baeb452f046661fbf83ae83535976`
有两个同属读取资源闭合的阻点：finally先分配／追加RawRecord，若MemoryError或Interrupt会跳过已知FD的close；
open未返回结果或FD登记失败时没有创建未知占位，后续read可能清掉原owner记录。
不改stat／身份／双观察／absence／deadline合同，本轮仅修资源收尾与对应测试。

现在在open前保存私有exact fs/path/flags attempt，返回后立即保存descriptor；非OSError的未返回创建异常保持sticky pending，
禁止新read和猜测FD清理。已知FD登记失败时仍独立close一次并严格EBADF读回，但不会因close通过抹掉登记unknown。
成功关闭的原引用不重复close；未解决的attempt／refs不清除，没有通用True解锁或自动恢复接口。
raw记录在单独try内，无论记录失败与否，嵌套finally仍尝试已知FD的一次关闭。
若只有raw记录失败且原FD已独立证明关闭，读取仍为unknown、不生成Actor；文件闭合事实可单独保留。
若创建／登记／close任何一项未知，public资源pending仍True，不能以file_count==closed_count替代完整资源证明。

明确OSError沿直接POSIX／CPython open失败无返回FD合同保留原reason，不把ENOENT／权限失败升为创建pending，
也不把它当PID absence。可信注入的_fs必须遵守相同合同；先分配FD再抛OSError的任意factory不在此直接API合同内。
主来源：[CPython v3.5.5 posixmodule.c](https://raw.githubusercontent.com/python/cpython/v3.5.5/Modules/posixmodule.c)
7178–7222显示open失败与成功返回FD的边界；
[其clinic wrapper](https://raw.githubusercontent.com/python/cpython/v3.5.5/Modules/clinic/posixmodule.c.h)2947–2950在实际FD返回后才PyLong_FromLong。
因此未返回Python结果的MemoryError不能据descriptor=None断言没有创建。

FD读回只证明close调用后该数字在观察时strict整数EBADF；复用后fstat成功或errno为float／bool／其它值均pending，
不再close可能的replacement。它不是OFD身份、ExecutorProof或flock继承证明。
调用者仍须序列化reader并保证这些私有FD的独占生命周期；不得让另一线程关闭／重配其FD后借此组件宣告资源安全。
两次proc观察始终不是wait／reap，所有reap_complete仍False；没有RF／IP／lock／signal操作。

新增7个命名专项覆盖raw MemoryError／Interrupt仍独立close、raw失败叠加close失败、未返回open（含已分配fake FD）、
登记前后异常保留unknown、明确OSError合同、close后FD复用不重关、严格EBADF类型。
本轮唯一新增／受影响命名批工具`b95d8e`：`python -B -m unittest -v <13 named tests>`，
**13 tests／0.017s／OK／host exit0**（7新增＋6受影响，含Python3.5 AST与实际core Actor形状）。
现50个独立测试方法，不称本版50整批重跑；上文babddd首次43的1 ERROR及c3d46d fixture增量原样保留。
这仍仅FakeFS／HOST合同证据，无实际/proc遍历、P011、网络、设备、Docker、全套或harness pin变更。
最终三SHA由交付消息提供；ROOT另行审阅部署依赖，当前reader不能提供mutation admission。
