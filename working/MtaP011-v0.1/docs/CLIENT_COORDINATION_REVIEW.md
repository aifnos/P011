# CLIENT 同步协调锁资源组件

2026-10-01。本轮仅新增 runtime/mta_client_coordination.py、tests/test_client_coordination.py 与本文。
`CLIENT_STORE_IMPLEMENTATION_NEXT.md` DRAFT原样保留；不改 core/FILES/codec/proc/旧V9/生产State或能力。
import／constructor无I/O；显式方法才有固定Linux文件／flock调用。不是 ClientInitStore、Executor、Provider、继承OFD、恢复或部署入口。

## 固定路径与 API

`ClientCoordination(run_token, exact core.Identity, timeout=3, _io, _clock)`：内部32位lowerhex token，只隔离私有run，不证明owner。
固定目录链 `/` → `/tmp` → `p011-mta-client-rfinit` → `client-<token>`；base/run须外层已经创建／审核，本组件不mkdir。
device锁为 `/tmp/p011-mta-p2p-device.lock`，pending为同域 `/tmp/p011-mta-p2p-device.pending`，journal锁只在固定既有run的 `journal.lock`。
没有任意root/path/ifname/shell/UI参数；可信 `_io`、`_clock`仅内部/HOST seam，不是恶意Python代码的沙箱。

- `acquire()`：一个lifetime仅尝试一次，返回实例专属私有LockSet；失败不静默重新stage、reopen或retry整条链。
- `validate(lockset)`：fresh目录/lock entry/FD身份、当前实际flock结果与pending观察；True只指当前本地同步检查，不是mutation授权。
- `read_pending(lockset)`：device锁原引用有效＋fresh祖先；只返回实际entry不存在观察，不解析、接管、覆盖或清marker。
- `release_journal(lockset)`：仅原journal FD关闭／严格EBADF读回；device FD与目录锚强引用仍保留。
- `close()`：独立尝试全部已知原引用，每个最多一次；不受先前deadline失效阻止最后关闭尝试。
- `read_closed(lockset=None)`：仅对原已attempted FD做fstat读回；不open、flock、close、修复、清unknown或新建资源。
  私有ClosedObservation带完整登记顺序的观察／unknown计数；不是core.CloseProof，不能作为Store.finish或pending清除回执。
- `status()`：固定stage/reason、计数与布尔；same_ofd_verified/executor_verified/store_implemented/mutation_admission/pending_modified恒False。

RLock只串行化**单个方法**，没有跨调用持有的journal RLock所有权；不能把它直接塞进ClientInitStore合同。
实际device/journal flock FD可在方法之间存活，但未来调用方仍须保证所有资源的独占生命周期与同owner跨调用序列化。
此组件不提供 inherited注册、fork/dup、role/ExecutorProof、actualwait/reap、complete/clear/finish。

## 目录、锁文件与同域 pending

目录使用DIRECTORY/NOFOLLOW/CLOEXEC，逐父dirfd stat与实际打开FD同身份：dev/ino/type/uid/gid/mode。
root/tmp要求root-owned真实目录；root无group/world-write，tmp可写仅允许sticky；私有base/run严格0700。
目录时间/size/nlink可因正常文件创建变化；只验证正linkcount，不把mtime/ctime不变伪当目录身份。
锁文件root-owned regular0600/nlink1/size0，固定empty-lock profile；额外hardlink、symlink/FIFO、非空或未知metadata拒绝。
既有锁先检查再NOFOLLOW/CLOEXEC/NONBLOCK/RDWR打开，entry与FD完整稳定身份一致；缺锁只用CREAT|EXCL0600创建。
创建竞争EEXIST不降级打开；锁文件从不unlink/recreate，失败可留下自己新建的empty锁entry，不声称无文件变更。
本轮不提供文件／目录fsync或journal发布，不能把empty-lock创建当durable marker或Store提交。
pending任何entry在首次锁创建前、device获取后与最终两锁获取后均阻断；symlink/目录/旧/未知内容也一样。
只有实际stat的严格整数ENOENT算不存在；权限/非integer errno/其它未知不算clear。
该观察不是pending写权；即使未来自己的CLIENT marker存在，本组件当前也不接纳。后续FILES/Store自有marker接线仍单独审查。

## 实际 flock 与预算

默认Linux实现显式载入CDLL(None,use_errno=True)，`flock(c_int,c_int)->c_int`；只有LOCK_EX|LOCK_NB（2|4），从不LOCK_UN。
open优先os.open(dir_fd)；不足时明确openat(c_int,c_char_p,c_int,c_uint)->c_int，不猜ARM syscall号、不依赖fcntl/resource/json。
实际平台须Linux/root、stat(dir_fd,follow_symlinks=False)能力；不符合则拒绝，未以HOST环境推断P011能力。
flock结果严格(result,errno)整数，0才acquired；-1且EAGAIN/EINTR允许在同一有限单调预算内再次请求。
其它明确负errno失败；未知返回shape/数值/未返回异常在调用之前已登记unknown，sticky lock_unknown/resource_pending，不继续重试。
重试pause最多每次0.01秒，0.1..10秒统一deadline；clock类型/range/finite/回退拒绝，hugeint在float前门禁。
预算是准入与有界NB重试，不硬抢占OS I/O、异常注入或RLock等待；close也不宣称可硬抢占。
validate对已知锁再次实际flock只证明当前调用结果，不能证明过去跨调用一直持锁，亦不签同OFD/跨进程Executor归属。
相同inode／FD数字／Identity或目录名都不是继承OFD；未来完整provider须实际fork资源链另证，此组件没有生成该证明的方法。

## 原引用与 unknown

每次open前登记exact IO+role ticket；实际返回FD马上保留，登记后的MemoryError/Interrupt／结果未返回不会因fd=None视为没创建。
直接可信POSIX open的明确OSError无返回FD按负结果合同记录；先分配FD再抛OSError的任意factory不符合这个内部IO合同。
本组件最多4目录锚＋2lock资源；任何未知创建保留原refs/IO，不能用零known计数代替absence。
close每个原FD最多一次；独立尝试所有其它FD，即使前一个失败；只在close实际返回None且fstat严格整数EBADF后记closed。
close消耗FD却报EINTR、FD复用、返回类型异常或读取失败都pending；不再close可能replacement，不提供泛True解锁。
read_closed可保留“当前某数字EBADF”的观察，但不会清sticky unknown；close报错后所有fstat为EBADF也不能使其complete=True。
读回只观察exact登记对象/数字；默认可信caller必须独占这些descriptor生命周期，不能由别线程换FD后伪签闭合。
没有资源时ClosedObservation.complete=False；已知negative open失败记录不算实际FD，未知open不能因其fd=None被删除。
公共错误固定CoordinationError.code，私有path/token/manifest/PID/argv不入status/repr；Interrupt可上抛，调用方不得把原异常自由文本打包。

## 实际 HOST 专项及未验证层

首次唯一命令：`python -B -m unittest discover -s tests -p test_client_coordination.py -v`。
工具 `f9374b`：**37 tests／0.055s／OK／host exit0，0 FAIL／0 ERROR**；没有重跑已过项或执行项目全套。
含当前Python3.5 AST／无assert副作用／纯import+constructor、固定paths/flags、EXCL竞争、目录和inode替换、pending前中后门禁，
typed fake libc flock/openat原型、EAGAIN/EINTR预算、late success过期、unknown open/flock强refs、独立所有close、严格EBADF、FD复用与只读闭合。
测试使用FakeOS/fake libc，actual os文件/进程调用、ctypes.CDLL与socket被禁；没有触及真实/tmp、真实flock或用户数据。
未运行WSL、Docker、ADB、RF、Provider、真实wait/reap、正式冻结、历史candidate、ZIP或真实Linux集成。
ROOT全文审查及独立真实HOST libc/锁竞争验证尚待；P011 Python3.5/实际filesystem/同OFD/CLIENT/原网恢复、手机层均未验证。
当前State接线与send/receive能力未变化，旧pending与原网络异常未由本组件修复或授权绕过。

[Linux4.14 locks.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/fs/locks.c)的filp/flock语义是设计依据，不是实际目标证明；
[open.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/fs/open.c)的close行为不允许盲目重关；
[CPython3.5 ctypes](https://raw.githubusercontent.com/python/cpython/v3.5.5/Doc/library/ctypes.rst)的明确原型/use_errno与平台能力需真实验证。
三文件完成后停写供ROOT全文审阅；不把这个有限同步组件命名或包装成完整CLIENT Store。
