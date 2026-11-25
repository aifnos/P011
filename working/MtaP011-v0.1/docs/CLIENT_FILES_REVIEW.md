# CLIENT 私有 journal 文件层

## 范围与路径

仅新增 runtime/mta_client_files.py、tests/test_client_files.py、本文。不修改 Store/core/codec/provider、旧 pending、native、冻结源或能力。
import／constructor无I/O；显式方法才调用真实Linux文件接口。不是 ClientInitStore、Executor、flock、恢复或 finish 实现。
ClientJournalFiles(run_token, identity)仅接受内部32位lowerhex token及真实core.Identity。
固定路径为 `/tmp/p011-mta-client-rfinit/client-<token>`；basename仅 journal.json和内部journal.XXXXXXXX.tmp。
外层负责创建/审查目录；本组件没有mkdir/任意root/path/用户目录接口。
Journal本身没有run或parent Actor：随机目录和合法schema只提供隔离，绝不赋予所有权、恢复权或RF许可。

## 已有全局 pending

只读 `/tmp/p011-mta-p2p-device.pending`；任何entry存在都阻断open/commit，包括symlink、目录、旧/未知version。
只有实际stat_at返回严格整数ENOENT才观察为不存在；权限/未知errno不当absence。
无写入、替换、unlink、clear/migrate旧pending，也不另建gate namespace。它是一次观察，不是实际device flock证明。
当前文件层甚至不接纳未来CLIENT自己的pending；后续同global域的Store接线需要另行审查明确身份/权限，不将本组件独立部署。

## 文件/目录与闭合

通过 `/` → `/tmp` → fixed base → fixed run逐组件dirfd打开：DIRECTORY/NOFOLLOW/CLOEXEC；已打开FD和当前父entry必须同身份。
root/tmp要求root所属真实目录；root不许group/world-write，tmp若可写必须sticky。base/run必须root-owned严格0700。
没有“所有祖先都0700”假设；目录dev/ino/type/uid/gid/mode用作身份，mtime/ctime/size不作为目录身份，避免正常create/rename自误拒。
journal与temp必须root-owned regular0600/nlink1；完整文件元数据含size/mtime_ns/ctime_ns，不含读取可变atime。
读取前先stat拒绝FIFO/非regular；open增加NONBLOCK/NOFOLLOW，并立即验证FD/entry同完整metadata。
默认Linux需要实际root与stat(dir_fd,follow_symlinks=False)支持，否则failclosed。
open优先Python3.5 os.open(dir_fd)，不足时明确libc openat(int,char*,int,uint)；rename使用明确renameat原型。
ctypes CDLL(None,use_errno=True)只在显式需要时载入；没有猜ARM syscall号、fcntl/resource/json假设、任意命令入口。
FD ticket在open之前登记，保存exact IO对象/返回FD；异常无明确负结果时opening_unknown保留，不凭零计数称已关。
close每个original FD最多一次，之后独立fstat严格EBADF读回；关闭或读回未知保留exact refs/resource_pending。
清理遍历独立尝试全部资源；不会重复关闭可复用FD，也不提供泛True清unknown的方法。最多256个lifetime tickets，超限在新open前拒绝。
timeout0.1..10秒、finite/type/range/clock-regression检查；每步准入但不硬抢占OS I/O或外部调度。

## compare-before-publish（非无锁原子CAS）

read_current返回私有不可变CanonicalRecord，完整canonical bytes、真实Journal、文件metadata、该实例issuer和generation。
commit只接受同实例当前generation receipt或None，且new record必须是同Identity真实Journal，经旧codec全部校验。
流程：fresh祖先/global pending → 完整bytes+metadata比较 → EXCL0600 temp → bounded写全 → file fsync → 关闭读回 →
第二次fresh祖先/global/完整bytes比较 → temp身份核对 → 同dirfd rename → directory fsync → fresh祖先/global/完整重读。
只有读回文件与本轮EXCL temp的稳定dev/ino/mode/uid/gid/nlink/size相同、完整字节与Journal key都相同、读取FD确关才返回新receipt；比较包含key未编码的Actor task state，避免仅key CAS漏洞。
本组件无跨进程锁；compare到rename之间不是原子条件更新。所有writer必须由未来可信owner/真实journal锁共同序列化。
不接受Bool guard伪签此事实，不宣称无外锁安全并发commit/恢复，RLock只保护本实例的同步方法。
任何file/dir fsync错误（含EINVAL/EBADF）失败，不沿用旧GO吞错策略。
rename前失败保留私有temp与write_pending；rename尝试后fsync/readback/关闭未知保留published_unknown＋write_pending＋原refs。
没有rollback、自动retry、删除temp、覆盖回旧journal、按名字接管已有temp或rebase。后续恢复须独立审查，组件不提供动作。
close自身未知发生在已发布之后同样标published_unknown；“文件闭合”不能冒充child/锁/OFD退出或Store finish。
临时目录仅same-boot持久化界面；未核目标filesystem/挂载，不声称跨boot/断电保存。

## 证据

本轮只允PC HOST FakeFS专项和Python3.5 AST；真实Linux tempfile集成由ROOT全文审核后另行执行。
HOST fixture不调用实际os/ctypes/socket、/tmp、flock、WSL、Docker、设备或RF；不会赋予实际可用capability。
唯一首次实际命令：`python -B -m unittest discover -s tests -p test_client_files.py -v`。
工具记录eb1f84：37 tests／0.173s／OK／host exit0，无FAIL或ERROR；未重跑已过项或运行项目全套。
包括当前Python3.5 AST/no forbidden ops、纯构造/import、fake typed libc原型、目录替换/权限、全部bytes/metadata比较、
short writes、EXCL冲突、两次fresh检查、file/dir fsync故障、rename后readback差异、未知opening/关闭、独立全部close与pending不修改。
这些都是HOST fixture证据，不是P011或真实Linux fsync/rename/FD、flock、跨进程序列化/崩溃验收。
未启动WSL/Docker、未执行真实tempfile集成、未碰设备/旧candidate/globalpending；三文件交ROOT全文review后停写。

## ROOT 独立审查增量：发布文件身份

首37项对应旧d6d773源码，保留原证据，不升级为当前整版通过。独立审查发现最终readback只比完整bytes/key，另一root-owned0600/nlink1的同字节inode可能被误当本轮发布文件；这是静态可见缺陷，不是实际P011竞态复现。
ROOT最小修正追加result.metadata[:7]与本轮written[:7]相等，包含稳定文件身份与size；rename前后正常时间戳变化不机械误拒。Linux4.14 [vfs_rename](https://raw.githubusercontent.com/torvalds/linux/v4.14/fs/namei.c)使用source inode，[shmem_rename2](https://raw.githubusercontent.com/torvalds/linux/v4.14/mm/shmem.c)保留它并更新ctime。
新增专项覆盖同bytes换inode、同inode换device和同稳定身份的合法时间戳变化。前两者保持write_pending/published_unknown、generation不前进、原读取FD独立关闭、拒绝再次commit；不删除已发布文件、不rollback。真实Linux验证仍另层，不因HOST fixture称Store/OFD/RF完成。
ROOT唯一命名新增/受影响专项工具c9ef0d：9 tests/0.063s/OK/host exit0，3新增+6旧受影响，包含当前Python3.5 AST/禁止操作边界；当前40方法，不是整版40或项目全套。未重跑首37，不改原判。

主要合同来源是现 mta_p2p_client_init.ClientInitStore/core与mta_client_journal_codec纯codec。
[CPython3.5.5 os](https://raw.githubusercontent.com/python/cpython/v3.5.5/Doc/library/os.rst)提供dir_fd平台检查；
[ctypes](https://raw.githubusercontent.com/python/cpython/v3.5.5/Doc/library/ctypes.rst)提供明确原型/use_errno；
[Linux4.14 open.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/fs/open.c)明确close不可盲重启；
[sync.c](https://raw.githubusercontent.com/torvalds/linux/v4.14/fs/sync.c)的fsync负结果不能当持久化成功。
