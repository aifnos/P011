# CLIENT文件层：Linux HOST专项入口

15:35 当前源检维护：ROOT与独立代理全文审查了 own-marker 接线及组合事务，
FILES 当前 SHA 为 `d95afa25d82c02592d3e4d5a904a397d0f3c366124f793433131bd3d62342ed3`。
本旧文件检查器仅更新该固定 pin 和精确测试断言，不调用 binding，也不增加 pending
准入。修改前的三文件已保存为不可覆盖的
`artifacts/SOURCE-client-files-checker-20261001-202ca29.zip`，SHA
`19e1c6033d266ead1a84667565b21db4de589f2d7e0486a76fdfcdd56607a530`，
三成员 SHA 和 CRC 由 ROOT1186a5 读回。历史21a405/202ca证据保留；当前真实
`--execute-reviewed` 尚未运行，旧17FD结果不升级为此版本。首次apply_patch因文档
锚不匹配而拒绝，60bf51确认源码与断言均未变化后才重试，非测试失败。

2026-10-01，仅新增harness、FakeIO测试及本文；不是P011设备checker。作者不执行Linux `/tmp` 写入、WSL/Docker、ADB、native、RF、网络、锁、全套或真实打包。

## 固定来源与入口

`host/client_files_linux_check.py` 默认/`--source-check-only`只读核5源码SHA、harness SHA及Python3.5 AST；不构造执行IO、不建结果或测试目录。
明确入口为 `python -B host/client_files_linux_check.py --execute-reviewed --expected-checker-sha256 <ROOT审定当前harness完整SHA>`。
不接受任意path、token、TTL、provider、IO或环境升级CLI；ROOT会通过既有kali-linux、`--user root`执行，harness不会启动WSL/Docker或改变用户。
必须Linux/euid0及真实dir_fd/stat/no-follow能力；未满足FAIL，不静默fallback运行。
仅加载固定内存源码，依赖import通过明确pinned模块映射，不sys.path导入、无sys.modules替换、无test fixture生产依赖。
固定FILES SHA `21a405410474665fca83ea4216d722a2a27b9ea24812dc71c58dfc2fc826d73b`，含ROOT最终readback metadata[:7]证明本轮temp inode相同；rename正常ctime变化不机械全比较。
历史FILES `d6d773…8350`及首37 HOST证据保持，不能用于本次真实Linux执行；ROOT修正后仅新增3+受影响6项c9ef0d9/9 PASS/.063s/exit0，非重新声称全部40已跑。
其余pins：core `88f16ec4c04d0f17e90ef90b912e3b5a3b1ce1a0a01240329702f4ded796889e`；codec `17d362826a90da7fe9d77a82495a34bbc56b4c67aaca608aa5565ee1d3369f73`；ip `1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5`；p011_json `fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88`。

## 实际Linux动作边界（仍待ROOT执行）

构造pure；显式execute后dirfd逐层打开 `/`、`/tmp`，核root所属、真实目录和身份，root不可group/world写，tmp可写时必须sticky。
先只读stat固定 `/tmp/p011-mta-p2p-device.pending`：任何entry包括symlink/未知schema都拒绝，只有严格ENOENT观察为absence。不写、迁移、清除pending，不取得device flock。
固定base `/tmp/p011-mta-client-rfinit` 已有则核root-owned0700；缺失可仅一次mkdir0700，EEXIST竞态拒绝而不是重试接管。
仅一次随机16B→32lowerhex token，EXCL mkdir一个 `client-<token>`0700；核entry与已开FD同身份，旧run或错误权限拒绝。mkdir后失败仍保留目录，绝不chmod/chown/rm/rmdir/unlink/回滚或自动重试。
所有setup anchors在commit前和末尾fresh核回；File组件内部继续执行原祖先/pending/CAS/fsync/readback门禁，不放宽源行为。
总20秒为准入/调用间预算，FILES每次固定3秒。OS syscall/调度不可抢占，不能宣称硬20秒中止；finally关闭不因预算耗尽而跳过。

## 明确synthetic记录与实验

确定性Identity、boot、actors、wlan0/IPv4逻辑baseline都只为schema构造；不是读取或描述实际Linux/P011网络、PID、candidate、STA、association。
无真实watchdog/controller/ticket/owned接口或IP。首次Journal stage=new，第二次prepared，均ready=false，deadline=123.0是synthetic schema字段而非真实租约。
执行首commit(None)→独立read_current比完整canonical bytes、完整metadata及Journal key→第二commit当前receipt→同样完整读回。
然后再次提交首receipt必须严格拒绝invalid_expected，fresh当前完整bytes/metadata/key仍为第二记录。
这只证明stale **generation** receipt拒绝，不是假造租约TTL到期、跨进程锁、崩溃恢复或生产Store finish。
仅本私有新run单writer；FILES compare-before-publish不提供无锁原子CAS或未来多writer许可。

## 独立FD证据与公开层

独立AuditIo在每次open callback前登记epoch，校验exactint FD，当前live编号不可重复。每epoch最多一次close，立即独立fstat严格EBADF；unknown保留，不重复close可能复用FD。
LinuxFileCheck构造pure，execute第一次入口在任何callback前设置once gate。实例强引用保存exact modules/raw/AuditIo/anchors/FILES对象；返回失败report后仍保留unknown资源，不覆盖或凭GC/destructor关闭。只有全部独立关闭证明与FILES闭合均明确成功才释放资源引用；无论成功或失败，二次execute固定already_attempted，零新open/mkdir/close。
真实execute-reviewed另有module-private容量1的强registry，在OS动作前保存完整check实例，结果writer抛错也不丢unknown引用或清registry。不能通过临时对象、自引用循环或return私有对象假保留。default/source-only仍允许，不提供恢复或registry清除CLI；同进程第二实际执行固定拒绝。
finally尝试全部已知未尝试epoch，不因其中一个close失败跳过其他；所有曾返回的原FD编号末尾再次独立fstat EBADF。
同时FILES自身status必须all_owned_fds_closed且无resource/unresolved/write/published_unknown。只有这些以及两次完整读回/stale拒绝全部真才PASS。
此proof范围是FILE组件及dirfd setup全部open epoch，不是进程所有FD或普通结果writer FD。后者在已闭合后的固定HOST artifact代码以独立with关闭，不补造EBADF事实。
结果仅固定bool/count/枚举及源码pins，P011、RF/network、flock、provider、Store、恢复权全部false；不输出token、实际路径、actor、raw或自由异常text。
新版公开结果固定于仓库 `results/client-files-linux-host-<UTC time>-<random>`，EXCL目录/公开双文件，不覆盖旧报告；stdout只JSON，不打印随机目录路径。
实验后synthetic journal/run/base保留少量私有文件供ROOT审查，不包含用户凭据。无自动清理脚本或授权。

## HOST FakeIO证据

本轮首次且唯一新harness专项：`python -B -m unittest discover -s tests -p test_client_files_linux_check.py -v`，目录 `working/MtaP011-v0.1`；工具 `bbf6f7` 完整13项各ok，`Ran 13 tests in 0.107s`、`OK`、host exit0（工具wall0.575s）。没有FAIL/ERROR、没有重复运行已通过项或项目全套，也没有执行真实Linux。
覆盖：pure构造/default、明确CLI/selfSHA、实际五源码pins及3.5 AST、确定synthetic两commit/完整readback/stale generation、base复用与run EXCL无重试、pending所有entry及后到entry、root/tmp/base owner/mode/symlink、同bytes不同inode最终拒绝、fsync保留temp、独立全部关闭且unknown不reclose、BaseException opening/非法FD、平台/token/预算失败。production无测试fixture import。
首批harness356行/18728B，历史SHA `bf43d4119bca74fef0ab0be24dd53ae8944fe887c306eb5ff1e0da2f3cc1d5cb`；tests256行/13472B，历史SHA `0a2efb9b5d547958aa094389ad99d6e8d787d7727caff4b68a7b39485438e15d`。ROOT全文审查后发现API返回失去unknown强引用及临时check对象缺口，因此仅增once gate、实例引用、单shot强registry与对应测试；不是重判首批13结果。
本次仅新增5＋必要受影响6命名批（工具 `9da2da`），目录 `working/MtaP011-v0.1/tests`，`python -B -m unittest -v test_client_files_linux_check.LinuxFilesCheckTests.<固定命名方法>`：新增unknown-close强引用/once、interrupted-open强引用、invalid-FD强引用、成功闭合释放但不得二次execute、registry在result-writer异常时保留真实实例5项；受影响constructor/default、explicit CLI、两commit、close unknown、interrupted/invalid open及sourcepins/Python3.5 AST6项。
实际完整11项各ok，`Ran 11 tests in 0.145s`、`OK`、host exit0（工具wall0.595s），没有FAIL/ERROR。不重跑首批13整套、不运行当前全部18或项目全套，不能把13+11相加冒充独立通过24项。
当前harness369行/19649B SHA `1aa06935daa55076bbb4b46289d4dd10fee62ff2033ab69fc373d979734579aa`；tests316行/17537B SHA `a6e6604be94e23e35d1538a16c4ad5b39ea88eb11034cbf853c72c9dc9c9c46a`。本文当前SHA另行交付，不自引用；本增量仍只有FakeIO，实际Linux/root/tmp/fsync/rename/FD及P011未执行。
FakeIO独立在本测试文件实现，生产harness不import它；真实os/ctypes/socket/subprocess均阻断。上述真实Linux/fsync/rename/EBADF、filesystem持久性仍未由作者执行，HOST fixture不得升级为P011或CLIENT可用。

## 2026-10-01 14:40 core pin 显式维护

ROOT全文核新finish源/恢复增量/新测试与77行review，三SHA与交审固定值一致；
本harness只使用Identity/Actor/Snapshot/Journal，不执行ClientInitLease、finish或Provider。
为保持一键source-only在当前工作树可用，仅将core pin由88f16e显式改为已审ec2d927，
加范围注释和一个pin断言，实际FILES/codec及执行逻辑不变，不放宽任何门禁。

修改前不可覆盖SOURCE `artifacts/SOURCE-client-files-checker-20261001-1aa069.zip`，
SHA `6cee0bed3914ebe301276d6986084d204e27b66532be11647a1fdfb9ff225b51`；
ROOT f2aba7实际读ZIP entry，原完整SHA仍1aa069…579aa。不是部署包，旧真实Linux
17FD结果仍对应旧checker，不升级成新源码实际I/O结果。

唯一受影响命名批ROOT工具 `6b2dd2`：source pin/3.5 AST、pure default、synthetic
两commit与stale generation，共3项/.059s/OK/exit0，FakeIO，不重跑旧18或整合1322。
ROOT `f2aba7` 仅 `--source-check-only` exit0，没有WSL、目录创建、flock、RF或ADB。
新checker SHA `202ca29d486219ef28c4deb8e25743cd30121d104516fb8c9dc2f6ef83a042ed`，
tests SHA `437ccd751436b72c5ddafaaf0b49c5ce6c885d5908b46e4511be56a1a8b6e545`。
未执行新checker的 `--execute-reviewed`，新pin不签新Linux或P011验收。
