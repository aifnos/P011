# 文件选择原资源生命周期修复

2026-10-01，仅修改runtime/mta_files.py，新增FakeIO专项及本文；不修改sender/State/worker/协议、storage安全路径、用户目录或冻结候选。不执行真实OS open、WSL/Docker、ADB、socket/network/RF或全项目套测。

## 已确认缺陷与最小变化

原open→fstat→fdopen中，fstat/fdopen抛错可能让rawFD没有进入entries，原except仅关entries而漏FD。
原close提前closed=True，首handle.close抛错会跳过后续handle，再调用又因closed直接skip。
现在每次open之前登记private ticket到registry，持有exact open/fstat/rawclose/fdopen callbacks、原returned值及实际wrapper，返回后立即保留。
返回exact非boolint FD才承认raw owner；trusted OS严格整数errno负open判known noreturned资源，BaseException/未知/畸形返回保持strongrefs+sticky pending，不关陌生数字。
fstat前后尚未发生fdopen时，普通错误/签名不一致可只关原raw owner一次并独立EBADF；初始EBADF失去raw归属则不再关可能复用的数字。
进入fdopen之前标transfer unknown，fdopen异常或畸形wrapper（含foreign fileno）不盲raw-close或close外国wrapper；保留exact原FD、wrapper/callback强引用，registry阻断新的open_selection。
成功wrapper必须原FD同exactint、strict closed=False、mode=rb、readable=True/writable=False及callable close。旧O_RDONLY/path/opaqueID/size/total规则保持，没有用户传入IO或路径的新入口。

## close与API语义

selection持有独立原ticket tuple，不通过可变public entries重新找owner，caller清entries不能漏原handle。
首次close逐个独立尝试所有已验证合法original handle或pretransfer raw owner，每epoch最多一次；首异常/BaseException不会跳过后续。
正常close返回None、strict wrapper.closed=True（claimed时）和original FD fstat严格EBADF分别观察；任一异常/未知/非None返回sticky pending。即使.closed=True、原FD已EBADF，close异常也不能变PASS。
.closed兼容含义是selection已失效/不可复用；全部首次关闭尝试后才True，不是完整FD退出证据。context enter在close requested后拒绝。
unknown重复close零IO且固定ValueError失败，不重close潜在复用FD；正常repeat返回None。没有隐藏clear/force-close/重试/GC/destructor授权。
严格closed ticket可从registry当前inventory释放，selection仍保留自己原ticket的只读观察。sticky registry pending不自动清，list_files可继续原只读扫描，open_selection拒绝新增资源。
open失败清理独立尝试此前所有known resources，catch BaseException后原异常重抛；正常stale路径/known negative open且全部资源已关不会假报unknown。

## 新增只读status（worker合同）

FileRegistry.lifecycle_status exact8keys：resource_count/open_attempt_count/close_attempted_count/wrapper_closed_count/fd_closed_count/unknown_count为int；resource_pending/closure_verified为bool。
FileSelection.lifecycle_status同8keys另加close_requested/selection_closed两个bool。没有名称、路径、opaque ID、FD数字、actor、raw或exception text。
counts为当前strong-owned ticket inventory，不是process/lifetimeFD总数；registry空且无sticky pending的closure_verified=True只表示当前无未明资源，不能证明无open历史或其他worker/provider闭合。
status只返回缓存的严格观察，不再OS调用、清除unknown或授予恢复/发送许可。worker只调exact selection.close一次（可以固定失败），再核lifecycle_status.closure_verified；不要手动循环entry handles或按.closed假PASS。

## HOST证据边界

全文读原mta_files和test_files，核sender及transport/service调用边界；保留API不自动跑实际TLS/tempfile集成。
新FakeFs模拟open/fstat/fdopen/wrapper/read/close，真实目录写/清理/外设blocked。3个必要旧命名方法仅在FakeIO注入下调用原test_files方法，不运行原setUp真实TemporaryDirectory；不把它们称真实文件系统测试。
唯一首次专项工具393bb1：在项目目录运行`python -B -m unittest discover -s tests -p test_file_selection_lifecycle.py -v`，24项全部ok（21项新增FakeIO、3项旧命名方法Fake适配），`Ran 24 tests in 0.043s / OK`，HOST exit0，工具wall0.432203s；其中包含Python3.5 AST。没有重复已通过批次、全套测试或实际文件系统测试。
这份HOST证据只覆盖代码与假IO资源合同；真实P011/OS FD/readback、sender运行、worker实际集成、手机传输均未测试。

## 稳定文件身份

runtime/mta_files.py：194行、10267B、SHA256 `c37a00be58487abee32abf7ded7ed857e059883aee680e049e6372d3d06681ae`。
tests/test_file_selection_lifecycle.py：267行、17145B、SHA256 `240be0f47f831bad1736c15ae0585764cd58c99474fbde0cf6d8d9db97c400ed`。
上述两源在唯一专项后未变；本文只追加实际证据，最终本文SHA由交付消息给出，避免自包含哈希。
