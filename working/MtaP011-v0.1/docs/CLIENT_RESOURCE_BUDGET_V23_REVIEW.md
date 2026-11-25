# CLIENT v23 原件资源信用账限定回执

本件仅新增 `candidate/client-resource-v23/runtime/mta_client_resource_budget.py`、`tests/test_client_resource_budget_v23.py` 和本文。已全文读 frozen v22 Store、v19 Provider、v21 DORA/DHCP及现行成本图；不改旧源、旧 manifest/F、历史、旧20秒 trial 或任一 TTL，不运行旧方法、设备、服务或网络。ROOT 独立负责 FILES/Store/Provider 新图的具体 hook、原登记与逐FD闭合核验。

## 实际接点与窄 API

`ResourceBudget(store, profile=SOURCE_PROFILE)` 只接受同定义域 actual `DurableClientInitStore`、原 `_mutex` exact RLock、`_epoch` 与唯一固定 profile 原件，注册在 Store `_resource_budget_v23`。Store/Provider import 位于方法内部，构造不读 `_files`，可在 Store 创建 FILES 前绑定。可选 `bind_provider(actual)` 允许其 `_store` 暂为 None、随后 attach 同一 Store，且只登记一次；bind时已指向实际Store则当场seal，否则首次_context见同Store后永久seal，不再接受退回None。owner/epoch/RLock/原绑定漂移拒绝新申请，原信用和返回物不删；漂移后returned仍先存原物、标late/sticky，settle终结actor但不放未知max。正常 Canonical/current/journal epoch/CAS/handoff advance不是 Store generation变化，旧信用保持历史原指针，不升级为 live 许可。

固定调用顺序为 `reserve(lane, kind, retained_payload_bytes)` → `started(credit)` → 原 producer → `returned(credit, actual_original, retained_payloads)` → 原 finally 的 `settle(credit)`。只有可信内部调用，不能接 HTTP、caller dict/capacity或任意 closure callback。`mark_unknown(credit)` 是实际发行者报告创建/后验未知的sticky入口，不是授权；不清原 unknown。没有refund/retire/close/observe_closed或恢复/网络认证方法。

reserve在创建前核固定count和共享byte headroom，预扣并登记 exact Credit。started登记 producer active。returned先保存原返回物及实际payload tuple，再做类型、计量与owner后验；未知、晚返回和超max都保留原物。settle只表示同步 producer真返回，不表示FD闭合；active/no-return/sticky/late不能释放未收敛额度。caller传 `True` 不能变成 `CloseProof`：broker从不发该类型、不能签资源闭合，ROOT仍必须消费现有 actual original registry/Store `_fd_closed`/Provider `_closed_fd`及per-FD即时证据。已闭合原件/evidence强引用和历史count仍保留，numericFD从不由broker重close。

## 两独立池与内存计量

固定lane只有 `PREPARATION_NETWORK` 和 `CLEANUP`，不可借用。固定kind及ROOT确认冻结的当前可信内表如下；这是有限 SOURCE profile，不是足够所有环境的声明。

| kind | preparation/network count | cleanup count |
|---|---:|---:|
| FILES_OPEN | 2304 | 256 |
| CANONICAL | 2304 | 256 |
| PROC_CALL | 8192 | 512 |
| COLLECTOR | 64 | 16 |
| KERNEL_READER | 64 | 8 |
| CAPS_READER | 64 | 8 |
| FD_RECEIPT | 131072 | 32768 |
| LEGACY_REQUEST | 2048 | 256 |
| LEGACY_PACKET | 131072 | 16384 |

各lane所有kind共享累计payload ceiling：网络64 MiB、清理32 MiB。不是每kind独占64 MiB，未增旧绝对期限。清理原16 MiB暂定池与actual collector16 MiB预留、内层proc2 MiB和已存Canonical冲突；ROOT据只读SOURCE finding仅将清理payload池固定为32 MiB，新纯HOST方法核此已命名nested形状可用，不签所有清理流程。计量分两账：累计 `retained_payload_bytes` 是 actual tuple内精确bytes长度；`inflight_payload_bytes` 是 producer的尚未收敛上界。reserve前核两者和max；已知 actual≤max时把actual从预留转入累计保留，actor仍active时max−actual继续占额；只在真实settle后释放这部分unused temporary reservation。不是退回已保留raw、原件、历史count或unknown票据。首次6方法中的10轮8 MiB max/小actual均可继续、累计实际55 B且每次settle后inflight为0，验证没有把所有max永久占用造成always-deny；该方法未被增量修订重复执行。

known safe_exhaustion在内层创建前拒绝，不新增resource未知、也不改Store sticky；已有active/unknown状态不会因它洗白。超出声明max是 producer预算未知overrun：actual先保留并累计，原max仍保留，网络撤权、清理池仍独立；不虚报cap内完成。malformed/超过4096个payload的tuple不可精确签完整计量，保留返回物并unknown。原始payload可能重复引用，按每次声明保留长度保守累计，不依赖hash相同去删原件。

这不是Python对象heap上界：object/list/dict/boxed integer/metadata/allocator、隐含子图与临时解码峰值仍UNKNOWN。payload由ROOT actual rows/`_raw`/`ProcObservation.raw`/source显式字段投影，漏掉的collector/StatusSource/Owner/Pending逐轮历史不能靠broker变成已覆盖；超过投影上限也必须unknown。8192不是已确认所有proc发行总数，3906旧推式不作全部路径上界。有限总图/额外原件维度/清理完整上界仍由独立上界文档与后续实接核定，不能据本表部署。

## 新 HOST 方法与证据边界

只从whole-pin过的v22 test选择graph/fixture定义AST，不import或执行旧TestCase/method。先核其Store/test和原v19 manifest24 sources，实际加载所需23个旧定义（不加载Executor入口）、用冻结v22 Store并新增broker；codec/core/coord/files/pending/Provider保持同域。首次新6方法覆盖：固定profile/不借用/共享bytes/count的precreate耗尽；10轮大max小actual；actual纯Provider两阶段绑定、不授权；actual Store FILES/Canonical/原per-FD evidence闭合后保留；active/unknown/late/overrun/owner漂移/foreign credit；Python3.5 AST/no-IO/no资源proof。增量新1方法核prebind与已绑定两分支的single latch及None漂移原件保留；再新1方法核实际累计历史后cleanup collector16 MiB+proc2 MiB并行预留、实际/count不退款和cancelled网络不得借清理池。两增量方法内均对各自当时源码/test做Python3.5 AST解析，nested方法解析的是final32 MiB版本。Provider._store二阶段变更只模拟accounting attach指针，不是实际Provider.attach或production gate证据。正向资源来自actual Store/FILES算法overFakeIO，不创建同名fakeFD或BooleanClosed授权。actual I/O adapters/proc、OS open/kill/waitpid、socket/CDLL/subprocess/Thread.start/sleep均有tripwire。

首次实际命令为 `python -B -m unittest discover -s tests -p test_client_resource_budget_v23.py -v`，cwd为 `D:\project\P011\working\MtaP011-v0.1`。工具 `0b8777`：6个不同新HOST方法全部 `ok`，`Ran 6 tests in 0.043s` / `OK`，HOST exit 0；该历史SOURCE SHA为 `d7ecddd7a7e17d215b80316cc51b98c775b8a2484da1e0de9c441ff3d0fe0b92`，test SHA为 `1136ade3eb2688c705f422fc89c90b8011ed583554d0babc818e2398c4c06cfb`，当时清理池16 MiB，不能回写成final8通过。

后续只执行新方法：`python -B tests/test_client_resource_budget_v23.py ClientResourceBudgetV23Tests.test_provider_original_store_single_latch_rejects_none_after_attach_and_retains_return -v`，工具 `57b6e4` / 1 method / 0.008s / OK / HOSTexit0（single latch修订、清理池尚16 MiB）；再执行 `python -B tests/test_client_resource_budget_v23.py ClientResourceBudgetV23Tests.test_cleanup_nested_collector_proc_headroom_with_retained_history_and_cancelled_network -v`，工具 `4ac08c` / 1 method / 0.007s / OK / HOSTexit0（final32 MiB池）。共3次命令执行、8个method执行/8个不同新methods，各自首次通过，无FAIL/ERROR、无修复重跑，旧测试方法执行数0。原profile方法仅将清理ceiling期望16→32静态同步，没有重跑原6；矩阵内subcases和10轮返回不是额外methods。

没有P011实际内存、时延、RF、baseline恢复、完整DORA、IP/endpoint或小米15 Ultra互传证据。ROOT实接的新方法另计，不冒作本文方法或旧测试重跑。

## 冻结读入来源

| 来源 | SHA-256 |
|---|---|
| v22 Store | `a829dfd10ed00ce4ea3fc8b4e850b917cb2e79d609de8dfa9ea096e33c2c97ab` |
| v22 test（只选定义） | `0eb618268144848b0e719bee6e67367d32f12e99f9f84356a53d0fa8175196e0` |
| v19 Provider | `58a55789c5069b06d1e5636113f2e1dc407c5c655c20c4f9519ba30c879e1e71` |
| v21 DORA | `0a0e521704c89467cee7bdaf8e656d684fb697016261143b6e82370594db083d` |
| v21 DHCP | `794421678866d04a10ca46fa9eb7e17174f24c4d9e705cf59016b457702003a0` |
| 成本图（读入当时） | `9a39ce256d2ff73fda099ec12d5f676e78a26d76243de74a091e8cd09e28137e` |

final broker为259行13521 B，SHA `b7bcca034c77dffa8ffc6e24a20ac19a81ae8981702c6f70f87acde1f6252f3c`；final test为346行23113 B，SHA `052018221bfcd493431b3e2370408d068874efe800a8088288740923a3288800`。本文不嵌入自身SHA，三件最终pins由ROOT冻结回执交付。旧FILES256、旧Provider reader8等未被本broker静默改动；预算信用本身不解决完整图消费接入或资源闭合问题。
