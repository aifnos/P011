# v20 只读 IPv4 私有投影补点

本候选只补冻结 v17 日志中的 IPv4 投影。已由 ROOT 给定的 v17 实际只读 PASS 仍不能替代完整当前网络与恢复证明：其两轮与 snapshot 的 IPv4 记为 `{}`，因为固定 `mta_ip` 的四种 namedtuple 类型具有空 `__slots__`。旧实际日志、源码及历史判定不改写。

## 固定来源与唯一 TARGET 增量

- v17 helper 全字节 SHA：`e2bd556d9d10fb80aeb2a2748837991336a0ba88f802635fad97d03d2cfa9a11`。
- 原 timing profile 全字节 SHA：`c2077c53c20ef3b6eb1dfc6d2d7a0658807f95569bfb6bd76b8df25155a19a3c`。
- 全文读上述两源，并读 v12 的精确四类型投影及原 `runtime/mta_ip.py`；v12 仅提供投影模式，不导入其 INIT、候选、LOADER 或执行入口。

新 wrapper 在私有模块中整 SHA 加载原 v17 helper，沿用其已冻结 v6/reference/notes 与 19 个源定义图。没有第 20 个模块、源替换、查询、IO、重试、状态恢复或无线补点。

在原 `projection` 的通用 tuple/list 分支之前插入两条 AST 语句：固定 `modules['mta_ip']` 引用，以及 exact type 判断 `IpSnapshot / AddressRecord / RouteRecord / RuleRecord`。只按这些固定类的 `_fields` 顺序递归构造字典。没有 `_asdict` 调用、通用 namedtuple 推断或子类 schema 升格。字段值、cacheinfo、metrics 与嵌套 tuple 仍按原规则投影；bytes 的 base64 和 ELF 的摘要规则保持。

生成器检查文本锚点唯一、完整文本逆向及 Python 3.5 AST；移除这两条语句后整个 TARGET AST 必须等于冻结 v17 的 TARGET。v17 首因安装及 `source_first_failures` 行保持原样，19 PINS / ENCODED / LOADER、baseline 原比较、10 秒 collector / 30 秒总预算、pending / unknown / CloseProof / public schema 均保持。

`build_source` 与 `execute` 的新候选 kind、公开 evidence/README 标识从原 SHA 固定 profile 的完整定义重建。每个标签替换也检查唯一、完整逆向，并只允许 AST 字符串常量变化；原 transport、150 秒超时、原始 stdout/stderr、HOST / remote exits 与日志目录私有内容规则保持。

默认 `SOURCE only`。显式只读仍必须同时给 `--execute-readonly` 和 exact reviewed driver SHA；不自动实际执行。此新增源码不授权无线、恢复、init 或新 boot 准入。

## 公开与私有边界

完整 IPv4 值仅进入原 private 日志，包括 rounds / snapshot。原公开 parse 固定 schema 不增加 IPv4、地址、接口或路由字段，`staging_attempted / rf_requested / restoration_verified / send_available / receive_available / phone_tested` 仍必须为 false。

原 sanitized ZIP 仍只包含 `result.json` 与 `README.txt`，不增加 private raw 或新 IPv4 字段。此次不生成实际设备日志或 ZIP。`diagnostic_complete` 仍只指诊断与登记 reader inventory 完成，不能签 baseline、完整当前网络、恢复、DHCP、手机或互传能力。

## 新 HOST 专项与验证记录

仅新增四个 HOST 方法：完整逆向/AST/冻结标签、实际 19 定义图与类型身份、具体非空嵌套 IPv4 字段/bytes/ELF/恶意 `_asdict`、公开 schema/default/显式 reviewed SHA 门禁。实际固定模块定义在内存加载；只执行 LOADER、v17 诊断安装及抽出的 projection 定义，未执行 TARGET。

`os.open/mkdir/unlink/rename/kill/system`、socket 与 subprocess 启动/调用均有 tripwire。未调用 ADB、设备、服务或网络，不重跑 v17 / v6 / 基线旧测试。

首次且唯一新专项（工具记录 `bff8a0`）：

`python -B -m unittest discover -s tests -p test_client_readonly_ipv4_v20_host.py -v`

实际 4 个不同新方法 / 0.457 秒 / OK / HOST exit 0。没有失败、错误或跳过，无补跑；旧已过方法不重跑。这是 SOURCE/HOST 投影证据，不是设备执行或手机验收。实际工具原输出保留在本次会话，不改写历史日志。

冻结并停写代码与测试：

- HOST：`49b891f9be285b13ec818c2e49739036abb769fc381cfb76f80bec670be360ed`，141 行 / 6455 B。
- Tests：`bca2cebd63f5e123dff607477c21f0c303065a25457a1ccb6470f2c607f5791f`，179 行 / 11837 B。

此文整字节 SHA 在交付 ROOT 时单独给出，避免自身摘要循环。三个新文件交 ROOT 全文复核；当前无 v20 设备实测、无完整网络/恢复签字，公开 send / receive / phone 能力仍 false。
