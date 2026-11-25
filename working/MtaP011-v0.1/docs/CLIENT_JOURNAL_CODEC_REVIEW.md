# CLIENT v4 私有 Journal 编解码准备件

本轮仅新增 runtime/mta_client_journal_codec.py、tests/test_client_journal_codec.py 与本文。
不是 ClientInitStore、真实磁盘适配器或恢复器；无 open/write/flock/fsync/CAS/atomic replace、
provider 调用、设备、网络、socket、进程、Docker、部署、冻结或公开结果包操作。
导入和错误对象构造无 IO。目标是 Python 3.5、现有 bundled p011_json；不用 stdlib json、
eval/pickle/object hooks 或动态 class/module tags。当前生产 receive/send 不变。

## 固定格式及 API

- encode_journal(exact core.Journal) → canonical bounded ASCII bytes。
- decode_journal(exact bytes) → 重新经当前 core 构造校验的私有不可变 Journal。
- envelope 只有 version=4、kind=p2p_client_rf_init_only、marker=p011-client-rf-init-v1-1、journal。
- identity 固定 candidate_sha/wpa_sha/ctrl_sha；WPA/ctrl 必须与当前固定 core pins 一致。
- Journal、Snapshot、Origin、Actor、Ticket、InterfaceTicket、IPv4 地址/路由/规则全部固定 key。
  非可选字段不能填 null；可选字段显式 null，missing 也拒绝；未知字段拒绝。
- bytes label 唯一形式是 label_hex=lowercase even hex 或 null，无 tagged object/base64/隐式转换；
  重建 bytes 后还由 core 验证长度、终止 NUL、没有中间 NUL。label_hex=empty 不等于 null。
- JSON arrays 重建为相应 tuple；所有行及 Actor.tasks 顺序、完整 task state、cacheinfo 四项、
  route metrics/可选数值、IPv6 原文本行全部保留，不以 Actor.key 或 IpSnapshot.structural_key 替代。
- stock pins 的原 core 构造规范顺序必须一致，解码不会将非规范输入悄悄排序后接受。

canonical 定义：bundled dumps(ensure_ascii=True,sort_keys=True,indent=None) 的精确 ASCII 字节，
含该编码器固定空格，deadline 必须是 core 存储的 finite float。decode 重建后再编码逐 bytes 比较。
多余空白/换行、key 顺序变化、替代 slash/unicode escape、另一数字拼写、裸 UTF-8 非 ASCII 等拒绝。
序列原顺序是私有记录的一部分，不擅自排序 task/interfaces/IP rows 或删除重复/约束。
拒 bool-as-int、浮点-as-int、负数、越界 PID/start/WDEV/ifindex/u32、类型子类和 arbitrary class。
完整 decode 复用当前核心构造与跨字段/阶段检查，但不修改核心，也不接受旧 GO 版本/角色迁移。

## 预算与隐私

固定最大 131072 bytes、8192 value nodes、深度 24；各数组还有原 schema 限额：
4096 IP/IPv6 rows、32 actors/interfaces、128 tasks、16 stock pins、15 metrics 与各固定 row width。
这些是全局及各表同时满足的上限，不承诺全部表最大值可同时装进一个 journal。
encode 在完整 dumps 前逐 token 计算精确 ASCII 长度预算，避免先分配超限 canonical 文本；
decode 先 bytes/UTF-8 门禁，bundled loads 拒 duplicate keys/NaN/Infinity/不成对 surrogate/
尾随 JSON/超深/超 nodes，再做 fixed schema/范围/核心构造与 canonical readback。
内建 parser 的结构预算拒绝统一映射 invalid_json；codec 自身预算有 byte_budget/structure_budget。

公开错误只有固定 JournalCodecError.code/args/repr；异常链以 from None 抑制，不把 parser/core
原异常文字放入公共 traceback。合法 Journal/Actor 等沿用 core 的 private repr。
原始 bytes/document 内含私有路径、原网络/Actor 数据；其 bytes repr 本来就包含原文，
调用方不得记录、展示、上传或放 ZIP。没有提供 public projection 或“complete”字段。
Python 内部代码不是恶意 monkeypatch 的沙箱；外层须 pin 此 codec、bundled parser、core/schema。

## 已验证和未验证

首次唯一专项：python -B -m unittest discover -s tests -p test_client_journal_codec.py -v，
工具 ef85c8，22 tests / 0.741s / OK / host exit0，无 FAIL/ERROR。
随后仅补异常链抑制与新增案例，工具 e17ce4 的 2 个命名受影响专项 / 0.023s / OK / exit0；
包含最终 runtime Python 3.5 AST 与禁止 open/socket/Popen 下纯 import/encode/decode。
当前测试文件 23 个方法，没有重跑本版 23 整组或项目全套，不把历史批次累计为一次全套通过。
HOST synthetic 覆盖完整 roundtrip、每个 map missing/unknown、所有数值家族、false/null/bytes、
完整 tasks/cache/metrics、duplicate/旧 GO、UTF-8/非有限/非 canonical、结构/转义后字节预算及隐私。

未验证 P011 import/实际 Python 3.5 执行、真实 journal 读写/权限/noSymlink/nlink/元数据、
fsync/原子性/锁域/CAS/崩溃/当前 boot/进程/接口/网络归属。解码的 ready/stage 只是历史私有值，
不能变成当前 ready、kernel complete、持久回执、权限认证或写入/恢复准入。
后续 Store 必须另审磁盘 envelope authenticity、原 references registry、同锁 current CAS、
所有实际 FD 独立闭合与恢复证明。本组件不自动写盘、不接管现有 pending、不提供静默 fallback。
