# CLIENT Prepare v10 HOST 接线审查

范围：新 SOURCE/HOST 候选，未执行 ADB、P011、RF、旧 START 或打包。
仅新增 host/client_init_prepare_v10_p011.py、tests/test_client_init_prepare_v10_host.py 与本文。
v9 四文件和所有来源模块均不回改；正式设备运行由 ROOT 审查/冻结后另行授权。

## 固定来源与最小差异

- 参考 v9 host：302cfa0d0ef395f45786da5e3c04ef6c4701d78b1aae8d9fd817d0e894f87161。
- TwoPhase：candidate/client-prepare-v10/runtime/mta_client_two_phase_lease.py，
  cc402317c4d07a37d82f2209f32bc688a212d04a1a3ec8fccdc95aa6ce6209d1。
- 新 host：cb50e2a92b669b64061f9872bcbb27265d3b3818517cc95cfabeaef3f8e714df。
- 新测试：dd8e0fa72654bc212eba4859a2f231141ca1ee3429062ddf1607b864d1def45c。

host 11 处精确替换可逆向恢复上述 v9 全字节：新 TwoPhase pin/path；头部、
kind、日志前缀；ENTRY 195、communicate 225、ready 52、RF 前剩余 155；
新增固定 init_not_ready reason 及终末 reason 选择。无额外 EOF 空行。
19 模块名字/顺序不变，8 个 SOURCE_LOCATIONS，其余 11 个仍从原 runtime 读取；
19 源 pin 只有 TwoPhase 改变。Provider 仍为 v9 的 8bb5dfae34ab7cc4…685798d6。
原 STATUS 来源/helper、WPA、旧 pending 拒绝、staging EXCL、无 kill/retry、
TTL 20、finish 90、raw/公开分层和完整成功合取均不变。

## 预算及真实继承接点

TwoPhase 新 start 将非 RF 准备限为 20 秒，在首 durable prepared 记录之前一次
建立不超过 20 秒的 active deadline；本 host 不改其谓词或实现。
ready 52 为准备 20 + active 20 + loader 10 + 余量 2；RF 前 155 为
ready 52 + finish 90 + after 5 + proof 5 + report 3。ENTRY 195 / transport 225
仍有 30 秒 HOST 等待余量；均为有限调用预算，不宣称硬抢占系统 I/O。
新图实际内存 LOADER 核验 LinuxClientInitLease 直接继承新 TwoPhase，
start 为该父类的方法，restore 则是 Provider 自有 override（默认 60）。
父 phase 的旧 restore 默认 20 不用于这个组合；没有伪造 mixed class，
也没有构造默认 IO/lease 来证明实际网络恢复。

恢复验收成功而初始化未 ready 时，pass 仍 false、能力仍关闭，
reason 为 init_not_ready，不再把这类结果错误记成 restoration_pending。
此记录修正不授予任何新的成功条件。

## 实际 HOST 批次

- 首批工具 3bdeff：7 方法，0.513 秒，exit 1；6 PASS，1 方法的
  delay=51.999 子场景 FAIL。Fake ready() 总推进 50ms，没有模拟数据到达时提前
  返回，导致临界事件越过窗口；保留首 FAIL，不是设备/生产 TwoPhase 失败。
  本批唯一新 19 源图 source_check、Py3.5 生成、真实类内存加载/restore override
  以及精确 v9 逆向均通过；无旧套测重跑。
- 窄增量工具 c576f6：3 方法，0.062 秒，OK，exit 0。
  仅首 FAIL 窗口方法、ROOT 新增 reason 方法及受影响精确逆向；
  Fake 改为到达事件时提前返回，覆盖 40、51.999、52.05；未改 TARGET。
- 当前 8 个不同方法通过来自上述分批，不声称单批 8 PASS。
- 元数据读回工具 04ffa3：exit 0；新 host/test 与 v9 四文件、TwoPhase pin 核对。
  此前 6f5a97 的 PowerShell 元数据枚举管道语法错误 exit 1 保留，
  不归为源码/单测/设备失败。

测试只使用 Fake 外设和 PC 固定源读取；tripwire 禁止实际 Popen/socket/kill/fork，
真实模块 loader 额外禁止 os.open/ctypes.CDLL。默认 main 仅 source-check；
本轮没有 execute-reviewed、真实初始化、恢复、手机关联或传输证据。
send_available / receive_available / phone_tested 均不开放。

