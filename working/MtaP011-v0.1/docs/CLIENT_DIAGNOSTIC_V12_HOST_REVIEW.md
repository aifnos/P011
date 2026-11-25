# CLIENT diagnostic v12 HOST 候选

仅 PC SOURCE / 新 HOST 方法；尚未执行 v12 ADB、staging、RF 或恢复。v11 唯一实机 FAIL 与原日志保持，当前 v11 文件仍保留。小米 15 Ultra 未开始实际互传验收。

## 固定差异

新入口 `host/client_init_diagnostic_v12_p011.py` 固定读取 SHA `89a982b0fba22e9720e00a98d95a84547287d38945567f2a53c639e8c5f09248` 的 v11 HOST，并保留其已固定 v10 基础。只替换候选/log 标签、3 个诊断 source pin/路径，以及 TARGET 的 private projection。20 名称/顺序不变；common、Coord、FILES、Parent、StageOwner、所有预算与 stdout parse 门禁不变。

projection 新增 exact `mta_ip.IpSnapshot / AddressRecord / RouteRecord / RuleRecord` 四类型，按冻结 `_fields` 保留每一字段。空表会明确为 addresses/routes/rules 三个空集合；其他 namedtuple/子类不能冒充这四个类型。没有 generic `_asdict`、新网络读取、公共地址暴露或基线/恢复准入放宽。旧实机 raw 的 `{}` 不回填。

默认仅 SOURCE；未冻结 pin 时默认与显式 execute 均拒绝。`HOST_CLIENT_DIAGNOSTIC_V12_SOURCE_CHECK.cmd` 只调用默认入口，未执行该 CMD。它不是部署、无线初始化或遗留文件清理按钮。

## 当前新测试

ROOT `7400d5`，`py -B -m unittest discover -s tests -p test_client_init_diagnostic_v12_host.py -v`：8 个新方法，0.341s，OK / exit0。包括实际 PC 20-source 校验与组合 SOURCE 的 Python3.5 AST、候选身份、只替换3源、TARGET除投影逐字等同、IPv4 非空/空/拒绝子类、旧投影兼容和未冻结执行拒绝。

这是最初 Provider pin `1bf7cae3…43dd0` 的证据。独立源审发现 OS 子类分类与 exact-type 合约不一致；作者仅修为16个 Python3.5 builtin OS族 exact类型，并精准分类回归。最终 Provider `17e09c40d4c04c048b46e50de1151a97726086c0b43cace8a0c7e5fd3d7eb288` 更换后，ROOT `edc2af` 仅重查受影响的实际 PC 图方法：1个 / 0.343s / OK / exit0。其余7个已通过方法不重跑；共8个不同方法分批证据，不称最终一次整八通过。

最终 F `549cd0652434d934134e465ddfc08c9baf7df9293acb7e567ce9c1a1285bd78f`，Phase `03210b8c83df82993a0322398169f1ac42836d52ab8e3add92617c34b9191bad`。SOURCE 字节核验、组合 AST 是 PC 证据，不是实际 v12部署或恢复。

没有执行旧测试套，也没有产生新设备日志或收发成功状态。没有清除旧 stage/pending、修改原厂/启动项/无线固件；新入口仍会原样拒绝非空旧 stage，不提供绕过。

## 必须分开的证据

F 的诊断只使用固定非秘密符号写入原 stderr，不能取代 FinishReceipt、原 FD 关闭、fresh absence 或完整 Snapshot.key。Phase/Provider 仍可能在诊断未覆盖的 try 外失败；Linux Lease 原构造未设置 Phase `_diagnostic_start`，F 将缺失视作 not_recorded，不造“未出错”。正式 CONNECT、内核关联、CLIENT IP/可信端点、GO 与 State/文件中心接线仍未完成，目标 active。
