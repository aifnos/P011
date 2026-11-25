# 固定 Startup anchors 单项 HOST 合同源码

唯一 selector：`ReceiveStartupAnchorClockV1Contract.test_actual_startup_anchor_density_io_and_refusals`。

运行时读取且校 exact bytes/SHA 的输入仅新测试内五个 pin：packaged old Factory、new Factory、单块五键 spec、packaged Executor、packaged Owner。测试读取真实 AST，仅编译选中 Scope/Files/ReadOwner 函数以及真实 Owner._now；辅助 subset 直接复制进新文件，不 import、读入或执行旧测试 methods、旧模块 imports/main、整个部署图。保一块 anchors forward/inverse 逐字合同。

Owner._context、State、Received Directory、sys.modules 环境、metadata/FD/content IO 是显式窄 fixture。fake FD 的 open/read/fstat/close 与 EBADF 只用来检查真实 _Files 函数的调用顺序和关闭票据，不签 native FD、完整 Owner/目录来源、真实私有源 SHA、P011性能或UI通过。Publication 仅使用上下文 fixture 对比实际 anchors 原分支；不造实际 Publication/handoff 资格。

同一个方法对比深 proc、usr、private 路径的 clock/full-check 密度和 stat/readlink 顺序，验证原 alias23次及原算法保留；浅路径、其他 prefix 和 Publication 分支保持。拒绝入口或成功出口 Received check 时不交付 anchors。实际 _Files.read 使用有限 fake contents/FD，保 open 前 full gate、逐chunk前后、SHA后 full gate及原 close ledger的一次关闭/重复被动消费，未跳过成功读。

在首个真实受测 metadata stat 的 fixture 回调后改 bound callback、alias_owner.clock、alias函数/code、Owner函数/code/clock、phase/cap、tuple或Files.attempt；要求下一个 metadata callback 在任何 injected body 执行之前拒绝。另覆盖原 prepare 到期（同20.0标量，不续期限）。不覆盖任意并发恶意内存改写，也不作为完整自防篡改证明。

本文件仅编写与源码读回，尚未 AST、SOURCE、HOST、测试、构建或设备执行。ROOT 后续只执行上述一个方法并记录原日志，不重旧套件。
