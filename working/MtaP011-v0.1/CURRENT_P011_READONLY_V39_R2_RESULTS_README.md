# P011 v39-r2 实际只读检查

验收手机登记为小米 15 Ultra；本次未操作手机，也未开始真实互传。

ROOT 首次执行新r2只读候选：HOST/remote exit均0，无timeout，HOST 10.735秒。原厂三文件pin、进程/镜像、Wi-Fi状态、接口及完整IPv4/IPv6两轮基线一致，Wi-Fi已连接。全局pending在采集前后均缺席。实际collector 418条累计资源记录和Proc 20代/804条累计open ticket均已确认闭合；不是同时打开418或804个FD。

只执行固定状态和netlink只读查询。没有staging、F/Parent/watchdog启动、扫描、配对、热点、P2P建组、地址/路由写入、原厂修改或清理旧目录。此结果仅证明本次完整采集及其资源闭合，不证明旧RF恢复、互传建链、收发或手机兼容。生产收发仍关闭。

公开结果：[public-result.zip](results/client-readonly-baseline-v39-r2-20261002-124020-e9808d5e/public-result.zip)，3568字节，SHA256 `240070164ff45df034f8a32f451b95fb581be0f8ff7b3a0ad5042b63da900877`。四成员为result、source-pins、README与SHA256SUMS，ROOT独立核CRC/逐bytes/35来源。原始stdout、stderr及源payload保留私有，设备标识、IP和进程细节不入公开包。

来源：driver `25e9437774f6d8b184f16e10a288debd7ae4885748a45ebc00b3a2bf92368c45`；leaf `cd4c3ef940ef12783dd0b91aba2805a4f4cbe50f2fe2bdccbddaa1db32f4b7ff`；35图 `4b9ea54997194ca895a3459cf88cd715b2ccc05e46c55b533920f8182314d07a`。HOST已核Python3.5 AST、header literal与Base64 roundtrip，最大payload行516；目标通过原STARTED/DONE/exit标记确认执行。

旧v39首试只在ADB传输层返回`error: closed`，无remote标记。旧回执中的started是调用前赋值，不是确认远端执行；仅作attempted解释，旧日志不改。新r2单独分离attempted与原STARTED确认。没有对旧方法原样重跑或在失败后启动无线修复。

下一步为可信静态staging、GO安全建组/恢复及完整HOST验证，再集成State/文件中心和双向收发；当前不是只剩人工测试。
