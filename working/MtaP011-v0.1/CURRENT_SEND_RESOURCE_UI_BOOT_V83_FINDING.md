# 发送资源闭合、互传页面与固定加载接线

2026-10-03。本阶段未访问 P011／手机、启动无线、重启或清除旧 pending。对端按小米 15 Ultra 记录，系统与原厂互传版本待真机验收确认。目标仍 active，生产收发仍关闭；尚非只剩人工测试。旧来源和失败结果保留。

## 1. Key79：异常释放不再误算已闭合

原 KeyPair 在 native free 返回前就设置 closed=True。Bridge79 现在保存原生成／关闭函数、库、key 和 native pointer 原件以及实际返回／异常；异常或未知纳入整体闭合判断，不据 key.closed 签资源已释放，不重复 free。

ROOT `ddc847` 首次唯一 HOST 方法通过：15 个独立夹具，child0、无超时，0.344 秒；unittest `Ran 1 test in 0.222s / OK`。实际执行固定 crypto 原 generate/KeyPair.close、Bridge79 四方法及 close/status。EC 库和指针、State/deployment/clock 前提明确是模型，不证明真实 libcrypto 释放或密码学，也不执行进程／管道／F／GATT／RF。

ROOT `e1aefb` 和另一位只读审计者核9份当前／保存输入、严格 raw 和四成员 ZIP 逐字节／SHA／CRC一致。stdout99 B、stderr100 B。[Key79 公开结果](results/go-send-key-close-v79-host-20261003-072854-8489dc11/public-result.zip)：2166 B，SHA `06f167eaf562c2181ee69f2d479c55d4edd272c1c3120da94caf9503235a869a`。[电脑一键入口](HOST_MTA_GO_SEND_KEY_CLOSE_V79_CHECK.cmd)仅 HOST；实际执行的是固定 Python checker，未称人工双击已验证。

## 2. UI80：明确准备、锁定选择、等待结果

候选将发送改为明确的“准备并搜索”→当轮设备选择→发送。准备／搜索时锁定文件、改名与模式切换；取消／停止搜索仍按实际动作发出。原文件 IDs 不一致时拒绝沿用已准备任务；刷新只 GET 状态，不隐式执行网络恢复。GO 的等待确认／等待结果分别显示，字节100%不是对方完成或网络恢复。

ROOT 首轮 UI80 `4b572d` 整体 FAIL：前两域断言走完，第三域 QObject.findChild 找不到动态 ListView 视觉节点。原页面不改；独立 R2 用实际 QQuickItem.childItems 视觉树定位，再以真实 Qt 鼠标事件点击，未虚构 delegate 或直接赋值代替点击。

ROOT R2 `33e39a` 整体 FAIL：原第3–6域断言走完，第7域离屏 grabWindow 返回空图。R3 只验证原剩余第7–8域，不重复前六域；改用电脑 Windows 平台、原 software backend 和短暂 HOST 窗口。缩放设置仅作用于子进程，截图未做像素编辑。

ROOT R3 `037038` 首次唯一新方法 PASS：两个剩余域，child0、无超时、1.641秒，unittest `Ran 1 test in 1.471s / OK`。实际 HOST Qt5.15 QML、MouseArea／按钮事件和窗口截图执行；request() 是明确的 inert HTTP 模型，不是服务或真实 XHR 晚回测试。R1/R2整体FAIL保持，不将有限证据合成原八域整体PASS。

ROOT `a2716d` 与 checker 作者的只读 artifactcheck 核6当前／保存来源、5 ZIP 成员和 PNG；作者核验不称独立测试设计。[R3 公开结果](results/go-send-ui-v80-r3-host-20261003-074813-4a5ac5f1/public-result.zip)：34623 B，SHA `dd346a767bdd2f41fbca28048c405bf3fb1cbe0fc705370095c305458d03766f`。[实际 HOST 截图](results/go-send-ui-v80-r3-host-20261003-074813-4a5ac5f1/host-ui80.png)：800×268、32341 B，SHA `7676552583526a2ac0fe135f305c3fb157871cd6a6e3499340afe606a4c8cc11`；ROOT已看图，所示等待结果页无文字重叠／裁切，有明确HOST标签，不冒充学习笔实屏。

[R3电脑一键入口](HOST_MTA_GO_SEND_UI_V80_R3_CHECK.cmd)仅末两域 HOST。旧 R1 ZIP 2015 B／`b6c58c7682239f92be63567992088ec2890bada8143ef954a4cdf2d67399cde3`，R2 ZIP 2258 B／`24992e22fc2f8f9970ed2c179d15eb451ebd4941997eb65388034cc6b439c3dd`，各仅 result/README；失败 raw 保留私有。两轮原件已只读复核，未覆盖或公开失败 trace。

## 3. 固定加载与本地 preflight：实现不等于准入

新增 Pub82-r2 的 preflight_local()/consume_local_preflight()，实际代码检查固定来源／ELF、既有根目录、pending 缺席、原 worker／PID／cap，以及原 PreparedSend selection/archive 与有界请求快照。其产出只有本地 DATA，不采样 helper／stock／完整网络基线，不授无线或恢复权限。bundle seal仍None，缺少真实readonly observer时，publish在任何新目录／文件创建前拒绝；20秒准备slice只发行一次。

SOURCE独审找到两处 finally 后拒绝未保留failure、导致status.failed可能False的诊断遗漏。82-r2仅保留首次同一异常并bare raise，未修改库存谓词、时钟次数、闭合或期限；旧82保留。82-r2完整源码／窄差异已ROOT和另一人读审，尚未动态执行其正向 preflight。

新 Boot83 将普通固定源表22→26：换State78/Session78，加入PreparedSend、Pub82-r2、Bridge79和canonical GO Loader。Loader使用真实 assets 路径／__file__，不伪装普通State路径；CLIENT F37保留canonical，CLIENT私有35图和GO私有24图不混入普通模块域。load仅建立定义，不构造State／Server、不探测helper、不启动RF。ROOT和另一位SOURCE审阅者完整读审来源、唯一新测试及27-source定义map，随后执行首次专项。

ROOT `df5287` 首次唯一 HOST83 方法 PASS：四个新域（正常26定义角色、unsafe assets零open、错放Loader无fallback、加载后__file__改动拒），child0、无超时、0.437秒；unittest `Ran 1 test in 0.270s / OK`。实际 Boot load/authenticate 与普通模块定义执行，FS/ARM metadata、source FD/EBADF、PID和clock明确为模型；不构造State/Server、不执行helper、Pub82正向preflight、私有35/24图、Parent/F或准入。

ROOT `aa90bc` 与另一位独立只读审计者核32当前／保存输入、固定Python、严格raw和4成员ZIP逐字节／SHA／CRC一致；stdout102 B、stderr100 B。[HOST83公开结果](results/go-send-fixed-boot-v83-host-20261003-080743-97f5d3e4/public-result.zip)：3719 B，SHA `68141e2a143542eadb5c97fed74b2a477e9562241df1f7d7c9c600a0a45dc773`。[电脑一键入口](HOST_MTA_GO_SEND_FIXED_BOOT_V83_CHECK.cmd)只做此新HOST专项，实际执行固定Python checker、未称人工双击验收。不能将定义加载或模型关闭升级为P011文件系统、发布seal、无线/网络恢复或真实手机互通。

| 当前来源 | 字节 | SHA-256 |
| --- | ---: | --- |
| Bridge79 | 63045 | `49d4a28c2156b8b99d0ac5965ec4f3cd4bdf617dddfbfcca90073e08e6a50cb4` |
| UI80 MtaPage.qml | 25341 | `2729358896390175557a2ec907286f8413fa600d0dee0397517ae4c9cd133c0a` |
| Pub82-r2 | 34324 | `ce61cc7a3b59f1e311078ccd590e1af001ffb95c378008767778f047ca8e38e2` |
| Boot83 | 18910 | `43c095f8bf78cf7fff493f76645a700c67a9c278a423ab531b1954109a6bc1b1` |
| 27-source定义map | 5830 | `aa566a842378082c53b762c30cf6cbc30c2345e60d11107a3fb5a32e9108f945` |

## 4. 后续实际工作

仍需固定asset seal与正式Owner原服务cap、readonly preflight producer/consumer、原F finish导出和独立网络恢复核验，以及接收正式准入／双向实机链。设计接点在 [实施计划](docs/SEND_ADMISSION_RESTORE_PLAN_V81.md)，计划本身不签实现或PASS。既有数据面／Linux TCP/TLS／进度专项已通过，不为本轮重跑旧方法。

设备旧pending／完整恢复未证属于先前记录，本阶段未现场刷新，也不据它断言无线损坏或已修复。正常重启许可尚未收到回复；不自动清记录、修驱动或试RF。后续P011动作前须读交接／版本表／最新radio，并新枚举显式ADB transport、只读当前基线。小米15 Ultra目前不用操作。
