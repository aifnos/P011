# 固定 tmp 别名 v11 核验入口

`HOST_CLIENT_TMP_ALIAS_V11_SOURCE_CHECK.cmd` 只在开发电脑检查固定源码图与版本身份，不调用 ADB、不启动 P011 或互传。新入口默认为 SOURCE-only；缺少任一稳定 pin 时拒绝。此 CMD 新制作但未运行，不把它标为设备测试。

本候选解决已只读取证的原厂 `/tmp -> /var/tmp -> /var/volatile/tmp` 布局准入。不是修改原厂目录，也不是互传正式安装包。当前主审、交叉审核和分批首错误记录见 `results/client-tmp-alias-v11-root-review-20261002/README.md`，最新统一见 `docs/LATEST_CHECKPOINT.md`。

实际入口必须另经完整最终来源审查并显式匹配 driver SHA；一次 INIT/restore 仍不是 CONNECT、DHCP/IP 或文件互传验收。不自动运行旧 START、清旧目录/pending、重试或终止未知进程。原始设备输出含私有身份，只供本地审查；公开结果 ZIP 仅包含 result.json 和 README.txt。

手机验收对象为小米 15 Ultra，具体系统及原厂互传版本未知。手机双向互通尚未测试，生产 send/receive 保持关闭。
