# P011 学习笔开发项目

面向碳氧 P011 学习笔的应用、工具与系统实验。设备侧基于 ARMv7 Linux、Qt 5.10 和 Wayland。

| 方向 | 源码 |
| --- | --- |
| B 站客户端 | [BiliP011](working/BiliP011-v0.1/client/ARCHITECTURE.md) · [独立仓库](https://github.com/aifnos/P011-Bili) |
| 浏览器 | [BrowserP011](working/BrowserP011-v0.1/) |
| 手机无线互传 | [MtaP011](working/MtaP011-v0.1/) |
| 工具箱和小游戏 | [ToolboxNext](working/ToolboxNext-v0.5.1-native/) |
| 菜单、显示、触摸及无线诊断 | [02_Tools](02_Tools/) |

## 使用边界

仓库包含公开源码、构建与测试脚本。设备固件、原厂程序和专有库、账号数据、现场日志及生成的安装包保存在各自的本机环境。构建时按对应项目的说明准备所需依赖与自有设备的原版输入。旧脚本中的本机路径占位符和历史产物引用需要按实际环境配置。

项目包含历史实验。运行前请查阅 [开发约定](01_Environment/03-继续开发约定.md) 和 [设备操作要求](AGENTS.md)。B 站的 ADB 安装环境有成功播放记录，免 ADB 安装尚待完整实机验收。手机互传尚待真实双向收发验收。

第三方组件的来源、版权和许可随对应目录保留。
