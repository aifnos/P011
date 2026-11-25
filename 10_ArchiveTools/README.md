# 归档辅助工具（全部为电脑端离线工具）

`Verify-Archive.ps1` / `verify_archive.py`：核对MANIFEST中的文件大小与SHA-256；允许另有working输出，清单不自包含自身。

`Rebuild-System.ps1` / `rebuild_system.py`：从8个原ZIP读取固定分片，按顺序重组新的system.img，不调用adb、ssh、刷机命令。仅完整版可直接执行。

`extract_qrc.py`：从固定原版Z03重新导出Qt资源，只读原版，不执行ARM程序，Windows非法文件名字节编码记录在资源映射。需要开发电脑Python3。

Python的镜像流式验证、实际写出、拒绝覆盖、QRC重导出已在归档主机执行。PowerShell脚本和CMD入口做了代码检查，但当前没有Windows执行环境，未声称在你的电脑验证通过。若遇到错误保留原文，勿修改系统执行策略或提升权限来硬装。

这些辅助工具不修复旧工具箱的Wi-Fi/退出问题，不是新一轮P011测试。
