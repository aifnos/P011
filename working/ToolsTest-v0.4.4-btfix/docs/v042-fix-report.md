# P011 Tools Test v0.4.2 修复记录

- 触发日志：`Unable to find type [IO.Compression.ZipArchiveMode]`。
- 发生阶段：`Test-P011ResultTools` 主机自检，在 `Find-Adb` 之前，因此该次失败未访问或切换 P011。
- 根因：结果模块只加载 `System.IO.Compression.FileSystem`，并使用 PowerShell 缩写类型 `[IO.Compression.ZipArchiveMode]`；用户的 PowerShell 环境无法解析该枚举。
- 修复：结果与 RAW 打包路径均显式尝试加载 `System.IO.Compression`、`System.IO.Compression.FileSystem`、`System.IO.Compression.ZipFile`，并使用完整类型名 `[System.IO.Compression.*]`。
- 设备端 QML、菜单候选、ADB/电池/无线电/浏览器/媒体/SSH 实现未改。
- 仍需实机/Windows 验证：本容器没有 PowerShell 运行时，无法在本机执行 PowerShell 自测；包内自检会在连接设备前执行。
