# P011 静态候选准备 v40-r2

最新实际回执：ROOT首次P011准备已通过，HOST/remote0、无超时、28.188秒；38新文件读回/fsync/封存、47原writer库存闭合，旧1条目保持，前后两新原只读owner共4轮完整基线一致。ROOT核原payload来源、sealed/内容SHA、Proc一次关闭及四成员[脱敏结果ZIP](results/client-static-stage-v40-r2-20261002-133155-c8d4fe04/public-result.zip)，SHA256 `431d04085c9ebc381d6050e1004fc4e36f58194b7d2d0f436aed2edb33ef4c4a`，4236B。只有静态准备范围通过；全部RF/部署/收发/手机准入保持False。[完整范围与后续](docs/LATEST_CHECKPOINT.md)。下方为SOURCE审核时点。

ROOT 已完整读取原 v40 两源及 r2 全部窄差异，核 Python3.5 AST、固定源哈希、默认 PC 检查和生成包。原 v40 不修改、不执行。作者及独立审查的 SOURCE 记录保留在 `candidate/client-static-stage-v40-r2/SOURCE-HANDOFF.txt`。

| 新来源 | 字节 | SHA256 |
| --- | ---: | --- |
| `candidate/client-static-stage-v40-r2/runtime/mta_client_static_stage.py` | 30601 | `64773fe9a3c75f9cce8e9938dc8f9dc1d4914e4d00728dcef728d686b90ba0a2` |
| `host/client_static_stage_v40_r2_p011.py` | 28215 | `bd48a8a0987e109fc6714e2f00686796a557f19c9edcd96a57cc458445c41f4f` |

生成包 3601769 字节，35 个只读源、原 leaf、新 stage、待存储 Pending 与 WPA 全部 Base64/原字节往返一致；最大 header 行 516，整个包通过 Python3.5 AST。仅生成及验证，未执行包或设备操作。默认 PC 检查 host0、`adb_invoked=false`。首次实际准备结果如有，将追加到最新检查点，不以本文件 SOURCE 审查替代。

本次隔离修正：本任务合法写入或 chmod 改变 size/mode 后，关闭仍根据首次登记的原 FD dev/ino/type/root uid/gid/nlink、新鲜身份及仅原目标权限执行一次，不能因过时业务元数据误拒关闭；业务写入、fsync、读回异常仍失败。所有 seal/sync 等操作在原期限内入场并后验；期限过后仍可关闭已知原 FD，但不签业务成功。未知关闭/EBADF不洗掉。

设备入口只向原固定私有根中新建唯一 EXCL 子目录，保全部旧条目及其元数据，不进入旧子树、删除或覆盖。两个只读 owner 在同一原 120 秒任务内新建，各独立 30 秒上限；使用原 `4b9ea549…` 图及 `cd4c3ef9…` leaf，核实际前后完整基线和资源关闭。存入 `0ea4db9b…` 图仅是数据，新 Pending 不执行。失败保留部分新目录，不自动重试或删除。

这不是原子设备级排他锁、正式部署、RF 准入或恢复回执。没有 F／Parent／WPA 启动、扫描、配对、GO、IP/DHCP、真实收发或手机验收。`source_factory_ready`、`rf_admission`、`deployment_available`、`send_available`、`receive_available` 与 `phone_tested` 继续为 false。

设备调用需同时明确 stage 开关、上述驱动完整 SHA 和重新枚举的唯一 P011 transport；模拟器不能被选为 P011。此前保存的只读 PASS 不能作为本次写入授权原件。不得使用旧归档 START 或将本文 SOURCE 状态转成已运行版本。
