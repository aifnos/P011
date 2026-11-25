# HOST67 UTF-8 文件边界聚焦记录

## 当前结论与证据层级

ROOT `3c6d64` 于唯一首次执行中通过六个新方法，host_exit=0、无超时、耗时0.266秒、旧方法0。ROOT `4ddf01` 只读审计与独立实际原件审核均PASS：7份私有snapshot、严格stdout／stderr与四成员ZIP按原件核对。候选67仅完成本次限定HOST验证，未部署；本记录不改变任何旧设备失败、pending或准入门。

测试采用私有局部ASCII/POSIX路径代理：非ASCII str调用被拒，合法UTF-8 bytes严格转译到真实HOST临时文件系统；文件内容、FD、ZIP及CRC读回使用真实HOST标准库。非法UTF-8枚举项是显式模型，因为Windows文件名不能表示任意POSIX bytes。没有更改全局os、sys.modules或文件系统locale。既有工具箱FileStore验证的是HOST读回，不是P011目录FD分支。真实POSIX ASCII runtime、实际P011、手机互通、RF、生产准入及实际网络恢复均未验证。

## 五件冻结交付来源

| 文件 | bytes | SHA-256 |
| --- | ---: | --- |
| `candidate/file-utf8-v67/runtime/mta_storage.py` | 15161 | `9bcc905c8cc44400a83ad5d4f0a2fc9dafb8d28c36ba40f76e7ce9cdc3857afb` |
| `candidate/file-utf8-v67/runtime/mta_files.py` | 10987 | `c6316be40cf34f017d1d2160f48989a55edfa0a60a2abe6a2ff6b656773f752b` |
| `tests/test_file_utf8_v67.py` | 24076 | `14f99e713c4b7ab0ba23e35ee5cf927ac0b1eb82a018ec92cd1cf49938be851e` |
| `host/file_utf8_v67_check.py` | 8708 | `1bcfa4514e4d49479b567b81eeb7d08e093fc24bfea0d90ffe911ada46fe4a66` |
| `HOST_MTA_FILE_UTF8_V67_CHECK.cmd` | 298 | `7b2cd5cdd6d675649a3dae9e3a94f55cf22dda5c690290b661c89e7b48fcf161` |

纯依赖保持：`runtime/mta_protocol.py` 17958 B／`4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57`；`runtime/p011_json.py` 8061 B／`fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88`；既有 `integration/ToolboxMta-v0.1/runtime/mta_toolbox_storage.py` 9114 B／`d9fa92a795729d88f6fac27705a2883adba8aac72423b4ebcd9220ffb78ddb51`。七份私有输入为checker、test、两候选和这三份依赖；CMD不是该次隔离子进程算法输入。

原正式runtime两件未改：`runtime/mta_storage.py` 14335 B／`3c5c5f65ef0c8eb9a0256a99f931faff40558484bb908e89acee1c1c0aa3b4d6`；`runtime/mta_files.py` 10267 B／`c37a00be58487abee32abf7ded7ed857e059883aee680e049e6372d3d06681ae`。67的新件显式编码POSIX路径为UTF-8 bytes，公开路径严格解码为str，Windows保持str；未修改原网络／State／Loader图或开放收发。

## 六个实际新方法

类名均为 `FileUtf8V67Tests`，只执行以下六项，没有重跑旧方法：

1. `test_encoding_modes_and_strict_public_paths`：UTF-8原生／公开路径、Windows str分支及非法编码／路径拒绝。
2. `test_chinese_catalog_selection_actual_bytes_and_close`：中文目录枚举、白名单、不透明ID、实际文件bytes／inode、一次close与EBADF。
3. `test_chinese_zip_receive_registry_and_unchanged_file_center`：中文ZIP接收、计数／内容读回、目录注册及既有HOST文件中心读回。
4. `test_same_chinese_filename_never_overwrites_existing_namespace`：两次接收生成不同结果命名空间，原有同名文件与输入ZIP保持。
5. `test_cancel_after_chinese_member_write_removes_only_owned_staging`：实际成员写入后取消，只清本次生成的staging，原有文件及输入ZIP保持。
6. `test_invalid_utf8_enumerated_names_are_pruned_not_surrogate_published`：模型非法UTF-8枚举项被裁剪，不公开surrogate，不影响有效中文邻项。

这些局部路径用例不是完整目录竞态安全证明。v68竞态候选并行SOURCE制作尚未冻结／测试，不写已修复或完成，也不将67结果外推给68。

## 一键入口及唯一实际结果

PC入口为 [HOST_MTA_FILE_UTF8_V67_CHECK.cmd](HOST_MTA_FILE_UTF8_V67_CHECK.cmd)，固定调用 `py -3 -B host/file_utf8_v67_check.py`；checker仅允许无参数PC检查，使用一次 `-I -B` 隔离子进程、60秒上限，不含ADB、无线、固件或服务启动。ROOT已唯一首次直接运行checker；CMD仅SOURCE核对，未点击或另行重跑。此DOC更新不执行入口，也不授权重复运行。

结果目录：[results/file-utf8-v67-host-20261002-225639-020ef5cd](results/file-utf8-v67-host-20261002-225639-020ef5cd)。[public-result.zip](results/file-utf8-v67-host-20261002-225639-020ef5cd/public-result.zip) 四成员、2199 B，SHA `1c02c20d46ba05c2f088dd014fe7fb09809ae943200438e9b8598b5332372acb`。

stdout 92 B／SHA `760af8fe7edf22a17af982142ef259dfba743a23c94233d8e331e8da50e62a56`，严格marker为 `HOST67_FILE_UTF8 new_methods=6 old_methods=0 simulated_ascii=true device=false phone=false`；stderr 101 B／SHA `ca928eb8edd69c760928be62595c6dc85c7e54fe0b336933f6a7abc8593e0d8a`，`Ran 6 tests ... OK`。ROOT与独审封口仅签这些实际输入／输出和ZIP原件，不追加设备或恢复结论；失败raw和历史日志不改写。

## 保持的阻点与下一边界

GO64仍整体FAIL／pending／完整恢复未证，本轮正常重启及本次临时记录处理许可仍待；不自动清pending、重试RF或操作设备。小米15 Ultra已记录，系统与原厂互传版本未知，不再重复询问手机型号。生产手机双向仍False，目标active，真实GO、typed IP／DHCP、State／文件中心和最终手机验收仍未完成；HOST67及本次DOC更新不把目标改为仅剩人工。
