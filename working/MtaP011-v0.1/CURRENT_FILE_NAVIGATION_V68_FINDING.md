# HOST68-r2 文件打开导航与异步竞态聚焦记录

## 当前结论与准确范围

ROOT `f0e026` 唯一首次直接运行固定checker PASS：host_exit=0、无超时、耗时0.922秒；一个新方法包含8个独立页面case，旧方法0。ROOT `4653e9` 只读审计及独立实际原件审核均PASS，核6份私有snapshot、严格stdout／stderr、四成员ZIP、原QML和旧未执行test的身份。候选未部署，不改写旧设备、无线及恢复结论。

ROOT `171a98` 预检HOST Qt5.15.2／PyQt5.15.11；测试只约束Qt5.x，不证明P011 Qt5.10.1兼容。实际候选QML及open回调／导航参与HOST Qt执行，但app.request是延迟in-memory fixture；派生playAudio只计dispatch，inert VideoPane只计Loader／停止事件，均无真实媒体I/O。独立原audio response生命周期没有修复或测试。本次不是实际设备页面、触摸、光学画面、物理播放、MTA收发、手机互通、RF、生产准入或网络恢复通过。

## 四件冻结交付来源

| 文件 | bytes | SHA-256 |
| --- | ---: | --- |
| `candidate/file-navigation-v68/device/FilesPage.qml` | 12524 | `34ecbd37bb0eabe36bf4f6d0a64086f29fe28340df54dbb97c066387e48ec523` |
| `tests/test_file_navigation_v68_r2.py` | 15496 | `bdd51ef0f99e22f5f219e12c0efb90b0a2b5816d3977d6e1d3ee3b0a9d43f9da` |
| `host/file_navigation_v68_r2_check.py` | 8556 | `4616f6ee51155fba0dab4c1e09a92440db9db2221de7a1648ac0934ca29b2adc` |
| `HOST_MTA_FILE_NAVIGATION_V68_R2_CHECK.cmd` | 309 | `412c90b357b6f39921d25a344a17328e6707af96e22716e13ff21f79fd6ff19d` |

原页面 `integration/ToolboxMta-v0.1/device/FilesPage.qml` 保持11950 B／`0ddd55b774e2ce9986f681886da2e69763e539d905de5dfb467e553a5ad32832`。旧 `tests/test_file_navigation_v68.py` 保持15209 B／`7179545a72b258571e32a9e68abb826a46bb729c0a8354bce9f5ed8be9470fa8`，仅SOURCE夹具断言阻断，从未执行；没有旧实测FAIL被覆盖或重跑。

r2测试唯一差异：合法video dispatch已计数1，返回后应该保留该累计计数。旧 `unselected(False)` 误强求计数0；r2改为分别核选中路径／类型清空、loading=false，并保持audio0／video1／toast0。候选QML本身未因该夹具修正改变，没有把测试修正当作新的物理播放实现。

其余固定依赖为原Theme.js 244 B／`308cc441d29a5d39e61e0418ad0b4dfbb3efa2be6ce0bf6e80577c73479d2edb`、Button.qml 665 B／`ef4f1f83c198ae40e56982eec7d1ee87d36185fae9bbf1b15ea8853b64dcb015`、Label.qml 269 B／`4f109dd7591c7363dc95883ca2c13cf43c3b9c9f461d72238d1567a52bd949fc`，均位于 `integration/ToolboxMta-v0.1/device/`。六份私有输入是checker、r2test、候选QML及这三份依赖；CMD未参与算法输入、未点击。

## 唯一新方法与8个独立case

方法：`FileNavigationV68Tests.test_only_new_open_epoch_path_navigation_and_loading_ownership`。每个case使用新页面与独立HOST目录，不把页面状态共享当作独立通过。

1. `back_preserves_new_listing`：打开音频请求未返时返回上级；旧回复不能选中文件或清除新目录listing的loading。
2. `directory_change`：切换到Received目录后，旧video回复不能恢复旧选中或影响当前listing。
3. `leave_refuses_late_and_future_open`：prepareLeave后忽略旧回复，拒绝新的open／load，不新增请求。
4. `refresh_supersedes_open_error`：刷新后旧open失败不清当前listing状态、不弹旧错误。
5. `new_same_path_open_owns_loading`：返回再打开同一路径时，旧generation回复不能夺取新pending path／loading；只有当前回复提交文本。
6. `transfer_view_invalidates_open`：进入传输页使旧open失效，返回传输页不恢复旧选择或错误。
7. `current_audio_dispatch_only`：当前合法音频回复只派生调用一次inert音频入口；没有执行/api/audio或真实播放。
8. `current_video_inert_loader_dispatch`：当前合法video回复派发一次inert Loader；返回清选择且累计video计数仍为1，不测试实际媒体插件或解码器。

## 入口与唯一实际结果

PC入口为 [HOST_MTA_FILE_NAVIGATION_V68_R2_CHECK.cmd](HOST_MTA_FILE_NAVIGATION_V68_R2_CHECK.cmd)，固定调用 `py -3 -B host/file_navigation_v68_r2_check.py`。ROOT实际只直接运行checker；CMD仅SOURCE核对、未点击或另行重跑。checker无设备／网络／媒体参数，一次 `-I -B` 隔离子进程、60秒上限，无重试、旧测试或服务启动。本次DOC更新不执行checker、CMD、Qt或设备。

结果目录：[results/file-navigation-v68-r2-host-20261002-231004-f906dab9](results/file-navigation-v68-r2-host-20261002-231004-f906dab9)。[public-result.zip](results/file-navigation-v68-r2-host-20261002-231004-f906dab9/public-result.zip) 四成员、2114 B，SHA `5d40652cf28191dbba6646c8032b00c4bcf951d642cefd4d6029ee3218c53a1b`。

stdout 103 B／SHA `0919737a7fda161457a4b6c1d00336c221220914b2fafee8a3068f29dbc18d55`；严格marker为 `HOST68_FILE_NAV new_methods=1 cases=8 old_methods=0 qt_host=true device=false physical_playback=false`。stderr 100 B／SHA `597d815fee91df39dcfa5fccc9b6b898dbe0d2310fa005b6862a0be88ca30ed2`，严格 `Ran 1 test ... OK`。只有原输入、exit0、无超时、严格marker／summary与原QML一致才允许四成员公开raw；失败raw保私有，不改写历史。

## 保持的未完成项

独立原audio response竞态尚未修复／测试，不能用派生inert方法掩盖这一缺口。没有部署候选、触发媒体或操作设备。GO64仍整体FAIL／pending／完整恢复未证，本轮正常重启及本次临时记录处理许可仍待；不清pending、不重试RF。小米15 Ultra已记录，系统／原厂互传版本未知，不重复问型号。生产手机双向未通过、目标active，仍需真实GO、typed IP／DHCP、State／文件中心与手机验收；67及更早文档保原时点历史。
