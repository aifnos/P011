# 发送阶段与真实进度文案（HOST QML）

范围仅正式 `device/MtaPage.qml` 与新增 `tests/test_ui_send_stage.py`。不改 State、生产 gate、Provider、网络动作、候选来源图或冻结快照。

页面从后端 `transfer.direction === "send"` 识别方向；只有当前公共状态仍为 connecting/transferring 时，才把 sendLifecycle 的 awaiting_confirmation 显示为“等待对方确认”、awaiting_result 显示为“等待完成结果”。接收请求、恢复、失败及终态始终优先，旧发送阶段不能覆盖它们。页面不把字节100%当对端完成。

发送进度使用已有 bytes/totalBytes 及其百分比。没有 filesDone 时只显示实际 totalFiles；只有 filesDone/totalFiles 为非负有限整数且 done <= total 才显示完成文件数，实际0也可显示。没有文件总数时不造0/N。接收已有真实文件进度保留，不增加发送落盘或对端成功字段。

HOST 专项复用既有 preview_mta_ui 的 QQuickView→正式 MtaPage.qml 路由，使用显式标记的 HOST status fixture，保持 endpoint/token 为空，不建HTTP预览服务、不启动收发或执行网络。覆盖两个等待阶段、真实字节与百分比、缺失/错误/有效文件数、接收确认、恢复/失败/终态优先级及发送tab不冒充方向。

Qt主机通过不代表 P011 Qt5.10.1、真实无线、手机互通或原网恢复通过。没有源码发布、候选graph变更或设备部署。

## 精确 HOST 批次

- `87563c`：`python -B -m unittest discover -s tests -p test_ui_send_stage.py -v`，首次新增9方法，`Ran 9 tests in 0.744s` / `OK`，host exit0，tool wall1.2821233秒。工具输出记录 `HOST_ONLY_QML_SEND_STAGE qt=5.15.2 device=false phone=false network=false`；每例检查 QML warnings=[]。没有首FAIL，不制造失败记录。
- `892cbe`：仅直接受影响的旧 `test_canvas_and_qt510`、`test_defaults_do_not_start_radio_or_show_fake_devices`，`Ran 2 tests in 0.003s` / `OK`，host exit0，tool wall0.4501142秒。没有重跑旧4方法文件或整个项目套测。
- `c06a36`：仅新增 `test_missing_or_invalid_total_files_never_becomes_zero_of_zero`，`Ran 1 test in 0.162s` / `OK`，host exit0，tool wall0.5766058秒，Qt5.15.2与无设备/手机/网络标记完整。已通过9项不重复；当前新增文件10方法按9+1批次保留，不宣称最终单批10通过。

原QML SHA256：`fd6a12abcb8a76f5694e5074fd17b0837462565eff4a2ad2087f527854d2f281`。当前正式QML：`be3d9bbdae4c0fc109ae984727b78b5a6d910be2bff7be6d6fa0086d3cdd64b0`。首9方法测试源：`9e0e112f1e39c12f1cfe43e1acf267aeb301e7c2794217773810f8d2960e2444`；仅追加最后单项后的最终测试源：`010479d501edc5bd9771c6b03b41a3c98dac4c853265452a37e2fe45162d15fe`。QML两次停写读回相同；执行输出是工具stdout/stderr合并展示，不声称独立raw日志归档。
