# CLIENT v15 kernel 接线 SOURCE/Fake 审查

范围：仅隔离 Provider/connection 接真实只读 kernel reader；没有部署、设备 GET、RF、手机、DHCP、IP 配置或生产准入。
旧 v14、原 runtime、F、Store/core/caps/alias/bridge/恢复代码不修改；新 F 与固定24图由 ROOT 另审。

## 固定来源

- Provider v14：4683e4ddc0e9b41adb44c028fb9dd102a63e3b62180e9f7e011fa1508414218c。
- Connection v14：6ea9c395669ccb321011ea195095e3868a3f3d7e3ad5a02cb97cab4d1a591eb0。
- 新 v15 reader（另一作者）：f16af6f1db74c9e6d74d2e56e6b469cf1ed589f27d3a1d5b4f897220cdeeb334。
- 本文实现 Provider：9e6b32141c8b1698edcc45e5459080168afe804c0bece1f5445bf8a355678136。
- Connection：4a561d8d385fc71870c6d46653b7855b304c854ca10f102f31d174096fd7f2d1。
- 新 test：0fdf5efc0ae7cef11a92c3d11f2d30cea08147bab6aa220fdea4a0be5fed6798。

## 实际内部 API / 归属

- `lease.connect_p2p(info, _checkpoint=exact_F_callback, _operation_epoch=actual_binding_epoch)`。
- epoch 必须 strict int、1..2^53；缺失不可用，不猜1，不提升解密字段为平台授权。
- callback 保持 True=取消，False=继续；异常/非 bool 取消。原20s绝对截止不续期。
- 每轮 STATUS → 完整 baseline → 新 kernel reader → 新 caps reader；两轮后原 final drain/新 context 检查。
- reader owner 是 exact `_Connection`，epoch按值核验；原 F callback 和原 absolute deadline 原样传入 reader。
- Provider 在构造前登记 ticket、构造返回立即留 original reader、read 返回立即留 original observation，再认证。
- readback 再创建两个 reader/两个 caps reader，不缓存旧 kernel 授权；每类最多8个 reader，原库存上限不扩大。
- 操作由原 run/readback 持有同 Store RLock；原 F/executor/boot/deviceOFD/currentJournal/Origin/controller门禁保持。

## 角色 / 关联 / 信道

- GET_INTERFACE 必须 actual CLIENT8、完整 Origin 一致、frequency 与两 STATUS 和 GROUP 一致。
- GET_STATION 必须唯一 actual station MAC 等于 STATUS bssid；BLE MAC 与 go_dev_addr 都不是 station 认证来源。
- associated/authorized/authenticated 必须实际 driver mask中的 TRUE；UNKNOWN/空表/unsupported不填补。
- 两轮 Origin/executor稳定key/boot/channel/stations（含实际 generation/mask/value）全等后才签私有 observation。
- caps 原件必须 actual `DecodedCaps`，保留完整 reader/raw/未投影属性库存；两轮比较的是完整 decoded约束，不冒称所有原始 WIPHY 字节或未投影 metadata全等。
- operating gate仅当前同phy恰 originalSTA2 + ownedCLIENT8；counts不再增加空CLIENT。
- distinct实际 `{station_frequency, client_frequency}` 数量 <= actual combo.channels；shared limit/max/coverage/software/radar/beacon约束保持。
- 沿原 `_caps_core` 精确BI策略：actual absentBI经原decoder为 all_beacons_identical/None，仅上述两个非beacon角色；minimum_gcd仅实际1，未知/更大值拒绝。
- 不用于AP/GO/其他role，不签endpoint/IP/生产可用；peer_mac_hint_matches仍只是原ctrl字段提示。

## 原资源 / 恢复门禁

- kernel original socket、两个 ifindex原件、每个 actual ProcReader与原FD refs全部强留在原Provider库存。
- 只接受 exact reader发行、原库存成员对应的当场 EBADF receipts；不由 caller bool/数字构造关闭证明。
- sequential ProcReader允许同fs/fd/reader多次出现，双方发行数量按multiset核验，原库存不去重；数字不是物理资源世代。
- 数字以后合法复用仍走原 `_closed_fd` / exact current registered live-owner+metadata判据；同metadata陌生复用不许可，不关新FD。
- 新 kernel unknown进入 `_begin` mutation/delete拒绝链与status；`_closed_objects`/原`_proof`独立核其真实尝试/关闭，资源unknown不重close。
- 业务role/frequency/MAC/flags拒绝但观察器全部实际闭合时，resource unknown=False；不把业务失败伪造为泄漏。
- 取消和异常也保留raw/实际返回及库存；reader失败由其原finally关闭，Provider不增加第二网络恢复owner。
- 原 restore60/CAS/current/marker/device-last/caps映射/alias/bridge方法AST保持；这里不签 actual restorePASS。

## 唯一新增专项证据

- 首批355013→等待6ba5fa：16方法，14.075s，OK，exit0；没有首FAIL/ERROR。
- 收尾新增最低FD复用；76ac26的 `-k actual` 实际选中1新+5相关=6方法（不是计划2），6.073s，OK，exit0；如实保留，不重整批。
- a540a7：仅受影响source/旧方法保持/Python3.5 AST方法1，.086s，OK，exit0。
- 共17不同新方法；不是17方法单批、旧suite、24图或P011验收。
- 测试实际调用新Connection.run/readback、真实新ClientKernelReader/ProcReader/caps transport over FakeIO；默认OS/socket/native/进程入口有tripwire。
- 覆盖双round、MAC不同于BLE、unknown/空station、role/frequency/flags、channel1/2、共享limit、两caps变化、epoch、取消保留raw、closeunknown拒mutation、合法/foreignFD复用及完整旧定义保持。
- 本作者不运行设备/无线/Parent/F，不创建实际结果ZIP；下一24图/source审与唯一实测由ROOT授权。
