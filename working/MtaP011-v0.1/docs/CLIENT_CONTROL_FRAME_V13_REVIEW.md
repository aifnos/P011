# 同 F CONNECT 私有 codec v13

仅新的 SOURCE / HOST 纯编解码组件，尚未接 F、Parent、Provider、State 或实际 GATT。没有设备、RF、socket、文件、线程或时钟操作；小米 15 Ultra 仍 NOT_TESTED。

## 固定 API 与绑定

`ControlBinding(exact_dict)` 接受且仅接受 version=1、run_token/nonce（32 位小写 hex）、candidate_sha（64 位小写 hex）、operation_id（本地正式操作 id）、native_epoch/operation_epoch（exact int 1..2^53）、gatt_session（原 native session，exact int 1..2^32−1）、receive_consent（strict True）。构造不验证真实 GATT/用户确认来源，父可信 handoff 必须核 exact Operation/Session/helper/key/worker/两 epoch/取消与确认。

`private_metadata()` 仅供内部帧，`public_metadata()` 仅 version 和 canonical metadata SHA；run_token、nonce、原会话、operation_id 不进 public/repr。P2pInfo.id 不被解释成本地 operation_id 或未来 WebSocket taskId。

`encode_connect(exact_binding, exact mta_protocol.P2pInfo)` 重新验证 mutable 协议对象，key 必须 None（已解密不等于可信）；返回 `CONNECT ` + sorted canonical ASCII JSON（binding、p2p 两键）+ LF。P2pInfo canonical ≤2048 字节，完整帧含 LF ≤4096。凭据只在内存/原 stdin；禁止 argv、日志、公包或追加旧 raw stdin 审计。Python immutable bytes 不承诺清零。

`ControlFrameDecoder(binding).feed(exact_bytes, eof=False)` 有界流解析；每段 ≤4096、累计最多4096+7（单次 CONNECT 加 CANCEL）。`take_connect()` 最多领取一次 private ConnectRequest；`private_info()` 返回新的 exact P2pInfo，可交未来现有 `lease.connect_p2p(info)`，但不是关联授权或读回。未知字段、重复 JSON key、非 canonical JSON、bool-as-int、绑定不匹配、重复 nonce、超长/未知输入全部 sticky 取消拒绝。

完整行边界 `CANCEL\n`、EOF 在同 feed 内优先于 CONNECT；尾随未完成帧延迟领取，取消会使此前已领取 request 失效。F 必须先排尽当下可读输入，且在 connection fresh/ctrl 发令/回复/有界采样检查点持续喂入，不能仅外层循环读取就声称及时取消。组件单调用者，不创建同步线程/锁或硬抢占任意 OS IO。

## 未完成的真实装配

本组件不会认证 metadata digest 的部署来源、BLE 同任务凭据、真实 consent、当前 journal/controller、期限或内核角色。必须由下一隔离 F 接线核 manifest/argv/token/绑定，再沿 exact 已拥有 lease/Store/controller 调用。关联成功也仍不签 kernel frequency、DHCP/IP/GO endpoint、完整恢复或收发完成；所有 public 状态明确 production/association/IP/endpoint false。

原 v11/v12 来源、旧 FAIL、stage/pending 与生产 gates 不修改。

## 实际 HOST 批次（不升级为设备）

- 首批工具 `7c0773`：`py -B -m unittest discover -s tests -p test_client_control_frame_v13.py -v`，21 新方法 / 0.117s / exit1，20 PASS、1 FAIL。失败是新负例按紧凑 JSON 替换 `"version":1`，实际 p011_json canonical 有冒号后的空格，替换未命中；不是已证解析器放行重复键。原失败保留。
- 仅修这个失败方法的真实字节变异并断言确有变化；工具 `b60782` 精确重跑 `test_duplicate_json_keys_and_noncanonical_encodings`，1 / 0.001s / OK / exit0。运行源码没有因此修改，另外20个通过方法不重复。
- 21 个不同新方法分两批通过，不称最终整批21 PASS。覆盖完整及每处分片/逐字节、原native session严格类型、canonical/重复键、固定绑定不匹配、重复nonce、单次领取、取消/EOF优先、已领取失效、secret/repr/public隔离、长度/累计预算；首批内 Python3.5 AST与无IO/无FProvider导入断言通过。

依赖只有标准库 hashlib/re、既有 p011_json 和 mta_protocol；不执行旧 F/Provider、正式20源 sourcecheck、旧 suite、设备或无线。帧和nonce唯一性只覆盖本 decoder；跨会话nonce和真实部署digest来源由可信父级 handoff负责。
