# 导航拒绝诊断 v3

此候选只为定位 v2 的 `navigation_receive_activity` 拒绝条件，不是互传修复发布。普通协议图仍使用 Publication v1；没有接入分类时钟优化，没有自动扫描、广播、配网、配对或收发用户文件。

Runner 将原取消观察器的同序短路条件分为12组，保存当次首次拒绝组及之前通过组。Worker 在当次取消观察后立即缓存这份有限 DATA，再保存原有的一次 idle 求值；原导航检查仍使用原条件。新增记录不续期、不授予资格，不调用额外时钟或资源 IO。Trial 投影、取消观察、idle 检查先后发生，不是同一锁下的原子状态快照。

原 `run_fixed` 返回并完成收尾后，严格绑定的私有投影片段只读取相应失败 traceback 中的缓存布尔值、计数和分组。没有重新检查关闭后的 State，也没有导出设备地址、凭据或任意对象字段。原51项公开结果和所有完成门保持，拒绝仍为 FAIL。

实际父 Runner、父 v2 Worker、四个单块差分及新源正反向绑定已接入新 HOST。默认 SOURCE 校验通过：199个输入、目标源码1993249 B；协议75角色／4169378 B、GUI20／4191494 B、FileCenter9／113690 B，以及原10／120／15秒、20秒显示、600＋60秒上限保持。没有重复构建或暂存未变 GUI。

2026年10月5日补充：ROOT唯一单方法HOST专项已通过，原求值／短路顺序、异常与投影严格绑定保持，fixture不代签完整Owner。14:36唯一P011新CONTROL仍在原 importing 准备阶段超时：五边界11.102620秒、超原10秒约1.102620秒，导航投影为NOT_APPLICABLE，无READY／点击／新截图。Owner／Startup资源／guardian／FD关闭、pending=false、有限原厂及carrierafter读回通过，原FAIL保持；没有改门或重用失败CONTROL。

[HOST结果](../../results/navigation-refusal-projection-v1-host-20261005-143537-8daeba7b/public-result.zip)，[实际准备FAIL](../../results/formal-receive-filecenter-navigation-publication-v3-navigation-test-20261005-143609-510ffe60/RESULTS.zip)。SOURCE和HOST不代表实际Received页面、手机互通或性能通过。

- 默认仅主机 SOURCE：`HOST_MTA_FORMAL_RECEIVE_FILECENTER_NAVIGATION_PUBLICATION_V3_CHECK.cmd`。
- ROOT 手动短时导航诊断：`TEST_MTA_FORMAL_RECEIVE_FILECENTER_NAVIGATION_PUBLICATION_V3.cmd`，不是自动执行入口。
- [SOURCE 结果](../../results/formal-receive-filecenter-navigation-publication-v3-source-20261005-143125-b9a5f296/RESULTS.zip)，SHA-256 `5d85ccc3dcb299430623c50fda4ee9edc7549046472c468913e2de5bb8399cb5`。
