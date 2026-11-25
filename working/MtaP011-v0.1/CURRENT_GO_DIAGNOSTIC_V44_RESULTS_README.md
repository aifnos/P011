# GO 私有诊断 v44：FAIL；另行当前只读检查 PASS

2026-10-02 唯一 v44 实机入口 HOST ADB exit0／remote exit1、无超时、35.140秒；原 F exit1、absence 成立，stdout／stderr／exec-error仍均0B，journal缺席。v44仅给 F.main 异常加私有限长 stderr，16个其他GO源码字节不变，未更改Native／Store／Bootstrap／Loader／权限或期限。没有取得首因，不把空日志当无异常。

这轮 after-read 只完成1轮；实际 BaselineCollector reason=`actor_unknown`，不是完整基线或恢复证明。`pending_absence_after=false`是未完成采集的默认投影，不能据此断言pending存在。父端FD／writer／Proc reader，以及两次readonly已观察collector tickets和Proc库存均闭合；该事实不替代子入口未导出的Native库存。

随后只为此异常运行固定旧v39-r2独立只读入口，没有stage／F／RF／恢复／重启：HOST／remote0、无超时、11.453秒，两轮完整采集PASS，global pending前后缺席、资源闭合。ROOT按完整Snapshot字段比较其结果与v44之前baseline，只剔除Actor.key规定的瞬时task状态，保留全部PID／start／live／IPv4 cacheinfo等字段，结果一致（`430504`）。不回填或改判原v44 FAIL，也不签完整原生恢复。

ROOT离线审计 `c07d3d` 核v44当前／复制源码、52源／3blob的实际payload、raw echo／私有JSON、原exit与ZIP；只读检查raw／pending事实／资源／四成员ZIP另核。原始日志、失败源均保留。

- [v44脱敏失败ZIP](results/go-bootstrap-diagnostic-v44-20261002-151157-30a9e7f6/public-result.zip)：两成员，SHA-256 `7be6aceaeaab06078cb6e7353bf012990c182d6c8ff5025f53db343663f1260c`。
- [独立当前只读ZIP](results/client-readonly-baseline-v39-r2-20261002-151615-63f7b8b3/public-result.zip)：四成员、3568B，SHA-256 `a5a4697c01ffd1ab7b38811af225972acec2929dc4b29dcda4c481ea6bd51bff`。
- v44 HOST SHA-256 `7dea031f5ab331a43a8451bd3b51b94e1b4f6615b251d2262a65dfd642dd45ef`；preparer `26cb32fb69d8854ab551be5c7af63827d1a6ff6f2627ec5629a9333b3031287d`；17map `de55ea0dbe39e88b9051a4a62128c275b19091921bb5bad465ba24b0d93c130f`；F `eb4314fe273411ff7c100f5ee4cdac244c46d557dc329536330532012d0723bf`。

源码显示GoBootstrap.run会保留业务failure并返回1，可能不进入main except。下一独立v45仅在F.bootstrap返回后输出已保留的原primary／restore traceback及final_phase，仍限总16KiB私有FD2；不制造未保留异常、不改变实际结果、原恢复或RF逻辑。GO-IP／DHCP v43仍为SOURCE制作。互传、手机、生产准入未通过，目标active，手机小米15 Ultra。
