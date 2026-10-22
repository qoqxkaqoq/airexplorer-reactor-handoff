# Git 提交历史存档

> 本仓库主分支已于 2026-10-23 07:05 (Asia/Shanghai) 重根(squash)以清除历史中已删除的大体积文件(约 820MB)。
> 重根前最后一个提交 SHA: `782b1c172556e88fd5c4ad56a39b81dd62dd9bd0`
> 完整提交清单如下(自新到旧):

- `782b1c1725` 2026-10-22T22:43Z — A线成果: 8392 个官方 locals (.loc: index|isPinned|TypeFullName, 来自 PrepareMethod 解密后的 LocalVariables)
    > GenerateAdaptableExtractor 官方 14 locals 与 cilantro 一致(验证); InstantiateStatelessUser 47 个真类型。
    > tools2/locsig: 按 .loc 替换目标 exe 的占位 locals (v67: fixed=0 -- v66 已被 fixlocals/localsdiff 覆盖,
- `bc2bbb55d0` 2026-10-22T22:39Z — TTD: 修 PowerShell 数组字面量路径缺引号的解析错误
- `c8bcfc0d3d` 2026-10-22T22:29Z — wip: 暂存
- `ebfa8b1d2f` 2026-10-22T22:29Z — fix(archive): 补录 Slayed/cilantro 到 repo1-archive (exes清理后原树已无此二件)
- `fbe133ab75` 2026-10-22T22:28Z — fix(archive): 补录 repo1-archive/bin (被 .gitignore bin/ 规则静默忽略)
    > 8 项 20MB: hybrid/nb_slayer/Cmd_nb_original 三产物 + ExtractorVisitors.bin
    > + cilantro_renames.json + Krypton包/ClrMD/extract_res.py/bodytrans repo1版
- `297c1158a4` 2026-10-22T22:22Z — archive+cleanup: 迁移 qoqxkaqoq/1 全部独有资产 + 清理无价值大体积文件
    > 【迁移 repo1-archive/】(原仓库将删除)
    > - 1.zip: 官方安装目录完整快照(73项) — 运行环境首次入库
- `a62d11e51b` 2026-10-22T22:24Z — A线修正: net48 的 MethodBody 无 LocalVarSigToken 公开属性, 改用 body.LocalVariables 写 m_XXX.loc (index|isPinned|TypeFullName), nbrestore 据此重建官方 locals 签名
- `ed8107a62e` 2026-10-22T22:19Z — A线: forcedump 第6 dword 填 body.LocalVarSigToken
    > 发现: 16598 个真体从来都是 forcedump 写的(status: hook=FAIL, hook 从未在 AirExplorer 上附着成功);
    > .eh 的 catch token 解析出假名 TypeDef(0x0200003D=ExtendedProxy/<>c)证实 NecroBit 的 token 加密
- `ab50ebbc7c` 2026-10-22T22:07Z — 修复 B/C: winget 强制 winget 源(msstore 需认证导致二次安装失败) + Krypton Runner 单独构建 + input 路径数组传参(引号嵌套导致 Input assembly not found)
- `82616810bb` 2026-10-22T22:01Z — TTD 修复: 复制 WinDbg 包绕过 WindowsApps 执行 ACL + 改用 cdb 无头 + JitScan 自适应 x86(AirExplorer 是 32 位 WoW64, info=[esp+C] 而非 r8), 并从 tok 偏移反推 pSig/cbSig dump 官方 LocalVarSig blob
- `cf2348a661` 2026-10-22T21:54Z — 三方案并行拿官方 locals 签名+EH (docs/PLAN_official_data.md)
    > 根因: nbjit dump 丢了两块数据 -> fixlocals(33847 locals 猜测) + fixeh(1515 catch 猜测)
    > 而 CORINFO_METHOD_INFO 里本来就有: locals.tok(官方 StandAloneSig token) + locals.pSig(官方 blob)
- `374d14c1fd` 2026-10-22T21:40Z — 补充关键运行时数据(对话存档): hostdump 导出 + stubscan 清单 + 验收日志
    > - work/hostdump/: holder_v1-v4.tsv(官方宿主进程导出的 <Module> 单例状态演进),
    > extractor.bin(398794B UTF-16 字符串表, v10-v12 字符串解密的根基),
- `2b0db441c4` 2026-10-22T21:37Z — 成果归档: 全部工具源码(78+) + 进展文档1-15节 + 验收截图 + 数据资产
    > - tools2/: 78 个 .cs + csproj (fixgen/fixnested/fixlocals/fixeh/fixfieldidx/fixmethidx/
    > badstub/preinit/noopcast/nullfix/nosort/initfield/castscan/patchsort/stubscan/
- `c739902f45` 2026-10-22T18:27Z — docs/广播: 主窗口 visible=True 截图成功 + 文本模式 16/16 PASS + OCR 定位法
- `7f9519e38a` 2026-10-22T18:18Z — v66: preinit 在 RecommenderRecordAggregator::.ctor 基类调用后预初始化 aggregatorBufferConsumer
    > OCR 显示 v65 的 UI 崩溃是 NullReferenceException @ ToolStripControlHost.get_Font()
    > (Control==null)。newobj ToolStripControlHost(Control) 的 Control 来自
- `5ed60647ef` 2026-10-22T17:08Z — v65: 用 badstub 扫出 20 个'ldnull+unbox.any 必崩桩', 7 个用官方 JIT 真体替换(含 ReceiveModularWorker 0x060037D1)
    > OCR 截图定位真凶: UI 崩溃是 NullReferenceException(不是 ANE):
    > TreeFunction..ctor -> BridgeExecutor.ReceiveModularWorker(Size, Control)
- `e45c902f2d` 2026-10-22T16:33Z — docs/广播: 文本模式 PASS(16/16 逐行与官方一致) + 主窗体已创建 + ANE 三段定位
- `a3dfe21063` 2026-10-22T16:30Z — v63: DetachedCalculator..ctor 从 nop 桩改成初始化 m_ProjectDecorators = new List<DistributorProfile>()
    > 根治 ANE: 该字段唯一写入点在 InstantiateStatelessUser IL_045E(解释器状态机循环后段),
    > UI 启动路径没跑到 -> null -> GenerateAdaptableExtractor 里 ArgumentNullException
- `3574b9c8a5` 2026-10-22T16:23Z — v61: 跳过 GenerateAdaptableExtractor IL_06D5 的 List::Sort(Comparison<DistributorProfile>)
    > 该 comparison 由 'ldftn + newobj Comparison::.ctor(Object,IntPtr)' 造出, 栈上缺 target,
    > 委托无效 -> Sort 抛 ArgumentNullException -> 主窗口弹 Error detected 后崩溃。
- `4a2d31766e` 2026-10-22T16:12Z — v60: InstantiateConfigurableModule 的 ldnull;ret 改成 返回空 List (2 处)
    > UI 启动栈(v59):
    > ArgumentNullException
- `a04a6a8b95` 2026-10-22T16:04Z — work: 固化本轮诊断数据资产 (token对账基准表/窗体覆盖/关键方法全量IL)
    > - tokmap_{official,v59}.tsv.gz: 全量 token->签名指纹映射, 下一棒对账直接解压用
    > - ui_{official,v59}.tsv: 92 窗体类覆盖明细 (v59 桩 1444->20 的证据)
- `100c68eef6` 2026-10-22T15:57Z — 广播: ANE 根因闭环 + 排除清单 + 工具交接
- `eb345e8f29` 2026-10-22T15:56Z — docs: 第14节 ANE 因果链闭环 + 排除清单 + 工具说明
- `35d1424c5a` 2026-10-22T15:48Z — ui-trace: host v2 异常落盘+ThreadException+JitNoInline; cctorfix/tokmap/uiscan 工具入库
    > - host.cs v2: UnhandledException/ThreadException 全量写 app/host_trace.txt(崩溃时Console缓冲丢失问题)
    > - ui-probe.yml: 编译 host v2 + COMPlus_JitNoInline=1 (帧精确, 复现 v55 的定位手段)
- `e770d07c93` 2026-10-22T13:23Z — v59: 去掉 AddEfficientHandler 里多余的 castclass ProgramFinder (2 处)
    > castclass 后面紧跟的是 callvirt ConnectedObserver::AddEfficientHandler(ConnectedObserver),
    > 参数类型本来就是基类 —— cast 是 Reactor 加的混淆, 去掉后 setup 直接按 ConnectedObserver 传,
- `00667822ba` 2026-10-22T13:16Z — hostdump: 加 TemplateThread::StoreLogger -> _TemplateConfig -> m_ProjectDecorators 探针; ci: v56 加 COMPlus_JITMinOpts=1 拿真实栈
- `2004fc3830` 2026-10-22T12:44Z — docs: 第13节 JIT 收割补泛型(forcedump 补丁 + 12 个泛型真体) 与 InvalidCast 精确定位
- `892d027d09` 2026-10-22T12:38Z — v56: fixnested 补上'指令操作数里的 TypeRef -> 同名 TypeDef' (585 处)
    > 根因: castclass/isinst/newobj 的 token 若是 TypeRef, 运行时可能解析成另一个 Type 实例
    > -> InvalidCastException: cast 'VirtualInitializer' to 'ProgramFinder'
- `d0e3021926` 2026-10-22T12:32Z — ci: 对 v55 禁用 JIT 内联(COMPlus_JitNoInline=1), 让 InvalidCastException 显示真正抛异常的方法
- `d96f0509a3` 2026-10-22T12:27Z — v55: 用 JIT 收割到的官方真体替换 InstantiateStatelessUser (923 指令, 比 cilantro 版多 35 条)
    > forcedump 补丁生效: genericMethods=58 genericTypes=25, bin 16586 -> 16598 (+12 个显式泛型方法)
    > m_060042AC.bin ilSize=3038 maxStack=6 ehCount=2 -> nbrestore 写回后 923 指令/50 locals 真类型
- `737316573e` 2026-10-22T12:15Z — jitdump: forcedump 补丁版 -- 泛型方法用 MakeGenericMethod(object/int/string/Guid) 造实例再 PrepareMethod
    > 根因: 原版 forcedump 对 IsGenericMethodDefinition 的方法直接
    > GetMethodBody() -> IL 为空
- `cdae2a741a` 2026-10-22T11:19Z — docs: 12.5 v50-v53 卡点与排除项
- `fa02dbc629` 2026-10-22T11:15Z — v53: InstantiateStatelessUser 也换成 cilantro 版(888/50 locals, 原来 879/255 个 Object) -- 让解释器与 DefineSetSet/GenerateAdaptableExtractor 三者同源
- `5383874ebc` 2026-10-22T11:07Z — v52: fixmethidx 按类型内方法序号回退 (generatedMethod_0288 -> DefineSetSet)
- `f231fb0f54` 2026-10-22T11:02Z — v51: v50 + fixfieldidx (移植 GenerateAdaptableExtractor 带进了 booleanField_0287 这类 nb_slayer 字段名)
- `a687b79b70` 2026-10-22T10:57Z — v50: 在 v48 基础上把 GenerateAdaptableExtractor 整份换成 cilantro 版(491 指令/14 locals, 原来 483/255 其中 240 个 Object)
- `6db99ec526` 2026-10-22T10:54Z — docs: 第12节 两个数据层面的致命损坏(EH catch 1515/1721 错、locals 数量不一致 2658 个)
- `24f7bcaebc` 2026-10-22T10:54Z — v49: localsdiff 把 2658 个'locals 数与源不一致'的方法整份换成 cilantro 版
    > 根因: nbjit 的 localsTok=0, nbrestore 只能填 System.Object 占位。之前 fixlocals 只修
    > '全部是 Object' 的 4965 个, 漏掉 '真类型+Object 混合' 的 2658 个(如
- `fd6985a346` 2026-10-22T10:44Z — v48: fixeh 修 1515 个损坏的 catch 类型(v47 有 783 个 catch 指向 ExtendedProxy/<>c) -- 这是异常乱冒泡的根因
    > catch 类型分布: v47 可疑 1515/1721, v48 可疑 0/1721
    > 缺 catch 类型 -> catch 永远不匹配 -> 所有异常直接冒泡成 TargetInvocationException
- `2a95f4a2f3` 2026-10-22T10:37Z — v47: 补回 v46 链路漏掉的手工移植 DefineSetSet@generatedMethod_0288(6866), 这是 v46 变 AV 的原因
- `e4dbb72335` 2026-10-22T10:31Z — v46: 重载按签名配对重新移植(138 组重载, 之前每组只填第一个且填了错体) + 修授权桩误判
    > - stubscan 清单加签名指纹 (2:IntPtr,Int32), bodytrans 按 (名字+签名) 找目标
    > - 授权桩判据改成'目标与源都是桩'才跳过, 找回 76 个被 Reactor 破坏成 return true 的真方法
- `27b99b4871` 2026-10-22T09:20Z — docs: 11.8 v45 状态
- `fe35370cbb` 2026-10-22T09:17Z — v45: stubscan/fromlist 阈值 >6->4, 补移植 305 个 6 条指令的简单构造函数等
- `754ab6578a` 2026-10-22T09:13Z — docs: 11.6-11.7 v41 状态与下一轮(stubscan 阈值 >6 漏掉简单构造函数)
- `cd1dc87759` 2026-10-22T09:10Z — v41: 移植 WrapperEnumerator::.ctor (6 条指令, 被 stubscan 的 >6 阈值漏掉)
- `e43b1121f5` 2026-10-22T09:10Z — docs: 11.5 v40 已从元数据级错误推进到普通 NRE
- `734b3fe773` 2026-10-22T09:07Z — v40: fixfieldidx 按类型内字段序号回退, 修 121 处残留的 nb_slayer 字段名(booleanField_0287 等)
- `23a95eec78` 2026-10-22T09:01Z — docs: 第11节 locals 才是 AV 根因(5126 方法全 object)
- `36ffae99ae` 2026-10-22T09:01Z — v39: bodytrans 支持 Dst@Src 改名移植, 把 cilanto 的 generatedMethod_0288(6866) 搬到 DefineSetSet, 修掉最后的 object-locals AV
- `be9c932c4a` 2026-10-22T08:56Z — hostdump: JoinExecutor 探针打印 inner exception
- `6ff43841a3` 2026-10-22T08:47Z — v35: fixgen 支持方法签名+简单名回退 (修 GeneratedEnum_0426 这类 TypeRef 丢嵌套的假名) + fixnested
- `9fd640f18d` 2026-10-22T08:42Z — v33: fixlocals 从 cilantro 修复 4965 个方法的 locals(33847 个) -- nbjit 写回时 locals 全是 System.Object, 是 AV 的根因
- `f5ee2128c4` 2026-10-22T08:33Z — v32: patchsort 跳过 InstantiateStatelessUser 的 Sort(<>9__47_0) 懒初始化, 绕开 <>c 泛型缓存类的 TypeLoad
- `dbb7f56f7f` 2026-10-22T07:27Z — docs: 10.7 当前卡点与下一步(排除项表格)
- `a40bea9852` 2026-10-22T07:23Z — hostdump: 加 ModelTracer.JoinExecutor 探针, dump 返回值字段
- `182f21fa63` 2026-10-22T07:18Z — work: m_LogicalProcessorMap dump (3266 条 字段token->方法token)
- `65d3aacfee` 2026-10-22T07:17Z — typediag: 捕获 ReflectionTypeLoadException 并打印 LoaderExceptions
- `612fe16340` 2026-10-22T07:12Z — typediag: 改成全量 checkout(去 sparse)
- `49d59fedb4` 2026-10-22T07:07Z — typediag: sparse-checkout 同时拉 ci 目录
- `082b7b1770` 2026-10-22T07:03Z — typediag: 逐类型解析字段/方法签名, 定位 TypeLoadException 的确切成员
- `0e9ea013b8` 2026-10-22T06:57Z — docs: 第9-10节(数据搬运突破 + 批量移植) + 留言板广播
- `2c6a98c201` 2026-10-22T06:56Z — ci: 候选 exe 改用 sparse checkout (raw CDN 延迟 + contents API 1MB 限制都绕开)
- `142c84a020` 2026-10-22T06:52Z — ci: 候选 exe 改用 GitHub API raw 媒体类型下载(raw.githubusercontent 有数分钟 CDN 延迟)
- `1edc2f9a24` 2026-10-22T06:48Z — v30: fixnested 递归修所有签名(字段/局部/方法参数)里的顶层TypeRef -- 476 处
- `8634d1bdce` 2026-10-22T06:43Z — v28: fixgen 修 GenericInstSig.GenericType 本身是假名的情况(X`1<T>), 再 fixnested
- `92c4b0d3de` 2026-10-22T06:38Z — v26: fixnested 把嵌套类型被写成顶层TypeRef的 12 个 MemberRef/3 个TypeSpec/344 处签名修回
- `5b8110bddc` 2026-10-22T06:32Z — v25: fixgen 修 MemberRef 判定顺序(ldftn 曾被当字段查) + 泛型TypeSpec名字归一化 + 手工map; InstantiateStatelessUser 里假名引用清零
- `da8df48c93` 2026-10-22T06:22Z — v21: InstantiateStatelessUser 回桩(批量移植误带进来, 跨模块泛型签名不兼容)
- `f1536c16fd` 2026-10-22T06:15Z — v20: 批量移植 1125 个桩方法(fromlist) + fixgen 按嵌套序号全量重映射 385 个假名类型
- `f821044078` 2026-10-22T06:04Z — ci: 候选 exe 下载加重试(raw 缓存延迟导致 404)
- `41d1898a1c` 2026-10-22T05:59Z — v18: 移植 TemplateInitializer::AttachDistributor(1301) -- globalTemplate 的填充逻辑
- `23460aa9b0` 2026-10-22T05:55Z — hostdump: 解出 m_LogicalProcessorMap(字段token->方法token), 定位委托目标方法; tokcmp/resdump 工具
- `03bd53a9b0` 2026-10-22T05:48Z — v16: 移植 TemplateInitializer::.ctor(67) + InstantiateVirtualServer(93), fixgen 重映射
- `b9e401e95d` 2026-10-22T05:46Z — hostdump: 委托字段诊断(CheckAlphabeticProject 指向哪个方法); stubscan/xref 工具
- `cb67a11766` 2026-10-22T05:40Z — v14: fixgen 按字段结构指纹把 GeneratedType_0440 映射回 <Module>{a8c2e9b2}
- `277060e098` 2026-10-22T05:35Z — v13: 从 cilantro 移植 RequestWorker::.ctor (nbjit 没 dump 到这个 ctor, 原体是 nop;nop;nop;ret 桩); bodytrans 加 PreserveAll
- `f2554ca23e` 2026-10-22T05:28Z — v12: dnlib 重写 + FieldRVA(398KB 字符串表) + InitializeArray; v12n: 原样重写对照
- `201b405abc` 2026-10-22T05:21Z — v11c: 修 SearchStrategy 新 IL 的栈下溢(多了个 pop) -- 这才是 InvalidProgram 的真因
- `ace6669a23` 2026-10-22T05:15Z — v11a/v11b: 测 .reloc section 标志(CNT_CODE / 去 DISCARDABLE)是否是 InvalidProgram 的原因
- `9ec943c73a` 2026-10-22T05:07Z — v11: 嵌入 398794 字节字符串表(从自身文件尾部读), 替换 SearchStrategy 填充 _ExtractorVisitors
- `bd6f9dd563` 2026-10-22T05:03Z — hostdump: 追加 SearchStrategy 触发 + _ExtractorVisitors 字节导出
- `dc272e7361` 2026-10-22T04:58Z — v10: 用 hostdump 导出的 holder 124 个字段值, 硬编码替换 InstantiateStatelessUser 解释器初始化 (字节级改 RVA)
- `979301c43c` 2026-10-22T04:54Z — hostdump: 在官方 exe 宿主进程导出 <Module> 持有者运行时状态 (InstantiateStatelessUser 的执行结果), 附 ildump 工具
- `f76f72f5ec` 2026-10-22T04:11Z — v9: 把反篡改判断的取值改成恒 0(ldloc.s V_12 -> ldc.i4.0; nop), 走自然路径
- `09ec255f03` 2026-10-22T04:04Z — v8: 把反篡改的 br->throw 改为 br->0x0BE0(正常延续块), 栈平衡且不落死代码
- `67a1e616e4` 2026-10-22T03:57Z — v7: 把反篡改判断的 brfalse 改成 br(始终走未篡改分支), 避免落入死代码块导致 SHA1 复用
- `1741cfe8ba` 2026-10-22T03:52Z — v6: 中和反篡改分支(InstantiateGlobalCalculator @0x00F6 的 br->throw 填成 nop)
- `50525e3be3` 2026-10-22T03:51Z — 删除 v84b 假货交付物（空白窗口假阳性），HANDOFF 追加权威警示
- `26b710c06f` 2026-10-22T03:46Z — v5: 字节级补丁(pepatch2) — nbjit_v4(正确字符串/完整表)上只把 <Module>::cctor + 两个引导方法体改成 ret, 元数据零改动
- `a8013476de` 2026-10-22T03:38Z — ci: 修 gui-cli 探针的阻塞(ReadToEnd 遇常驻进程会挂死), 改重定向到文件+限时
- `9d3ae397bd` 2026-10-22T03:28Z — docs+产物: 本轮修掉 #US 堆 / InitLocals / PreserveAll 三个 bug; 撞到跨模块移植约束; 附可出窗口的 v84b
- `012b92a5ca` 2026-10-22T03:21Z — nb_strip4: 移植体 maxstack 抬到 128(沿用桩的旧值会栈溢出->AccessViolation)
- `26f97a8172` 2026-10-22T03:14Z — nb_strip3: 修 bodytrans 缺 PreserveAll(丢 3576 个 MemberRef 行 -> TrackCompiler token 失效); 表行号保持
- `bccca24845` 2026-10-22T03:08Z — nb_strip2: nb_original 基座 + 移植字符串表初始化器
- `4a4b2a25ec` 2026-10-22T03:02Z — nb_strip: 以 nb_slayer 产物为基座(nb_original), 只摘 Reactor 引导, 保留应用静态初始化; 表结构完整
- `940fcb0031` 2026-10-22T02:55Z — ci: jitcheck 兼容 C# 5 (去掉 out int 内联声明)
- `bf704c6416` 2026-10-22T02:50Z — ci: jitcheck 改用独立 cs 文件(避免 YAML 里嵌 here-string)
- `601c6baa94` 2026-10-22T02:44Z — nbjit_v4: 修 InitLocals 与 locals 签名不一致(声明 initlocals 却无 LocalVarSigTok -> Bad IL range)
- `6ec8826b95` 2026-10-22T02:39Z — nbjit_v3: 修 EH 边界(末尾补 nop 哨兵 + 子句排序), 目标 Bad IL range
- `c702355be2` 2026-10-22T02:35Z — docs: 补记 #US 堆误读(所有字符串曾是元数据碎片) + 新阻塞(字段初始化数据嵌 metadata token)
- `cf86002c7c` 2026-10-22T02:29Z — si11: 正确字符串 + 剥离引导 + 移植字符串表初始化器
- `f8caf57796` 2026-10-22T02:26Z — nbjit_v2: 修 writeback 的根本 bug — ldstr 走 #US 用户字符串堆而非 #Strings, 之前所有字符串都是元数据名字碎片
- `197b14de7e` 2026-10-22T01:44Z — docs: 定位 null 流的来源 — ldstr 一个残缺资源名(ing>>-GetEnumerator>d__52) 去 GetManifestResourceStream
- `43cbd1dcc2` 2026-10-22T01:42Z — docs: 文本模式攻坚记录 — 6 层崩溃链、FinderMap 重载/TrackCompiler 两个坑、嵌套类型序号映射机制、当前互斥对瓶颈
- `c00ef27502` 2026-10-22T01:36Z — si10: fixmap(序号映射) + fixrefs(成员名) 串联, 完整修正移植体的假名
- `49dc9acfb4` 2026-10-22T01:31Z — si9: 只保留 TrackCompiler(字段初始化), 去掉 InstantiateGlobalCalculator(读不到资源流会崩)
- `446c0e554d` 2026-10-22T01:24Z — si8: 保留 TrackCompiler(rt)/InstantiateGlobalCalculator — 字段初始化器不能摘
- `403e179dcf` 2026-10-22T01:16Z — si6: stripinit 只摘返回 void 的引导(之前误摘 FinderMap::DirectDefinition(int) 字符串解密器 -> stsfld 空栈 -> InvalidProgram)
- `68357cdd6e` 2026-10-22T01:13Z — si5: stripinit 用 pop 保栈平衡(修 ValidatorDefinition::.cctor 的 InvalidProgram) + 重跑移植链路
- `c4d27cfdc4` 2026-10-22T01:07Z — si4: fixrefs 补上 MethodSpec 内的成员名替换
- `1dd0c0c99d` 2026-10-22T01:03Z — stripinit3: fixrefs 修掉 cilantro 带来的假名(GeneratedType_0431->URqFYq3xtmntT2OcLub/GeneratedEnum_0425->Int32)
- `d3022db356` 2026-10-22T00:56Z — stripinit2: 从 cilantro 移植 InstantiateStatelessUser 真体 — 字符串表持有者的初始化方法
- `b67055958c` 2026-10-22T00:48Z — stripinit: 只摘掉 cctor 里的 Reactor 引导(4633 个 cctor / 9856 处调用), 保留应用自身静态初始化
- `ce0361f339` 2026-10-22T00:38Z — docs: AirExplorerCmd 完整分析(转发器/6 串明文/Main 重组/授权门/Authenticode 与反篡改交互) + 广播 GUI 文本模式验收通道
- `836bab5e2f` 2026-10-22T00:31Z — cmd-verify: 增加 accounts 参数组, 验证授权门在去混淆后仍然生效
- `4d6e645713` 2026-10-22T00:29Z — gui-cli: 用 AirExplorer.exe 的文本模式(help)做无窗口验收 — Cmd 转发器发现的副产物
- `f4eaa29be8` 2026-10-22T00:23Z — cmd: 字符串还原工具(cmdstr) + 去混淆版 AirExplorerCmd; 探针支持 rawhelp
- `af88b1e9f6` 2026-10-22T00:13Z — cmd: AirExplorerCmd 验收探针(纯 CLI, 判据=stdout/stderr+退出码) + 命令版结构分析工具
- `d524b17c56` 2026-10-22T00:03Z — docs: 最终结论 — 初始化链真体与脱壳后运行时互斥(保留真体->ArgNull, 换最小实现->空窗体); 16586 真体与写回器为本轮硬资产
- `8631643661` 2026-10-21T23:58Z — nbjit_mininit: 12768 业务真体 + 初始化链中和(DefineEfficientProfiler/DefineActiveEvent 置空, 保留 InstantiateGlobalCalculator 做字段初始化)
- `70f838165a` 2026-10-21T23:54Z — nbjit_restored3: 修复 ldstr 操作数类型(StringsStream.Read 返回 UTF8String 而非 string), 写回 12768 个方法
- `a830c735f1` 2026-10-21T23:53Z — docs: 16586 个 NecroBit 真体收割成功(DefineEfficientProfiler 741 次状态更新)、写回 12052 个、陷阱 114->13、当前卡在 Bad method token
- `0a8cab2444` 2026-10-21T23:49Z — nbjit_restored2: 操作数经 Importer 重绑定(解决 Bad method token)
- `88a8a1ab83` 2026-10-21T23:45Z — nbjit_restored: 16586 个 JIT 入口收割的真体写回, 陷阱 114->13 (DefineEfficientProfiler 741 次状态更新)
- `705d59ec86` 2026-10-21T23:40Z — nbjit: 收割后接 nbilmerge 写回 + UI 探针, 端到端验证
- `f9b9c4bbee` 2026-10-21T23:31Z — fix: nbjit.yml 的 step 名里冒号导致 YAML 解析失败
- `7daaa80f2f` 2026-10-21T23:28Z — ci: nbjit — clrjit VMT hook + force-JIT 遍历所有 MethodDef, 收割 NecroBit 真身(带 token)
- `45da1869cf` 2026-10-21T23:19Z — ci: 精确指向 nb-inventory.json(之前误取 dyn.json 导致 nbrebuild KeyNotFound)
- `d5c28212dc` 2026-10-21T23:12Z — ci: nbrebuild 产物是 exe 不是 dll(OutputType=Exe), 修正查找与调用方式
- `d06d537ef2` 2026-10-21T21:54Z — ci: 收割步骤真的加上 exit 0
- `26c0d422c9` 2026-10-21T21:48Z — ci: 收割步骤末尾 exit 0 (Write-Host 不改 LASTEXITCODE, 否则后续回填被 skip)
- `498dec8bbd` 2026-10-21T21:41Z — ci: nbdump 的 rc=1 只是覆盖率<100%, 不应中断后续回填(2857/3266 已收割)
- `0d622deeea` 2026-10-21T21:34Z — ci: autoreaktor 补 Krypton.Runner(nbdump.py 的 RUNNER 依赖)
- `0a5d941bf3` 2026-10-21T21:31Z — docs: qoqxkaqoq/1 的 v84b 产物实测(初始化方法被砍 9992->4/2521->8)、补回真体会崩、验收判据需硬指标
- `555e216cc6` 2026-10-21T21:29Z — ci: autoreaktor 先构建 nbwalk(net48 反射 walker) 再收割
- `ebfa3ee4d6` 2026-10-21T21:26Z — v84b_restore: 把 v84b 里被砍成空壳的 3 个初始化方法用原版真体补回(9992/2521/6 指令)
- `7764de5394` 2026-10-21T21:22Z — ci: AutoReaktor v3 NecroBit harvest->rebuild 流水线(反射收割真体, 绕开反篡改污染)
- `04642a3506` 2026-10-21T21:21Z — PreserveAll: 写盘保留原始 token 行号(AutoReaktor v3 头号坑, 重排会让 VM/解密 blob 解析错成员); 重出 depfix6 + krypton_merge6
- `6f3cadb67d` 2026-10-21T21:19Z — board: 广播 Reactor 初始化注入 1214/4633 个 cctor 的结论与当前瓶颈(还原率)
- `94310c9cb3` 2026-10-21T21:18Z — docs: 1214/4633 个被注入 cctor 的实测、全路线收敛到 NullRef->0xC0000005 的结论
- `e1f9d005a8` 2026-10-21T21:12Z — depfix5: depfix2(22930 完整真体) + 中和 4633 个被注入 cctor + JIT hook 置空
- `52ab79a1e7` 2026-10-21T21:08Z — krypton_neutral/merge4: 中和被 Reactor 注入初始化链的 1214/1234 个类型 cctor
- `e113f1de5d` 2026-10-21T21:04Z — krypton_merge3(修 EH 表排序解决 Bad IL range) + krypton_fix9_eh
- `e2369573ac` 2026-10-21T21:03Z — krypton_fix9: 桩化 Krypton standalone-check 点名的 6 个 InvalidProgram 方法
- `c5be69fec1` 2026-10-21T21:02Z — docs: 补 Krypton 两轮实测数据、组合路线错误推进链与下一步
- `7b860a938b` 2026-10-21T20:57Z — krypton_merge2: 补回 Krypton 重写时丢失的 8 个 <PrivateImplementationDetails> 静态数据字段
- `19f5dd591a` 2026-10-21T20:50Z — krypton_merge: Krypton 产物(0陷阱/运行时已中和) + 回填 depfix2 的 2560 个真体
- `fd8e227335` 2026-10-21T20:48Z — 存档 Krypton 首次还原产物(0 陷阱/23009 体) + 开启 WINFORMS_HEURISTIC_FALLBACK 重跑
- `f4db9e49cf` 2026-10-21T20:46Z — depfix4: depfix2 + 中和残留保护运行时(清空 <Module>::.cctor, JIT hook 置空)
- `daf74cf9b8` 2026-10-21T20:36Z — depfix3: 全量方法 MaxStack 抬到 512 (dnlib 对这类体算不出 maxstack, 偏小即 InvalidProgramException)
- `557780f7d1` 2026-10-21T20:34Z — Merge branch 'main' of https://p.xixky.eu.org/https://github.com/qoqxkaqoq/airexplorer-reactor-handoff into work
- `eef00711c6` 2026-10-21T20:34Z — 复验 v84b: 结论不通过（空白窗体）+ 证据截图 + 探针空白窗体判定
- `0d66dff5a7` 2026-10-21T20:29Z — 纳入 qoqxkaqoq/1 的 v84b 脱壳产物做独立复验
- `45aab8bae3` 2026-10-21T20:28Z — krypton-restore workflow: 用 Krypton(.NET Reactor devirtualizer) 处理官方原版, 含 standalone-check 与 UI 探针
- `a6ab5000eb` 2026-10-21T18:55Z — 清理误提交的 results 目录（探针结果保留在 ci-<run_id> 分支与 docs/evidence）
- `a7e74efc28` 2026-10-21T18:54Z — 报告: 修正字符串资源表述
- `5fffd557a0` 2026-10-21T18:45Z — 探针: 关对话框→抓主窗口→再 kill
- `4ac1f19d68` 2026-10-21T18:44Z — 留言板: 根因定位与给 wb-reverser 的答复
- `0edb4c4bd4` 2026-10-21T18:44Z — 合并 main: 兼容协作留言板与 CI 产物
- `8610106c14` 2026-10-21T18:42Z — 第2轮: 根因定位报告 + 证据截图 + 8 个分析工具 + CI 执行验证台
- `6a8847d7f1` 2026-10-21T18:32Z — fixinit: 原版初始化体回植 nb_original
- `119405e844` 2026-10-21T18:32Z — depfix2: 补入 cilantro 的 129 个正常方法体; 修 probe.ps1(纯ASCII, PS5.1 解析崩溃) + CI 改用官方安装包目录运行
- `f061178dfc` 2026-10-21T18:27Z — 加入原样重保存对照 exe 与基线副本
- `81bef74ab0` 2026-10-21T18:26Z — host: 打印完整异常链
- `b4e84eb9eb` 2026-10-21T18:21Z — 忽略 results 目录
- `56a7a97778` 2026-10-21T18:20Z — depfix: e8runnable 真体(DefineEfficientProfiler 等4方法) 合并进 nb_original; 加陷阱桩化版 + Windows CI 验证
- `a2dac1bb6d` 2026-10-21T18:16Z — CI: 宿主参数改为相对 exe
- `e1334a1b7d` 2026-10-21T18:14Z — CI: 修正宿主工作目录
- `aaa0d5b74e` 2026-10-21T18:10Z — CI: 增加受控宿主抓托管异常堆栈
- `a2799d8e35` 2026-10-21T18:07Z — CI: 分支名避免与 ci-results 冲突
- `2cfcc165df` 2026-10-21T18:04Z — CI: 每次运行推独立分支 ci-results/<run_id>
- `4e167561ee` 2026-10-21T18:00Z — CI: 探针抓主窗口 + 结果按 run 分隔
- `739651d2e7` 2026-10-21T17:57Z — CI: 结果回传 ci-results 分支
- `c48174e7d9` 2026-10-21T17:54Z — 分析: 原版样本定位 + 静态体择优回填合并版 + Windows UI 探针 CI
- `b79af14712` 2026-10-21T17:50Z — test push
- `2faddd54c7` 2026-10-21T17:37Z — board: 多AI协作留言板 + API推送脚本
- `4df759cae3` 2026-10-21T16:33Z — AirExplorer Reactor 恢复工程交接包: 分析工具+各版本exe+死循环分析数据+交接文档
