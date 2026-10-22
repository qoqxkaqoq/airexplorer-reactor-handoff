# 进展文档 — wb-reverser（2026-10-22 02:00–05:00）

> 接手自 HANDOFF.md。本轮工作全部在 Linux 沙箱做静态分析 + GitHub Actions(Windows) 做运行时验证。
> 结论先行：**前任"卡在 DefineEfficientProfiler 死循环"的判断是对的，但"只有这 1 个陷阱体"是错的；
> 死循环这一关已经过了，现在卡在回植后启动即抛 InvalidProgramException。**

---

## 1. 环境接入（可直接复现）

| 项 | 情况 |
|---|---|
| 仓库 | 72MB，含 7 个 exe。直连 github.com 超时，走 `https://p.xixky.eu.org/https://...` 代理 4 秒 clone 完 |
| 推送 | 直连不可用，写了 `scripts/gh_sync.py`（走 GitHub Git Data API，按路径提交，互不覆盖），exe 也能推 |
| SDK | .NET 6.0.301 → 加装 8.0.426（工具链是 net8.0）；dnlib 3.3.4 从 NuGet 正常还原 |
| 官方原版 | **已从 airexplorer.net 拉到 OnlineInstaller，7z 解压得到原版 `AirExplorer.exe`**（work/app/） |

## 2. 三个改变方向的发现

### 发现 1：被反篡改污染的方法不是 1 个，而是 114 个（depfix 基线上是 134 个）

写了 `tools2/trapscan.cs`：判据是"大 switch + 索引局部变量全方法只写 1 次 + 从 case 块有回边跳回分发点"
（三个条件同时成立才判陷阱，避免把一次性 switch 分发误报成循环）。

各版本实测：

| 版本 | 方法数 | 含大 switch | **确证必死循环** |
|---|---|---|---|
| nb_original | 22930 | 3182 | **114** |
| fixed_v126 | 22847 | 2691 | **141** |
| skip_decrypt | 22847 | 2690 | **140** |
| hybrid | 22930 | 3550 | 18 |
| cilantro | 22933 | 3222 | 12 |
| e8runnable | 22930 | 23 | 0 |
| Slayed | 22753 | 7 | 0 |

被污染的不止初始化链，还有 `DetachedClient::CreateFolder`、`MonitorProgram::NotifyIterablePool`、
`Requester*` 等大量业务方法。也就是说：**前任 126 轮里移植的不止一个坏体，是 114 个坏体。**

### 发现 2：`e8runnable` 就是官方原版的原样副本，里面存着初始化链的真体

- `md5(官方 AirExplorer.exe) == md5(e8runnable) = a12b5c573e1b54e98cccc29351eaa066`
- 原版里 22926 个方法是 `nop;nop;nop;ret` 空桩（Reactor 加密态），只有 4 个方法是明文真体，
  即 Reactor 的解密引擎：`DefineEfficientProfiler`(9992) / `InstantiateGlobalCalculator`(2521) /
  `DefineActiveEvent`(6) / `SearchAdapter`(Main, 213)
- 同一个 `DefineEfficientProfiler`，两个版本指令数完全相同(9992)、switch 表 625 项目标顺序完全相同，但：

| | nb_original（前任基线） | e8runnable / 原版 |
|---|---|---|
| `stloc V_72`（状态变量） | **1 次** | **741 次** |
| `stloc V_104`（垃圾变量） | 1751 次 | 0 次 |

**反篡改的改写手法由此确认：把所有 `stloc V_72` 换成 `stloc V_104`，状态机就永远不推进。**
这也说明 e8runnable 是"反篡改未触发时"的产物，是本项目唯一未被污染的初始化链真体来源。

### 发现 3：回植真体后不再卡死，但启动即抛 InvalidProgramException

- depfix / depfix2 在 CI 上 **2 秒内退出，退出码 0xE0434352**（CLR 未处理异常），
  而 nb_original 是 30 秒 CPU 吃满 30 秒的死循环 → 死循环问题已解除
- 另一位 agent 的同思路版本（`fixinit: 原版初始化体回植`）抓到的堆栈：

```
System.TypeInitializationException: '<Module>' 的类型初始值设定项引发异常
 ---> System.InvalidProgramException: Common Language Runtime detected an invalid program
      at CloudClient.Templating.DispatcherInitializer.VerifyCombinedStateRequest()
      at CloudClient.Templating.DispatcherInitializer.DefineEfficientProfiler()
```

即：**回植的 DefineEfficientProfiler 真体会去调用 `VerifyCombinedStateRequest`，
而该方法在 nb_original 侧的 IL 被 CLR 判定为无效程序**（典型原因是方法头 MaxStack 小于实际栈深）。

## 3. 产出

### 新版本 exe（未改动仓库既有 exe）

| 文件 | 构成 |
|---|---|
| `exes/AirExplorer_depfix.exe` | nb_original + 原版初始化链真体（DefineEfficientProfiler 等 4 个方法） |
| `exes/AirExplorer_depfix_stubbed.exe` | depfix + 112 个陷阱体改成最小桩（对照用） |
| `exes/AirExplorer_depfix2.exe` | depfix + 从 cilantro 补回 129 个正常方法体（陷阱 134 → 8） |

### 工具（tools2/，.NET 8 + dnlib 3.3.4，源码即文档）

| 工具 | 用途 |
|---|---|
| `recon` | 样本画像：PE 节 / 资源 / 方法体 RVA 分布 / 模块 cctor 链 |
| `trapscan` | **批量确证"必死循环陷阱体"**（控制流可达性分析，非正则/grep） |
| `trapstub` | 把陷阱体替换成最小桩，卡死→功能缺失（附 `--report-only`） |
| `merge` | 把 src 的非桩真体批量覆盖到 dst（带防桩覆盖保护） |
| `merge2` | **精准补体**：只替换"dst 是陷阱 且 src 正常"的方法 |
| `stackchk` | 控制流感知的 IL 栈验证器，找会被 CLR 判 InvalidProgram 的方法（可 `--fix` 自动抬 MaxStack） |
| `rescan` | 定位 Reactor 加密资源与其解密方法、DNR JIT hook 方法 |

### CI

- `.github/workflows/ui-verify.yml` + `ci/probe.ps1`：Windows runner，
  从官方安装包 7z 解压出 `app\`，用候选 exe 覆盖后再跑（裸 exe 缺运行时邻居，会让本来能跑的候选显得是坏的）。
  记录：是否出主窗口 / 窗口标题 / CPU 时间 / 是否加载 WinForms / 退出码，有窗口则截图。
- 踩坑：PowerShell 5.1 用旧代码页解析无 BOM 的 UTF-8 脚本会把中文吃掉并导致语法解析崩溃，
  脚本已改成纯 ASCII。

## 4. 现状与下一步建议（按性价比排序）

**当前卡点**：`depfix2` 启动 → cctor → DefineEfficientProfiler(真体) → `VerifyCombinedStateRequest` → InvalidProgramException。

1. **修 IL 有效性（正在做，最优先）**
   用 `stackchk --fix` 把 MaxStack 不足的方法统一抬高（+8），产 `depfix3`，重新 CI。
   如果修完仍有 InvalidProgram，说明不只是 MaxStack 问题，需要进一步查栈类型错配
   （同一个槽位在不同路径上类型不一致也会触发 InvalidProgram）。
2. **顺手把 cctor 链上剩下的 8 个陷阱补掉**
   depfix2 还剩 8 个（cilantro 侧自身也是陷阱的那 5 个 + 少量）。
   这 5 个在 cilantro 里也无正常体，需要另找来源。
3. **原版 → 静态解密（方案 a，治本）**
   原版 exe 已在手（`work/app/AirExplorer.exe`），它有完整的 Reactor 加密数据区。
   已知线索：
   - Reactor ≥ 4.5.0.0（找到 DNR 的 JIT hook 方法 `DispatcherInitializer::InstantiateSegmentedRunner`，
     签名 `UInt32(IntPtr,IntPtr,IntPtr,UInt32,IntPtr,UInt32&)` = de4dot 的 CompileMethodType.V2）
   - 解密器 `DefineEfficientProfiler` 引用资源 `ErrorReceiver.ValidatorViewer`(356328B)，
     并带 `xorKey = 1173269726 (0x45EEACDE)`
   - 6 个嵌入资源全部是高熵密文（熵 7.9–8.0），其中 `ValidatorGenerator.DefinitionError` 2.3MB 最像方法体数据区
   - 对照 de4dot `dotNET_Reactor/v4/MethodsDecrypter.cs` 的 DNR4.0+ jitter-hooked 解析路径即可
   - **关键障碍**：解密后数据按 RVA 映射回方法，而 nb_original 的 RVA 已被 nb_slayer 改写过，
     所以必须用原版 RVA 布局，或改用方法 token 定位
4. **别再做的事**
   - 不要基于陷阱体做移植/修复（陷阱体的 case 块内容已被整体替换成垃圾，真逻辑不在里面，反推不回来）
   - 不要再用裸 exe 直接跑来验证（缺运行时依赖，结论不可靠）

## 5. Krypton 实测结果（2026-10-22 05:0x，第二轮）

| 指标 | Krypton 产物 |
|---|---|
| 方法数 | 23009（0 无体） |
| 确证死循环陷阱体 | **0**（nb_original 是 114） |
| 含大 switch（控制流平坦化残留） | 15（nb_original 是 3182） |
| 体积 | 5.3MB（原版 9.6MB，加密数据与 native stub 已清） |
| `standalone-check` CCTOR | **ok=4797 / fail=50**（TypeLoad 6 / FileNotFound 5 / NullRef 39） |
| standalone-check 其它 | NullRef 421、FileNotFound 217、TypeLoad 37、**InvalidProgram 9**、DllNotFound 1 |
| 已重建 | 27 个 WinForms 窗体构造函数、74 个 Dispose(bool)、80 个 hidden call |
| UI 探针 | `FAIL-EXITED(code=-1073741819)` = **0xC0000005 访问违规**，无窗口 |

开了 `KRYPTON_WINFORMS_HEURISTIC_FALLBACK=1` 重跑，结果与首轮一致（27 个窗体重建数不变），
说明那 5 个"`UI for X was not recovered`"的窗体靠这个开关补不回来。

**9 个 InvalidProgram 方法（Krypton 直接给了名字，可精准修）**：
`StatelessSenderAggregator::AggregateSymbolicProc`、`StatelessSenderAggregator::DirectNotifier`、
`StatelessSenderAggregator::ReflectConnection`、`AggregatorEvaluator::Start`、
`VisualElementValue::ValidateVirtualCommand`、`CommandTransmitterMap::RunCommonChain`（另 3 个未列出）。

### 组合路线的错误推进链（每一层都是可定位的具体错误，不是玄学）

| 版本 | 启动错误 |
|---|---|
| nb_original | 死循环，CPU 100%，无窗口 |
| depfix2（真体回植） | `InvalidProgramException` @ `VerifyCombinedStateRequest` |
| depfix3（MaxStack 抬到 512） | 同上（说明不只是 MaxStack 数值小，是 CFG 汇合处栈深不一致） |
| depfix4（中和保护运行时） | 前进一层：`InvalidProgramException` @ `StatelessModel::.cctor` |
| krypton（纯） | `NullReferenceException` → `0xC0000005` |
| krypton_merge（回填 2560 真体） | `MissingFieldException: <PrivateImplementationDetails>{A53A4920-...}.D5B7247C...` |
| krypton_merge2（补回 8 个静态数据字段） | `BadImageFormatException: Bad IL range` |

附带结论：补 `<PrivateImplementationDetails>` 字段时，字段类型 `__StaticArrayInitTypeSize=N`
必须显式带上 `ClassLayout.Size=N`，否则 dnlib 写盘会报 `initial value size != size of field type`。

### 追加：Reactor 把初始化注入进了成百上千个类型的 .cctor

用 `neutralize2`（判据：`.cctor` 里调用了 `DispatcherInitializer` / `WrapperProvider` 的静态方法）实测：

| 版本 | 被注入的 .cctor 数 |
|---|---|
| Krypton 产物 | **1214** |
| depfix2 | **4633** |

Krypton 只清了 `<Module>::.cctor`，`StatelessModel::.cctor` 里仍完整保留着
`ValidateAccessibleResponderManager → DefineEfficientProfiler → InstantiateGlobalCalculator(重复两次) → DefineActiveEvent`。
把这两者的 cctor 都中和掉之后，`krypton_merge4` 从 `Bad IL range` 前进到了 `NullReferenceException`——
**说明 cctor 残留确实是 Bad IL range 的成因之一**。

### 当前：所有路线收敛到同一个错误

| 版本 | 启动错误 |
|---|---|
| krypton（纯） / krypton_fix9 / krypton_fix9_eh / krypton_neutral | `NullReferenceException` → **0xC0000005** |
| krypton_merge4（回填+补字段+修EH+中和cctor） | `NullReferenceException` → **0xC0000005** |
| depfix5（完整真体+中和4633 cctor+hook置空） | `NullReferenceException` → **0xC0000005** |

共同特征：2~3 秒内退出、`cpu=0`、无窗口。也就是说**启动早期的某个静态依赖是 null**。
这与 Krypton `standalone-check` 报告的 **421 个 NullReferenceException** 吻合：
它把还原不了的方法桩化成了 `ret`（回填前就有 2560 个这类桩），返回 null 后下游就炸了。
另外它报告 `DllNotFoundException total=1 (ConfigViewer::ReadIterator)`，
以及 `StatelessModel::.cctor` 里用 `ldnull + ldftn ModelConnectedMap(IntPtr,IntPtr)` 构造委托——
native 回调路径也是访问违规的候选来源。

### 下一步（按性价比）

1. **桩化那 9 个 InvalidProgram 方法**再跑一次纯 Krypton 产物（最快，能验证 0xC0000005 是否由它们引起）。
2. **修 Bad IL range**：是 EH 表的嵌套/顺序问题（跳转与 switch 目标越界已排查为 0），
   需要做 EH 区间排序与嵌套校验。
3. 421 个 NullReference 提示：Krypton 产物里运行时解密出的字符串/资源仍大面积缺失，
   即便窗体建起来也大概率是空内容——这点要有心理预期。

## 6. 已有最高水位：`qoqxkaqoq/1` 仓库的 v84b（能出窗体，但空白）

用户提示了另一个仓库 `github.com/qoqxkaqoq/1`，里面是一个已经搭得很完整的工程
（12 个 workflow：`unpack` 66KB / `ar_patch` 144KB / `ar_fix` 32KB / `ar_krypton` 17KB …，
外加 `1.zip` 9.2MB、`agents.md` 分析报告、`plan.md`）。
它的 `agents.md` 顶部有一份 2026-10-22 04:35 的复验更正，结论是：

- `unpacked-final`（run 39526859528）的产物 **进程存活、标题 `Air Explorer v5.11.0` 正确**
- **但窗体内容为空**：主窗口只有 **300×300**（原版 945×788），窗口总数 **20 → 6**，
  无工具栏/账号树/控件子窗口
- 静态上它确实完成了方法体恢复（**25346 体 / 空壳 110 / ldstr 2099**）
- 失败点自述：**UI 构建链被"中和"**——`资源装载链中和`、
  `InstantiateGlobalCalculator 已重写（最小字段初始化）`

我把该 artifact（16MB）下载下来实测，**与上述自述完全吻合**：

| 方法 | 原版真体 | v84b |
|---|---|---|
| `DefineEfficientProfiler` | 9992 指令 | **4 指令**（`ldstr trace.log` …） |
| `InstantiateGlobalCalculator` | 2521 指令 | **8 指令** |
| `DefineActiveEvent` | 6 指令 | 1 指令 `ret` |

**我尝试用原版真体补回这三个方法（`exes/AirExplorer_v84b_restore.exe`），结果：
`ArgumentNullException @ <Module>::.cctor`**——因为原版这几个方法内部依赖 Reactor 的运行时状态
（加密资源 + 解密器），而 v84b 已经把运行时中和掉了，直接放回去反而崩。
**结论：不能整体恢复，只能"部分恢复"**——需要从 2521 指令里剥出真正做字段/资源初始化的那部分，
跳过解密部分。这是一项需要逐指令读逻辑的活。

### 顺带澄清一个判据问题（对方报告里也提到了）

原来的 PASS 判据是"进程存活 + 窗口标题存在"，这会产生**假阳性**（v84b 就是因此被误判通过）。
建议改用硬指标（已写进 `ci/probe.ps1` 的 VERDICT，可直接复用）：
① 主窗口 ≥ 800×600；② 进程窗口数 ≥ 15；③ 主窗口截图非纯色（像素方差阈值）；
④ 存在 `Add account` 之类子控件窗口。

## 7. 本轮的最大突破：16586 个 NecroBit 真体全部收割成功

在 `qoqxkaqoq/1` 与联网检索的指引下，改用 **JIT 入口收割**（AutoReaktor v3 的 `v3/jitdump`）：
进程挂起 → APC 注入 `clrjit_dump.dll` → 在 `clrjit.dll` 加载时装 `ICorJitCompiler::compileMethod` 的 VMT hook，
把**运行时亲手交给 JIT 的那份 CIL** 直接落盘。`--force` 会先跑完模块初始化器（让 anti-tamper 干净结束），
再用 `RuntimeHelpers.PrepareMethod` 遍历每一个可解析的 MethodDef。

CI 实测（`.github/workflows/nbjit.yml`）：

```
[fd] done: prepared=16040 failed=693 skipped=4613 eh=2127 dumped=16586
status: body=16586 | eh=2218 | 总 IL 字节=3,820,742
```

**16586 个方法体**——与 HANDOFF 里"16586 个方法体 RVA=0 加密存储"的数量完全一致。
每个 dump 落成 `m_<token>.bin`：

| 偏移 | 字段 |
|---|---|
| 0 | token (u32) |
| 4 | ilSize (u32) |
| 8 | maxStack (u32) |
| 12 | ehCount (u32) |
| 16 | options (u32) |
| 20 | localsTok (u32) —— **恒为 0** |
| 24 | raw CIL 字节 |

`m_<token>.eh` = `[u32 count][count × 28B CORINFO_EH_CLAUSE]`，
clause = 7×u32: flags(0=Catch/1=Filter/2=Finally/4=Fault), tryOff, tryLen, hOff, hLen, classTok|filterOff, reserved。

### 污染问题解决了

`m_0600419C.bin`（DefineEfficientProfiler）实测：

```
ilSize=37072  maxStack=8  ehCount=9
stloc V_72 (fe 0e 48 00) 出现 741 次     ← 真体
stloc V_104 (fe 0e 68 00) 出现 0 次      ← 无陷阱特征
```

对比 nb_original 的 1 次。**JIT 入口拿到的确实是未被反篡改污染的体**——
因为反篡改在"正常初始化后"就没有理由再替换 IL 了，这条路在结构上绕开了它。

### 写回：`tools2/nbrestore.cs`（12052 个方法写回成功）

自己实现的写回器，关键设计：

1. **token 认原版、locals 认 nb_original**：原版 NecroBit 方法是空壳（locals=0），
   而 nb_original 的 locals 签名完好但 token 布局被 nb_slayer 改过 → 按 `FullName::MethodName` 跨模块取 locals。
2. 自己解析 IL（opcode 表 + 操作数类型 + 两遍法回填跳转/switch 目标），不依赖 `CreateCilBody`。
3. EH 按 IL offset 映射回指令；`TryEnd/HandlerEnd` 落在方法末尾时置 null。
4. 写盘前做操作数类型校验（`Validate`），不合格的方法跳过而不是写坏文件。
5. 写盘用 `MetadataFlags.PreserveAll | KeepOldMaxStack`。

结果：**12052 个方法写回，确证陷阱体 114 → 13**，控制流平坦化 3182 → 2428。
`DefineEfficientProfiler` 的 `stloc V_72` 从 1 次变成 741 次。

### 当前卡点：`BadImageFormatException: Bad method token`

`nbjit_restored2` 启动即 `<Module>::.cctor` 抛 `Bad method token`。
已排查：
- cctor 本身 IL 正常（5 条指令，call 的 token 0x0600419C/0x06004192/0x06004194/0x06000001 都对）
- 用 `Importer.Import` 重绑操作数无效——**对本模块 MethodDef 它是原样返回，等于没重绑**
- 4534 个方法未能写回（3818 个因原版/nb_original 两侧都取不到 locals，其余为 token 解析不到）

**下一步建议（按可行性）**
1. 对写回的每个操作数做**按名字+签名重建 MemberRef**（不是 Importer），把 dump 的 rdts 彻底洗一遍；
   可复用 `tools2/merge2.cs` 里的 `RebindRefs` 思路。
2. 只写回"体内不引用任何外部 token"的方法（保守集），先验证这条路能否启动，
   再逐步放开——可快速判断 `Bad method token` 是否只来自少数方法。
3. 用 v84b 的元数据做基座（它的 token 布局与 Reactor 运行时一致），把 nbjit 的真体灌进去。

### 最终结论（2026-10-22 08:0x，本轮收尾）

**从 `Bad method token` 一路推进到 `ArgumentNullException`，然后撞上一堵结构性的墙：**

| 版本 | 结果 |
|---|---|
| `nbjit_restored3`（12768 真体，含完整初始化链） | `ArgumentNullException @ <Module>::.cctor` |
| `nbjit_mininit`（12768 真体 + 把 DefineEfficientProfiler / DefineActiveEvent 置空） | 同样 `ArgumentNullException` |

桩化两条之后仍然崩，说明剩下的 `InstantiateGlobalCalculator` 真体就是崩点——
而它正是 v84b 作者当年被逼"重写成最小字段初始化"的那个方法。

**所以矛盾的形状是清晰的：**

> **Reactor 初始化链的真体** 与 **脱壳后的运行时** 是互斥的。
> 真体内部依赖 Reactor 的加密资源与运行时状态（AES 解密器、委托表、静态字段）；
> 而"脱壳"这个动作本身就把这些依赖剥离了。于是：
> - 保留真体 → `ArgumentNullException`（依赖缺失）
> - 换成最小实现 → 字段/资源没初始化 → 窗体建出来但内容空白（v84b 的 300×300）

这不是再修一个 bug 能解决的，而是要求**把初始化链本身也完整静态解密**——
也就是把 `InstantiateGlobalCalculator` 那 2521 条指令里"做解密"的部分换成"直接给结果"，
逐指令读懂它到底初始化了哪些字段、给了什么值。这是本项目剩下唯一有意义的攻坚方向。

**本轮净收益（可被下一棒直接使用）**
1. `work/nj_art/jitout/` 与 CI artifact `nbjit-dump`：**16586 个真体的 m_<token>.bin + 2218 个 .eh**，
   格式已在本文档第 7 节写明。这是全项目最硬的资产——前任 126 轮从未拿到过。
2. `tools2/nbrestore.cs`：可用的写回器（token 认原版、locals 认 nb_original、自己解析 IL、EH 重挂）。
   已知坑：`StringsStream.Read` 返回 `UTF8String` 不是 `string`，直接塞给 dwriter 会报
   `InlineString got UTF8String` 而把方法静默丢弃。
3. 陷阱判定与组合工具链（trapscan / merge2 / normalize2 / nbrestore），以及可复现的 Windows CI。

## 8. 与其他 agent 的协作

- 仓库建了 `board/` 留言板（规则见 `board/README.md`），我在 `board/agents/wb-reverser.md`。
- 已知另一位 agent 在做同源思路（`fixinit: 原版初始化体回植`），并已有官方安装包的取法
  和"受控宿主抓异常堆栈"的能力，两者思路撞车，建议直接在留言板对齐，避免重复。

---

## 9. 真突破：把"解释器执行结果"当作纯数据搬过来（v10 → v13）

前面所有轮次都卡在同一件事上：`TemplateArgument::InstantiateStatelessUser<T>` 是**泛型方法**，
JIT 收割拿不到；唯一的真体在 cilantro（nb_slayer 产物），跨模块移植必 AV。

**换了个问法之后路就通了**：不移植解释器，而是把**解释器跑出来的结果**搬过来。
这些结果全是纯数据——没有委托、没有反射句柄、没有模块绑定。

### 9.1 `ci/hostdump.ps1`：在官方 exe 的宿主进程里导出运行时状态

关键约束：**必须用 Windows PowerShell 5.1（.NET Framework 4.8）**，
`pwsh 7` 是 .NET 8，`Assembly.LoadFrom` 加载 .NET Framework 程序集会失败。

```
LoadFrom(app\AirExplorer.exe)
  -> RuntimeHelpers::RunModuleConstructor(module)   # 跑 <Module>::.cctor, 199ms
  -> 枚举 <Module>{*} / DispatcherInitializer / TemplateArgument 的所有静态字段
  -> SearchStrategy(资源流, 0)                       # 触发脚本 44, 把资源解进 _ExtractorVisitors
  -> 导出 _ExtractorVisitors 原始字节 + 再 dump 一遍
```

产出（CI artifact `hostdump`，两次运行共 2 分钟）：

| 目标 | 内容 | 大小 |
|---|---|---|
| `<Module>{a8c2e9b2…}` 的 `m_0d0b145b…` 单例 | **124 个 int 字段** | — |
| `DispatcherInitializer::_ExtractorVisitors` | **398,794 字节** UTF-16 字符串表 | 389 KB |

`_ExtractorVisitors` 的结构（从 `InstantiateTransferableProgram` 的 IL 读出来的）：

```
[4 字节 int32 length][length 字节 UTF-16LE 字符][4 字节 int32 length]...
```

而 `InstantiateTransferableProgram(offset)` 的参数就是**字节偏移**，
调用点是 `ldc.i4 K xor holder.field` —— 两个操作数都是常量，可以离线算。

**离线验证**（`ArgumentGateway..cctor`，不跑程序）：

| 字段 | offset | 解出的字符串 |
|---|---|---|
| `m_df3c7fc7…` | 277204 | `https://www.airexplorer.net/checkversion/?ad=1&sv=1` |
| `m_b24a88b7…` | 277518 | `https://www.airexplorer.net/bugReport/sendbug.php` |

对齐完全正确 —— 这条路是通的。

### 9.2 v10：硬编码 holder 单例（`tools2/initholder.cs`）

把 `<Module>{a8c2e9b2}::r6cf451d…()`（原本调 `InstantiateAccessibleProcessor(45,…)` 的 26 条指令）
整个替换成：

```
newobj holder::.ctor ; dup ; ldc.i4 <v> ; stfld m_xxx ; ... ×124 ; stsfld 单例 ; ret
```

**字节级**：只追加方法体 + 改 MethodDef.RVA 列，元数据表零改动（v9 的反篡改绕过依赖表行号）。
结果：`ArgumentGateway..cctor` 的 NRE 消失，推进到
`ArgumentOutOfRangeException @ BitConverter.ToInt32` —— 即 `_ExtractorVisitors` 还是空数组。

### 9.3 v11 系列：三次失败与三个教训

| 版本 | 做法 | 结果 | 教训 |
|---|---|---|---|
| v11 | 字节级追加 398KB + 改 SearchStrategy 为 `FileStream+Read` | `InvalidProgramException` | **栈下溢**：`stsfld` 之后栈上还剩 `FileStream`，只需 1 个 `pop`，我写了 2 个 |
| v11a/v11b | 改 `.reloc` 的 section 标志（加 `CNT_CODE` / 去 `DISCARDABLE`） | 同样 InvalidProgram | **section 标志不是原因**，别往这边查 |
| v11c | 修掉多余的 `pop` | `BadImageFormatException: Bad class token` | 复用的 `MemberRef`（`FileStream::.ctor` / `Stream::Read`）是**孤儿行**，签名里的 TypeRef 不可解析 |

**另一条弯路**：我以为 `newarr` 的操作数要 `TypeDefOrRefEncoded` 压缩编码，改成 `8D ED 02` 后
dnlib 直接解析不出操作数。**`newarr` 是 `InlineType`，4 字节 raw token**，不需要压缩。
（`ldtoken` 同理。）

### 9.4 v12：dnlib 重写 + FieldRVA（`tools2/rebuild2.cs`）

既然孤儿 MemberRef 不可信，就让 dnlib **重新生成全套 token 和 PE 布局**：

```csharp
// <PrivateImplementationDetails> 里加一个 __StaticArrayInitTypeSize=398794 的字段
fld.InitialValue = blob;          // dnlib 的 FieldRVA 属性名是 InitialValue
// SearchStrategy 换成 7 条指令
ldc.i4 398794 ; newarr byte ; dup ; ldtoken __strtab
call RuntimeHelpers::InitializeArray ; stsfld _ExtractorVisitors ; ret
```

写盘 `PreserveAll | KeepOldMaxStack`。

**对照组 v12n**（同样 dnlib 重写、但不做任何修改）跑出和 v10 完全一致的
`ArgumentOutOfRangeException @ BitConverter.ToInt32` ⇒ **dnlib 重写本身是安全的**，
可以放心用它做后续所有改动。

v12 结果：

```
NullReferenceException
   at AirExplorer.Values.ArgumentGateway.EvaluateVisibleAttribute()
   at CloudClient.Models.StatelessModel.SearchAdapter(String[] info)
```

**`ArgumentGateway..cctor` 通过了**——字符串表这条链彻底打通。

### 9.5 v13：`RequestWorker::.ctor` 是空桩

新的 NRE 来自 `EvaluateVisibleAttribute` 第一段：

```
call RequestWorker::WriteRequest()      // 返回 m_RequestClient
ldfld  RequestWorker::_RequestSorter    // ← null
...
callvirt TemplateInitializer::DefineTransferableRecord(string)
```

`RequestWorker::.ctor` 在 nbjit 的 16586 个 dump 里**没有**（`m_06002AF0.bin` 不存在），
nb_original 里它是 `nop;nop;nop;ret`，而 **cilantro 里有完整的 74 条指令**。

用 `bodytrans`（补上 `PreserveAll`）移植 —— 16 处引用重绑到目标模块。

### 9.6 当前结论

> **卡点从"解释器拿不到"变成"少数方法 nbjit 没 dump 到"**。
> 后者是**可枚举、可批量修**的：遍历目标模块里所有 ≤4 条指令且只含 `nop/ldnull/ret` 的方法，
> 从 cilantro 同名同签名移植即可。

`bodytrans clonetree` 已经实现了"从入口方法 BFS 调用树、dst 缺失/桩就移植"的批量模式，
下一轮可以直接用。

---

## 10. 从"单点修"到"批量补"（v14 → v25）

第 9 节把字符串表这条链打通后，剩下的问题变成一句话：
**nbjit 的 16586 个 dump 覆盖不到全部方法，缺的那些是桩。**

`tools2/stubscan` 统计（v14 vs cilantro）：

```
total=30886  stub=2308  transplantable=1254  noSrcBody=1054
```

即 **2308 个桩**，其中 **1254 个**在 cilantro 里有真体。

### 10.1 委托字段的目标方法可以离线查（`m_LogicalProcessorMap`）

`TrackCompiler(RuntimeTypeHandle)` 是 Reactor 的"数据驱动字段初始化器"：
它读资源 `CollectorTransaction.ValidatorProject`（26KB，加密），
建一张 **`Dictionary<字段token, 方法token>`**，然后对每个静态字段
`Delegate.CreateDelegate(field.FieldType, Module.ResolveMethod(...))` + `SetValue`。

**这张表可以在官方宿主里反射拿到**（`ci/hostdump.ps1` 第 5 步），共 **3266 条**：

```
K|67119178|167776645|System.Collections.Hashtable::ContainsKey     <- CheckAlphabeticProject
K|67119179|167774686|System.Collections.Hashtable::get_Item        <- VerifyAdjustableSelector
```

于是"这个委托字段到底调什么"从**猜测**变成**查表**。
（顺带确认：这两个不是缺失方法，就是 Hashtable 的两个 BCL 方法。）

### 10.2 `tokcmp`：先证明 dnlib 重写没打乱 token

这是继续往下走的前提。拿 7 个关键 token 在官方 `e8runnable` 和我们的版本里逐一解析：

```
OK 0x060062C4 AlphabeticWrapperValidator::ExecuteExplorer ...
OK 0x0400284A ValidatorParserCollection::CheckAlphabeticProject
OK 0x06002B06 TemplateInitializer::InstantiateRandomIterator
same=7 diff=0
```

`PreserveAll` 确实保住了表行号 —— 所以 `TrackCompiler` 里写死的 token 仍然有效，
dnlib 重写这条路是安全的（v12n 对照组也印证过）。

### 10.3 `bodytrans fromlist`：一次移植 1125 个

给 `bodytrans` 加了 `fromlist` 模式：读 `stubscan` 的清单批量移植，
跳过 `ldc.i4.1; ret` 的授权桩。

```
[fromlist] ok=1125 skip=129 fail=0
```

### 10.4 `fixgen`：假名类型的三层映射

`bodytrans` 的 `RebindRefs` 只按"名字"重绑字段/方法，管不了"类型本身被改名"。
`fixgen` 按优先级三层匹配：

| 层 | 规则 | 命中 |
|---|---|---|
| mapN | 同父类型下按 `NestedTypes` 序号（+ 指纹校验） | 多数 |
| mapP | 同父类型下按指纹唯一 | 少数 |
| map | 全局指纹唯一 | 少量 |
| mapM | 手工 `--map A=B` | 补漏 |

413 个假名类型 → **385 个映射成功**，28 个无候选（多为 `<>c__DisplayClass` 的字段顺序差异）。

### 10.5 三个真 bug（都出在 fixgen）

| # | Bug | 症状 | 修法 |
|---|---|---|---|
| 1 | 只替换指令操作数，不管 `Body.Variables` | `TypeLoadException: GeneratedEnum_0425`（locals 签名里） | 加 `FixSig` 递归替换 TypeSig（数组/byref/泛型实参都覆盖），修了 35 处 |
| 2 | `TypeSpec` 的 `FullName` 带泛型实参（`X\`1<Y>`），map 的 key 是 `X\`1` | 泛型 `<>c` 类的引用全部漏掉 | 加 `Norm()` 去掉 `<...>` |
| 3 | **`MemberRef` 同时实现 `IField` 和 `IMethod`，代码先判 `IField`** | 所有 `ldftn`/`call` 到 TypeSpec 上的方法引用都被当字段查表 → 静默漏掉 | 先判 `IMethod` |

第 3 条影响最大：修完后 `methods` 从 **0 变成 106**，`InstantiateStatelessUser` 里的
`GeneratedType_0431<T>::generatedMethod_0290`（对应官方 `URqFYq3xtmntT2OcLub\`1::r3vw2AFBgZ`）
才被正确重绑，假名引用计数从 4 → **0**。

### 10.6 版本推进表

| 版本 | 改动 | 结果 |
|---|---|---|
| v13/v14 | 移植 `RequestWorker::.ctor` + fixgen(`GeneratedType_0440`) | NRE 从 `..cctor` 移到 `DefineTransferableRecord` |
| v16/v18 | 移植 `TemplateInitializer::.ctor` / `AttachDistributor` | 仍在 `DefineTransferableRecord`（Hashtable 空） |
| v19/v20 | 批量 1125 + fixgen 全量 | 推进到 `ModelTracer.JoinExecutor`，但 `TypeLoadException: GeneratedEnum_0425` |
| v21 | `InstantiateStatelessUser` 回桩（排除误移植） | 确认卡点就是它（NRE @ JoinExecutor） |
| v22–v25 | fixgen 三个 bug 全修 | 假名引用清零 |

**当前状态**：v25 已把 `InstantiateStatelessUser` 的真体（888 指令）连同它依赖的
`GeneratedType_0431<T>` / `GeneratedEnum_0425` 一起重绑干净，等待 CI 验证。

### 10.7 当前确切的卡点（v30）

```
TypeLoadException: Could not load type 'URqFYq3xtmntT2OcLub`1'
   at TemplateArgument.InstantiateStatelessUser<T>(...)
   at TemplateArgument.InstantiateAccessibleProcessor(43, ...)
   at ModelTracer.JoinExecutor(String[] first)
   at StatelessModel.SearchAdapter(String[] info)
```

已经排除的：

| 假设 | 验证 | 结论 |
|---|---|---|
| 类型被改名/丢了 | `ildump` 看 TypeDef | attrs=0x2103、nested=True、gpc=1，与官方**完全一致** |
| 泛型参数丢了 | `gpc=1` | 一致 |
| 嵌套关系丢了 | `nested=True` | 一致 |
| 签名里的顶层 TypeRef | `fixnested` 递归修了 476 处 | 修完仍崩 |
| 整个模块加载不了 | `ci/typediag.ps1` 遍历 4884 个类型 | **bad=0**，只有 24 个外部依赖缺失（WebView2/Newtonsoft 等） |
| 反篡改 | 官方宿主里反射调 `JoinExecutor` 也抛 `TypeInitializationException` | 是环境限制，不是我们的问题 |

**剩下的怀疑**：`URqFYq3xtmntT2OcLub\`1` 是编译器生成的 `<>c` 缓存类，
`InstantiateStatelessUser<T>` 里 `ldsfld <>9` 用的是 **FieldDef token**，
JIT 需要按**当前泛型上下文**实例化 `<>c<T>`；而这份体是从 cilantro 移植来的，
`<>c` 的泛型参数绑定可能和官方有细微差别（cilantro 的 `GeneratedType_0431\`1` vs 官方 `URqFYq3xtmntT2OcLub\`1`）。

**下一步（按可行性排序）**
1. **patch 掉排序分支**：把 0x47A–0x494 那段 `<>9__47_0` 懒初始化换成 `ldnull; stsfld`，
   排序退化为默认比较（`List<T>.Sort()` 无参重载），绕开 `<>c` 的加载。
2. **改进 jitdump 捕获泛型实例化**：现在只对 MethodDef 落盘，`InstantiateStatelessUser<int>`
   走 MethodDesc 路径没抓到。改 hook 用 `CORINFO_METHOD_INFO.ftn` 反查 MethodDesc，
   能拿到**官方那份真体**（而不是 cilantro 的），从根上消除移植差异。
3. 逐方法硬编码运行时结果（成本最高，但确定能过）。

### 10.8 本轮净收益

- **数据**：`work/final_map.tsv`（3266 条委托映射）、hostdump 的 holder.tsv + extractor.bin
- **工具**：`hostdump / initholder / injectstr / rebuild2 / stubscan / bodytrans fromlist /
  fixgen / fixnested / restub / tokcmp / resdump / xref / typediag`
- **认知**：Reactor 的初始化是"数据驱动 + 反射建委托"，静态还原必须按"导出运行时数据"的思路做，
  而不是逐条解密

---

## 11. locals 才是 AV 的根因（v32 → v39）

### 11.1 `patchsort`：先绕开 `<>c` 的 TypeLoad

v30 卡在 `TypeLoadException: Could not load type 'URqFYq3xtmntT2OcLub\`1'`。
`patchsort` 把 `InstantiateStatelessUser` 里

```
ldloc.0 ; ldfld m_ProjectDecorators ; ldsfld <>9__47_0 ; ... ; callvirt Sort(Comparison<T>)
```

整段（10 条指令）换成 `pop` —— 不排序，也就不触发编译器生成的 `<>c` 泛型缓存类加载。
TypeLoad 消失。

### 11.2 真正的大坑：5126 个方法的 locals 全是 `System.Object`

`nbjit` 的 dump 格式里 `localsTok = 0`（第 7 节已写），`nbrestore` 只能填一堆
`System.Object` 占位。**在 full trust 下 JIT 不验证 IL**，于是
`ldloc`（object）+ `ldfld`（具体字段）会按 **object 的布局**算偏移 → 直接
`AccessViolationException`，而且堆栈指向的方法名毫无规律，极难定位。

`tools2/fixlocals`（从 cilantro 按名取）修了：

```
allObjectMethods=5126  fixed=4965  locals=33847  miss=161
```

AV 位置立刻从 `GenerateAdaptableExtractor` 后退到 `DefineSetSet` —— 证明方向正确。

### 11.3 剩下 162 个：名字被 nb_slayer 改过

`DefineSetSet`（6819 指令）在 cilantro 里叫 **`generatedMethod_0288`（6866 指令）**，
签名相同（`(TemplateThread, HandlerPublisher)`），locals 92 个。

给 `bodytrans` 加了 `DstName@SrcName` 语法：

```
bodytrans cilantro v35 v37 <Type> "DefineSetSet@generatedMethod_0288"
→ [rbind] 重绑 1325 处引用
→ [trans] 移植 6866 指令
```

locals 一起搬过来，再跑 `fixgen`（127 处）+ `fixnested`（13 处）清掉假名。

### 11.4 试过但从根上封死的一条路

想从**官方 exe** 的 `MethodDef` 表读 `LocalVarSigTok`（行内偏移 14）拿最权威的 locals。
读出来是 `0x33CB0001` 这种乱值 —— 因为 **`LocalVarSigTok` 不在 MethodDef 表里，
而在方法体的 fat header 里**；NecroBit 方法 RVA=0，签名跟着体一起加密，读不到。

**结论**：locals 的唯一来源就是 cilantro（及其改名映射）。`fixlocals` 的 161 个 miss
需要逐个用 `Dst@Src` 手工对齐。

### 11.5 v37–v40：从 AV 走到普通 NRE

| 版本 | 改动 | 结果 |
|---|---|---|
| v37 | `bodytrans Dst@Src` 把 cilantro 的 `generatedMethod_0288`(6866 指令) 搬到 `DefineSetSet` | 假名清零后 AV 消失 |
| v39 | + fixgen(127) + fixnested(13) | `MissingFieldException: booleanField_0287` |
| v40 | `fixfieldidx` 按"类型内字段序号"回退，修 **121 处**残留的 nb_slayer 字段名 | **NRE @ `WrapperEnumerator.PatchCommand`** |

**这是个质变**：AV/TypeLoad/MissingField 都是"元数据层面坏了"，而 NRE 是
"某个对象为 null" —— 属于正常业务逻辑范围，可以顺着调用链补初始化。

v40 的完整栈（已经进入 `InstantiateStatelessUser` 的脚本执行第 4 层）：

```
WrapperEnumerator.PatchCommand(ConnectedObserver setup)
  TemplateThread.InstantiateSymbolicTransmitter(Boolean)
    TemplateThread.DefineSetSet(HandlerPublisher)
      TemplateThread.GenerateAdaptableExtractor(Boolean&)
        TemplateThread.PlanRunner()
          TemplateArgument.InstantiateStatelessUser<T>(...)
            TemplateArgument.InstantiateAccessibleProcessor(43, ...)
              ModelTracer.JoinExecutor(String[])
                StatelessModel.SearchAdapter(String[])
```

### 11.6 v41：又一层（`WrapperEnumerator::.ctor` 被阈值漏掉）

v40 的 NRE 在 `WrapperEnumerator.PatchCommand`：`m_ProfileWrapperList` 为 null。
`WrapperEnumerator::.ctor` 在 v40 里是 `nop;nop;nop;ret` 桩，而 cilantro 里是 6 条指令
（`new List<ConnectedObserver>()` + `stfld`）。

**为什么批量移植漏了它**：`stubscan` 的"源必须有真体"判据写的是 `> 6` 条指令，
而 6 条正是最简单的字段初始化构造函数 —— 一批 `.ctor` 因此全部漏掉。

移植后（v41）NRE 上移到 `TemplateThread.InstantiateSymbolicTransmitter` 内部。
**下一轮该做的**：把 `stubscan`/`fromlist` 的阈值从 `>6` 改成 `>4`，重跑批量移植，
把这类"6 条指令的构造函数"一次补齐。

### 11.7 本轮到 v41 的净收益

- **根因级发现**：`locals` 全 `System.Object`（5126 个方法）—— 这是之前所有 AV 的真正来源，
  而且 JIT 不验证、堆栈不可读，极难定位。修了 4965 个（33847 个 locals）。
- **6 个新工具**：`fixlocals` / `fixlocals2`（官方路线，已证伪）/ `fixfieldidx` /
  `patchsort` / `nestedchk` / `lvchk`
- **1 个语法扩展**：`bodytrans DstName@SrcName`（源方法被改名时显式映射）
- **错误层级**：`TypeLoad` → `AV` → `MissingField` → `NRE`（元数据问题基本清完）

### 11.8 v45：阈值修正后批量补 305 个

`stubscan`/`fromlist` 的源真体阈值 `>6` 改成 `>4` 后重扫：

```
total=30886 stub=1346 transplantable=422 noSrcBody=924
[fromlist] ok=305 skip=117 fail=0
```

再跑 fixgen(133 fields/127 locals) + fixnested(10/3/7) + fixfieldidx(10)。

**v45 仍然 NRE 在 `TemplateThread.InstantiateSymbolicTransmitter(Boolean)`（1060 指令），
但调用栈已经稳定在最内层**：

```
TemplateThread.InstantiateSymbolicTransmitter(Boolean)
  DefineSetSet(HandlerPublisher)
    GenerateAdaptableExtractor(Boolean&)
      PlanRunner()
        InstantiateStatelessUser<T>(...)
          InstantiateAccessibleProcessor(43, ...)
            ModelTracer.JoinExecutor(String[])
```

下一轮：在 `InstantiateSymbolicTransmitter` 里找 `ldfld` 的 null 目标（1060 条指令，
但控制流平坦化后真正的直线逻辑不多），或者继续按"缺方法体"补。

---

## 12. 两个"数据层面"的致命损坏（v46 → v49）

这一轮不再逐个补方法，而是去检查**元数据里成批的数据结构**，发现两个影响面极大的 bug。

### 12.1 重载配对：138 组重载，每组只填了第一个

`stubscan` 早就按完整 `MethodSig` 建索引（正确），但 `bodytrans fromlist` 读清单时
只拿到 `type|name`，用 `FindMethod` **按名字取第一个**匹配。

`TemplateListener` 有 3 个 `.ctor`：

```
cilantro:  0x2711C  0x2717C  0x271B8      ← 三份不同的真体
v45:       0x97528  0x64E1B  0x64E1B      ← 只有一个被填, 另两个还是同一个桩
```

修法：清单加**签名指纹**（`2:IntPtr,Int32` = 参数个数:各参数简单类型名），
`bodytrans` 按 `(type, name, sigkey)` 三元组找目标。

```diff
-T|Type|.ctor|dst=4|src=17
+T|Type|.ctor|2:SecureString,SecureString|dst=4|src=17
+T|Type|.ctor|2:IntPtr,Int32|dst=4|src=29
```

顺带修了授权桩判据：原来"目标 ≤4 条且含 `ldc.i4.1` 就跳过"，
把 76 个**被 Reactor 破坏成 `return true` 的真方法**（如 `RegSolver::Equals`，
源 53 条指令）也一起跳过了。改成"目标与源都是桩"才跳过。

### 12.2 EH 的 CatchType 有 1515 / 1721 是错的

这是本轮最重要的发现。跑 `ehstat`（新工具）统计 catch 子句的 CatchType 分布：

| 文件 | catch 总数 | 可疑 |
|---|---|---|
| 官方 `e8runnable`（只有 23 个未加密方法有体） | 23 | 0 |
| `cilantro` | 1748 | 4 |
| **我们的 v47** | 1721 | **1515** |

前两名：

```
783  CloudClient.Proxies.ExtendedProxy/<>c              <-- 不是异常类型
586  CloudClient.Networking.ClientClient/LogicalFieldClient  <-- 不是异常类型
```

`<>c` 是编译器生成的缓存类。`catch (ExtendedProxy.<>c)` **永远匹配不到任何异常**，
于是所有 `try { ... } catch { ... }` 全部失效，异常直接冒泡。

这解释了为什么前 20 轮一直"往上一层推一层"：每一层的 try/catch 都是废的。

根因在 `nbrestore.AttachEh`：它按 **28 字节** 读 clause、用 `mod.ResolveToken(cls)` 取
CatchType。JIT 的 `CORINFO_EH_CLAUSE` 是 **24 字节**，28 字节的步长让第 2 个以后的
子句全部错位；即使是第 1 个子句，`cls` 也不总是合法 token。

修法（`tools2/fixeh.cs`）：不修 dump，直接把 CatchType 从 cilantro 的同名方法按序号搬过来。

```
[fixeh] bySrc=1459 toException=56 alreadyOk=206
catch 子句总数=1721  可疑=0
```

### 12.3 locals 数量本身就是错的（2658 个方法）

`fixlocals` 原来只修"**全部** locals 都是 `System.Object`"的方法（4965 个）。
但还有一批是"真类型 + 一堆 Object 混合"：

```
GenerateAdaptableExtractor   我们的: 255 locals (240 个 Object)
                             cilantro:  14 locals
```

**locals 数量都对不上**，说明这两份 IL 不是同一份 —— nbjit dump 的体是
Reactor 平坦化后的版本（每个基本块一个临时变量），cilantro 是另一条路径还原的。

这种情况按 index 换类型是无效的，只能**整份移植**。给 `bodytrans` 加了 `localsdiff` 模式：

```
[localsdiff] ok=2658  srcMissing=159  sameCount=112
```

### 12.4 版本推进

| 版本 | 改动 | 结果 |
|---|---|---|
| v46 | 签名配对重跑全链（漏了 `DefineSetSet` 手工移植） | AV @ `DefineSetSet`（退步） |
| v47 | 补回 `DefineSetSet@generatedMethod_0288` | `FileNotFoundException: bandwidth.xml`（**业务错误**） |
| v48 | `fixeh` 修 1515 个 catch 类型 | `InvalidCastException: VirtualInitializer → ProgramFinder`，`exit_code=4` |
| v49 | `localsdiff` 换 2658 个方法的体 | 待验证 |

v48 的 `exit_code = 4` 值得单独说：这是**程序自己返回的退出码**，不是 `-1073741819`（AV）
也不是 `-532462766`（未处理异常）。也就是说程序已经能正常启动、解析命令行、走完初始化、
输出错误信息、然后正常退出。剩下的是**逻辑不对**，不是**跑不起来**。
