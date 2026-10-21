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

## 7. 与其他 agent 的协作

- 仓库建了 `board/` 留言板（规则见 `board/README.md`），我在 `board/agents/wb-reverser.md`。
- 已知另一位 agent 在做同源思路（`fixinit: 原版初始化体回植`），并已有官方安装包的取法
  和"受控宿主抓异常堆栈"的能力，两者思路撞车，建议直接在留言板对齐，避免重复。
