# AirExplorer 逆向恢复工程 — 交接文档

> ⚠️ **2026-10-22 第二轮接管：本文第 2、4、5、6 节的核心前提已被实证推翻，请先读
> [`docs/接管报告_第2轮_根因定位.md`](docs/接管报告_第2轮_根因定位.md)。**
>
> - `exes/AirExplorer_e8runnable.exe` = **厂商原版 v5.11.0.0**（MD5 与官网安装包一致），它在 Windows 上**能正常启动并显示 UI**（见 `docs/evidence/baseline_register_account.png`）。
> - `analysis/dep_il.txt` 与 `nb_original.exe` 落盘的方法体一致，其「死循环」实为**局部变量索引被改坏导致的非法 IL**（Mono: `Invalid IL code ... IL_09EE: add`），原版同名方法可正常执行。
> - 真正根因：Reactor 运行时依赖 `.text` 尾部 3.2MB 加密负载 + **绝对 RVA**；**任何 dnlib 全量重写**都会破坏之——「原样 resave」这个阴性对照都会崩（`InvalidProgramException`）。
> - 结论：不要再基于 `nb_original`/`dep_il.txt` 做移植；改造必须走「布局保持型」路线，或直接使用原版。
> - **`qoqxkaqoq/1` 的 v84b「终局交付」已复验：不通过**——窗口标题对，但窗体 300×300 全空白（窗口数 20→6）。见 `docs/复验_qoqxkaqoq1_v84b_不通过.md`。


> 交接时间：2026-10-22 00:31 (Asia/Shanghai)
> 状态：**卡在解密初始化死循环**，需要下一棒接手

## 1. 任务目标与验收标准

**目标**：恢复被 .NET Reactor 混淆的 AirExplorer（网盘客户端，.NET Framework WinForms 程序）到可运行状态。

**验收标准（用户明确）**：程序启动后 UI 截图中出现网盘内容（云盘文件列表等）才算成功。

## 2. 技术背景

- 原程序被 .NET Reactor 深度混淆：
  - **16586 个方法体 RVA=0**（加密存储），运行时由初始化流程解密
  - `<Module>::.cctor`（9 条指令）调用 `DispatcherInitializer::DefineEfficientProfiler()` 做解密初始化，随后调用 8 个 Start* 方法（StartLogger、StartBooleanMonitor、DelegateTimestamp 等）
  - `DefineEfficientProfiler` 是解密链核心：解密字符串表、委托数据（含 320 万元素大数组、256 块解密）、方法体
  - 状态机/反篡改特征：控制流平坦化、常量算术链（如 V_27=1752151224、V_104 加法链）、SizedTypeReference 链（2e6/1ff/163/127…）
- 早期工具链：nb_slayer（恢复 16586 方法体 → nb_original）、cilantro（反编译重建）
- CI 验证环境：Windows runner，轮询 probe（记录进程存活/窗口句柄/崩溃），产物从 artifacts 下载

## 3. 已完成工作与产物

| 产物 | 说明 |
|---|---|
| `exes/AirExplorer_nb_original.exe` | nb_slayer 恢复方法体版，运行时链保留（**本机测无 UI**） |
| `exes/AirExplorer_e8runnable.exe` | 早期可运行候选（**无 UI**） |
| `exes/AirExplorer_hybrid.exe` | 混合版（**无 UI**） |
| `exes/AirExplorer_cilantro.exe` | cilantro 版；DefineEfficientProfiler 被简化为 `ret`，cctor 还调 `<Module>::m8DEEBCC2CD9F727()`（也是空 ret）（**无 UI**） |
| `exes/AirExplorer_Slayed.exe` | nb_slayer 输出中间版 |
| `exes/AirExplorer_fixed_v126.exe` | 最新修复版（fix3）：ciphertext 核验 57/57 通过、委托数据与原版字节一致（**CI 与本机均无 UI**） |
| `exes/AirExplorer_skip_decrypt.exe` | 实验版：DefineEfficientProfiler 整体替换为 `ret`（跳过解密）（**无 UI** → 证明解密初始化必需） |
| `analysis/dep_il.txt` | **DefineEfficientProfiler 9992 指令全量 IL 导出**（含 switch 表、EH 表）——本轮分析的核心材料 |
| `tools/` | 60+ dnlib 分析/移植工具源码（.NET 8 console，NuGet: dnlib 3.3.4） |

## 4. 核心谜题：DefineEfficientProfiler 死循环（铁证）

`DefineEfficientProfiler`（9992 指令、105 局部变量、9 EH）是 625-case 的 switch 状态机。**离线模拟执行发现它在数学上必死循环**：

1. 入口：`V_72 = 530`（IL offset 0009-000E），`ldloc V_72; switch`（0012-0016）派发到 case 530（目标 09DF）
2. **V_72 全方法只在 000E 赋值一次**——之后无任何 `stloc V_72`——switch 索引永不变
3. case 530（09DF）的代码块：
   ```
   09E0 ldsfld Boolean DispatcherInitializer::isRecommenderObserver
   09E5..09FD  V_104 += -1752150775; V_104 += -1296244883
   0A01 brtrue ->0012      ; 弹 ldsfld 的布尔，true 也回 switch
   0A06..0A1E  V_104 += -455906055; V_104 += 601675341
   0A22 br ->0012          ; false 也回 switch
   ```
   → 无论 isRecommenderObserver 真假，都回到 `switch(V_72=530)` → **回到 case 530 → 死循环**
4. 唯一写 `isRecommenderObserver=true` 的代码在 641C（另一 case 的块）——**永远执行不到**
5. switch 表 625 项**全部唯一**（无重复目标，排除表损坏）
6. `V_27 = 1752151224` 是死代码（赋值后从未使用）——反篡改污染特征

**推论**：这个 9992 指令体（来自运行时 JIT hook dump，即 jitdump）是 **Reactor 反篡改陷阱版**——dump 时刻反篡改已触发，真实初始化逻辑被替换成了死循环陷阱。**真正的 DefineEfficientProfiler 逻辑不在这个体里**。

## 5. 已排除路线

- ❌ 直接跑半解密版本（nb_original/e8runnable/hybrid/cilantro/Slayed）——用户本机全部无 UI
- ❌ 跳过初始化（skip_decrypt）——程序后续解密全失败，无 UI
- ❌ 按死循环体移植（fix1-3）——cctor 卡死（CI 单步 probe：900 万+步不返回，StartLogger 从不执行）
- ❌ switch 表恢复/对齐补丁（v108）——表本身无损坏（625 项全唯一）

## 6. 下一步建议（按优先级）

1. **从加密区直接恢复真正的 DefineEfficientProfiler 体**
   - nb_original 里该方法壳存在但 RVA=0——真实体在加密数据区（附加 section / 资源）
   - 需要 Reactor 解密算法：研究 de4dot 的 Reactor 模块、reactor-unpacker、以及该样本对应 Reactor 版本的 key 旋转/元数据布局
   - 密钥/元数据线索：V_104 加法链常量、SizedTypeReference 链、cctor 常量 530（初始状态）
2. **重新运行时 dump（避免反篡改触发）**
   - 在 cctor 执行**前**hook JIT/dump 全托管内存镜像
   - 或用 dnSpy/windbg 调试原版，在 DefineEfficientProfiler 首指令断点 dump IL
   - 注意：反篡改可能检测调试器/钩子——需要隐蔽 hook（硬件断点、页保护等）
3. **验证死循环结论**：用 `analysis/dep_il.txt` 写个模拟器复现（入口 case 530）
4. **备选**：cilantro 路线（空初始化）+ 手工补字符串/资源/委托解密——工作量大但可控：缺失数据会在运行时以异常形式暴露，逐项补齐
5. 参考 `docs/修复轨迹_v126.txt` 了解全部 126 轮 CI 验证历史与每轮结论

## 7. 工具清单（tools/，.NET 8 + dnlib 3.3.4）

- `dumpmeth` — 按类型名/方法名导出方法 IL
- `dumpfull` — 全量 IL 导出（含 switch 表、EH 表）→ 生成 dep_il.txt 的工具
- `bodytrans` — 方法体移植/stub 替换（fix 版生成工具；stub 模式可把方法替换为最小桩）
- `analyze` / `maxchk` / `entrychk` — 统计、入口点、maxstack 检查
- 其余 50+ 工具各有单一用途，源码即文档

## 8. 关键方法定义（供检索）

- `CloudClient.Templating.DispatcherInitializer::DefineEfficientProfiler()` — 解密初始化（Void）
- `DispatcherInitializer::StartBooleanMonitor(LoggerValueAllocator)` — cctor 第二调用
- `DispatcherInitializer::DelegateTimestamp(ProfilerErrorBrowser)` — 320 万元素数组初始化
- `<Module>::m8DEEBCC2CD9F727()` — cilantro 版 cctor 的第二调用
- Main 入口 token：06002D22 `StatelessModel::SearchAdapter(String[])`（所有版本一致）

## 9. ⛔ 假货警示：v84b（2026-10-22 已全部删除，禁止再引用/交付）

曾有 v84b「终局交付」（NecroBit 脱壳版）被多个 agent 当作成果反复交付，业主已要求从本仓库全部删除（3 个 exe、证据截图/日志、复验文档）。

复验结论（权威记录，勿再翻案）：

- 进程存活、窗口标题正确（`Air Explorer v5.11.0`），但主窗口是 **300×300 纯空白窗体**：无工具栏、无账号树、无文件列表；窗口总数 20（原版）→ 6（v84b），控件树塌陷
- 按验收标准（主窗口 UI、网盘内容可见）判定**不通过**；"v84b PASS" 的说法仅基于窗口标题，属**假阳性验收**
- 技术遗留价值：v84b 方法体恢复率高（空壳桩 110 vs 原版 5808，ldstr 2099），NecroBit 脱壳本身可行，卡点在 **UI 构建链未恢复**——后续应从"恢复 UI 构建链"方向切入，而不是重交 v84b 或重跑同路线


## 14. v59 → ANE 因果链（2026-10-22 深夜，清言接力诊断）

**现状**：v59 文本模式 CI=PASS（16/16 exit 0）。UI Probe（首次真正探测 v59）：
主窗体已创建（Air Explorer v5.11.0 hwnd 存在不可见），初始化线程抛
`ArgumentNullException @ GenerateAdaptableExtractor` → 进程 0xe0434352 崩溃。

**完整因果链（已闭环）**：
1. `TemplateThread::GenerateAdaptableExtractor` IL_0498 `List::AddRange(V_13)`
2. `V_13 = InstantiateConfigurableModule(V_4, false)`（06004527）
3. 该方法开头：`if (_TemplateConfig?.m_ProjectDecorators == null) return null`（IL_000B-0011）
4. **`m_ProjectDecorators` 全模块唯一写入点 = `TemplateArgument::InstantiateStatelessUser` IL_045E**（914 指令 JIT 收割真体）：
   `m_ProjectDecorators = new List<>(V_12)`，位于解释器状态机循环后段
5. UI 路径没有跑到该写入点 → 列表保持 null → AddRange(null) → **ArgumentNullException("collection")**

**已排除**（勿重查）：
- token/引用错位：官方 55781 vs v59 57872 全量指纹对账，仅 1 处嵌套类歧义，IL 引用类 100% 齐
- 资源表/Main IL：官方与 v59 完全一致
- 委托三连（146 处）：target 均来自 cctor 初始化的 `<>9`（newobj 桩 ctor 仍返回非 null 实例，无害）
- `a13Nrt3eN4sDIpSxIRj` 之谜：它只是个 byte enum（0200065A），12.5 的怀疑解除

**下一步（唯一有希望方向）**：
解释器状态机为何 UI 分支没走到 IL_045E。两条路：
a) 官方宿主 hostdump 反射导出官方运行时的 `m_ProjectDecorators` 内容（类型+顺序+条数），
   对照 v59 判断"该有但没写"还是"顺序/分支不同"（同 12.4 拿字符串表的方法）
b) 给 v59 的 InstantiateStatelessUser 关键状态点插 trace（Console.Error），CI 直接启动跑 UI 路径

**新工具**（tools/）：
- `tokmap8` <exe> <out.tsv>：全量 token→签名指纹映射（对账基准）
- `cctorfix8` <exe> dump|scan|meth|fldref|fix：委托三连扫描/精确 IL/字段引用查找
- `uiscan8` <exe> [out.tsv]：92 个窗体类覆盖统计（v59 桩 1444→20）

**host v2**（tools/ci/host.cs，CI 自动重编译）：异常落盘 host_trace.txt +
ThreadException + COMPlus_JitNoInline=1。注意：宿主 Assembly.LoadFrom 会绕过
native stub → `<Module>` cctor 链在宿主里必炸 InvalidProgramException
（VerifyCombinedStateRequest）——宿主路线只适用于数据导出，不适用于整程序运行。

**work/ 数据资产（本轮固化，直接复用）**：
- `tokmap_official.tsv.gz` / `tokmap_v59.tsv.gz`：两版全量 token→签名指纹映射（解压后对账，tokmap8 可重新生成）
- `ui_official.tsv` / `ui_v59.tsv`：92 窗体类方法覆盖明细（uiscan8）
- `gae_full.txt`：GenerateAdaptableExtractor 491 指令完整 IL（不截断）——ANE 因果链证据
- `isu_full.txt`：InstantiateStatelessUser 914 指令完整 IL——m_ProjectDecorators 唯一写入点在 IL_045E
- `ydh81.txt` / `tt_full.txt`：委托三连相关类完整 IL
