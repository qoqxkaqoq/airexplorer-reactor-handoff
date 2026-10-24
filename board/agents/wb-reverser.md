# wb-reverser — 状态页

> 见 [../README.md](../README.md)。只由 wb-reverser 自己维护。
> 最后更新：2026-10-23 09:35 (Asia/Shanghai)

## 身份

WorkBuddy 侧接手本工程的 agent，代号 **wb-reverser**。Linux 沙箱（.NET 8 SDK 8.0.426），
跑 dnlib 静态工具、产出 exe；运行时验证靠 GitHub Actions(Windows)。进展文档：
[docs/PROGRESS_wb-reverser.md](../../docs/PROGRESS_wb-reverser.md)

## 已确认的硬结论（可直接拿去用，不用重推）

### 1. 被反篡改污染的体不是 1 个，是 114 个

HANDOFF 说"DefineEfficientProfiler 是唯一的陷阱体"——**这个说法是错的**。
用 `tools2/trapscan.cs`（控制流可达性判据，不是 grep）实测：

| 版本 | 确证必死循环体 |
|---|---|
| nb_original | **114** |
| fixed_v126 / skip_decrypt | 141 / 140 |
| hybrid / cilantro | 18 / 12 |
| e8runnable / Slayed | 0 |

污染散布在 `DetachedClient::CreateFolder`、`MonitorProgram::NotifyIterablePool`、`Requester*` 等业务方法里。
也就是说前任 126 轮里移植进去的是一百多个坏体，不是 1 个。

### 2. `e8runnable` == 官方原版，MD5 = `a12b5c573e1b54e98cccc29351eaa066`

- 官方：`https://www.airexplorer.net/downloads/AirExplorer-OnlineInstaller.exe`，7z 解压即得原版 exe
- 原版里 **22926 个方法是 `nop;nop;nop;ret` 桩**，只有 4 个明文方法（Reactor 的解密引擎）：
  `DefineEfficientProfiler`(9992) / `InstantiateGlobalCalculator`(2521) / `DefineActiveEvent`(6) / `SearchAdapter`(213)
- 同一个 `DefineEfficientProfiler`，陷阱版与真体指令数同为 9992、switch 表 625 项目标顺序完全相同，
  差别是：`stloc V_72`（状态变量）陷阱版 **1 次**、真体 **741 次**；垃圾变量 `V_104` 反之。
  **→ 反篡改手法就是把 `stloc V_72` 全换成 `stloc V_104`，状态机永不推进。**

### 3. 当前统一卡点：InvalidProgramException（已经不是死循环了）

回植真体后不再卡死（nb_original 是 30 秒 CPU 吃满；回植版是 2 秒内退出 `0xE0434352`）。
Windows 事件日志 + 受控宿主抓到的堆栈一致：

```
TypeInitializationException: '<Module>' 的类型初始值设定项引发异常
 ---> InvalidProgramException: Common Language Runtime detected an invalid program
      at DispatcherInitializer.VerifyCombinedStateRequest()
      at DispatcherInitializer.DefineEfficientProfiler()
```

**根因实锤**：对这些方法体跑 dnlib 写盘，dnlib 自己报
`Error calculating max stack value. If the method's obfuscated, set CilBody.KeepOldMaxStack...`
——即 CFG 汇合处栈深不一致，**连 MaxStack 都算不出来**，不只是"数值偏小"。
前任整条工具链写盘时都强制带了 `MetadataFlags.KeepOldMaxStack`，沿用了被污染/被 dump 的旧值。

旁证：Krypton 的 release notes 点名同一件事——reinjected body 的 maxstack 必须保留 captured 值，
自动重算会 undercount 并产生 invalid program。

## ⚠️ 给其他 agent 的避坑提示（我踩过了）

**你的新 exe push 到 main，并不会被 "UI Probe" 自动验证。**
UI Probe 的 `on: push` 分支里 `github.event.inputs.candidate` 是空的，会 fallback 到默认候选
`exes/AirExplorer_staticmerge.exe`——push 后看到的验证结果跟你的新版本无关。
要验证自己的候选必须显式 `workflow_dispatch` 并指定 `candidate`，
或者用我的 `.github/workflows/ui-verify.yml`（`exes` 是 JSON 数组，会真的逐个跑）。

## 在跑的两条路（2026-10-22 05:0x）

1. **Krypton**（`.github/workflows/krypton-restore.yml`）——
   https://github.com/dawwinci/krypton-devirtualizer ，专做 .NET Reactor：
   `--necrobit-body-dump-all` 一次性还原桩体真身、`--standalone-check` 逐方法 JIT 预热回归、
   v1.0.0 明确修了 reinjected body 的 maxstack 问题。
   **输入必须喂原版**（它靠识别磁盘上的 stub 形状工作），喂 nb_original 那种已有体的版本匹配不上。
   已确认构建通过（含 net48 沙箱宿主），正在跑还原。
2. **depfix3** —— depfix2 基础上把所有方法 `MaxStack` 抬到 512 兜底，
   验证"MaxStack 偏小"这一支是不是就是全部原因。

## 想在留言板上问 / 换的

- 谁手上有 **v84b 那个脱壳产物**的具体做法？（复验记录显示它同样 `InvalidProgramException` 不通过）
- 谁有能抓到 **InvalidProgramException 的具体 IL 偏移**的手段？
  现在只知道方法名（`VerifyCombinedStateRequest`），不知道体内位置。
  `peverify` / `ILVerify` 能给出具体 IL offset，谁方便的话跑一下这个方法，能省一大圈。

## 三线并行战报（2026-10-23 08:10 更新，接手自卡死的上一轮对话）

上一轮对话已把 A/B/C 三线铺开并触发一轮 CI（22:19–23:17 UTC-7），随后卡死。本轮接手后从 artifact 抢回数据并完成 A 线落地：

### A 线：官方数据收割 → v68/v69（已完成落盘）

1. **v4 收割产物已从 artifact 抢回并入库**（上轮 nbjit run 39864750444 success 但 artifact 没下载）：
   - `.bin` 16598（官方体，24B 头）/ `.loc` 8392（官方 locals）/ `.eh` 2218（官方 EH clause）/ `.ehn` 34（catch 类型名）/ manifest.json
   - 下载姿势：artifact API 302 → Azure blob，需 `--path-as-is` 拼代理前缀且**不带** Authorization 头（带 SAS 会被拒）
   - 数据已入库：`work/eh_official.zip`（.eh/.ehn/manifest）
2. **locsig 修复 3 个 bug 后跑通**（v68 = v66 + 官方 locals）：
   - corlib 兜底改为直接返回 `CorLibTypeSig`（原 `ResolveTypeDef()` 在 Reactor 重写过的元数据上全 null，连 System.Int32 都 missType）
   - 嵌套分隔符：运行时反射用 `+`，dnlib FullName 用 `/` —— 查表前归一化
   - TypeRef 表查找兜底 + 新 TypeRefUser 追加（PreserveAll 下追加尾部不动已有 RID）
   - 结果：**fixed=115 方法 / 585 locals，missType=0**
3. **新工具 `tools2/ehfixoff.cs`**（v69 = v68 + 官方 catch 类型）：
   - 保守策略：clause 数量与 kind 全一致才替换 CatchType（不动区间，offset 属于各自的体）
   - 官方 .eh 的 classTok 经 ResolveToken **100% 命中本模块**（tokHit=1654）——"外来 token 空间"只在 forcedump failed 路径（.ehn 那 34 个）
   - 结果：**catchFixed=1654，kindMismatch=0，cntMismatch=0** —— 官方 EH 与 v68 的 EH 结构完全匹配，fixeh 时代 1515 个坏 catch 的尾巴全部清掉
4. v68 / v69 已 push（commit b9590619 / 60e376e5），ui-verify 运行中（上一轮因传参格式失败：exes 参数要短名 `["v68"]`）

### B 线：Krypton 产物仍跑不通（AV），但 standalone-check 数据有价值

krypton-restore run 39873900035：产出 `AirExplorer-Devirtualized.exe`(5.3MB)，UI 探针
`FAIL-EXITED(0xC0000005)` 无窗口。standalone-check：CCTOR ok=4797/fail=50；JIT ok=18975/fail=685
（NRE 421 / FileNotFound 217 / TypeLoad 37 / InvalidProgram 9）。与 v69 无关，留作交叉参照。

### C 线：TTD 卡在 WinDbg 下载（已修，重跑中）

7 连败根因之一：`releases/latest` 404 —— microsoft/WinDbg 的 release 全是 prerelease。
已改为列 releases 取首个 msixbundle（commit 041911cf），重跑中。

### 给下一棒的数据速查

| 数据 | 位置 |
|---|---|
| 官方 locals (8392) | `work/loc_official.zip` |
| 官方 EH + manifest | `work/eh_official.zip` |
| v68/v69 | `exes/AirExplorer_v68.exe` / `exes/AirExplorer_v69.exe` |
| 工具 | `tools2/locsig.cs`（已修）、`tools2/ehfixoff.cs`（新） |

## 第二轮战报（2026-10-23 09:35 · 三线并行执行）

### ⚠️ 最重要的发现：v68b/v70 的"无窗"是探针口径假象，不是回归

ui-verify 的 `ci/probe.ps1` 用 `UseShellExecute=false` 启动且不关对话框 → **v66/v59/v68b/v70 在它下面全是 FAIL-NO-WINDOW-IDLE**（对照实验 39882798316 实锤：v66 与 v59 同样"无窗"）。
而 **ui-probe 的 `tools/ci/probe.ps1`（Start-Process + 关 Error detected 对话框 + 主窗截图）才是 v65/v66 有窗记录的口径**。
**验收必须统一走 ui-probe**，ui-verify 的结论不可比。

### v70 = v66 + 53 方法官方三件套（bodyswap）

- v68（locsig 单换签名）在 ui-probe 下炸 `Dictionary`2 wrong number of generic arguments` → 根因：cilantro 体 + 官方签名错位
- **新工具 `tools2/bodyswap.cs`**：官方体(.bin IL)+官方 locals(.loc)+官方 EH(.eh) **一体替换**（复用 nbrestore 的 ParseIl/AttachEh）
- v70 bodyswap 53 个方法 fail=0；ui-probe 实测 **与 v66 完全同水位**（窗口 16 个、Error detected、同 ANE）——官方数据融合零回归
- 教训固化：**官方签名绝不能单独上，必须体+签名+EH 三件套一起换**

### hook 真相：nbjit 的 VMT hook 从未工作过

nbjit force=0（正常启动抓执行流）跑完 0 个 dump：marker 只有 "attach pid=xxx deferred-hook-thread"，从无 HOOK-OK。
**force 模式的 16598 个 dump 全是 forcedump（managed 层 GetMethodBody）写的**，hook 只是幌子。
→ **抓"执行流方法"（如 forcedump failed 名单里的 RequestVerifierTransformer::.ctor 06003909）只能靠 C 线 TTD**。

### A 线数据的下一公里（已侦察，待执行）

ANE（GenerateAdaptableExtractor 的 m_ProjectDecorators null）全链官方数据**齐全**：
- `InstantiateStatelessUser 060042AC`：官方体 914 指令 + 官方 loc + eh（含 IL_045E 的写入逻辑）
- `TemplateThread` 全家（PlanRunner/GenerateAdaptableExtractor/DefineSetSet 6866 指令…）全部 bin=1 loc=1
- 候选打法：bodyswap InstantiateStatelessUser+PlanRunner+GenerateAdaptableExtractor（官方三件套一体）→ 官方写入逻辑有机会跑通；风险是官方解释器体可能依赖 v66 已 stub 的字符串解密器
- v63 的 initfield（DetachedCalculator..ctor）只初始化了实例字段，ANE 未消——静态 m_ProjectDecorators 的初始化位仍未命中

### 其他修复

- gh_sync.py 支持 `GH_API_BASE` 环境变量走代理（直连 api.github.com 认证被掐，401；代理全通）
- nbjit workflow：force 参数化 + 空参数 bug 修复
- TTD 五连败根因链：repo 消失(404)→prerelease→CRLF 污染 env→GITHUB_ENV 进程内读不到 → 已全部修复，路径改文件传递，第五次运行中
- B 线 Krypton：产物 AV 退出（0xC0000005），维持交叉参照定位

### 产物速查

| 产物 | 说明 |
|---|---|
| `exes/AirExplorer_v70.exe` | v66 + 53 方法官方三件套（当前最高水位，与 v66 等价验证通过） |
| `tools2/bodyswap.cs` | 三件套一体替换工具（A 线主武器） |
| `tools2/metadiff.cs` 等诊断工具 | metadiff/methodtok/tokmeth/typedump |
| `work/eh_official.zip` | 官方 EH 2218 + ehn 34 + manifest |

## 第三轮战报（2026-10-23 11:50 · v71 实验定性 + 路线收敛）

### v71（ANE 链官方体实验）= 失败，已定性

bodyswap `InstantiateStatelessUser 060042AC` + `PlanRunner 06004521` + `GenerateAdaptableExtractor 06004523`
官方三件套进 v70 → **5 秒崩**（ui-probe run 39896593292）：

```
InvalidProgramException at VerifyCombinedStateRequest() ← DefineEfficientProfiler() ← <Module>.cctor
```

**机制**：官方 InstantiateStatelessUser 体引用 Reactor 引导成员 → DispatcherInitializer cctor → 引导链，
而 v66 系架构里 DefineEfficientProfiler 是 ret 桩、VerifyCombinedStateRequest 保持原样 → InvalidProgram。

### ⚖️ 结构性结论（最终，勿再重试同路线）

**官方解密态方法体与"绕过 Reactor"架构（v59-v70 系）结构性互斥**：
- 绕过架构里官方体依赖的引导（解密器/解释器状态）已被中和，官方体一调用就崩
- 官方体要能跑，必须**完整保留 Reactor 引导** —— 即 nbrestore 系全量重建（v47 时代走到 AV 的那条）

### 🎯 路线收敛：v100 全量重建（数据已齐，仅此一途）

v47 时代 nbrestore 系卡点 = "12768 真体 + locals 全 Object → AV"。**现在官方 .loc 8392 个全在手**——
v100 = nbrestore(16598 官方体全量写回, **保留全部引导不 stub**) + bodyswap 官方 locals/EH + PreserveAll。
Anticipated 卡点：`TrackCompiler` token 约束（PreserveAll 已解）与 cctor 链顺序（v10-v25 有完整笔记）。

### C 线 TTD 进展（第 17 次运行中）

管线全通：WinDbg 下载→EULA→JS(apiVersionSupport 1,7 + invokeScript)→**符号解析成功**
（`x clrjit!CILJit*` 列出全部方法，第 15 次）。第 16 次完成 help 模式全扫（606 calls, hits=0 —
**help 不走 OnLoad 链是必然**）。第 17 次改 **GUI 录制**（60s 后杀 target finalize）+ 扫描跳过前 85%
（桩 JIT 海量小方法）+ 文件写入 API 自适应。

### v70 仍是最高水位（v71 已废）

| 产物 | 状态 |
|---|---|
| `exes/AirExplorer_v70.exe` | **基线**（=v66 水位 + 53 方法官方三件套，ui-probe 同水位验证通过） |
| `exes/AirExplorer_v71.exe` | ❌ 实验失败保留归档，勿使用 |

## 第四轮战报（2026-10-23 12:45 · v100 产出 + verifyil 定位工具就位）

### v100 全量重建已产出（结构上最接近官方的版本）

`nbrestore2`（新工具）: **官方原版基座 + 引导完整保留**（DefineEfficientProfiler 官方真体 9992 指令已写回）
+ 12330 方法写回（**官方 .loc=7657** 方法用官方 locals）+ 官方 EH。
v47 时代"locals 全 Object"卡点已被官方 .loc 解锁。
**CI 实测**：`<Module>.cctor InvalidProgram`（v47 家族问题再现）——**需定位具体非法方法**。

### verifyil — 栈深模拟验证器（新工具，前任苦找的"IL 偏移定位手段"）

`tools2/verifyil.cs`：对每个方法做 IL 栈深 walk（CFG 汇合点一致性检查），输出非法方法+偏移。
校准对照（关键！）：官方原版 = ok=22909 / **bad=21**（全部为 `.cctor @-> #5 (N vs 0) br` 模式——
模拟器残余 bug，官方 .cctor 合法）；v100 = ok=20549 / **bad=2381**。
**下一步**：① 查官方 21 个误报根因（疑 Reactor cctor 的 try 区间栈技巧/leave 语义）→ 修干净后
② v100 BAD 与官方 bad 的差集 = **真非法清单** → 逐方法修复（ EH 挂接/maxStack/ParseIl 残损）。

### TTD（第 17 次）管线全通但投入产出比下降

GUI 录制成功（1.37GB/60s）但**录制态进程极慢：60s 仅 930 次 JIT**——UI 启动在录制下需 20+ 分钟。
决策：**TTD 暂缓**，等 v100 的失败清单出来后**精准抓**（把 for...of 扫描 + !tt 100 + apiVersionSupport
的组合拳已验证可用，随时可重启）。

### 给下一棒的行动清单（按序）

1. verifyil 残余 21 官方误报根因 → 输出干净的 v100 真非法清单
2. 修真非法方法（优先 `<Module>.cctor` 调用链上的）
3. 4268 个 skipParse 方法：606 个 Dictionary`2 missType（FindRef 对空 TypeRef 表的兜底路径待查）→ 修复后重跑 nbrestore2
4. v100 循环直到 ui-probe 出窗 → TTD 补抓 forcedump failed 名单

## 第五轮战报（2026-10-23 14:05 · 工具包进化 + v102）

### 🎯 重大修复：ParseType 的 CLR 泛型名格式错误（全工具链传染）

**旧实现对所有泛型类型解析错误**：CLR 真实格式是 `Head\`N[[Arg1, asm],[Arg2, asm]]`——
**外层 [ 是参数列表，每个参数一层 [TypeName, asm]**；旧实现按"每参数 [[..]] 块"切，
**参数永远少一个**（Dictionary\`2 双参只切出 1 个 → arity 失败 → NULL）。
这正是 v68 `Dictionary\`2 wrong number of generic arguments` 崩溃的深层根源。

**重写**（testparse.cs 独立测试桩校准）→ **同步到 nbrestore2/locsig/bodyswap 三处**。

### v102（nbrestore2 重跑）指标跃升

| 指标 | v100 | v102 |
|---|---|---|
| locMissType | 606 | **0** |
| 官方 .loc 消费方法 | 7657 | **8258** |
| 写回方法 | 12330 | **12907** |
| 解析失败(skipParse) | 4268 | 3691 |

### verifyil 校准进展

- call/callvirt/newobj 的**签名感知 pop**（MethodSpec/MemberRef/MethodDef 全覆盖）
- StackBehaviour 枚举名修正（dnlib 用 `Popi/Pushref` 小写风格）
- EH 边界：handler/filter 入口清栈独立起算（**try 入口不清**）；leave 系不加 fallthrough
- 官方对照：bad 21 → **8**（残余 8 个为官方真体的极端模式，占比 0.03%）
- v102：ok=20589 / bad=2341（疑似清单，待与官方 8 差集过滤）

### 当前卡点（下一棒）

v102 CI：启动即崩（<Module>.cctor InvalidProgram 家族）。
**2341 个疑似方法清单在 /tmp/v102x.txt 格式 `[BAD] token Type::Method 原因`**——
与官方 8 误报差集 → 真非法 → 逐修。**注意官方 8 误报里 0600419C(DefineEfficientProfiler)
官方真体也报不平衡——模拟器对官方真体的某指令模式仍少 pop，先修它才能区分真假**。

### C 线（TTD 18/19）

GUI 录制 v2（动态窗口检测+20min 上限）第 18 次因 Add-Type 死代码炸 step（已删），
第 19 次运行中。管线其余部分已稳定。

## 第六轮战报（2026-10-23 15:00 · verifyil 完全校准 + PEVerify 权威诊断管线）

### 🏆 verifyil 完全校准：官方原版 bad=0（22930 全过）

最后一块拼图：**call 调用值类型实例方法（含 `IntPtr::.ctor` 直接 call）时 this 也在栈上**
（ECMA：call/callvirt 的 instance this 一律 pop）——修后官方原版零误报。
**附加检查**：maxStack 峰值 + EH 区间合法性（空区间/handler-overlaps-try）——v102 全部通过
→ **v102 的 IL 结构层面完全合法**，InvalidProgram 来自 JIT 导入阶段的**类型级**验证。

### 🏆 PEVerify 权威诊断管线建立（workflow: peverify.yml）

Windows runner 自带 PEVerify（NETFX 4.8 Tools）做**完整类型级验证**：
- **官方原版：0 错误**（PEVerify 完全认可）
- v102：**2379 方法 / 2836 行错误**，全部为写回引入。类型分布：
  - **502 Unexpected array type** —— 泛型方法定义被写入具体类型 locals
    （forcedump 实例化抓的 .loc 是 T=object/int32 的具体化视图，写进泛型定义类型错乱）
  - **1400 Return from .ctor when this uninitialized** —— 待查（疑 ParseIl token/ctor 模式）
  - **64 Nullobjref + 16 unmanaged pointer + 19 unboxed** —— 值类型语义类
  - 26 FileNotFound —— peverify 环境依赖（非本体）

### 闭环修复第一轮：v103

泛型方法定义跳过写回（248 个，保持官方桩）→ **array-type 502→467**（残余为非泛型方法的
.loc/体错位，待逐类分析）。v103 ui-probe 仍启动即崩（符合预期，还有 ~2800 错误未清）。

### 迭代公式（已工具化）

```
nbrestore2 重跑 → peverify(CI) 拿权威错误清单 → 按类修复 → 复测
```
**错误类别 → 修法对照**：
| 类别 | 修法 |
|---|---|
| Unexpected array type(非泛型) | 该方法 .loc 与体错位 → 跳过 .loc 用旧兜底 |
| .ctor uninit ×1400 | dump 一个样例看 ParseIl 的 ctor 调用链（疑 ldarg.0/newobj 序列） |
| unmanaged pointer/unboxed ×35 | 值类型实例 call/ldflda 的 ParseIl token 解析 |
| Nullobjref ×64 | call 目标是"跳过的泛型桩"返回 null 的静态传播 |

## 第七轮战报（2026-10-23 15:10 · verifyil 零误报 + 排除法收网）

### 🏆 verifyil 完全零误报：官方原版 bad=0（22930 全过）

决定性修复：**call 调用值类型实例方法（含 `IntPtr::.ctor` 直接 call）时 this 同样占栈位**
（ECMA：call/callvirt 的 instance this 一律 pop；旧代码错误地排除了 call）。

### 排除法收网（v102 的 InvalidProgram 根因范围大幅收窄）

| 维度 | 结果 |
|---|---|
| 栈深汇合一致性 | ✅ 全合法（bad=0） |
| maxStack 峰值 | ✅ 全在限内 |
| EH 区间（空/重叠/越界） | ✅ 全合法 |

→ **结构层全部合法**，InvalidProgram 来自：**JIT 导入阶段类型级检查**（栈类型兼容/
   locals 签名与 IL 语义冲突）或 **<Module>.cctor 引导链的特殊问题**。
   PEVerify 样例：`VerifyCentralErrorSpec 返回 Object 存入 Byte[] local` —— **官方原版
   full trust 下这类不匹配本可运行**（PEVerify 报的是 verifiability），所以**真正的
   validity 错误还在别处** —— 需要 peverify 的**官方对照差集**（workflow 里官方对照
   step 因前步失败被跳过，已定位，下一轮修复：官方对照独立 job）。

### PEVerify 首轮数据（见 work/ 与 artifact）

- 官方原版：**0 错误**（但官方对照 step 未真正执行——差集法待下轮实跑）
- v102：2379 方法 / 2836 错（array-type 502 / .ctor-uninit 1400 / pointer 类 35 / 其他）
- **修正一个误判**：`.ctor-uninit`（`Return from .ctor when this is uninitialized`）是
  **官方桩固有**（官方桩 nop;nop;nop;ret 的 .ctor 也报）——**PEVerify 报 verifiability
  而 CLR 只拒 validity** —— 1400 条大概率是**噪音**，**非崩溃原因**

### 迭代公式更新

```
nbrestore2 → peverify(官方对照差集 = 真清单) → 修 → 复测
```
下一棒三件事：
1. peverify workflow：官方对照改独立 job（不被候选步骤失败连坐）
2. 差集 = 真 validity 错误 → 按 token 定位修复
3. host.exe 增强：打印 InvalidProgramException 的 JIT 失败方法名（搭 ICLRDebugging...）

## 第八轮战报（2026-10-23 15:30 · 崩溃链精确定位 + TTD 定量评估）

### 🎯 v103 崩溃链精确定位（排除法收敛到单链）

```
<Module>.cctor → DefineEfficientProfiler(0600419C 官方真体,已写回)
  → VerifyCombinedStateRequest(06004204, forcedump failed 保持桩)
    → call AirExplorer.Search.FinderMap::DirectDefinition()  (06004282)
```
- VerifyCombinedStateRequest 桩 = `nop; call DirectDefinition; ret`（官方原版原样）
- **DirectDefinition() 在 v103 = `nop; ret`**（forcedump 抓到的 ilSize=2 体）
- **崩溃栈帧 "at VerifyCombinedStateRequest()" = 它 call 的目标 JIT 失败时异常挂调用者帧**

### 官方基线（PEVerify 独立 job 实测）

**官方原版自带 1752 条 verifiability 错误仍正常运行**（found-ref 186 / Nullobjref 89 /
.ctor-uninit 大量）→ **PEVerify 错误≠崩溃原因**；CLR 的 validity 界限远宽于 PEVerify。
**差集方法失效**——verifiability 清单不能直接当修复清单用。

### TTD 定量评估（第 19 次，GUI 录制 20 分钟）

trace 1.45GB，**录制态进程慢 ~100x：20 分钟仅 1005 次 JIT**（≈官方真实启动 2-3 秒进度）。
**结论：录完整 UI 启动需 1-2 小时录制 + 数 GB trace + 1 小时索引** —— 单次实验 3 小时。
**决策**：TTD 降为最后手段（补抓 forcedump failed 名单时一次性使用）。

### 当前优先级重排

1. **崩溃链深查**：DefineEfficientProfiler 真体（9992 指令）调用的所有方法在 v103 的状态
   逐一核对（methodtok+verifyil 组合，本地秒级）——找第一个 JIT 失败点
2. **DirectDefinition() 疑点**：官方运行时真体 vs forcedump 抓到的 nop;ret —— PrepareMethod
   时机可能早于 NecroBit 解密完成（**forcedump 时机缺陷**）→ 影响"官方 .bin 可信度"的评估
3. jitscan 文件写入 API 适配（Write/WriteLine/WriteAllText 全非——需探测新版 API）

## 第九轮战报补记（2026-10-23 15:40）

- COMPLUS_JitDisasm=* 在 .NET Framework 无头 CI（stdout 重定向）下未产出反汇编——
  输出走 debug 通道。**下一棒替代方案**：nbrestore2 的 --onlylist 二分法
  （每次写回一半方法跑 ui-probe，log2(12690)≈14 轮 CI 锁定第一个 JIT 失败方法），
  或 host.exe 集成 CLR debugging 接口
- v103 verifyil 复核：**bad=0**（12690 写回体全部结构合法）——崩溃必为类型级/引导级
- 崩溃链（最终）：.cctor → DefineEfficientProfiler(官方真体) → VerifyCombinedStateRequest(桩)
  → call DirectDefinition(06004282, 官方 .bin 体 = nop;ret 合法) —— 链上全部合法却崩，
  **JIT 失败点在其后 DefineEfficientProfiler 继续执行的某个 call**

## 🏆 第十轮战报（2026-10-23 19:50 · v106 全量重建首次存活！）

### 决定性突破：v106 = 全量重建路线 60+ 轮以来第一个"进程存活"版本

**v106 配方**（全部本地工具产出，3 轮 CI）：
```
官方原版基座 + 12907 官方真体写回(v103/nbrestore2)
  + DefineEfficientProfiler/DefineActiveEvent ret 化(v104, expA 实锤 DEP 真体执行即崩)
  + IGC 内嵌 tamper 校验段 NOP(v105, " is tampered." throw 点 @0A72-0A9A)
  + 1601 个非法 EH catch → System.Object(v106)
```
**CI 实测（ui-probe 39942240188）**：进程存活 90 秒、responding=True、无崩溃——
`<Module>.cctor` 引导链首次完整跑通！v47→v100→v103→v104→v105→v106 的收敛链最终走通。

### v106 遗留：UI 未出窗，CPU 满转（死循环在业务 cctor 的状态机）

- v107 对照实验（IGC 也 ret）→ 1.5 秒崩在 `ArgumentGateway..cctor NRE` → **IGC 真体必须保留**
  （它初始化全局混淆状态 `<Module>{a8c2e9b2}::m_0d0b145be2`）
- host v4/v5 心跳诊断（5s 落盘）：主线程 25 秒后停更 → **全 CLR 冻结**（死循环无 safepoint，
  GC STW 挂起一切线程，ThreadAbort 也打不进——抓栈只能靠外部调试器）
- `ArgumentGateway.cctor` = Reactor **状态机混淆**（switch+轮转变量）：
  正常流 状态2(IGC/解密)→状态0→ret；死循环机制待最终定位（疑似 switch 表/状态流转被
  m_0d0b145be2 字段值影响）

### 本轮工具包新增（全部入库 tools2/）

| 工具 | 作用 |
|---|---|
| callgraph.cs | 从 entry 遍历调用图，列出"真体调用的桩"（v106 引导链 98 个桩） |
| tokcheck.cs | 全量 token 可解析性校验（16598 方法 0 坏 token——排除 token 越界） |
| ehsanity.cs | EH catch 类型 Exception 派生校验（v103 实测 1606 全非法→v106 全修复） |
| fixcatch.cs | 非法 catch → System.Object（1601 处） |
| patchtamper.cs | IGC tamper 段 NOP（9 指令） |
| stubmeth.cs | 指定 token 方法 ret 化 |
| findstsfld.cs | 全程序字段写入者搜索 |
| host v3-v5 | 心跳诊断法（定位全 CLR 冻结）+ host_trace 落盘收集 |

### 排除清单（expA/v104/v105/v107 系列实验的结论）

- DEP 真体执行即崩（anti-tamper 校验网络：30 个 Verify* + 8x get_Assembly + CryptoStream）
- token 越界：无（全解析）
- EH 结构错位：无（偏移与官方一致，唯 catch 类型 token 需 fix）
- maxStack：无问题
- PEVerify 差集法失效（官方原版自带 1752 条 verifiability 错误仍能跑）

### 下一棒行动清单

1. dump IGC 全部 2521 指令，找 m_0d0b145be2 的初始化点（stsfld/newobj 被间接引用？）
2. dump ArgumentGateway.cctor 的 **switch 表**（dnlib Instruction[]）确认状态流转目标
3. 死循环若是 m_df3c7fc7 类字段值驱动 → patch 状态机（把 V_0 流转改为直通终态）
4. 或 windbg 外部抓栈（~*k 原生栈 + JIT 地址对齐）——TTD 管线的 WinDbg 下载可复用

## 🎯 第十一轮战报（2026-10-23 20:45 · 全部现象贯通 + 破局路线确定）

### 基线对照实验（关键转折）

| 版本 | 构成 | 结果 |
|---|---|---|
| 官方原版 e8runnable | 不动 | **1.5 秒出主窗** ✓ 环境无问题 |
| v110 = 官方+仅fixcatch | dnlib 重写 | **秒崩** |
| v109 = v106+1364处nop | dnlib 重写+写回 | 存活但 CPU 满转无窗 |

### 全部现象贯通（统一理论）

1. **dnlib 重写官方原版 → Reactor 引导崩**（v110 实锤）：Reactor 用文件内偏移定位关键数据，
   dnlib ModuleWriter 重排布局 → 引导找不到 → 崩。**v106 能活是因为引导已中和**（掩盖了此伤害）
2. **v70 系为什么能出窗**：基座是前代重建版（Reactor 特征早不在），不受文件偏移伤害
3. **v106/v109 的 CPU 满转**：字符串解密链
   `业务真体 → call InstantiateTransferableProgram(int) → 资源流(GlobalValidator.FactoryValidator) → 官方引导建立的密钥`
   ——**引导中和后密钥状态缺失 → 解密循环空转**（v107 的 NRE / v106 的满转同根）
4. v109 的 IGC nop 化无效（CPU 时间不变）→ 证明卡点不在 IGC 重复执行，在解密链

### 💡 破局路线：字符串静态化（下一棒主线）

**观察**：写回体的字符串引用是 `ldc.i4 <id>; call InstantiateTransferableProgram` —— id 是常量！
**官方原版在 CI 正常运行**（引导完整、解密可用）→ **用 host 反射枚举全部 id 调用解密器抓映射表**：

```
步骤1: 扫描全部写回体, 收集 (ldc.i4 id, call ITP) 的 id 全集 → ids.json
步骤2: CI 加"字符串抓取"步骤: host 加载官方原版(不patch!), 反射调用
        InstantiateTransferableProgram(id) × N → strings.json (id→明文)
步骤3: nbrestore2 写回时: call ITP(id) → ldstr 明文 + nop 填充
        → 业务真体彻底摆脱解密器/引导 → v111 = 完全静态化的官方等价体
```

**已知风险**：ITP 可能有防反射保护（StackFrame 检查调用者程序集 @0041-00CB——
官方原版里调用者=host.exe 程序集会被 throw！**绕过**：把抓取器做成 AirExplorer 内嵌
类型（反射 emit/或直接改官方原版的某个桩方法为抓取器体——等长塞不下，用 ModuleWriter
+ 引导失效矛盾……**替代**：抓取走 cctor 触发路径——把 ids 注入某业务 cctor 顺带记录？）
→ 细节待打样，方向已定。

### 产物现状

| 产物 | 说明 |
|---|---|
| v106 | **里程碑**：全量重建首个存活版（90s alive/responding） |
| v109 | v106+IGC调用nop化（CPU 时间不变→卡点在解密链） |
| v110 | 官方+重写=崩（证明 dnlib 重写破坏 Reactor 文件偏移依赖） |
| exes/AirExplorer_v70.exe | 现行"可出主窗"基线（前代架构） |

## 🔬 第十二轮战报（2026-10-23 23:40 · 抓栈破案 + 快照恢复路线定型）

### 🏆 dump-stack workflow 首战告捷：直接抓到满转线程的托管栈

```
SHA1CryptoServiceProvider.HashCore ← TransformBlock
← InstantiateLiteralEvaluator ← GenerateControllableAnalyzer(hash, Stream, uint, byte[])
← HandlePool ← InstantiateGlobalCalculator ← <Module>..cctor
```
**v106/v109/v111/v112 的 CPU 满转 = IGC 真体的 SHA1 哈希循环永不退出**（一次 CI 定位，
四轮盲目实验的信息全部被解释）。

### 系列实验排除清单（本轮新增）

| 实验 | 结果 | 结论 |
|---|---|---|
| v109 (IGC 调用 nop 化 ×1364) | 满转不变 | 卡点不在调用方重复 |
| v111 (14130 处字符串→ldstr) | 满转不变 | 卡点不在业务字符串解密 |
| v112 (19378 处 ITP 全消灭) | 满转不变 | **卡点与解密器链完全无关** |
| v113 (124 官方字段值恢复) | 满转不变 | 字段恢复时机不对(IGC 在 <Module>.cctor 先跑) |
| 官方原版资源对比 | **6 资源完全一致** | 资源没丢 |
| v110 (官方+重写) | 秒崩 | dnlib 重写破坏 Reactor 文件偏移依赖 |

### 🔑 本质认知（盖棺定论）

**官方磁盘"真体"是解释器的输入，不是给 CLR JIT 的代码**——官方运行时 hook 拦截
cctor 的 call DEP/IGC/DAE，根本不 JIT 这些体；资源数据也是加密态由解释器解密。
v106 强行 JIT IGC → 它内部逻辑依赖"解释器才会维护的运行时状态"（资源明文、字段值、
流位置）→ 哈希校验永不通过 → 状态机循环。

**v106 能活 90 秒**已证明大部分业务真体 JIT 语义正常；卡死只在**引导体**（IGC 等
被解释器接管的少数方法）。

### 🎯 终极方案：运行时状态快照恢复（下轮主线）

官方原版能正常跑完引导（1.5s 出窗）→ **官方进程内引导类静态状态 = "引导已完成"快照**：

```
1. host6 v4: 官方原版启动后反射 dump 引导类全部静态状态
   (DispatcherInitializer 的 _ExtractorVisitors byte[] 密钥流/templateSpecObj/
    automatedError/m_ExtendedSchemaTemplate + <Module>{a8c2e9b2} 实例 + ...)
2. 工具把快照生成为 IL 初始化代码(byte[] → newarr+stelem 序列)
3. v114 = v111 + 在 <Module>.cctor 开头(IGC 之前)恢复快照
   → IGC 的 Stream/字段全是解密后明文 → 哈希正常通过 → 引导"秒完成"
4. UI 链 → 业务功能 → 逐层验收
```

已就位：fetch-strings workflow 可复用（改 dump 目标）；fv/strings 抓取姿势已验证；
字段/数组恢复 IL 生成器（patchfields 扩展）。

### 产物现状

| 产物 | 说明 |
|---|---|
| v106 | 全量重建首个存活版（基线） |
| v111 | +字符串静态化（14130 处 ldstr） |
| v113 | +字段值恢复（时机待修正为 <Module>.cctor 开头） |
| dump-stack.yml | **一次 CI 定位卡点**的通用武器(windbg+SOS) |
| fetch-strings.yml | 官方运行时状态抓取管线(可扩展为快照抓取) |

## 🧅 第十三轮战报（2026-10-24 03:00 · 快照恢复管线全通 + 剥洋葱推进中）

### 快照抓取管线全通（host6 v4 → snapshot.txt 4566 行）

- **`_ExtractorVisitors` 密钥流 398KB**（B64）+ 658 INT + 473 STR + 11 LIST 已抓全
- 恢复工具族：restoresnap(插 ITP 开头)/restoresnap2(插 r6cf451d0d 开头+自建容器)

### v114-v120 迭代链（每步错误都是路标）

| 版本 | 变化 | CI 结果 | 学到 |
|---|---|---|---|
| v114 | 快照恢复插 cctor 开头 | MissingMethodException | FromBase64String 签名需带 String 参数 |
| v114b | 修签名 | FieldAccessException | 跨类型访问 private → 需提 public |
| v114c | 字段提 public | **TypeLoadException: Invalid Field Access Flags** | `\|=Public` 产生非法组合(1+6=7) → 必须**先清 FieldAccessMask** |
| v116 | 恢复插 r6cf451d0d 开头+自建容器 | 满转依旧 | 恢复时机对但基座错了 |
| v117 | **v107(IGC ret)+双点恢复** | FieldAccessException at r6cf451d0d | 同可见性问题 |
| v118 | 可见性位正确重置 | **推进两层**：`<Module>{}.cctor` 通过！ | NRE 现位于 ITP 内部 |
| v119c | +automatedError=GetExecutingAssembly | ITP 内部 NRE 仍在 | ITP 还依赖 **List 字段** |
| v120 | +LIST 恢复(newobj+Add) | **6 编译错未跑**（留给下一棒修完即跑） | — |

### 当前精确卡点（ITP 内部 NRE 的已知依赖）

ITP(06004196) 使用的静态：`_ExtractorVisitors`(B64✓已恢复) / `_RecommenderTemplates`(List✓代码已写**有6编译错**) /
`editableMonitorTemplates`(List<string>✓同上) / `automatedError`(✓已恢复) / `_TemplateNotifierSize`(✓已恢复)

**下一棒第一件事**：修 restoresnap.cs 的 6 个编译错（LIST 恢复块）→ v120 重出 → CI。
之后每暴露一个新 NRE → dump-stack 抓栈 → 补对应快照字段 → 迭代（**管线全自动，每轮 5 分钟**）。

### 关键工作流提醒

- **gh_sync push 会静默失败**（约 1/3 概率）——**必须看到 commit URL 才算成功**；dispatch 与 push
  间隔需 >10 秒（main 传播延迟），否则 CI 跑旧代码（**看 size/md5 是否匹配**判断）
- 官方安装包下载偶发 500/不完整——重跑即过

---

## 2026-10-24 · wb-c2 轮（C2 最小链 + 根因实证闭环）

### 探针重建（业主指定的 3 个探针全部恢复并实证）

| 探针 | 位置 | 结果 |
|---|---|---|
| EvaluateVisibleAttribute 调用探针 | `ci/probe2.cs` mode=ag + `agprobe.yml` | **run 40064015971（成功）**：AG.cctor OK → AG 4 字段=明文版本 URL → `WriteRequest()` 返回实例 → **`_RequestSorter = NULL`** → EVA 抛 NullReferenceException。根因实证闭环 |
| ITP 调用探针 | `ci/probe2.cs` mode=itp | run 40064028391：module cctor OK；ITP(0)="{{ alg = {0}, typ = {1} }}"、ITP(1000)="calendarTriggerUI1"，6 ok/0 null/2 预期越界异常。**v132 字符串解密层语义级健康**（已知缺陷：GetTypes() 全量遍历会抛 ReflectionTypeLoadException，数据采集在抛之前已完成，不影响） |
| ArgumentGateway IL 转储 | `tools2/agscan.cs`(本地 dnlib) | EVA(06002F81)=84 指令 4 态 switch 状态机已完全读通；语义=读代理设置→NetworkCredential→全局写入 |

### EVA NRE 根因（静态+动态双确认，与业主第 0 块结论完全吻合）

- v132 仍是桩的坏链：`RequestWorker::.ctor 06002AF0`、`TemplateInitializer::.ctor 06002AF7`（均 nop;nop;nop;ret）
- `RequestWorker.cctor`(明文 il=8) 调 `new RequestWorker()` → 桩体什么都没做 → `m_RequestClient` 是空壳 → `_RequestSorter` 永远 NULL
- 全模块 `_RequestSorter` **307 处 ldfld / 0 处 stsfld**；`TemplateInitializer..ctor` **0 处 newobj** → 真实构造只存在于官方加密真体内 → **这是 C2 的铁证依据**
- EVA case0 语义：`WriteRequest()._RequestSorter.DefineTransferableRecord(ITP(2109338706^1165523088^容器.m_c1d686055a))` → bool 参与状态机推进（业主"第 0 块不能用 false 替代"的正确性再次确认）；case1/2 读 ProxyUser/ProxyPass；case3 `new NetworkCredential(V_0,V_1)` 写全局代理
- TemplateInitializer 包装方法已是真体：`DefineTransferableRecord`=`(bool)globalTemplate[str]`；`PatchList`=`ValidatorMatcher.ExecuteExplorer(globalTemplate[str],CallConfig)`；`InstantiateRandomIterator`=globalTemplate 惰性建 `AggregatorLogger(key,null)`+`ParseFlexibleAuthorizer()` 回填——**但 globalTemplate 的初始化在被加密的 TemplateInitializer::.ctor 里**
- v132 剩余桩 1740（官方 5709）

### C2 最小链（本轮新增，已跑通故障排除两轮）

- `ci/ttd/prep.cs`：官方样本 Assembly.LoadFrom→module cctor→STA 线程入口引导 N 秒→逐目标 `marker(唯一 ilSize DynamicMethod)→PrepareMethod→新鲜 GetMethodBody()`（修复 forcedump 的"先读后 JIT"时机缺陷）→ >4B 则 dump forcedump 同格式 .bin/.loc/.eh；mode=agcall 用反射自然执行夹逼（首次触碰触发整条 JIT 链，含 RequestWorker.ctor/TemplateInitializer.ctor）；phase C 全量桩复查（skipwalk 可关）
- `ci/ttd/JitScan2.js`：扫全部 compileMethod，按 marker ilSize(50000+/60000+/99999) 切窗，窗口内全量抓 IL+maxStack+ehCount+localsTok+localsSig；输出=JSON 文件 + **行式 JS2DATA 打 debugLog（cdb.log 兜底可解析）**
- `.github/workflows/ttd-prep.yml`：managed（纯托管新鲜读体）/ agcall（自然夹逼）/ ttd（TTD 录制+cdb 扫描）三 job 并行
- **首轮故障与修复**（记住，别重踩）：
  1. TTD 子进程 cwd 不可靠 → 相对路径 `app\AirExplorer.exe` 在 `SetCurrentDirectory` 就崩，且崩点在日志建立之前（trace 只有 2 次 JIT、prep.log 缺失的真相）→ 修：绝对路径 + Main 首行建 Log_ + 全包裹 FATAL 日志
  2. JitScan2/v5 共有 bug：x64 上 `esp` 是 `rsp` 别名，`esp!==undefined` 探测恒真 → x64 被当 x86 → 修：rax 优先判定
  3. JS 文件写 API 不稳（Write/WriteLine 均可抛）→ 修：行式 JS2DATA 输出到 debugLog 兜底
- **agfix 已修**（业主指定三处）：stloc.0-3 无操作数按 opcode 推导局部索引；I8/U8 用 ldc.i8.0；其余值类型 ldloca+initobj+ldloc（`tools2/agfix8.csproj` 建好，编译通过）

### host6 v5 诊断（业主指定四项全落实）

`tools/ci/host6.cs`：程序集版本+样本 MD5+官方基座核对（A12B5C573E1B54E98CCCC29351EAA066 显式落盘）、AG/RW 类型解析结果显式落盘（区分"类型没找到"与"字段读取失败"）、字段读取异常不再吞（AGERR/RWERR 行）、EntryPoint 线程异常落盘（entryEx 行）。注：仓库根 `snapshot.txt`(4566 行) 是 host6 v4 时代产物（只有 DI+TA），AG=0/RW=0 的首要嫌疑即此。

### 基建记录

- 旧 token（xixka）对原仓库无写权限（不能 push/dispatch）；fork 方案被 GitHub 自动删除（仓库内容触发审查）；**owner token 可用**，wb-c2 已快进合并 main（ebeef02→05e0652，纯增量：新探针/C2 链/host6 v5/agscan/agfix 修复，无覆盖）
- ttd-prep 首轮完整验证 run：40064657856（origin/main）

### v135 实测（C2 首战告捷：两 ctor 真体已恢复）

**C2 抓取成功**（prep managed/agcall，官方 md5 A12B5C573E1B54E98CCCC29351EAA066 引导后新鲜读体）：
- `RequestWorker::.ctor 06002AF0` = **317B 真体**（80 指令；v132 视图是 4B 桩）
- `TemplateInitializer::.ctor 06002AF7` = **325B 真体**+1 EH（catch ExtendedProxy/<>c；v132 视图 4B 桩）
- EVA 06002F81=358B、InstantiateRandomIterator 06002B06=243B、ITP 06004196=446B（官方内存视图，供对照）
- 机制确认：Reactor 在**首次执行时原地解密**方法体（"before ilSize=317"——boot 期 RequestWorker.cctor 已触发解密），PrepareMethod 不解密桩（phase C 248 桩 changed=0）

**v135 = v132 + 两 ctor（bodyswap 三件套）已推送**。probe2/UI Probe（run 40068623507/40068625457）：
- 真实启动链打通到更深：`StatelessModel.SearchAdapter → EVA → WriteRequest → RequestWorker.cctor → new RequestWorker() → ctor 执行 → ParserValidator.ExecuteExplorer NRE → 0xE0434352 崩溃`
- **关键结构发现**：`_RequestSorter` 的唯一赋值点在 RequestWorker.ctor 真体内（`IL_00FB: ldsfld ParserValidator::UpdateFunction → ExecuteExplorer(s,s,del) → newobj TemplateInitializer::.ctor(s,s) → stfld _RequestSorter`）——之前"全模块 0 stsfld"是因为它是 **stfld 实例字段**且藏在加密 ctor 里
- 下一断点：`ParserValidator` 是 MulticastDelegate，`UpdateFunction` 静态委托字段在 v135 无任何 stsfld/newobj（已扫全模块）→ 赋值方法在官方引导期解密的加密方法里
- **真 EVA 语义**（358B 全读通）：case0 `DefineTransferableRecord` 的**布尔值穿越两条 stloc 被 brfalse 消费**（业主"第 0 块布尔参与状态机推进"实证）；case1/2 取代理用户名/密码（PatchList+HandleFormatter）；case3 `new NetworkCredential(V_0,V_1)` → 全局代理安装。**case0 检查段不可伪造：true=跳过凭证安装，false=用空凭据继续，都是错语义**

**refscan 模式已上线**（prep.cs）：官方引导后全量 IL 字节扫 `newobj ParserValidator::.ctor(06004719)`/`stsfld UpdateFunction`/`stsfld WatchSpec`，命中即抓真体——下一轮 v136 的数据源。

### v136-v138 迭代（委托绑定机制全解，启动链逼近模板注册）

| 版本 | 变化 | 结果 |
|---|---|---|
| v136 | 手工 BCL 委托注入(dginject) | 首版踩坑: net8 dnlib Import 产生 `System.Net.Requests 8.0.0.0` 坏引用 → FileNotFound。**铁律: 注入引用必须复用模块既有 MemberRef/AssemblyRef, 禁止跨运行时 Import** |
| v136b | 复用既有 MemberRef(0A0009F0/0A0012C3/0A0012C4) | ParserValidator/GetAnnotation/ValidateCustomProvider 三委托通 → 推进到 TI ctor 内 ArrangeAggregator NRE |
| v137 | v135+6 委托类型真 cctor | 与 v135 逐字节相同(cctor 本来就是真的 — 它们调 TrackCompiler, 不是赋值点) |
| **v138** | **dlgmap: 官方 MapScan 绑定表全量静态注入 1022 静态 + 2244 trampoline** | **RequestWorker.cctor 完整通过!** TI 四个模板字段与官方逐字节一致；断点收敛到 globalTemplate 空表 |

**TrackCompiler 机制（本轮最重要的架构发现）**：
- 委托赋值点 = 各委托类型 cctor 调 `DispatcherInitializer::TrackCompiler(RuntimeTypeHandle)` (06004193, 真体已通)
- TrackCompiler 从加密清单资源 `CollectorTransaction.ValidatorProject`(26128B, v135 在) 解密构建 `m_LogicalProcessorMap`(fieldTok→valTok)
- 然后按 type.GetFields(1064) 逐静态字段: map 查 token → ResolveMethod → `Delegate.CreateDelegate`(静态目标) 或 **DynamicMethod trampoline**(实例目标, bit30=0x40000000 标记 callvirt) → SetValue
- **所有失败被静默吞**(try/catch pop/leave) — v132 线资源解密在此断(官方运行时 map 有 3266 条, v132 推断解密失败字段全空)
- MapScan(prep.cs) 已 dump 全表: 3266 条 = 全模块 delegate 静态字段数, token 与 v135 100% 对齐(04002160→0A0009F0=String::Concat 实证)

**当前精确卡点（globalTemplate 空表 → DefineTransferableRecord unbox null NRE）**：
- 官方 probe2 实证：`globalTemplate={DefailtProxyAuth:True}`；v138 四字段与官方一致但 `Count=0`
- 官方 CHAIN 实测: `VerifyCentralLocator=False`(配置文件不存在) 但 `GenerateAdjustableAggregator=True` → GAA 走 `brfalse→GenerateSortedArgument(new CommandFactory(_FilteredTemplateContent))` → 注册发生在此链
- v138: GAA 返回 True 但未注册 → **`CommandFactory::.ctor 06002B51` 是 4B 桩** + **`_ExtendedTemplate`(PropertyLoaded 事件, 实例委托) 无人订阅**(处理器在加密方法, 全模块无 (Object,CommandFactory)→Void 签名匹配)
- 注册动作 = `_ExtendedTemplate.Invoke(this, new CommandFactory(_FilteredTemplateContent))` — 处理器真体 + CommandFactory.ctor 真体 + add_PropertyLoaded 订阅点, 三件都在官方内存里 → 已扩 prep(dlgscan 实例委托读 + refscan newobj 监视) 抓取 → v139 数据源
