# 文本模式攻坚记录（A 级验收）

> 2026-10-22 · wb-reverser
> 目标：让 `AirExplorer.exe help` 跑通（exit 0 + 16 个命令名）。
> 结果：**未通过**，但把崩溃点从"`<Module>::.cctor` 直接挂"推进了 6 层，并拿到了两个可复用的工具机制。

---

## 1. 验收通道（这轮新增的基础设施）

`AirExplorerCmd.exe` 只是个转发器（详见 `docs/CMD_ANALYSIS.md`），它把 `help` 交给同目录的 `AirExplorer.exe`，
再把子进程 stdout 抄到控制台。所以 GUI 版自带文本模式：

```powershell
AirExplorer.exe help     # 官方: exit 0, 36 行帮助, 16 个命令
```

workflow `.github/workflows/gui-cli-verify.yml`，判据是硬的（不看窗口）：

- `exit_code == 0`
- stdout 含 `Air Explorer 5.11.0 command line`
- 16 个命令名逐个 `^name\s` 命中

这条通道**比 GUI 启动早得多**，是当前唯一能精确 diff 的回归测试。

---

## 2. 逐个候选的实测（全部失败，但失败点在移动）

| 候选 | 构建方式 | exit_code | 崩在哪 |
|---|---|---|---|
| 官方 e8runnable | — | 0 | **PASS** |
| nb_original | 原始基线 | — | 死循环（文本模式下也没输出） |
| depfix2 | 真体回植 | `0xE0434352` | `<Module>::.cctor` → `VerifyCombinedStateRequest` InvalidProgram |
| krypton | Krypton 还原 | `0xC0000005` | `StatelessModel.SearchAdapter` NRE（`EvaluateVisibleAttribute` 被桩成 ret） |
| krypton_neutral / krypton_merge4 | 中和 cctor | `0xC0000005` | 同上 |
| depfix6 | neutralize2 全清 cctor | `0xC0000005` | `ArgumentGateway.EvaluateVisibleAttribute`（`m_RequestClient` 为 null） |
| nbjit_restored3 | 16586 真体写回 | `0xE0434352` | `<Module>::cctor` → `RandomDecryptor(Stream null)` |
| si6 / si10 | 见下 | `0xE0434352` | 逐层下探（见第 3 节） |

关键教训：**把 cctor 一律清成 `ret` 是错的** —— 应用自己的静态单例永远不会初始化，
下游会以各种 `NullReferenceException` 的形式炸在莫名其妙的地方（`m_RequestClient` 就是典型）。

---

## 3. si 系列：从 cctor 一路下探到第 6 层

构建链（全部离线，`tools2/`）：

```
nbjit_restored3                       # 16586 个 JIT 收割体已写回
  └─ stripinit  (只摘 Reactor 引导, 保留应用初始化)
       └─ bodytrans  (从 cilantro 补 InstantiateStatelessUser)
            └─ fixmap   (按嵌套类型序号把假名映射回官方名)
                 └─ fixrefs (补成员名)
```

每轮的崩溃点（每修一层就前进一层）：

| 版本 | 崩溃点 | 原因 | 修法 |
|---|---|---|---|
| stripinit | `ArgumentGateway..cctor` NRE | 字符串表持有者 `<Module>{a8c2e9b2}::m_0d0b145b` 为 null | 需要 `TemplateArgument.InstantiateStatelessUser`（泛型，JIT dump 里没有） |
| stripinit2 | `TypeLoadException: GeneratedEnum_0425` | transplanted body 带着 cilantro 的假名 | fixrefs / fixmap |
| si4 | `MissingMethodException: generatedMethod_0290` | 同上，成员层 | fixrefs 扫 MethodSpec |
| si5 | `ArgumentGateway..cctor` InvalidProgram | 摘掉了 `FinderMap::DirectDefinition(int)` —— 它其实是**字符串解密器**，导致 `stsfld` 从空栈取值 | 只摘"返回 void"的调用 |
| si6 | `ValidatorDefinition.ExecuteExplorer` NRE | `ValidatorDefinition::MatchRunner` 为 null：`TrackCompiler(rt)` 是**字段初始化器**，被我摘了 | `KeepMethods = { TrackCompiler }` |
| si8 | `<Module>::cctor` ArgumentNullException | 保留 `InstantiateGlobalCalculator()` 后，它内部 `RandomDecryptor(Stream null)` | 去掉该保留项 |
| si9/si10 | `ValidatorDefinition::.cctor` NRE | 又回到"没有 InstantiateGlobalCalculator" | **卡住（见第 5 节）** |

### 两个必须记住的坑

1. **`FinderMap::DirectDefinition` 有重载**：无参 `void` 的那个装 JIT hook；(int)→string 的那个是**字符串解密器**。
   按"声明类型"批量摘调用会把后者一起摘掉，症状是 `stsfld` 前凭空多一个 `pop` → InvalidProgram。
   **只能按返回类型判断**。
2. **`TrackCompiler(RuntimeTypeHandle)` 不是引导**，它是"按类型句柄初始化该类型静态字段"的例程。
   摘掉它，`ValidatorDefinition::MatchRunner` 之类的静态对象永远是 null，报错位置会离真正原因很远。

---

## 4. 一个可复用的机制：嵌套类型"序号映射"

cilantro（nb_slayer 产物）把编译器生成的类型改成了 `GeneratedType_0431` / `GeneratedEnum_0425` 这类假名，
直接移植会 `TypeLoadException`。但实测发现：

> **同一父类型下，cilantro 与官方的 `NestedTypes` 顺序完全一致。**

例：`CloudClient.Templating.TemplateArgument` 两边都是 40 个嵌套类型，逐位对齐：

| 序 | 官方 | cilantro | 字段 |
|---|---|---|---|
| 0 | OperationalCalculator | OperationalCalculator | 完全一致 |
| 7 | `m4iNrp3uTHM9viOH5bc` | `GeneratedEnum_0425` | `value__` |
| … | … | … | … |
| 26 | `URqFYq3xtmntT2OcLub`1` | `GeneratedType_0431` | `<>9, <>9__47_0, VerifyMonoAllocatorEncryptor` |

所以 `tools2/fixmap.cs` 可以**批量**还原假名：找源里的序号 → 取目标同序号类型 → 就地改名；
成员（方法/字段）按类型内顺序对齐。这比手工映射 413 个类型可行得多。

> 之前的 `fixrefs.cs` 是针对单个方法的手工映射（`GeneratedEnum_0425 -> System.Int32` 那一步其实是错的，
> 正确的是 `m4iNrp3uTHM9viOH5bc`）。两者现在串联使用：fixmap 管类型，fixrefs 管成员。

---

## 5. 当前确切的瓶颈

`ValidatorDefinition::.cctor` 与 `InstantiateGlobalCalculator()` 构成一个**互斥对**：

- **摘掉** `InstantiateGlobalCalculator` → `ValidatorDefinition::MatchRunner` 等静态字段永远 null → NRE
- **保留**它 → 它内部 `DispatcherInitializer.RandomDecryptor..ctor(Stream)` 收到 **null 流** → ArgumentNullException

已排除"资源被写丢"：`recon` 对比 `e8runnable / nbjit_restored3 / si10`，6 个嵌入资源名称与大小**完全一致**
（含 2.3MB 的 `ValidatorGenerator.DefinitionError`）。所以那个 null 流是**运行期用名字去取、名字算错了**，
或者它根本是从**自身文件**按偏移读的（Reactor 的 NecroBit 数据在 PE 尾部）。

进一步读 `InstantiateGlobalCalculator` 的正文，null 流的来源已经定位到具体三条指令（`work/igc_nb.il` 第 0BE0 行起）：

```
0BE0  ldsfld   Assembly DispatcherInitializer::automatedError
0BE5  ldstr    "ing>>-GetEnumerator>d__52"            <-- 明显是个被截断/损坏的字符串
0BEA  call     CheckRemoteProfiler(Assembly, string)  <-- 拿它去 GetManifestResourceStream
0BEF  newobj   RandomDecryptor(Stream)                <-- 于是收到 null
```

也就是说：**它按名字取资源，而那个名字是一段残缺的字符串**（`ing>>-GetEnumerator>d__52` 看起来是某个
`...>d__52` 类型名的尾巴）。这不是"资源被写丢"，而是**字符串常量本身不对**——
很可能是 Reactor 的字符串保护在 JIT 之后仍会改写 `#US` 堆引用，或者这条 ldstr 本应由运行时补全。
下一步应当先确认官方原件里同一位置的 ldstr 是什么（用 JIT dump 的原始字节比对）。

`InstantiateGlobalCalculator` 有 **2521 条指令**，这正是 v84b 作者当年被迫"重写成最小字段初始化"的那个方法
—— 两条独立路线在同一个方法上撞墙，这个结论现在有第三次印证。

---

## 6. 下一步（按性价比）

1. **读 `InstantiateGlobalCalculator` 的 2521 条指令**：找出它打开哪个流、名字怎么算的。
   有真体在手（`work/nj_art/jitout`），这是纯阅读工作，不是猜。
2. **只补它需要的那个流**：如果是按名字取资源，直接把名字改成 6 个已知资源之一即可。
3. 若它是从自身 PE 尾部按偏移读（NecroBit 数据区），那就要在 stripped 版本里保留那段数据
   —— 这条要结合 `docs/PROGRESS_wb-reverser.md` 第 7 节的 dump 格式一起看。

工具已全部入库：`stripinit / bodytrans / fixmap / fixrefs / pairlist / unresolved / nestcmp / typemembers / findfield`。
