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

---

## 7. 补记（同日）：找到写回工具的致命 bug —— `ldstr` 读错了堆

`nbrestore` 里一直写的是：

```csharp
var u8 = ((ModuleDefMD)mod).StringsStream.Read(t & 0x00FFFFFF);   // 错
```

`ldstr` 的 token 是 `0x70xxxxxx`，指向 **`#US`（用户字符串）堆**，不是 `#Strings`（元数据名字堆）。
所以此前写回的每一个字符串常量都是**元数据名字的碎片**：`"AirExplorer"`、`"ystem"`、`"ources"`、
`"ing>>-GetEnumerator>d__52"`……全都能在类型/成员名里找到出处。

这正是 `InstantiateGlobalCalculator` 里"按名字取资源却拿到 null"的真正原因：

| | ldstr 的值 |
|---|---|
| 旧（错） | `"ing>>-GetEnumerator>d__52"` |
| 新（对） | `"ValidatorArgument.EmitterReporter"`（6 个嵌入资源之一） |
| nb_slayer 产物 | 同上，一致 |

改成 `mod.USStream.Read(offset)` 后，`nbjit_v2` 里 `InstantiateGlobalCalculator` 的字符串
（`" is tampered."` / `"SHA1"` / `"ValidatorArgument.EmitterReporter"`）与 nb_original **完全一致**。

**影响面**：此前所有"写回真体"的候选（`nbjit_restored*`、`depfix*`、`si*`）字符串全是坏的。
这条修复之后，`12768` 个方法体才第一次"内容正确"。

## 8. 新暴露的结构性阻塞：字段初始化数据里嵌了元数据 token

修好字符串后，`nbjit_v2` 的崩溃变成：

```
BadImageFormatException: Bad IL range
   at DispatcherInitializer.ObserveConverter(IntPtr)      <- JIT hook 安装
```

而剥离引导后的 `si11` 变成：

```
ArgumentOutOfRangeException: Token 0x0a000996 is not valid in the scope of module AirExplorer.exe
   at DispatcherInitializer.TrackCompiler(RuntimeTypeHandle)
   at ValidatorDefinition..cctor()
```

`TrackCompiler` 做的事是：**用写死在字段 RVA 数据里的 metadata token，去 `Module.ResolveMethod`
解析出成员，再给该类型的静态字段赋值**。而我们的重写会让 `MemberRef` 表布局变化，
这些 token 就失效了。

这是个比"字符串/方法体"更底层的耦合：**Reactor 的字段初始化数据绑定在原始元数据行号上**。
任何会改动 `MemberRef`/`MethodSpec` 表的重写（移植、加方法、去重）都会打断它。

可选解法：
1. 写盘时保证 `MemberRef` 表的 RID 与原始完全一致（不能增删、不能去重）——需要 dnlib 层面的表级控制；
2. 把 `TrackCompiler` 改成"逐个 token 容错"（解析失败就跳过），先让流程跑通，缺的字段另想办法补；
3. 反过来：不重写元数据，只把方法体**原地**写回（保持 token 表一字节不动）——理论上最干净，
   但要求方法体长度不变或 RVA 重排后仍能对上（PE 允许改 RVA，token 表不动，这条其实可行）。

第 3 条是目前看来最有希望的：**只改 MethodDef.RVA 与代码字节，绝不碰元数据表**。

---

## 9. 补记二：又修掉三个真 bug，并撞到一个绕不过的约束

### 修掉的三个 bug（都会让"体是对的却跑不起来"）

| # | Bug | 症状 | 修法 |
|---|---|---|---|
| 1 | `ldstr` 从 `#Strings` 读 | 所有字符串是元数据名字碎片 | 改 `mod.USStream.Read(offset)` |
| 2 | `InitLocals=true` 但 `LocalVarSigTok=0` | `BadImageFormatException: Bad IL range` | `body.InitLocals = oldVars.Count > 0` |
| 3 | `bodytrans` 缺 `PreserveAll` | `MemberRef` 从 5818 掉到 2242 → `TrackCompiler` 报 `Token 0x0a000996 is not valid` | 写盘加 `PreserveAll`（表行号保持 5818） |

第 3 条尤其隐蔽：`TrackCompiler` 用**写死在字段 RVA 数据里的 metadata token** 做 `ResolveMethod`，
而 dnlib 默认会把"当前没被引用"的 MemberRef 行整批丢掉，行号一错，token 立刻失效。

### 撞到的约束

修完上面三条后，链路推进到：

```
ArgumentGateway..cctor
  -> <Module>{a8c2e9b2}..cctor
    -> TemplateArgument.InstantiateStatelessUser[T]     (从 cilantro 移植)
      -> TemplateThread.PlanRunner
        -> TemplateThread.GenerateAdaptableExtractor
           AccessViolationException
```

`InstantiateStatelessUser` 是字符串表的初始化器，而它在**原模块里是桩**（`ldnull;ret`），
JIT 收割也没拿到（泛型方法被跳过，目录里只有 `.eh` 没有 `.bin`）。
唯一的真体来源是 cilantro —— 但那是**另一个模块**，方法体里带着该模块自己的常量/偏移，
搬到 nb_original/官方模块里就 AV。**跨模块移植这个方法是不可行的**。

### 因此

- `nb_strip3/4`（nb_slayer 基座 + 正确表行号 + 移植初始化器）已经能跑到字符串表解码这一步，但过不去；
- 真正的解法只剩"**在同一个模块内拿到这个方法体**"，也就是必须让 JIT 收割覆盖泛型实例化
  （现在的 hook 只对 MethodDef 落盘，泛型实例化走的是 MethodDesc 路径）。

### 可运行的产物

仓库里唯一**真的能起来并显示主窗口**的是 `exes/AirExplorer_v84b_window.exe`（v84b，300×300 空窗体）。
它是"能运行"意义上的下限交付：进程存活、窗口出现，但网盘内容为空。
