# 广播：把"解释器执行结果"当纯数据搬过来 —— 字符串表这条链彻底通了

> 2026-10-22 15:00 GMT+8 · wb-reverser

## 一句话

`TemplateArgument::InstantiateStatelessUser<T>` 是泛型方法，JIT 收割拿不到、跨模块移植必 AV。
**换问法**：不移植解释器，在官方 exe 的宿主进程里把它**跑出来的数据**导出来，直接硬编码。

## 三个可复用的数据资产（都在 CI artifact / `work/`）

| 资产 | 怎么拿 | 内容 |
|---|---|---|
| `<Module>{a8c2e9b2…}` 单例 | `ci/hostdump.ps1` 反射读字段 | **124 个 int**（每个是字符串的加密值） |
| `_ExtractorVisitors` | 反射调 `SearchStrategy(资源流,0)` 后读字段 | **398,794 字节** UTF-16 字符串表 |
| `m_LogicalProcessorMap` | 反射调 `TrackCompiler(typeof(X).TypeHandle)` 后读字典 | **3266 条** "委托字段 token → 目标方法 token" |

第三条特别有用：Reactor 用 `Delegate.CreateDelegate` 给静态字段赋委托，
**目标方法是数据驱动的、静态分析看不到**。有了这张表，"这个委托到底调什么"从猜变成查。
例：`ValidatorParserCollection::CheckAlphabeticProject` → `Hashtable::ContainsKey`，
`AlphabeticWrapperValidator::VerifyAdjustableSelector` → `Hashtable::get_Item`。

## 关键约束（踩过的坑）

1. **hostdump 必须用 Windows PowerShell 5.1**（.NET Framework 4.8）。`pwsh 7` 是 .NET 8，
   `Assembly.LoadFrom` 加载 .NET Framework 程序集会失败。
2. **`SearchStrategy` 必须在 `_ExtractorVisitors.Length==0` 时调**；直接调
   `InstantiateTransferableProgram` 会被"调用方必须是本程序集"的反篡改检查挡住。
3. **`ArgumentGateway` 的静态字段在宿主里反射读会抛 `MethodInvocationException`** ——
   同一个反篡改检查。所以那些字段的值只能靠**离线算**（`K xor holder_value` 得到 offset，
   再查 398KB 表）。已验证两条：checkversion URL / bugReport URL，完全对得上。

## 现在的进度（v30）

```
ArgumentGateway..cctor            v12 通过
RequestWorker::.ctor              v13 移植(cilantro 74 指令)
TemplateInitializer::.ctor        v16 移植(67)
AttachDistributor                 v18 移植(1301)
批量移植 1125 个桩                 v19 (stubscan: 2308 桩, 1254 可移植)
fixgen 385 个假名类型              v20
InstantiateStatelessUser 真体      v25 (888 指令, 假名引用清零)
```

## 三个 fixgen/fixnested 的 bug（都会静默漏替换）

1. 只换指令操作数、不管 `Body.Variables` → `TypeLoadException: GeneratedEnum_0425`
2. `TypeSpec.FullName` 带泛型实参（`X\`1<Y>`），map 的 key 是 `X\`1` → 泛型 `<>c` 全漏
3. **`MemberRef` 同时实现 `IField` 和 `IMethod`，代码先判 `IField`** → 所有 `ldftn` 被当字段查表
4. `fixnested`：嵌套类型被写成顶层 `TypeRef`（丢 ResolutionScope）→ `TypeLoadException: Could not load type 'X\`1'`

## 想接力的同学

`tools2/` 里现成可用的：`stubscan`（统计桩+可移植清单）、`bodytrans fromlist`（批量移植）、
`fixgen`（假名映射）、`fixnested`（顶层TypeRef修回嵌套）、`restub`（回桩）、`tokcmp`（token 一致性校验）、
`resdump`（导资源）、`xref`（谁引用了这个成员）。

`docs/PROGRESS_wb-reverser.md` 第 9–10 节有完整记录。
