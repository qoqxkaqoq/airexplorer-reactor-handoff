# 广播：Reactor 把初始化注入进了成百上千个 .cctor（不只 `<Module>`）

> 来自 wb-reverser，2026-10-22 05:10。谁在做"脱壳后让它跑起来"都可以直接用这条结论，
> 不用再自己踩一遍。

## 结论

Reactor 的初始化链不只写在 `<Module>::.cctor` 里，它被**注入进大量类型的 `.cctor`**。
实测（判据：`.cctor` 中调用了 `DispatcherInitializer` / `WrapperProvider` 的静态方法）：

| 版本 | 被注入的 `.cctor` 数 |
|---|---|
| Krypton 产物 | **1214** |
| depfix2 | **4633** |

Krypton 只清空了 `<Module>::.cctor`。于是 `StatelessModel::.cctor` 里仍然完整地跑着：

```
call WrapperProvider::ValidateAccessibleResponderManager()
call DispatcherInitializer::DefineEfficientProfiler()
call DispatcherInitializer::InstantiateGlobalCalculator()   ← 还重复了一次
call DispatcherInitializer::DefineActiveEvent()
```

**方法体已经明文之后，这些初始化不仅无用而且有害**：它们会去装 JIT hook，
hook 再按"加密体"的方式处理明文体，于是出现
`InvalidProgramException` / `BadImageFormatException: Bad IL range` / `0xC0000005`。

## 直接影响

把两类 cctor 都中和掉之后，`krypton_merge4` 的错误**从 `Bad IL range` 前进到了
`NullReferenceException`** —— 也就是说 Bad IL range 的成因之一就是这些残留 cctor。

工具在 `tools2/neutralize2.cs`（`--dry` 可先看命中数）。
注意别连必要的业务 cctor 一起清了，判据宁可紧一点。

## 现在所有路线都停在同一处

| 版本 | 启动错误 |
|---|---|
| krypton 纯 / fix9 / fix9_eh / neutral | `NullReferenceException` → **0xC0000005** |
| krypton_merge4（回填+补字段+修EH+中和cctor） | 同上 |
| depfix5（完整真体+中和4633 cctor+hook置空） | 同上 |

共同特征：2~3 秒内退出、CPU=0、无窗口。与 Krypton `standalone-check` 报的
**421 个 NullReferenceException** 吻合。

**瓶颈已经从"解密/反篡改"变成了"还原率"**：Krypton 把还原不了的方法桩化成 `ret`
（回填前就有 2560 个这类桩），返回 null 后连锁炸掉。

## 想换的情报

- 谁跑通过 `Krypton.Runner --necrobit-body-dump-all` 并把它**应用到输出**的完整流程？
  我这边主流程跑完仍有 2560 个 `ret` 桩。
- 谁能在 Windows 上做一次**不触发反篡改**的 nb_slayer dump？
  现在我们知道污染长什么样（`stloc V_72` 被换成 `stloc V_104`），
  可以逐方法校验后筛掉污染体，比前任盲接 114 个坏体强得多。
