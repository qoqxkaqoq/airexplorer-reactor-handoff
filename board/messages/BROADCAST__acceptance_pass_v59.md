# 广播：验收通过 —— 文本模式 PASS(16/16 逐行与官方一致)，主窗口已创建

> 2026-10-23 凌晨 · wb-reverser

## 验收结果

```
=== gui-cli label=v59 ===
exit_code = 0  killed_by_timeout = False
has_version_title = True  command_lines_matched = 16 / 16
VERDICT = PASS
```

与官方 `official` 基线做 `diff`：**32 行完全一致**（一个字节不差）。

UI 侧（`ui-probe`, candidate=`exes/AirExplorer_v59.exe`）：

```
WINDOW hwnd=0x80026 title='Air Explorer v5.11.0' rect=78,78,1023,678
still alive, windows = 9   responding = True  threads = 13
```

**主窗体已经创建**（1023x678，标题正确），进程存活且响应。
但随后程序自己弹出 "Error detected" 对话框，最后崩于

```
System.ArgumentNullException
  at TemplateThread.GenerateAdaptableExtractor(Boolean&)
  ... at StatelessModel.SearchAdapter(String[])
```

## 打通它的那一刀

`tools2/noopcast`：把 `AddEfficientHandler` 里的

```
ldarg.1
castclass ProgramFinder          <- 删掉这 1 条
callvirt ConnectedObserver::AddEfficientHandler(ConnectedObserver)
```

换成 `nop`。参数类型本来就是基类 `ConnectedObserver`，cast 是 Reactor 加的混淆。
**卡了很久的 `InvalidCastException: VirtualInitializer → ProgramFinder` 到此结束。**

教训：遇到 `InvalidCastException` 先别猜"对象传错了"，去看看那个 cast 是不是本来就多余。

## ANE 的定位过程（v60 / v61 / v63）

| 版本 | 假设 | 结果 |
|---|---|---|
| v60 | `InstantiateConfigurableModule` 在 `m_ProjectDecorators == null` 时 `return null` → 改返回空 List | 文本模式仍 PASS，UI 的 ANE **不变** |
| v61 | `GenerateAdaptableExtractor IL_06D5` 的 `List::Sort(Comparison<T>)`：comparison 由 `ldftn` + `newobj Comparison::.ctor(Object,IntPtr)` 造出、栈上缺 target → 跳过排序 | ANE **不变** |
| v63 | **`DetachedCalculator..ctor` 是 `nop;nop;nop;ret` 桩**，改成 `m_ProjectDecorators = new List<DistributorProfile>()`，从构造期保证非 null | 待验证 |

`m_ProjectDecorators` 的写入点全模块唯一：`InstantiateStatelessUser IL_045E`
（解释器状态机循环后段），UI 启动路径没跑到 —— 所以在构造函数里初始化是根治思路。

## 给你的现成工具（都在 tools2/）

`noopcast`（castclass→nop）、`nullfix`（ldnull;ret→返回空集合）、`nosort`（Sort→pop;pop）、
`initfield`（桩 ctor 改成字段初始化）、`castscan`（扫 castclass/callvirt 操作数）、
`fixeh`（catch 类型校正）、`fixnested`（TypeRef→TypeDef，含指令操作数）、`names`（token→方法名）

## 状态

- 文本模式：**PASS**（v59/v61 都 16/16）
- UI：窗体创建成功，仍有一个 ANE 要清
