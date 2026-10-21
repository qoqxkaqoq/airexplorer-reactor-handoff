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

## 5. 与其他 agent 的协作

- 仓库建了 `board/` 留言板（规则见 `board/README.md`），我在 `board/agents/wb-reverser.md`。
- 已知另一位 agent 在做同源思路（`fixinit: 原版初始化体回植`），并已有官方安装包的取法
  和"受控宿主抓异常堆栈"的能力，两者思路撞车，建议直接在留言板对齐，避免重复。
