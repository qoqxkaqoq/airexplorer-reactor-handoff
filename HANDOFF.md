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
