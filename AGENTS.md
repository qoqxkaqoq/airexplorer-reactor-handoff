# AGENTS.md — AirExplorer 逆向恢复工程 · 全体 Agent 目标与约定

> 更新：2026-10-23 11:40 (Asia/Shanghai) · 维护者：wb-reverser
> 本文件是所有接手 agent 的第一入口。历史细节见 `HANDOFF.md` 与 `docs/PROGRESS_wb-reverser.md`。

## 🎯 当前目标（业主确认）

把被 .NET Reactor 混淆的 AirExplorer v5.11.0.0 重建为**去混淆、可分析、可修改且功能与官方一致**的版本。

**验收标准（业主原话，不可放宽）**：
程序启动后 UI 截图中出现网盘内容（云盘文件列表等）才算成功。
 alive but no window == FAIL；300×300 空白窗体 == FAIL（v84b 假阳性教训）。

## 📍 当前状态（2026-10-23）

| 里程碑 | 状态 |
|---|---|
| 文本模式 `help`（16 命令） | ✅ PASS，与官方逐字节一致（v59 起） |
| 主窗口框架（标题栏/图标正确） | ✅ v65 起（内容区黑屏） |
| UI 初始化 OnLoad | ❌ ANE：`GenerateAdaptableExtractor` 的 `m_ProjectDecorators` null |
| 网盘业务功能 | ❌ 未开始（OnLoad 之后的层） |
| **当前最高水位产物** | **`exes/AirExplorer_v70.exe`** = v66 + 53 方法官方三件套（零回归） |

## 🧰 数据资产（史上最全，直接可用）

| 资产 | 位置 | 说明 |
|---|---|---|
| 官方解密方法体 ×16598 | `work/`（jitout 需从 artifact 重下）或 `exes` 构建链 | 24B 头：tok/ilSize/maxStack/ehCount/preExtra/localsTok |
| 官方 locals ×8392 | `work/loc_official.zip` | 每行 `index\|isPinned\|TypeFullName`（运行时 CLR 格式） |
| 官方 EH ×2218 + catch 名 ×34 + manifest | `work/eh_official.zip` | 28B CORINFO clause；classTok 可 ResolveToken 100% 命中 |
| 主武器工具 | `tools2/bodyswap.cs` | **体+locals+EH 三件套一体替换**（唯一安全姿势） |
| 诊断工具 | `tools2/metadiff.cs, methodtok.cs, tokmeth.cs, typedump.cs` | 见源码头注释 |

## ⚠️ 已实证的硬约束（违反必炸，别再踩）

1. **官方签名绝不能单独上**——cilantro 体 + 官方 locals 错位 → `Dictionary\`2 wrong number of generic arguments` 启动即崩。必须 bodyswap 三件套一起。
2. **dnlib 写盘必须 `PreserveAll | KeepOldMaxStack`**——Reactor 的字段初始化数据里嵌着原始 token，表 RID 一变就 `Token not valid`。
3. **验收只认 `tools/ci/probe.ps1`（ui-probe workflow）**——`ci/probe.ps1`（ui-verify 用）启动方式不同且不关对话框，v66/v59/v70 在它下面全显示"无窗"，**结论不可比**（对照实验 run 39882798316）。
4. **nbjit 的 VMT hook 从未工作**——force 模式的 dump 全是 managed 层 forcedump 写的。抓"执行流方法"（forcedump failed 名单，如 `RequestVerifierTransformer::.ctor 06003909`）**只能靠 TTD**。
5. **网络**：git 直连不通走 `https://p.xixky.eu.org/https://...`；API 直连可用但认证被掐时用 `GH_API_BASE=https://p.xixky.eu.org/https://api.github.com python3 scripts/gh_sync.py push`；artifact 下载需 302 location 原样拼代理 + `--path-as-is` + **不带** Authorization。

## 🗺️ 路线图（按优先级）

1. **TTD 抓执行流方法**（进行中，第 15 次运行）
   - workflow `ttd.yml` 全链已打通：WinDbg 经 `aka.ms/windbg/download`→appinstaller→prss CDN；JS 需 `initializeScript(){ return [new host.apiVersionSupport(1,7)]; }` + 逻辑放 `invokeScript`（新版 WinDbg 移除了 legacy host 全局）；cdb 先 `!tt 100` 跳 trace 末尾再 `.reload /f clrjit.dll`（lm 冻结在 trace 起点）
   - 目标：`ilSize=2283`（=RequestVerifierTransformer..ctor 官方体）的 compileMethod 调用，取 IL + localsTok + localsSig
2. **ANE 根治**：bodyswap `InstantiateStatelessUser 060042AC`(914 指令) + `PlanRunner 06004521` + `GenerateAdaptableExtractor 06004523` 官方三件套——官方数据已确认齐全（methodtok 验证 bin=1 loc=1）
3. **每修一层暴露一层**：OnLoad 之后逐层清（OCR 截图定位法见 PROGRESS 15.1）
4. **B 线 Krypton**：产物 AV，仅作 standalone-check 交叉参照，不投入

## 🤝 协作约定

- 每人只写自己的 `board/agents/<name>.md`；结论性发现**必须**写进留言板（这是留言板存在的唯一理由）
- 新 exe 命名 `AirExplorer_<方案名>.exe` 放 `exes/`；push 用 `scripts/gh_sync.py`（见上方网络约束）
- 产物验证一律 `ui-probe` workflow（candidate 传 `exes/xxx.exe` 路径）
