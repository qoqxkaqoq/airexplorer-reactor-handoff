# C 线（脱壳重建）归档 · 2026-10-24

> 业主决定：**只做 A 组（官方 exe 静态改版），B（旁路脚本）与 C（脱壳重建）放弃**。
> 本文件是 C 线的资产索引与重启指南。全部数据资产保留在仓库，随时可复活。

## 一、C 线最终状态（截至归档）

- 最高产物：`exes/AirExplorer_v140.exe`（v141diag 为其注入诊断版）
- 运行水位：进程存活，走完 SearchAdapter 状态机 state0→3，进入 `Application.Run(ctx)` 消息循环
- **未达标：0 窗体**（官方 @2s 即有 1 个 AdvancedClient 实例）
- 首要卡点（已定位，未修复）：`InitializerReg..ctor (06002BD1)` 在候选版是空壳（5×nop+ret）

## 二、窗体创建点之谜 —— 已解（本轮成果，重启时先读这节）

1. `CloudClient.Registry.InitializerReg` **继承 System.Windows.Forms.ApplicationContext**，
   就是 `Application.Run(ctx)` 的 ctx（经 `LiteralContextValidator.ExecuteExplorer` 桥）。
2. `ValidateDynamicEncryptor (06002BCE)` = **双检锁懒汉单例工厂**（Monitor.TryEnter/Exit 代理 + `if(_ParserModel==null) _ParserModel = new InitializerReg()`）。SearchAdapter 调它 4 次属正常。
3. `InitializerReg..ctor (06002BD1)` 官方真体（加密）必然做三件事（候选版空壳导致全链断裂）：
   - `regRecommenderList = new List<AdvancedClient>()`（解释静态扫描 List::.ctor 0 命中）
   - 调 `MergeManager (06002BD6)`
   - `MainForm = regRecommenderList[0]`（ApplicationContext 语义）
4. `MergeManager (06002BD6)` 状态机已完整解出（候选版明文真体 52 条指令）：
   ```csharp
   var client = new AdvancedClient(false);
   regRecommenderList.Add(client);
   client.FormClosed  += OpenScheduledBuffer;   // 经 LocalTesterValidator::VerifyAdvancedOrder 代理
   client.FormClosing += OpenScalableWriter;    // 经 RemoteStackValidator::PauseDispatcher 代理
   client.Show();                                // 经 AdjustableInspectorValidator::ProcessPool 代理 → Control::Show()
   ```
5. 实证链：v141diag 注入日志（run 40102463958）`VDYN×4 + INITREG×4 = 单例工厂每次重试都抛异常`
   （空壳 ctor 不初始化 regRecommenderList → MergeManager 首行 Add 即 NRE）；
   6s dump 主线程在 RunMessageLoop(ApplicationContext) 内空转，`!dumpheap -type AdvancedClient` = 0。
6. **重启动作**：bodyswap 恢复官方 06002BD1 真体三件套 → v142 → bootcfg 验证 TAG 出现 CTOR/MERGE + dumpheap 出现 1 实例。

## 三、数据资产索引（全部在仓库 work/，57+ 文件已跟踪）

| 资产 | 文件 | 说明 |
|---|---|---|
| 官方 token 地图（100%） | `work/tokmap_official.tsv.gz` | 55781 行 TypeDef/FieldDef/MethodDef/TypeRef/MemberRef 全表 |
| v59 对照地图 | `work/tokmap_v59.tsv.gz` | |
| 官方 locals ×8392 | `work/loc_official.zip` | 每行 `index\|isPinned\|TypeFullName` |
| 官方 EH ×2218 | `work/eh_official.zip` | 28B clause，classTok 可 ResolveToken |
| 加密资源 ×6 | `work/res_*.bin` | ValidatorProject 等，md5 与官方一致（faf6a669...） |
| 字符串解密 | `work/strmap.tsv` / `work/strings_tsv.txt` | ITP 语义已实证 |
| 委托绑定表 3266 条 | MapScan 工具产出（重跑 `tools2/dlgmap` 或 CI） | fieldTok→valTok |
| 方法体 dump ×16598 + EH ×2218 | **`work/dump_official_16598.zip`（已入库 2026-10-25）**——run 39864750444 全量官方真体，24B 头格式见包内 MANIFEST.txt；forcedump failed 名单（如 06002BD1）不在其中，需 TTD 补抓 |
| 工具 | `tools2/bodyswap.cs`（三件套一体替换，唯一安全姿势）、`tools2/agscan8`（IL 转储）、`tools2/injectlog.cs`（入口日志注入） | |

## 四、硬约束（违反必炸，历史教训全录）

1. bodyswap 必须「方法体+locals+EH 三件套一体换」，单换任何一件 = 启动即崩
2. dnlib 写盘 `PreserveAll | KeepOldMaxStack`（Reactor 嵌 token，RID 一变就 Token not valid）
3. 注入引用只复用模块既有 MemberRef/AssemblyRef，禁止跨运行时 Import
4. restoresnap 恢复 List<T>：Add 引用按声明类全名精确匹配
5. 官方签名绝不能单独上（cilantro 体 + 官方 locals 错位 → Dictionary wrong number of generic arguments）
6. v133/v134 对 ArgumentGateway 全类 NOP = InvalidProgramException，禁止；v132 为基线
7. 验收只认 `tools/ci/probe.ps1`（ui-probe workflow），ci/probe.ps1 结论不可比
8. CI 探针必须带超时；bootcfg workflow 里有现成的 cdb/sxe/procdump 模板

## 五、可复用于任何线的已验证知识

- TrackCompiler 机制全解（`board/agents/wb-reverser.md`「门闩链真解」等章节）
- ITP(06004196) `new Dictionary` 覆盖 m_LogicalProcessorMap → 之后 TrackCompiler 必 KeyNotFound（v140 启动 43 个 vs 官方 0 个）
- nbjit 强抓天花板 = 16598/33130；failed 名单只能 TTD 精准补（PrepareMethod 链已验证可跑）
- SearchAdapter 状态机全解、门闩链（SetPreferredAppMode）全解 —— 见 board/agents/wb-reverser.md

## 六、A 线（当前主线）对 C 线资产的复用点

| A 线需求 | 复用资产 |
|---|---|
| 激活直通（A2/A1） | tokmap 定位 `ExpandableCommand/<AssertValidLicense>d__8::MoveNext (06000CEE)`（**明文 150 条 IL**，无需还原）；Portable.Licensing 公钥字节串在 IL 中 |
| 数据便携（A3） | tokmap 定位 `Environment::GetFolderPath` (0A000159) 及 4 个调用类 |
| 暗桩扫描 | strmap 特征词、3266 委托表找 Timer 回调、xref 工具 |
| 长稳验证 | injectlog 注入模板 + bootcfg cdb 模板 |
