# AGENTS.md — AirExplorer 逆向恢复工程 · 全体 Agent 目标与约定

> 更新：2026-10-24 (Asia/Shanghai) · 维护者：wb-reverser
> 本文件是所有接手 agent 的第一入口。历史细节见 `HANDOFF.md` 与 `docs/PROGRESS_wb-reverser.md`。

## 🎯 当前目标（业主 2026-10-24 确认，方向已变更）

**只做 A 组：在官方 exe 上做静态改版，交付单个可用 exe。三个需求：**

1. **激活直通**——任何情况下激活校验成功（方案：A2 公钥替换+自签 License，退路 A1 IL 判定直改）
2. **数据便携**——用户数据放 exe 启动目录 `data/`（方案：A3 `Environment::GetFolderPath` MemberRef 重定向）
3. **暗桩清理**——找出并处理所有隐藏校验/降级点（先三路扫描，再逐点处理）

**方法约束（业主确认）**：放弃注入类方案（杀软误报）；放弃 B 组旁路；**C 组脱壳重建归档**（见 `docs/ARCHIVE_c-line.md`），资产保留、不再投入。

**A 线验收标准**：官方 exe 改后（1）正常启动出窗、功能与官方一致；（2）激活校验恒通过；（3）数据落 exe\data；（4）暗桩清单处理完且长稳验证通过。

## 📍 当前状态（2026-10-24 · 方向变更日）

| 里程碑 | 状态 |
|---|---|
| 文本模式 `help`（16 命令） | ✅ PASS（v59 起，C 线遗产） |
| C 线脱壳重建 | 🗄️ **已归档**（`docs/ARCHIVE_c-line.md`；最高产物 v140：进程活、进消息循环、0 窗体） |
| 窗体创建点之谜 | ✅ 已解并归档（InitializerReg=ApplicationContext，ctor 空壳是根因——重启 C 线先读归档文档第二节） |
| **A 线：激活/便携/暗桩目标定位** | ✅ 详见 board/agents/wb-reverser.md（AssertValidLicense 明文、GetFolderPath 入口） |
| A 线：三路扫描（xref/字符串/委托回调） | ✅ dscan 全量扫 16598 真体完成：激活=3 布尔字段门控、BC/字符串路径证伪、GFP 9 点、暗桩清单（见 board） |
| A 线：A1 激活包 | ✅ 出包成功 swapped=6 fail=0（`exes/AirExplorer_A1lic.exe`，tools2/a1patch.cs），⏳ 待 ui-probe CI 验证 |
| A 线：tamper 验证实验 | ⏳ 待做（官方 exe 改 1 字节 → CI 启动测试；A1lic 本身就是官方派生改体，CI 结果同时回答 tamper 问题） |
| A 线：A3 便携化 | ⏳ 待做（9 个 GetFolderPath 调用点重定向 exe\data，清单见 board） |
| A 线：暗桩清理 | ⏳ 待做（DispatcherInitializer 8 Process 反射 + 06004194 Debugger + Timer，清单见 board） |

**⚠️ 历史修正**：旧记录"v139 主窗口完整渲染 ✅ / Register account 对话框 ✅"**已证伪**——带截图的成功 run（40088489266）`_candidate.txt = candidate: official`（官方基线），v139 真实 ui-probe = windows=0。勿再引用。

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
6. **手工 IL 字节里的 token 是小端**：0x0A000188 → `{88 01 00 0A}`。写成 `{88 01 0A 0A}` = rid 越界 → bodyswap `[bad-operand]`。报 null operand 先查字节序。
7. **bodyswap ParseType 兼容两种泛型格式**：紧凑 `Dict`2[[A]][[B]]` 与 CLR 运行时完整 `Dict`2[[A, asm],[B, asm]]`（块内多参数，分隔符=平衡点上的 `],[ `）→ loc_official.zip 的 .loc 可直接用。

## 🗺️ 路线图（A 线，按优先级）

1. **三路扫描**（只读，产出暗桩候选清单）：
   - ① xref：`06000CEE <AssertValidLicense>d__8::MoveNext` + `CommandVSLicenseStatus`(0200058B) + `ModelAccountLicenseSource`(020005D7) 全部调用点
   - ② `work/strmap.tsv` 特征词（trial/expired/unregister/limit/watermark/purchase/days）
   - ③ 3266 委托绑定表反查 Timer/DispatcherTimer/SystemEvents 回调
2. **读 06000CEE 的 150 条 IL**：判定本地/联网校验、定位公钥字节串与判定分支
3. **tamper 验证实验**：官方 exe 改 1 无害字节 → bootcfg CI 启动测试（决定 A1/A2 落地方式；官方派生链注入过 7 方法可跑，预期无 tamper）
4. **GetFolderPath 调用点清单**（0A000159 xref）→ A3 重定向实现
5. **一次出包**：激活 + 便携 + 暗桩逐点，全部改完出单个 exe → bootcfg/ui-probe 验证
6. **长稳验证**：injectlog 挂所有校验点，跨天/改系统时间跑，确认无残余暗桩触发

（C 线原路线图已归档至 `docs/ARCHIVE_c-line.md`）

## 🤝 协作约定

- 每人只写自己的 `board/agents/<name>.md`；结论性发现**必须**写进留言板（这是留言板存在的唯一理由）
- 新 exe 命名 `AirExplorer_<方案名>.exe` 放 `exes/`；push 用 `scripts/gh_sync.py`（见上方网络约束）
- 产物验证一律 `ui-probe` workflow（candidate 传 `exes/xxx.exe` 路径）
