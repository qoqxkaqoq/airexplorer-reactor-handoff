# AGENTS.md — AirExplorer 逆向恢复工程 · 全体 Agent 目标与约定

> 更新：2026-10-24 (Asia/Shanghai) · 维护者：wb-reverser
> 本文件是所有接手 agent 的第一入口。
> **2026-10-26 起当前状态与战果见 `agent.md`（原 board/ 留言板已删除，全文在 git 历史）。本文件保留立项期目标与约定。**
历史细节见 `HANDOFF.md` 与 `docs/PROGRESS_wb-reverser.md`。

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
| C 线脱壳重建 | 🗄️ **已归档**（`docs/ARCHIVE_c-line.md`；最高产物 v140：进程活、进消息循环、0 窗体；全量真体 dump ×16598+EH ×2218 已入库 `work/dump_official_16598.zip`） |
| 窗体创建点之谜 | ✅ 已解并归档（InitializerReg=ApplicationContext，ctor 空壳是根因——重启 C 线先读归档文档第二节） |
| **A 线：激活/便携/暗桩目标定位** | ✅ 详见 agent.md（AssertValidLicense 明文、GetFolderPath 入口） |
| A 线：三路扫描（xref/字符串/委托回调） | ✅ dscan 全量扫 16598 真体完成：激活=3 布尔字段门控、BC/字符串路径证伪、GFP 9 点、暗桩清单（见 agent.md） |
| A 线：A1 激活包 | ⛔ **补丁逻辑完成但宿主死刑**——a1patch 5+1 处全成功（swapped fail=0），但 CI 四连测证明 **nb_original 裸基座就 0 窗 CPU 100% 死循环**（与补丁无关），nb_original 族不可用（详见 board 2026-10-25 节） |
| A 线：壳机制边界 | ✅ 已钉死：baseline 原位全是桩（真体运行时从 3.2MB 负载回填）；dnlib 重写必崩；唯一文件级路=负载密文 known-plaintext 重加密（需解 token→(offset,len,key) 表） |
| A 线：tamper 验证实验 | ✅ 间接完成：nb_original+6 补丁存活 150s 无自毁（壳不杀文件改动，但也没用因为宿主本身 0 窗） |
| A 线：A3 便携化 | ✅ **launcher 方案 CI 全验收通过**（run 40115006727）：`portable/AirExplorer_Portable.cmd` 重定向 USERPROFILE/APPDATA 等到 exe 旁 `data\`，官方 exe 零修改零注入；Accounts.xml 等用户数据落 data\、真实 profile 零残留、主窗完整渲染（MAIN_CONTENT=CONTENT）；依赖集固化 `portable/deps.zip` |
| A 线：负载解密 | ✅ **重大突破（10-25）**——Reactor 运行时 PRNG keystream 完全破译并验证 3266/3266（`work/decrypt_prng.py`）；6 资源读取链全摸清：2.33MB 主库由 `0600428A WrapperProvider::WrapCommonSorter`（23KB IL、420 块平坦化）读取，**解密循环在它自己体内**（RandomDecryptor 只是 BinaryReader 转发壳）；解密输出 → Deflate 解压 → 反射跳板调用 |
| A 线：回填机制破译 | ✅ **v4c 实锤（10-25）**——回填 = 托管 IL 调 `Marshal.WriteInt32`（调用链：驱动器方法 → `060041FA VerifyCustomIteratorRunner` 19B 壳 → mscorlib_ni NGEN）；负载流对连续 0x00 游程跳过（r10 读游标 +4/写、rbx 条目偏移、条目头 10B）；**驱动器方法本体 MISSING from dump**（060041FA 无静态调用方）；负载流 ≠ 资源原文件（37 已知明文 dword + 全偏移 prng 链扫描三连证伪）→ 细节见 agent.md 第 VIII 段 |
| A 线：主库明文导出 | ✅ **interp.py 282M 步跑通（10-25）**：deflate-input 与资源等长（流变换）→ 解压 4260864B = **完整 PE 程序集**，但内容 = **626 嵌入资源的卫星包**（1 类型 0 方法，UI/本地化），不含激活逻辑；keystream 全程已知、可同尺寸回写 |
| A 线：暗桩清理 | ⏳ 依赖负载重加密路线（暗桩在加密体里，文件级改不到） |

**A 线激活直通的落地路径（10-25 v5 更新）**：**v5 战术 = TTD 回放态 SOS `!dumpil`/`!ip2md` 直接读回填后的解密 IL**（不需要 GC heap，绕开 dumpheap/clrstack 回放态限制）：P3 用 writerIP bp 命中后 `!ip2md` 栈上 JIT 帧 → 拿驱动器方法 MethodDesc + 完整 IL（静态读密文流结构+key 推导）；P4 `!dumpil <BASE> <token>` 直读 dump-MISSING 方法（06003909/06002BD1）真体 → 离线实现负载 decrypt/encrypt → A1 五补丁重加密 → 单 exe 启动即 Pro。CI 长稳验收用 `.github/workflows/a-soak.yml`（`ci/soak.ps1`，7 分钟进程活+窗在+无错框，已 PASS）。

**⚠️ 历史修正**：旧记录"v139 主窗口完整渲染 ✅ / Register account 对话框 ✅"**已证伪**——带截图的成功 run（40088489266）`_candidate.txt = candidate: official`（官方基线），v139 真实 ui-probe = windows=0。勿再引用。

## 🧰 数据资产（史上最全，直接可用）

| 资产 | 位置 | 说明 |
|---|---|---|
| 官方解密方法体 ×16598 | `work/dump_official_16598.zip`（run 39864750444 归档） | 24B 头：tok/ilSize/maxStack/ehCount/preExtra/localsTok；forcedump failed 名单不在其中 |
| 官方 locals ×8392 | `work/loc_official.zip` | 每行 `index\|isPinned\|TypeFullName`（运行时 CLR 格式） |
| 官方 EH ×2218 + catch 名 ×34 + manifest | `work/eh_official.zip` | 28B CORINFO clause；classTok 可 ResolveToken 100% 命中 |
| 主武器工具 | `tools2/bodyswap.cs` | **体+locals+EH 三件套一体替换**（唯一安全姿势） |
| 诊断工具 | `tools2/metadiff.cs, methodtok.cs, tokmeth.cs, typedump.cs` | 见源码头注释 |
| PRNG 破译 | `work/decrypt_prng.py` | `prng_round/keystream/decrypt/encrypt`，3266/3266 验证；known-plaintext 重加密的核心 |
| 平坦化线性化 | `work/flat.py` | `python3 work/flat.py <dumpfile> [stateVar] [switchVar] [out]`；0600428A 走通 389/420 块 |
| 具体解释器 | `work/interp.py` | 0600428A 专用，跑到 DeflateStream 导出 `/tmp/mainlib_*.bin`；新 token 加进 BUILTINS/ARITY/AR 三张表 |
| 原位 IL 验证 | `tools2/peekil.cs` + `peekil8.csproj` | 读 exe 原位 IL，判定"哪些方法原位即真体"（如 06004264） |
| 资源清单解析 | `work/reslist.py` | cor20 资源区逐条列出（名字/大小/熵）——"3.2MB 负载"=6 个伪名资源 |
| 对齐无关 PRNG 探针 | `work/probe_prng_al.py` | numpy 向量化 prng_round，1 字节对齐全扫负载（XOR 直解 IL 假设证伪工具） |
| 反汇编 | `tools2/disasm8.csproj`（产物 disasm8.dll） | `dotnet disasm8.dll <exe> <dumpDir> <tok|--str s>`，dump 真体完整反汇编 |

## ⚠️ 已实证的硬约束（违反必炸，别再踩）

1. **官方签名绝不能单独上**——cilantro 体 + 官方 locals 错位 → `Dictionary\`2 wrong number of generic arguments` 启动即崩。必须 bodyswap 三件套一起。
2. **dnlib 写盘必须 `PreserveAll | KeepOldMaxStack`**——Reactor 的字段初始化数据里嵌着原始 token，表 RID 一变就 `Token not valid`。
3. **验收只认 `tools/ci/probe.ps1`（ui-probe workflow）**——`ci/probe.ps1`（ui-verify 用）启动方式不同且不关对话框，v66/v59/v70 在它下面全显示"无窗"，**结论不可比**（对照实验 run 39882798316）。
4. **nbjit 的 VMT hook 从未工作**——force 模式的 dump 全是 managed 层 forcedump 写的。抓"执行流方法"（forcedump failed 名单，如 `RequestVerifierTransformer::.ctor 06003909`）**只能靠 TTD**。
5. **网络**：git 直连不通走 `https://p.xixky.eu.org/https://...`；API 直连可用但认证被掐时用 `GH_API_BASE=https://p.xixky.eu.org/https://api.github.com python3 scripts/gh_sync.py push`；artifact 下载需 302 location 原样拼代理 + `--path-as-is` + **不带** Authorization。
6. **手工 IL 字节里的 token 是小端**：0x0A000188 → `{88 01 00 0A}`。写成 `{88 01 0A 0A}` = rid 越界 → bodyswap `[bad-operand]`。报 null operand 先查字节序。
7. **bodyswap ParseType 兼容两种泛型格式**：紧凑 `Dict`2[[A]][[B]]` 与 CLR 运行时完整 `Dict`2[[A, asm],[B, asm]]`（块内多参数，分隔符=平衡点上的 `],[ `）→ loc_official.zip 的 .loc 可直接用。
8. **baseline(A12B5C57) 原位全是桩**：官方 exe 的保护方法原位 = `nop;nop;nop;ret` 族桩，真体运行时从 .text 0x620000~0x920000 的 3.2MB 加密负载解密回填内存。**dscan one 的反汇编来自 dump 不是 exe 原位**，别再被它骗。
9. **nb_original 是塌缩坏宿主**：裸基座 CI 0 窗 CPU 100% 死循环（150s 不停）。它 + 任何补丁 = 全灭。唯一 CI 验证能出窗的官方 exe = `exes/AirExplorer_baseline_verified.exe`（A12B5C57）。**安装器误判已纠正**（board 10-25-II）：官网安装器（md5 1d1a829e）实测完整——解出 A12B5C57 主程序+全套依赖；之前"新安装器解不出主程序"是**下载截断**，官网下载路径仍可用（保险起见 deps 已固化 `portable/deps.zip`）。

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
