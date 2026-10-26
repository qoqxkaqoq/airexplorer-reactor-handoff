# C 线第二步 — 方法体还原与清单报告（IL_REPORT）

日期：2026-10-26 ｜ 产物根：`work/c2_pack/` ｜ 基线：`airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe`（md5 a12b5c573e1b54e98cccc29351eaa066，9668976 B，全程只读未改）

数据来源（均本轮实测）：
- `work_a1/dec_Viewer.bin`（356328 B，与 C 线第一步产物 `work/c2_pack/dec/dec_Viewer.bin` 逐字节一致）
- `airexplorer-reactor-handoff/work/dump_official_16598.zip`（官方 JIT 全扫 dump；MANIFEST 载明 source exe md5 与基线相同，即本 exe 的运行期真体）
- `airexplorer-reactor-handoff/work/mdrva.py`（按任务书要求实际调用）
- `work_a1/ildis.py`（反汇编引擎；其单字节码表 0x11–0x1F 段有错，本轮在驱动脚本内修正后使用，见 §5）
- 生成脚本：`work/c2_pack/c2_step1_parse.py`、`c2_step2_bodies.py`、`c2_step3_dis.py`；数据：`c2_step1.json`、`c2_coverage.json`、`c2_step3.json`

---

## 1. 覆盖率（可还原方法数 / 总数）

| 口径 | 数量 | 说明 |
|---|---|---|
| MethodDef 总数 | **30886** | mref/mdrva 同一算法解析 #~ 表 |
| RVA==0（无方法体：抽象/运行时实现等） | 7956 | 不存在可还原体 |
| RVA≠0（有体方法） | **22930** | 还原目标域 |
| **可还原（完整 IL）** | **22165** | = JIT dump 16598 + exe 明文槽 5567 |
| 部分还原（vault 条目 + 槽尾，前 4B 票据洞） | 765 | vault 条目 ∩ dump 缺失（含已知 forcedump 缺口 06002BD1） |
| 不可还原 | 0 | — |

- **可还原率：22165/30886 = 71.76%（全方法）；22165/22930 = 96.66%（有体方法）；计 765 部分还原则有体方法 100% 至少拿到 vault 元数据+槽尾**。
- 产物：`work/c2_pack/bodies/<RVA6大写>.bin`×22165（完整体）+ `<RVA6>.partial.bin`×765；清单 `bodies_manifest.tsv`（rva/tok/name/source 四列）。
- 交叉验证：`bodies/3FAFD0.bin`（06004192）与上一会话 `work_a1/a3_il_06004192.bin` 逐字节相同；`bodies/3FDE7C.bin`（0600419C）同 ✓。校验器系 5 方法（4192/419C/4198/41A2/41A3）exe 明文槽 IL 与 JIT dump IL **逐字节一致**（本轮 cmp 实测）。
- mdrva.py 实际调用：23 个重点 token 全量运行（输出存 `mdrva_key_methods.txt`）；另随机抽 1000/5106 个 vault token 批量过 mdrva.py，token→RVA→名字 **1000/1000 全对**，证明 vault_index.tsv 映射无偏。

## 2. dec_Viewer.bin 条目表结构（本轮逆向 + 双源验证）

条目节律（锚定 RVA 后逐字段验证）：

```
[RVA:4][t1:4][fat0:4 = maxstack<<16|fatflags16][t2:4][locals:4 (0 或 0x11xxxxxx StandAloneSig)]
[body8:8 = ticket4 + 真IL首4字节]
若干 block: [ptr:4][ndw:4][ndw 个 dword]     ← ndw 多为 2（16B 单元），末块 ndw=3 或 5
（紧接下一 entry 的 RVA，即任务书所述 nxtRVA 节律）
```

- 锚定判据：dword∈MethodDef RVA 集 ∧ fat0&0xFFFF∈{0x3003,0x300B,0x3013,0x301B} ∧ locals==0 或表号 0x11。
- **实测有效条目 5106 个，RVA 零重复**；条目长直方图 56×3174 / 88×1013 / 72×313 / 104×172…（全文件 4016/5106 条可被 block 流无残差解析完）。
  注意：任务书估计"约 9153 个 RVA"无法复现——全文件对齐扫描共 7229 个 MethodDef-RVA dword（7228 个不同值），其中 2123 个是 IL 常量误中，真条目 5106。此差异如实记录。
- **双源结构验证**（vault ∩ JIT dump = 4341 条）：
  - fat0 的 maxstack == dump maxstack：**4341/4341（100%）**；
  - body8[4:8]（真 IL 首 4 字节）== dump IL[4:8]：**4338/4341（99.93%）**；
  - 整体重装 `[vault 4B] + [exe 槽 +20 起] == dump IL[4:]`：**4216/4341（97.1%）** → 证实"方法体散布存储"：exe .text 槽 = tiny 桩 + 零垫 + IL 尾，vault 条目补真 IL 前 4 字节，运行期由 Necrobit 还原（dump 头部前 4 字节为 ldc.i4 票据，如 `20 7d f4 8d`）。
  - 125 条不匹配均为**单字节洞**：exe 槽里是 0x00、dump 里是被运行期填回的值（例 0600012A@rva 0x4D48：`25 3a 00…` vs `25 3a 12…`）；这些洞字节不在 vault 条目 block 里（逐例查证 il[8:12] 均不命中），填充源未定位（疑 Proc 资源）——这 125 个方法的完整体仍由 dump 提供，不影响覆盖率。
- vault fat0 的 locals token 与 dump 头 localsTok 字段不一致（37/4341）——dump 的 localsTok 字段基本恒 0（forcedump 未捕获），vault 的 0x11xxxxxx 才是权威值；fat 头 = vault(fatflags|maxstack|locals) + dump(ilsize)。
- 产物：`vault_entries/<RVA6>.bin`×5106（原始条目字节）+ `vault_index.tsv`（rva/tok/name/pos/size/fat0/maxstack/locals/ticket/chunk/block 形状）。

## 3. 重点方法反汇编结论（`work/c2_pack/dis/`×23 文件，ildis 引擎+修正码表+token/字符串注记）

### 3.1 校验器系
- **06004192 InstantiateGlobalCalculator**（rva 3FAFD0，IL 8970B，exe 明文槽）：含 `System.Security.Cryptography.CryptoStream::.ctor`、`RSACryptoServiceProvider::.ctor`（IL_2222/IL_22A9）——即已知 SHA1/RSA 验签校验器#1；大量调用 DispatcherInitializer 微型助手（ValidateSequentialSpec×12、CheckIdentifiableConfig×5、VerifyVerifier×4…）。
- **0600419C DefineEfficientProfiler**（rva 3FDE7C，IL 37072B，exe 明文槽）：IntPtr 构造×21、ToInt64×20、Assembly.get_Assembly×8，资源名字符串族 "CloudClient.Clouds.CloudNaver.Properties.Resources" 等——vault/资源装载机制本体（解密器），与 A2 简报一致（改动红线，本轮只读）。
- **06004198 InstantiateSegmentedRunner**（IL 311B）：IntPtr.Size 分支 + Marshal.ReadInt32/ReadInt64 + Hashtable.get_Item——native 桥（驱动器数据区查表）。
- **060041A2 FormatContainer / 060041A3 UpdatePredictor**（IL 97/85B）：`keogyBbmx(060041A6)` → 拼资源名 → `StopClient(0600419F)` → `VerifyScopeAnnotationInspector(06004284)`(native 导出解析) → `Marshal.GetDelegateForFunctionPointer` → 缓存委托后 Invoke——native 函数托管桥（与 s26 结论互证）。

### 3.2 06004194（Debugger.IsAttached）
22B，vault-backed（exe 槽为 tiny 桩，dump 还原）：
```
call System.Diagnostics.Debugger::get_IsAttached
brfalse ret
ldstr "…Properties.Resources…"  newobj System.Exception::.ctor  throw
```
→ 反调试绊线：调试器在场即抛异常。位于 DispatcherInitializer(TypeDef#1570, CloudClient.Templating)。

### 3.3 便携化 GFP（Environment.GetFolderPath）调用点 9 处全实证
| token | 方法 | SpecialFolder 参数 |
|---|---|---|
| 060028BF/060028C0/060028C1 | ExecuteFormatter/DirectEngine/SumScopeChooser | 40 UserProfile |
| 06002AF6 / 06001260 | InstantiateExtendedInspector / IncludeWriter | 26 ApplicationData |
| 06002CC2 | SolveBuilder | 0 Desktop |
| 06002F2F | RunPolicy（5 处） | 13 MyMusic, 16 DesktopDirectory, 17 MyComputer, 39 Pictures, 5 MyDocuments |
| 06003D01 | SumOrderedManager（2 处） | 17 MyComputer, 16 DesktopDirectory |
| 060004AA | RequestAdvancedCompressor | 37 System |

全部为 `ldc.i4(s) N; call 0A000159 System.Environment::GetFolderPath` 直调（无反射包装），静态改写可行性与 mainlib 管线（a2_build）互补。

### 3.4 DispatcherInitializer 系 8 个 Process 反射方法（与 wb-reverser.md:826 清单逐一对上）
各为 7–10B 的单属性探针 thunk（疑经 zdec/Project.bin 委托绑定表被运行期串成进程/模块自检）：
| token | 方法 | 探针 |
|---|---|---|
| 060041FF | ReplaceUser | Process.GetCurrentProcess |
| 06004200 | ValidateFlexibleErrorSpec | Process.MainModule |
| 06004201 | OpenService | ProcessModule.BaseAddress |
| 06004208 | TestVerifier | Process.Modules |
| 0600420B | ValidatePassiveFormatterEngine | ProcessModule.ModuleName |
| 0600420E | AssessCompressor | ProcessModule.FileVersionInfo |
| 0600422D | ValidateInterruptibleCacheAuthorizer | Process.Id |
| 0600423E | AdaptWriter | ProcessModule.ModuleMemorySize |

另注：该类型内真正的重反射方法族为 0600418C(Activator.CreateInstance)/06004193(Delegate.CreateDelegate+FieldInfo.SetValue)/06004196(Type.GetMethod)/0600419B(MethodBase.Invoke)/0600419D(PropertyInfo)/06004206(Type.GetType)（0600419C 亦含 GetType+GetField，已归校验器系），如需可按同管线补拆。

## 4. dec_Proc（work/c2_pack/dec/dec_Proc.bin）处理结果

- 文件**存在**（C 线第一步产物，47915 B）——但按其 README/日志：**未解密、原样 passthrough**（Proc key 未知；熵 6.177 b/B，远低于真密文 Viewer/Project ct 的 7.999/7.994）。
- 本轮用 Viewer 同款条目签名（RVA 锚 + fat0 + locals 判据）扫描：**0 个条目锚**（对照 Viewer 同扫描 5106）→ 当前字节不构成方法体条目表，**不向覆盖率贡献任何方法体**。
- 头部形态：2B 头 0x9C3A + 47913B（奇数）主体；k26 曾判其为 (tag,值) 字节对流、条目量级≈方法数（23924）——与"逐方法混淆参数表"假说相容，但 key 未得前无法证实。**Proc/Emitter 维持"不可解"状态**。
- 对照：`dec_Project.bin` == `work_a1/zdec/Project.bin`（零 key，委托绑定表）；`dec_Factory.bin`/`dec_mainlib*.bin` 与已知产物一致；`dec_Viewer.bin` == `work_a1/dec_Viewer.bin`（cmp 实测）。

## 5. 工具修正与复现说明（如实）

- `work_a1/ildis.py` 单字节码表 0x11–0x1F 段整体错位（如 0x14 标成 ldc.i4.0，实为 ldnull）且缺 0x27/0x70/0x71/0x76/0x7A/0xC2/0xC6/0xE0；本轮在 `c2_step3_dis.py` 内对 ildis.OPS1 注入修正（以 handoff/work/flat.py 的规范表为准，即上会话 a3_dis_* 的同款表）后调用其 `disasm()`，未改 ildis.py 原文件。
- ldstr 注记为尽力解码：本 exe #US 堆为混淆/交叠布局，取多对齐×LE/BE 最长可打印前缀（如 0x70000ADC → "…Properties.Resources"）；报告结论不依赖具体串文本。
- `mdrva.py` 输出 token 印成 `0600004192` 形（'0600'+%06X 的拼接瑕疵），rid=去前缀后 6 位十六进制，本轮解析按此校正；RVA/名字无碍。
- dump 头 24B 实为 [tok][ilSize][maxStack][ehCount][preExtra][localsTok]（MANIFEST），ildis.py 只读 ilSize/maxStack/eh 三项，未用字段不影响其输出。

## 6. 产物清单

```
work/c2_pack/
  IL_REPORT.md                 本报告
  bodies/                      22930 文件：22165 完整体(<RVA>.bin) + 765 部分体(<RVA>.partial.bin)
  bodies_manifest.tsv          rva\tok\tname\tsource
  vault_entries/               5106 个 vault 原始条目 <RVA>.bin
  vault_index.tsv              条目索引（含 fat0/maxstack/locals/ticket/chunk/block 形状）
  dis/                         23 个重点方法注记反汇编 <tok>_<name>.il
  mdrva_key_methods.txt        mdrva.py 对 23 重点 token 的原样输出
  c2_step1_parse.py / c2_step2_bodies.py / c2_step3_dis.py   全部可重跑
  c2_step1.json / c2_coverage.json / c2_step3.json            机器可读结论
```
