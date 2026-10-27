# AirExplorerUnpacker — 进度账本（tools3/unpacker）

> 汇报纪律：每步结论/产物即时写盘 + push。PASS/FAIL 只认门禁脚本输出。
> 立项书：`docs/UNPACKER_PLAN.md`；总览：`agent.md`。
> 本文件由 Linux 侧 agent 维护（2026-10-26 会话）。

## 环境与工程

- Linux + dotnet SDK 8.0.427（dotnet-install 装于 /usr/share/dotnet）+ NuGet **dnlib 4.4.0**（未用 NRS 捆绑 net472 dnlib）
- 工程：`tools3/unpacker/AirExplorerUnpacker.csproj`（net8.0）+ `Program.cs`（CLI）
  - 子命令：`inspect`（模块体检+manifest 对齐）、`s1`（体注入）、`ehprobe`（EH 解析实验）、`checksig`（dummy/签名统计）、`scanil`（null operand 扫描）、`tokinfo`（方法元数据）、`dumptype`（类型细节）、`scansem`（跨类型 Property/Event 残留）、`scanmi`（MethodImpl 归属）、`bodyhex`（体重线性化）
  - 独立子工程 `VerifyTypes/`（MetadataLoadContext 全类型加载验证；主 csproj 已 `Compile Remove` 排除）
- 仓库 clone/push 走代理前缀 `https://p.xixky.eu.org/https://github.com/...`（直连 github.com:443 间歇挂死；token 已拼 remote URL）
- CI：`.github/workflows/unpacker-gate.yml` 双段（ubuntu 构建 S1 → windows-2025 反射加载诊断 + ILVerify + probe_iso + soak_iso）；支持 `only_tokens` 输入做对分定位

## 数据源定案（全部经全量交叉验证）

| 数据源 | 内容 | 权威性验证 |
|---|---|---|
| `work_a1_pack/memdump/module_text.bin`（9,596,928B） | **运行时模块 dump，方法布局偏移 = RVA − 0x2000**。含每个 manifest 方法的运行时方法头与运行时 IL | ① 头解析 22930/22930（tiny 12476 + fat 10454）；② locals token 全部合法（rid ≤ 3174）；③ **IL 与 JIT dump 全量逐字节全等（dump_full 16598/16598）**；④ codesize vs zip ilSize 全等 |
| `work/dump_official_16598.zip` | maxStack/ehCount + **CORINFO EH（28B/条）** | EH 是 Necrobit 方法运行时真实 EH（mt 的 EH 区=磁盘票据不可用）；与磁盘明文槽 0x41 段双源一致 |
| `work/loc_official.zip` + `work/c2_pack/vault_index.tsv` | locals 备用源 | 本轮未用（mt 运行时头的 locals token 全覆盖，8049 缺口问题消解） |

### 关键真相（血泪，勿重推导）

1. **c2_pack 的 `slot_plaintext` 5567 里有 905 个假体**（磁盘槽是 stub，slot_body 解析出垃圾）。S1 一律用 mt 运行时体。
2. `vault_partial` 765 的完整真体也在 mt 里——部分体问题消解。
3. **NRS rem-junks 的破坏清单**（S1 必须逐一修复，详见修复历史）：
   - 建 3 个 dummy 类型收容 203 个方法（177 个在 manifest），**签名改坏 + ParamDef 参数行删除 + Attributes 改 abstract + 无体**，并**删除调用点**
   - **删除了 673 个类型**（TypeDef rid 错位，不能盲 resolve token）
4. **dnlib 写盘三大坑**（全部实测）：
   - fat 头 maxstack 是完整 16 位（不是 >>12）
   - `CreateCilBody` 手动重载的 ehData 格式：**flags 字节低 6 位必须=1、0x40 位=fat**（即 fat=0x41），**dsize 不含 4B 段头**
   - `Importer.Import(MethodSig)` 丢调用约定位；跨模块 TypeDef 会被转成**自引用 TypeRef**（坏引用）
   - `md.Parameters` 是懒缓存，签名恢复前若已物化则不反映新签名——需手工构建参数绑定列表
5. **CORINFO EH 与 CLI EH 的 flags 差异**：CORINFO fault=**3**，CLI fault=**4**，原样透传=InvalidProgram。

## S1 当前统计（`out/s1_report.txt`）

```
injected=22930 fail=0 no-tok=0 bad-body=0 eh-dropped=53
sig-restored=175 attr-restored=177
type shells added=673（NRS 删除的类型补壳）
产物: out/m1_s1_full.exe（~9.37MB）
自检: MethodDefs=30912、entrypoint=06002D22、token 对齐 22930/22930、
      fat 10452、总指令数 ~1.11M、StandAloneSig 3174 保留、null operand=0
```

## M1 门禁进展（Windows CI 实测，VERDICT 全记录）

| # | 版本 | 死法 | 结论 |
|---|---|---|---|
| 1 | 首版全量 | FAIL-EXITED(0xE0434352) `InvalidProgramException at .cctor()` | maxstack 全 0 bug（已修） |
| 2 | maxstack 修 + dummy 跳过 | `Abstract method with non-zero RVA` | NRS abstract 位残留（已修：Attributes 恢复） |
| 3 | attrs 解耦 | `The signature is incorrect` | Importer 弄坏签名（已修：手工 token 保真克隆） |
| 4 | 收紧到 dummy 恢复 | `Could not load type 'dummy_ptr'` | NRS 删 ParamDef 行 + 删 673 类型（已修：ParamDef 重建 + 类型壳） |
| 5 | 壳首版 | `Duplicate type '<>c'` | 嵌套类型壳撞名（已修：FullName 展平） |
| 6 | 壳首版2 | 仍 dummy_ptr | 2 个 fail 方法的坏签名拖死类型（已修：失败完全回滚） |
| 7 | **闭包对分**（159 法） | `InvalidProgramException at DefineEfficientProfiler()` | **cctor 与 dummy_ptr 加载已通过**！EH 段格式坑（已修：dnlib ehData 0x41 格式） |
| 8 | 壳全量 | `No Instance Field in an Enum` 等 137 个 | 壳继承 enum/Delegate（已修：壳统一 Object 基类密封类） |
| 9 | 最新全量 | `Could not load type 'dummy_ptr'`（GetTypes 5580/5581） | **仅剩 dummy_ptr 一个类型加载失败**；闭包版已过此关 |

**死法分类结论（M1 判据）**：不是资源缺、不是启动链结构性死——是注入工程细节，已收敛到**唯一类型（dummy_ptr）的 CLR 类型加载验证**这一层。闭包版（159 方法注入）证明：模块级修复（壳/签名/EH）方向正确，cctor 已通过。

## M1 最新定位（CI 成员级诊断, run 40339106106）

- `Module.ResolveMethod` 逐 token 扫描（30912 个）：**bad=205, 全部是 dummy_ptr 的成员**，
  错误统一为 "Could not load type 'dummy_ptr'"（成员解析因所属类型失败而失败）。
- **其余 5580 个类型全部健康**（含 673 个壳）——问题精确锁死在 **dummy_ptr 类型定义本身**。
- **下一棒的锤子方向**（按嫌疑排序，均为 NRS 残留元数据 + 类型表错位的交互）：
  1. **ClassLayout 行**：AutoLayout 类型挂了 ClassLayout 行 → CLR TypeLoad 直接拒
  2. **MethodImpl 行**（显式 override）：class 列指向的基线 TypeDef token 因 673 类型删除而错位
  3. **FieldRVA 行**：129 个 static Byte 字段中带 RVA 的，Field 列错位
  4. **PropertyMap/EventMap**：dnlib 语义视角 scansem=0，但需表级复查
- 工具已就绪：`scanmi`（MethodImpl 表级扫描，dnlib 4.4 表 API 待适配）、`dumptype`、`scansem`、
  CI 诊断步骤（反射 GetTypes + ResolveMethod 逐成员）常驻每轮门禁。

## M1 续（mono 本地调试回路 + 两个关键修复, 2026-10-26 晚）

- **mono 本地调试回路建立**：`mono --verify-all` 拒载（元数据严格校验），但 `mono 直接运行` 能加载到 cctor；
  配合 `/tmp/mhost/host*.exe` 宿主（ResolveMethod 定点 + RunClassConstructor + 异常链展开）实现**秒级 Linux 本地定位**，
  替代 3 分钟/轮的 CI 迭代。注意：mono 的一致性检查比桌面 CLR 严（stloc 类型不匹配它必拦，官方票据 IL 依赖
  full-trust 验证豁免），mono 的 "Invalid IL code" ≠ Windows 死因——但它抓的**签名级错误是真 bug**。
- **修复 9（mono 点名）：签名克隆丢 CorLibTypeSig** —— System.Void 被当普通 TypeDefOrRefSig 重建 →
  写出 ELEMENT_TYPE_VALUETYPE + Void token（应为 ELEMENT_TYPE_VOID）。mono 直接报
  "Could not load signature of dummy_ptr::m004192"。修法：CloneTypeInto 对 CorLibTypeSig 按 ElementType
  映射回 s_mod.CorLibTypes（Void/Boolean/.../IntPtr/UIntPtr 全表）。修复后 mono 签名错误消失。
- **修复 10（RemapResolver）：mt IL 的 TypeDef/TypeRef/MemberRef token 是基线空间**，NRS 删 673 类型后
  Slayed 的 rid 错位（如 castclass 0x02000628 在 Slayed 解析到错位类型、box 0x01000066/0x02000629、
  callvirt 0x0A000025 错位 MemberRef）。修法：IInstructionOperandResolver 包装（RemapResolver），
  对 0x01/0x02 表按基线解析→FullName→Slayed 对象映射（TypeDef 含壳、TypeRef 按全名），0x0A 表按
  "类::名(签名)" key 映射 Slayed MemberRef。
- **GenericParam 排除**：177 个 dummy 方法的 GP 行与基线全一致（checkgp 0 mismatch）。
- **当前 Windows 状态**（run 40346499628，Void 修复+重映射后首次全量实测）：VERDICT 仍
  FAIL-EXITED，dummy_ptr 仍拒载（GetTypes 5580/5581）。**下一步 = dummy_ptr 成员对分**：
  把 177 个恢复方法用 --exclude 分半回滚，log2(177)≈8 轮 CI 定位坏成员；
  或接入 Windows shell 用 peverify 一次列全（见汇报）。

## M1 突破：rid 复用总根源 + 完整恢复（2026-10-26 深夜）

- **mono 谜团解开**：此前 mono "拒载 dummy_ptr" 是假象——`asm.GetType("dummy_ptr")` 抛
  TypeLoadException 只是因为**这个顶层名不存在**（真实类型名是 `dummy_ptr.{GUID}`，含点和花括号）。
  用正确全名测试：**Slayed 原版与 PROD 的 dummy_ptr.{GUID} 在 mono 下完全健康**（类型+203方法+129字段全解析）。
- **减法实验排除了所有静态元数据嫌疑**：ClassLayout/attrs 组合/abstract 残留/GP 行/MethodImpl/
  Property-Event 语义/locals token(10347 全对齐)/EH catch token(1670 全对齐)/FieldRVA(全在段内)。
- **总根源（reuse 命令实测）**：NRS rem-junks 对 **177 个方法 + 129 个字段做了 "rid 复用"**——
  同一 MethodDef/FieldDef token，身份完全替换（`<Module>::GuideCalculator` → `dummy_ptr.{GUID}::m000004`、
  `<Module>::CheckControllableArgumentEnumerator` 字段 → `f000001`...），并把它们全部挂到
  dummy_ptr.{GUID} 下。**mt IL 是基线 token 空间**，call/ldsfld 解析命中 dummy 成员 → 触发加载
  dummy_ptr.{GUID} → 桌面 CLR 拒载（mono 宽松不拒）→ cctor 链死。
- **修复 12（完整恢复）**：对 177 方法+129 字段搬回基线的 DeclaringType（`<Module>` 归 GlobalType，
  其余经 s_tdByFull 壳映射）+ 真名 + 字段签名 CloneTypeInto 重映射。恢复后 **reuse=0**
  （token 语义与基线完全归位），`06000004=<Module>::GuideCalculator`、
  `06004236=DispatcherInitializer::EncryptSolver`（static+真体）全部实证。
- **产物静态验证全绿**：disasm 逐 token 对照基线一致（ldsfld/call/box 目标全对，壳类型替换符合预期）；
  压栈序列与 call 签名匹配。mono 剩余的 "Invalid IL code" 是 mono 对官方票据 IL 的一致性检查
  比 CLR 严（已知特性，不作 Windows 判据）。
- CI run 40365001632 = 完整恢复版首次全量实测。

## M1 终局突破：四大雷连除（2026-10-27 凌晨, run 40371984806）

- **雷 1（修复 12 补充）rid 复用完整恢复生效**：mono 实证 06000004=<Module>::GuideCalculator、
  06004236=EncryptSolver（真名+真归属+真体），reuse=0。
- **雷 2（修复 13）EH 紧凑段格式**：mt 快照的 EH 区是 dump 工具自定义紧凑格式
  （flags2B+tryOff2B+tryLen1B+hOff2B+hLen1B+cls4B，共 12B/子句，段头 flags byte=0x01+dsize3B）。
  三方法（06000288/0600034F/060003AB）反汇编 IL 边界实证全吻合，cls=System.Exception token 合理。
  S1 兜底解析加此分支（带边界校验防误判）→ **eh-dropped 53→0**。
  此前 53 个方法的 try 块悬空 = dnlib GetMaxStack 炸点（bodytest 意外暴露）= Windows BadImageFormat 源。
- **雷 3（修复 14）壳循环 GetTypes 全集**：mod.Types 只含顶层，嵌套类型全部被误判"被删"建壳，
  且 s_tdByFull[FullName]=shell 无条件覆盖真类型映射 → 同一类型双身份（box→壳 class，locals→真 struct）
  → mono/CLR 验证不匹配拒载。修后 **shells 673→2**（真被删的只有 2 个），mono 的
  DefineEfficientProfiler InvalidProgram 立即消失。
- **雷 4（诊断认知）mono 内联 bug**：4 指令小函数（ldsflda+ldarg.0+call
  GetRuntimeTypeHandleFromMetadataToken+ret）被 mono 内联后 intrinsic 上下文坏 →
  ArgumentNullException: Invalid handle。NoInlining 标记后消失。**Windows CLR 无此问题，不需改产物**。
- **mono 环境极限**：cctor 链推进到 GenerateConfigurableSpec 的 kernel32 P/Invoke（Windows-only），
  Linux/mono 无法再深。到此 **mono 已验证：5581 类型全载、DefineEfficientProfiler JIT 通过、
  cctor 运行至 Windows-only API** —— 元数据/IL 层面产物健康。
- run 40371984806 = 全修复后的 Windows 实测。

## M1 雷五（修复 15, run 40374303199）：CORINFO EH 子句乱序

- Windows 死法推进到 `InstantiateGlobalCalculator (06004192)` 的
  `InvalidProgramException: CLR detected an invalid program`（mono 被 kernel32 P/Invoke 挡住没验到此方法）。
- 排除 ldstr 越界（规范边界扫描 27 个 token 全在 #US 范围内；此前的"越界"是粗扫把操作数字节误当指令）。
- **真凶**：**CORINFO EH dump 的子句顺序是 CLR 运行时内部序，直接透传给 CLI 元数据后违反
  ECMA-335 的子句排序规则（必须按 tryStart 升序、嵌套内层排在外层之后）→ JIT 直接拒整个方法**。
  全量统计：**792 个多子句方法中 626 个乱序**（如 06004192 的 tryStart 序 0xA9B,0xBE0,0xFB,0xB51）。
- **修复 15**：三处 EH 构建路径（zip CORINFO 源 / mt fat 兜底 / mt 紧凑兜底）统一按
  `(tryOff asc, tryLen desc)` 排序。
- 附注：mt IL 里仅 27 个 ldstr（官方字符串大部分在 FactoryValidator 加密池，由运行时函数按 token 取回
  —— 即 S2 的回接对象，与 #US 无关）。

## M1 当前死点与证据链（run 40375716905 = 回退排序版, 死点复现确认）

- Windows: `InvalidProgramException at InstantiateGlobalCalculator (06004192)`（cctor 第 2 个调用）。
- **已排除**（每项都有实证）：
  - ldstr 越界（规范扫描 27 token 全合法；早前"越界"是粗扫误报）
  - 指令流差异（fulldiff 06004192 = 2521/2521 条 0 差异；调用链 060041D1/D2/D3/D4/06004264 全 0 差异）
  - EH 边界（4 子句全在指令边界）、CatchType 身份（0200003D 三方一致 = ExtendedProxy/<>c，类型存在健康）
  - locals 对齐、签名/attrs 恢复、rid 复用、类型壳、ImplAttributes 差异(NoInlining 无碍)
  - ILVerify StackUnexpected = 噪音（官方代码依赖 full-trust 跳过验证，基线同样报）
- **EH 排序已回退**：CORINFO 原序满足 ECMA「内层在外层前」硬规则（run 40371984806 证明 0600419C 通过），
  tryOff 升序反而破坏嵌套关系（run 40374303199 死点前移到第 1 个方法）。
- **疑点收敛**：方法内容与基线一致但 JIT 拒 → 剩余差异只能在「写出层」——dnlib 重新编码的
  方法体头 flags、EH fat/small 选择、#US 重编码、或 cctor 链上其它未 diff 的方法。
- **下一棒工具已就绪**：fulldiff（任意方法全指令对比）——扫 InstantiateGlobalCalculator 的完整
  调用闭包（用 cctor_closure.txt 扩展）；或 bodytest+CI 二分 06004192 体；或对比 dnlib 写出的
  原始方法体字节（raw hex）与 mt 源。

## M1 写出层验证 + bodytest CI 工具链（2026-10-27 凌晨, run 40388322484/40389150972）

- **写出层字节级验证（06004192）**：PROD 原始方法体与 mt 源完全一致——
  head `1b 30 07 00...`（flags=0x301B: fat+InitLocals+MoreSects, maxstack=7）、IL 8970B 逐字节相等、
  EH fat 段 0x41/dsize=100/4 子句一致。（脚本曾把 offset2 的 MaxStack=0x0007 误读为 flags——虚惊。）
- **调用闭包全 diff**：06004192 的 49 个 call 目标（43 个在 manifest）fulldiff **全部 0 差异**。
- **结论**：InstantiateGlobalCalculator 及其调用链与基线**逐指令逐字节一致**——
  Windows JIT 拒的原因不在 IL/方法定义层，剩余嫌疑：
  (a) cctor 链上其它方法的关联状态（再上游）；
  (b) dnlib 写出的其它方法（0600419C/06004194/06000001 的写出层）；
  (c) 元数据表级（Assembly/Module/ManifestResource 等）；
  (d) 某个"运行时取串调用"的参数错位（NRS 字符串加密的运行时函数群）。
- **bodytest_tok CI 工具链就绪**：dispatch 带 `bodytest_tok=06004192` 即空体化该方法再探针
  （注意第一版步骤未拷贝到 cand\ 导致不生效，已修）。
- run 40388322484（bodytest 未生效版，md5 与全量版相同，结果复现死点=回退排序确认）。
- run 40389150972（bodytest 06004192 生效版）= 定位死因是否在该方法体的决定性实验。

## M1 bodytest 实验结果（run 40391057907）与下一棒

- **bodytest 06004192（空体）实验生效**：死点从第 2 个调用跳过 06004192、06004194，
  直达第 4 个调用 **06000001（m8DEEBCC2CD9F727, tiny pop 单指令）**，报
  `BadImageFormatException: Bad IL range`。
- **结论 A**：06004192 与 06004194 的"体"都通过了 JIT——主产物死在 06004192 是**体引用的环境**问题，
  不是方法本身。
- **结论 B**：06000001 = `pop` 空栈单指令（官方同款，官方 cctor 调用它时栈同样为空）。
  `Bad IL range` 是 bodytest 变体布局下的新现象，与主死因独立，暂不追。
- **bodytest CI 工具链三连修**：workflow 步骤路径(cand/)、先构建工具(probe job 无构建产物)、
  写临时文件再 mv(dnlib mmap 占用)。dispatch 示例：`bodytest_tok: "06004192"`。
- **bodyvariant 工具已就绪**（half1/catexc/noeh 三模式）：下一棒对 06004192 做变体二分——
  catexc(CatchType→System.Exception) 判 catch 类型敏感性；noeh(去EH) 判 EH 结构敏感性。
  另可对 06004192 的 0x1B TypeSpec/0x0A MemberRef 做「解析身份」级对比（fulldiff 只比 token 值，
  不比 token 指向的内容——TypeSpec 的泛型实例化内容是剩余盲区）。

## M1 双变体实验（run 40392959428/40392954476）：EH 整体排除

- **catexc**（06004192 的全部 catch CatchType→System.Exception）：死点不变。
- **noeh**（06004192 去 EH + leave→br）：死点不变。
- **结论：06004192 的 InvalidProgram 与 EH 无关**（类型与结构双重排除）。
- bodytest_tok 已支持 `token:mode` 格式（bodytest 空体 / bodyvariant catexc|noeh|half1|half2）。
- **剩余嫌疑（按序）**：
  1. **0x1B TypeSpec 解析身份**（fulldiff 只比 token 值，TypeSpec 的泛型实例化内容是盲区；
     ILVerify 的 "expected ICryptoTransform/Stream" 系列指向泛型调用链）
  2. **#US/字符串运行时取回调用的参数错位**（NRS 字符串加密函数群，S2 范围）
  3. **元数据表级**（- TKCA/ManifestResource/ExportedType 等）
  4. **cctor 链上游（0600419C 的调用闭包）的同类问题**

## 线路1建成：Wine+dotnet48 本地调试回路（2026-10-27 早, 决定性基础设施）

- **Wine 9.0 + wine32:i386 + winetricks 20260125-next + .NET Framework 4.8 全部装成**
  （dotnet48 verb 在 wine9 下需新版 winetricks；prefix 需重建）。
- **本地复现 Windows 死点成功**：`wine AirExplorer.exe` 与 CI windows-latest **一模一样**
  （InvalidProgram at InstantiateGlobalCalculator at .cctor）——**迭代速度 10分钟/轮 → 秒级**。
- **秒级二分实验**（本地跑通）：
  - bodytest 06004192 空体 → 死点移到 06000001（与 CI run 40391057907 完全一致 ✓）
  - excl4（4 个 cctor call 全空体+exclude stub 化）→ 死点进 DefineEfficientProfiler 内部：
    **VerifyProcessor(IntPtr) 的 JIT**（新层暴露）
  - **excl5（06004192+060041A5 都空体化）→ JIT 仍拒 VerifyProcessor**——
    **空体 ret 都被拒 = 死因不在方法体，在方法元数据或声明类型**！
- **PEVerify 上 CI**（.NET Framework SDK 真验证器，run 40418929017）：1245 错误三类——
  Type load failed（系统性）/ Unable to resolve token（ExecutorTree::MonitorTransferableUser offset 0x6B
  可精确查）/ found X expected COMException（token 身份错位）。peverify.log 已入 artifact。
- **VerifyProcessor 是 NRS 运行时代理函数族**（keogyBbmx 取指针 → 动态拼 "Close"+"Handle" →
  StopClient(P/Invoke GetProcAddress 变体) → GetDelegateForFunctionPointer → castclass TemplateBuilder
  → callvirt Invoke）——全链引用与基线 0 差异。
- **下一棒**：DispatcherInitializer 类型全成员 stub 化二分（定位类型内坏成员）；
  060041A5 的 ImplMap 残留检查；PEVerify 的 Unable to resolve token 清单逐个修。

## 全类型 stub 实验（决定性）：死因锁定「写出层布局」

- **DispatcherInitializer 全 219 方法 stub 化** → 死点变为
  `BadImageFormatException: Bad IL range at InstantiateGlobalCalculator()`。
- **两种 stub 化（bodytest 与 S1-exclude-stub）都触发 Bad IL range**——
  **Bad IL range = CLR 读方法 IL 时范围越界（RVA/size 与 .text 段不符）**——
  **这是 dnlib 写出层的布局问题，不是 IL/元数据语义问题**！
- **主线死因（全注入版的 InvalidProgram）极可能同源**：dnlib 写出的方法体区
  存在某处 RVA/大小/对齐错位，JIT 读到坏范围 → InvalidProgram/Bad IL range（随布局而异）。
- **下一棒（本地 wine 秒级）**：写「全方法 RVA+codesize 越界扫描」工具，找出坏方法；
  或对比 dnlib 写出的方法体表与 mt 源；或怀疑 PreserveAll 与方法搬移(rid复用恢复)的
  交互导致 MethodDef RVA 表重排错位——尝试关掉部分 Preserve 选项二分。

## 下一步（按优先级）

1. **成员级定位**：CI 已加 `Module.ResolveMethod` 逐成员诊断（workflow 诊断步骤），下一轮门禁读 MFAIL 输出，精确定位 dummy_ptr 里加载失败的成员
2. **对分收尾**：若成员级诊断不清楚，用 `--only`/`--exclude` 在 dummy_ptr 的 203 个成员上二分
3. **M2**：S2 字符串回接（mt 的 ldstr token 是运行时 #US 偏移；Slayed #US 是磁盘混淆堆——需要建立 token→池字符串映射，池在 `work/c2_pack/dec/dec_Factory.bin`，8539 条 [int32 byteLen][UTF-16]）
4. **M3**：S3 委托重接（zdec/Project.bin 3266 条 [Field 0x04][MemberRef 0x0A|0x4A]）
5. **M4**：S4 资源重嵌（dec/ 4 资源 + mlres 626）+ S5 写出（已有 PreserveAll|KeepOldMaxStack）

## 复现命令

```bash
cd tools3/unpacker && ./build.sh s1
# 闭包对分: dotnet bin/Release/net8.0/AirExplorerUnpacker.dll s1 ... --only cctor_closure.txt
# CI: gh workflow run unpacker-gate.yml -f only_tokens=tools3/unpacker/cctor_closure.txt
```

## 2026-10-27 决定性突破日：主线 InvalidProgram 根因链全部打通

### 新工具链（本轮新增）
- **scanrva**：全方法头/足迹扫描（tiny/fat 解码、section 越界、资源区重叠、OVL 共享/交叉检测）
- **epinfo**：PE 级 EP/section/COR20/import 对比（产物 EP=dnlib 写的 mscoree IAT thunk → Reactor native bootstrap 已绕过）
- **scanres**：全方法全 operand token 解析扫描（30.9 万 token failed=0）
- **tokmap**：mt 原始 IL operand 在官方/产物两边解析身份对比（官方 token 序 vs Slayed token 序）
- **tsmap**：TypeSpec/StandAloneSig/MethodSpec 全表逐 rid 身份对齐（三表 diff=0 ✓ 对齐）
- **sigdiff/diagsig**：签名链身份对比与完整 TypeSig 链 dump
- **attrcmp**：方法级元数据属性全面对比
- **patchstub**：stub/copybody/copybatch/noeh/impl/stubfile/prune 多模式实验平台
- **测试基座**：本地 Wine 秒级复现（先 Wine 后 CI 纪律）

### 根因链（每步有实验证据）
1. **共享 RVA 桩 = 主线 InvalidProgram 根因**：Slayed 骨架把 1.5 万+ 桩方法指向同一 RVA（0x3828 等），
   dnlib 写出时无 CilBody 方法保留旧 RVA 列 → 新文件里 footprint 与邻居交叉 → CLR JIT 拒
   （mono 不拒！CLR 独有校验）。**修复16**：dedup 全量 stub 化（15821 个）。
   → 微实验：两方法共享 RVA 的最小 exe CLR 接受（SHARED_RVA_OK），证明是"旧值残留"而非共享本身。
2. **abstract 残留**：Slayed 剥体方法保持 abstract+无体 → TypeLoad。**修复17**：全局清理（非接口类型）+ <Module> 强制 static/清 virtual。
3. **__ReactorRemoved 壳方法未归位**：官方 06004284=CloudClient.Handling.ObserverValue::VerifyScopeAnnotationInspector，
   产物里留在扁平壳 → call token 解析身份错位（tokmap 首个 mismatch）。**修复18**：非特殊类型的壳用真名+真基类重建
   （enum/delegate/abstract/interface/嵌套仍扁平壳兜底）→ 06004284 已归位真名类型。
4. **当前最后 JIT 拒点 = 06004181（DispatcherInitializer::.cctor）**：99 条、EH1、maxstack4、slot_plaintext 源。
   - 全部静态验证通过：指令/89 operand(EH1 处理后 59 operand mismatch=0)/EH 结构/头/属性（唯一 DIFF=ImplFlags，已证非因素）
   - **mono 完全过 JIT**（死点=运行时层 ArgumentNullException Invalid handle），**Windows CLR 拒** → CLR 独有校验
   - **prune 二分（保留前 N 条+ret）**：N=2/60/65 过（3 次复跑稳定）、N=10/30/62/68/70/80/90/99 拒（重跑稳定）
     → **非单调 = 布局敏感型拒**：.cctor 体大小变化 → 全局布局移动 → 交叉点变化
   - noeh（删 EH+leave→br）后 InvalidProgram 消失（EXIT=5 空异常 ToString 失败 = 更深运行时问题）
   - dupRva 仍有 16017：dnlib 对 identical tiny 体（ret）合并共享（合法）+ 修复16 只清 >2 条组的漏网（已全量化）
5. **S2 层已可见**：mono 下 DefineEfficientProfiler(0600419C) 运行时 ArgumentNullException（BinaryReader null）
   / Invalid handle = 字符串池未回接（dec_Factory.bin 8539 条待接）——**JIT 层在 mono 侧已全通**。

### 下一棒最高价值动作
1. **06004181 布局敏感拒**：suspects = (a) 体区与 PrivateImplementationDetails 数据字段(ldtoken 0400207E→FieldRVA)交叉；
   (b) fat 头 MoreSects 位与 EH 段物理布局；(c) prune=60/65 的"幸运布局"反推交叉点。
   工具就绪：prune 模式二分、scanrva 交叉清单、tokmap。
2. **或直接切 S2**：mono 侧 JIT 全通，先用 mono 驱动 S2（字符串回接）/S3（委托表）开发，
   Windows CLR 布局问题随后收尾（06004181 单点）。
3. **CI 回归**：修复16/17/18 后需跑一次完整 windows probe 确认死点与本地一致。

### CI 回归（run 40446834843, 修复16/17/18 后）
- probe VERDICT = FAIL-EXITED(code=-1073741819 = 0xC0000005 AV) — 与本地 failfast 同族，死点一致 ✓
- 反射诊断新线索：MFAIL 06004667/06004668 "Could not load type System.Security.Principal.WindowsImpersonationContext from mscorlib" — mscorlib TypeRef scope/版本错位待查
- PEVerify 诊断错误 1245→2325（诊断步骤非门禁；样例=匿名类型 ctor 的 this 未初始化告警）
- 结论：Windows 侧死点=06004181 failfast 族（与本地 Wine 一致），mono 侧 JIT 全通 → S2 开发可在 mono 驱动下先行

## 06004181 最终定位（2026-10-27 中午）：dnlib 写出的 EH 段头畸形

**决定性发现**（磁盘字节级对比）：
- 0600419C（9EH、CLR 过）：EH 段头 `41 dc 00 00` = flags 0x41(EHTable|FatFormat) + DataSize 0xDC=220（9 fat 子句）✓
- 06004181（1EH、CLR 拒）：EH 段头 `01 10 00 00` = flags 0x01(**缺 EHTable 位 0x40**) + DataSize 0x10=16（4 头+12B=1 个 **small** 子句）
- → dnlib 写出了"FatFormat 标志 + small 子句"的混合畸形段：CLR 读出非 EHTable 段 → EH 全部丢失 → leave 失效 → InvalidProgram
- → mono 容忍此格式（mono 过 JIT）；Windows CLR 不容忍

**实验矩阵**（全部本地 Wine 秒级）：
- 手动补 0x40 位（41 10 00 00）：仍 InvalidProgram（DataSize=16 与 FatFormat 的 24B 子句矛盾）
- 重建 small 段（44 00 00 4a 01...）：仍 InvalidProgram → 段头之外还有问题或多个方法有同类畸形
- noeh（删 EH+leave→br）：InvalidProgram 消失 ✓ → 拒因确系 EH
- copybody 06004181 到 22711 基座（体相同）：InvalidProgram 消失 → 体本身无辜

**下一棒修复路径（高置信）**：
1. S1 写出后处理：遍历全部 MoreSects 方法体的 EH 段，校验段头（EHTable 位 0x40 必须在、
   DataSize 必须与子句数匹配 small=4+12n/fat=4+24n、FatFormat 位与子句格式一致），
   畸形段用 dnlib 重新写出（先在 CilBody 层破坏性重设 ExceptionHandlers 强制 dnlib 重编码），或字节级重建。
2. 找 dnlib 4.4 写出 0x01 段头的触发条件（疑与"1 个子句/small 段"相关，0600419C 9 子句 fat 正常）。
3. 批量统计：全产物有多少 MoreSects 方法的段头异常（06004181 决非唯一）。
4. 修完后 wine probe → 预期 InvalidProgram 清零 → 死点进入 S2 运行时层（BinaryReader null / Invalid handle）→ 接 S2。

## 修复19 落地（2026-10-27 12:xx）：EH 段畸形字节级重建

- **fix_eh_sections.py**：扫描全部 MoreSects 方法体，修复 dnlib 畸形 EH 段
  （flags=0x01 缺 EHTable 位 0x40 + DataSize=4+12n small 子句）→ 重建为合法 small 段
- 全量运行（dumpall 30912 方法 → MoreSects 有效 17 → 修复 11 畸形段）
- **结果：InvalidProgram 清零（0 次）**，死点前进到
  `Bad IL range at GenerateAdaptableCollection ← DefineEfficientProfiler ← .cctor`
  = 修复16 dedup 未覆盖的"非共享邻居交叉"残留（scanrva OVL 可定位）
- 流程: dumpall → fix_eh_sections.py → wine 测试

## 死点再前进（2026-10-27 12:xx）：0600419A 的 EH 子句数据畸形

- fix19 后 InvalidProgram=0，新死点 `Bad IL range at GenerateAdaptableCollection(0600419A) ← DefineEfficientProfiler`
- 0600419A = 又一个 6 条反调试桩（call IsAttached→throw），rva=0x23F24，EH=1
- **其 EH 段已被 fix19 修为 small 正确头（44 00 00 00）但仍 Bad IL range**
- **根因下沉：EH 子句数据本身畸形** — hOff=0x0600（1536）远超 18B 体 → 子句解析/转换错位
  （疑 slot_plaintext 的"mt fat 兜底"解析路径或 CORINFO→CLI 转换 offset 基准错）
- 官方磁盘 0600419A 为明文桩（官方 EH 可直接对照）→ 下一步对比官方 EH 原始字节即可修 S1 解析

## 死点突破进入 S3 层（2026-10-27 12:xx 下午）

- **0600419A prune 实验**：保留前 2 条（避开 EH）→ `Bad IL range` 消失
- **新死点**：`BadImageFormatException: Bad binary signature (0x80131192) at VerifyProcessor(IntPtr) ← DefineEfficientProfiler`
- **VerifyProcessor = NRS 运行时代理函数族**（GetDelegateForFunctionPointer → castclass → callvirt Invoke）
- **Bad binary signature 根因**：函数指针来自 NRS 运行时（未回接的委托表/字符串池）→ 非托管签名与托管签名不匹配
- **= S2（字符串池回接 dec_Factory.bin 8539 条）+ S3（委托表 zdec/Project.bin 3266 条）的范畴**
- **结论：JIT/元数据层已全通（修复16-20），剩余死点全部在 S2/S3 运行时回接层**

### 完整修复清单（本轮新增）
- 修复19：fix_eh_sections.py EH 段畸形字节级重建（11 段）→ InvalidProgram 清零
- 修复20：CorInfoToCliEh 子句有效性校验（cls<0x01000000/越界/全零 → drop）+ mt 磁盘段兜底同款校验 + 官方明文体 EH 兜底（OfficialEhToCli）

### 下一棒（S2/S3 直道）
1. S2：ldstr/取串调用回接（dec_Factory.bin，8539 条 [int32 byteLen][UTF-16]）
2. S3：委托表回接（zdec/Project.bin，3266 条 [Field 0x04][MemberRef 0x0A|0x4A]）——VerifyProcessor 在此消解
3. 每完成一段 → dumpall + fix_eh_sections.py + wine 验证死点前进

## S3 委托表回接落地（2026-10-27 12:xx）：3266/3266 全量成功

- **CmdS3**：读 Project.bin（3266 条 [Field 0x04][Member 0x0A|0x4A]），
  0x4A=带 Reactor 标志 0x40 的 MemberRef（去 0x40 还原），
  生成 `<Module>::InitDelegates`（ldnull → ldftn member → newobj 委托.ctor(object,IntPtr) → stsfld field ×3266），
  `<Module>::.cctor` 尾部插 call
- **结果：delegates=3266 skip=0（字段/成员/ctor 全部解析成功）**
- 委托对样例：`ValidatorFormatter::ValidateResponsiveChecker ← String::Format`、
  `ActiveValidator::SplitProc ← PropertyInfo::GetValue`（委托类型 .ctor(object,IntPtr) 全部在产物中存在）
- **死点变化**：VerifyProcessor 从运行时层 `Bad binary signature` 变为 JIT 拒 `InvalidProgram`
  （S3 加 InitDelegates 后布局移动触发 VerifyProcessor 的布局敏感拒——同 06004181 模式）
- **下一棒**：VerifyProcessor（tokinfo/disasm/prune 三板斧）+ 剩余布局敏感拒的系统性收尾
  （疑点：fix19 只修 11 段，MoreSects 扫描 skipped=10825 需复核）

## ldstr 排除（2026-10-27 12:xx）：06004192 的 3 个 ldstr 全部在 #US 范围内

- 06004192 IL 里有 3 个 ldstr（"is tampered."/"SHA1"/"ValidatorArgument.EmitterReporter"）
- token 0x70000A26/0xA42/0xA4C 全部 < 产物 #US size 0x454C → ldstr 排除
- 注意：tokmap 的 operand 过滤漏了 ldstr（string operand 不是 ITokenOperand）——后续工具需补
- VerifyProcessor(060041A5) 18 条指令完美（keogyBbmx→StopClient→GetDelegateForFunctionPointer→castclass）
- VerifyProcessor prune 实验工具故障（dangling branch 目标），需修 prune 工具后再二分

### 当前完整状态
- 修复 16-20 全部落地，InvalidProgram 主链清零
- 死点：VerifyProcessor JIT 拒（布局敏感型，prune 实验证实 0600419A 同类）
- S3 已全量回接（3266 委托）
- 剩余：布局敏感拒的精确机制（06004181/06004194/0600419A/060041A5/06004192 同族）+ S2 字符串层

## 06004192 二分完成（2026-10-27 13:xx）：布局敏感模型最终确认

- prune 工具重写（栈平衡 dangling 处理：dangling 分支→nop/pop 等价、尾部按模拟栈深补 pop*+ret、EH 全删）→ 零噪声二分可行
- **06004192 二分结果**（12 轮）：坏点∈[1766,1771)，但该区间 5 条全是普通数组指令（ldc.i4/add/stloc/ldloc/stelem.i1）
- **06004192 的 EH 段正常**（41 64 00 00 = 0x41 + DataSize 100 = 4 fat 子句，子句数据与官方一致）
- **结论：布局敏感模型最终确认** —— InvalidProgram 报错方法（InstantiateGlobalCalculator）自身体/EH/token 全部正常，
  拒因=它的体大小变化驱动全局布局移动 → 某个"体区交叉点"进入/离开 JIT 视野
  （prune 06004192 改变它自己的体大小 → 后续方法整体移位 → 交叉点变化 → 二分边界非单调）

### 下一棒精确修复路径
1. **scanrva 增强**：不只检测"同 RVA 共享"，增加"footprint 与相邻体边界重叠"检测
   （当前 OVL=同 lo 排序相邻比较，可检测交叉——但 06004192 不在 OVL → 交叉在别的方法间）
2. **候选**：fix19 的 skipped=10825（cs 保护跳过）里有未修复的畸形段；16017 dupRva 中 dnlib 合并的 identical 体
   与"非 identical 但 RVA 相同"的混合需要区分
3. **备选**：06004192 体大小扫描（prune N=1766..2521 全跑一遍找"过"的 N）→ 反推交叉点位置
4. **备选**：MSBL 布局对比 —— 用官方 exe 的方法布局（dupRva=0）作为布局模板强制 dnlib 按官方 RVA 排布

## ⚠️ 重大认知修正（2026-10-27 13:xx）：EH 段格式权威解读（corhdr.h）

**ECMA/corhdr.h 权威定义**（推翻此前全部段头解读）：
```
CorILMethod_Sect_EHTable   = 1     ← bit0-5 的类型码 1 = EHTable
CorILMethod_Sect_FatFormat = 0x40  ← bit6 = FatFormat
CorILMethod_Sect_MoreSects = 0x80  ← bit7 = MoreSects
Kind & KindMask(0x3F) = 类型码（1=EHTable）
SMALL 段: Kind byte(bit6=0) + DataSize byte(独立 8-bit 字段)
FAT 段: Kind byte(bit6=1) + DataSize 24-bit(bytes1-3)
```
- **`01 10 00 00` = 合法 small EH 段**（Kind=0x01=EHTable、DataSize=0x10=16）——dnlib 写法正确
- **`41 dc 00 00` = 合法 fat EH 段**（Kind=0x41=EHTable|FatFormat、DataSize=0xDC）——正确
- **fix19 的 `44 00 00 00` 重建 = Kind 0x44 → 类型码 0x04 无效 → CheckILMethod 的 CHECK(sectSize>0) 失败 → 0600419A 的 Bad IL range 是 fix19 自己造成的！**
- **fix19 作废**：fix_eh_sections.py 的段头重建逻辑撤销，当前最佳产物 = out/s3.exe（S1+修复16-18+S3，无 fix19）
- **CLR "Bad IL range" 抛点 = PEAssembly::GetIL → CheckILMethod 失败（cordecoderhelpers.h）**
  校验链：tiny/fat 头 → IsFat/GetSize>=3 → CheckRva(rva, codeEnd) → More 段链 → 每段 Kind 解析 → CHECK(sectSize>0) → CheckRva(rva, sectEnd)
- **当前死点（S3 版）**：VerifyProcessor JIT 拒 InvalidProgram（S3 布局移动触发，同布局敏感族）
- 06004181 的 `01 10 00 00` 段合法，其 Bad IL range另有来源（S3 后已消失）

## VerifyProcessor 定性（2026-10-27 13:xx）：体本身被 JIT 拒（非布局）

- prune N=10/14 都 InvalidProgram → VerifyProcessor(060041A5) 的拒是"体本身"，与布局无关
  （不同于 06004181/0600419A 的布局敏感族）——18 条指令 IL 完美（ldsfld/brtrue/keogyBbmx/StopClient/
  GetDelegateForFunctionPointer/castclass TemplateBuilder/callvirt Invoke/ret）
- S3 前它"过 JIT"（Bad binary signature 是运行时层），S3 后变 JIT 拒——
  S3 的 InitDelegates（3266×4≈13K 条指令的大方法）加入后触发
- **下一棒**：
  1. VerifyProcessor 的 2 个 ldstr token #US 范围检查（同 06004194 方法）
  2. tokmap 官方/产物 operand 对比（注意补 ldstr：string operand 不是 ITokenOperand）
  3. InitDelegates 拆分/移位实验（布局敏感性隔离）
  4. 或者先跑 mono probe out/s3.exe 看 mono 侧死点（mono 可能容忍）

## 修复21（2026-10-27 13:xx）：m_*.eh 前导 DWORD 偏移修正——部分生效

**根因确认**（06004192/0600419A 双例对照）：
- m_*.eh 的每条 28B 子句 = [4B 前导（恒 0）] + [flags][tryOff][tryLen][hOff][hLen][cls]（6 DWORD）
- 旧代码从子句头读 flags → 全部字段错位 1 DWORD（06004192 读出 tryOff=0/tryLen=0xA9B/hLen=0xB46/cls=0x0B 全错）
- **修复21**：字段读取起点从子句头 +4（跳过前导）→ 字段全部对上官方语义

**当前状态**：
- eh-dropped 从 2001（校验拦截错位子句）变化中；**新 fail=217："ehData 28B parsed as 0 clauses"**
  ——BuildFatEh 输出正确 28B（41 1C 00 00 + fat 子句），但 dnlib CreateCilBody 解析报 0 子句
- 死点变为 VerifyProcessor `Bad format (0x8007000B)`——EH 修复链路接近打通但 dnlib 解析环节卡壳
- official-eh-fallback=0（官方兜底未触发，dbg 打印无输出=0600419A 的 mt 兜底仍"成功"给出垃圾，校验待复核）

### 下一棒（最后一段直道）
1. **"ehData 28B parsed as 0 clauses"**：dnlib CreateCilBody 对 BuildFatEh 输出的 28B 解析 0 子句——
   打印 ehData hex（S1 内）+ 检查 dnlib 的 EH 段 flags 判定（0x41 应走 fat 分支）
2. 注意 fail=217 的方法被跳过注入（rollback）——需修好后再全量
3. VerifyProcessor 的 `Bad format 0x8007000B`（E_INVALIDARG）= GetDelegateForFunctionPointer 参数错——S2/S3 层
4. 修好后预期：cctor 链全通 → 窗口出现 → probe/soak

## ehData 打印诊断（2026-10-27 13:xx）：217 fail 的样本数据

- fail 点已打印 ehData hex（x5 样例：`41 18 00 00 00 00 00 00 5B 00 00 00 AD 00 00 00 5E 00 00 00 00 00 00 00 00 00 00 00`）
- 解析：flags=0x41(EHTable|Fat) DataSize=0x18=24、子句=[flags=0][tryOff=91][tryLen=173][hOff=94][hLen=0][cls=0]
- **异常点 1**：hOff=94 < tryOff+tryLen=264（handler 在 try 区间内 = 非法 EH 结构）
- **异常点 2**：hLen=0、cls=0（空 handler）
- **异常点 3**：这些方法 IL 较短（tryOff=91 可能越界）→ dnlib 指令绑定失败 → "parsed as 0 clauses"
- **判断**：这批 EH 数据来自 mt 磁盘段兜底路径（修复21 偏移修正后 mt 票据解析出的"新垃圾"），
  需要对 mt 兜底路径补与 CorInfoToCliEh 相同的有效性校验（hOff >= tryOff+tryLen、cls 有效、指令边界）
- 或者更干净：**直接禁用 mt 磁盘段兜底**（PROGRESS 早已证明 mt 的 EH 区不可用），只留 corEh + 官方兜底
