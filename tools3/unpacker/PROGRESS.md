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

## 修复23（2026-10-27 13:xx）：手动 EH 构造绕过 dnlib 解析

- **CorInfoToCliClauses**：corEh 校验后直接返回子句列表（不再经 BuildFatEh→ehData→dnlib 解析）
- **CreateCilBody 不传 ehData**（MoreSects 标志去除），body 创建后手动构造 ExceptionHandler：
  offset→指令映射 → TryStart/TryEnd/HandlerStart/HandlerEnd 绑定 → CatchType=mod.ResolveToken(cls)
- 死点再前进：VerifyProcessor 从 `Bad format 0x8007000B` 变为 `Index not found 0x80131124`
  （=castclass 02000630 TemplateBuilder 嵌套壳类型的元数据查找失败——修复18 的嵌套壳仍为扁平名）
- fail=309（手动 EH 绑定失败率略高于 dnlib 路径 217，但 EH 数据正确性大幅提升）

### 下一棒收尾清单
1. 修复18 扩展：嵌套类型的壳也用真名（挂产物外层类型 NestedTypes 下）——02000630 TemplateBuilder 类
2. 手动 EH 绑定失败的 309 个方法逐类分析（tryOff/hOff 在指令边界的对齐）
3. S2 字符串回接（dec_Factory.bin）
4. 全流程: S1 → fix 段校验 → S3 → wine → CI probe/soak

## 修复24（2026-10-27 13:xx）：嵌套类型真名壳挂产物外层

- 壳构建的 special 判定移除 DeclaringType 条件——嵌套非特殊类型也走真名壳
- 嵌套壳挂产物外层类型的 NestedTypes 下（FullName 自动=外层/Name，如 DispatcherInitializer/TemplateBuilder）
- 死点稳定：VerifyProcessor `Index not found`（=GetDelegateForFunctionPointer 收到 NRS 未回接的无效指针 → S2/S3 层）
- **JIT/元数据层修复完成度：修复16-24 全部落地**；剩余死点全部在 S2（字符串池）/S3（委托已回接 3266）运行时回接层

## 决定性里程碑（2026-10-27 17:xx）：程序首次无异常存活

### 本轮修复链（25-34，全部有逐字节对照证据）
- **修复25**：m_*.eh 布局 = [4B count][28B = flags+tryOff+tryLen+hOff+hLen+cls+pad4B]
  （与官方 fat 段逐字段对照 0600419C/0600419A 双例验证）——修复21 的"+4 前导"解读作废
- **修复26**：BuildFatEh 的 DataSize = 4 + n*24（含段头自身），旧值少 4B → dnlib 读 0 子句
- **修复27/28**：EH 统一子句列表路径；注入后自检（null operand/switch 元素/EH 边界）
- **修复29→34 迭代**：dnlib EH 边界语义 = **EXCLUSIVE**（TryEnd=区间外第一条；
  写出 TryLen=TryEnd.Offset-TryStart.Offset）。inclusive 使 tryLen 全部 -5 → InvalidProgram
- **修复30**：EH flags 完整保留 catch(0)/filter(1)/finally(2)/fault(4)——修复23 全建成
  Catch+null CatchType 是写出崩溃真凶
- **修复31**：官方兜底校验（官方加密方法磁盘 EH 乱码不可信）+ EH 拦截时 leave→br
- **修复33**：mt 12B/子句段 = **NRS compact 格式**（flags2B+tryOff2B+tryLen1B+hOff2B+hLen1B+cls4B）——
  与官方磁盘 06004181 逐字节对照（00 00 4a 01 0b 55 01 06 18 00 00 01 → try=(330,11) h=(341,6) cls=0x01000018 全合法）；修复32 的"ECMA small"解读作废（官方磁盘 IL 与 mt IL 完全一致=slot_plaintext 明文）
- **修复34**：EH 边界回滚 exclusive → **mono 下 InvalidProgram 清零**（0600419C 的 endfinally 错误消失）

### 里程碑结果（Wine/Windows CLR 实测）
- injected=22930 **fail=0**（首次零失败全量注入）
- stub 0600419C(DefineEfficientProfiler) 后：failfast 消失 → 死点="AirExplorer is tampered"
  （06004192 InstantiateGlobalCalculator 的 NRS 反篡改校验逻辑执行——**程序活着**）
- 再 stub 06004192 后：**EXIT=124 无异常、CPU=0 空闲等待**（首次完整存活，挂点=NRS 初始化等待）
- mono 侧：EH 全通，死点=ArgumentNullException Invalid handle（VerifyScopeAnnotationInspector
  读到 default ModuleHandle——authenticatorNotifier 初始化链，mono 特有路径）

### 下一棒（最后直道）
1. **反调试桩族精细处理**：stub 0600419C 使 NRS 初始化依赖（chooserObject/visibleCheckerTemplatePtr）
   缺失 → 后续 VerifyProcessor.Invoke 等待。方案：不全 stub，只 patch tamper 检查点
   （06004192 的 ldstr "is tampered." 分支跳转）或让 0600419C 体保留但 patch 其 tamper 分支
2. **验证产出窗口**：cctor 链全通后 WPF Main（06002D22 SearchAdapter 213 条已注入）应出现窗口
3. **S2 字符串池回接**（dec_Factory.bin 8539 条）——官方字符串仍走运行时取串函数
4. CI probe/soak 双门槛

## 反调试桩族行为定性（2026-10-27 17:xx 末）

- **untamper 工具落地**：`patchstub <in> <out> untamper <tok清单>` —— 把"newobj Exception.ctor; throw"
  模式的 throw 换成 pop（1 字节 0x7A→0x26，偏移不变，栈平衡直落正常流）
- **实验矩阵**（Windows CLR / Wine 实测）：
  - stub 0600419C(DefineEfficientProfiler) → failfast 消失 → "AirExplorer is tampered"(06004192 throw)
  - stub 0600419C+06004192(untamper 不够,全 stub) → **程序存活 45s+ 无异常 CPU=0 等待**（无窗口）
  - 保留 0600419C+untamper 06004192 → **2 秒内静默死**（托管层无 Exit 调用 →
    **native 反调试系统 TerminateProcess**——0600419C 初始化 NRS native 运行时后自检环境即杀进程）
- **定性**：0600419C 是 NRS native 反调试系统的托管初始化入口；保留它=激活 native 自杀；
  stub 它=存活但 NRS 代理初始化缺失（chooserObject 等字段 null → 后续等待/挂起）
- **下一棒最高价值**：
  1. WINEDEBUG=+relay 抓 st2b（stub 版）的最后调用序列 → 定位挂点调用
  2. 0600419C 体内找到 native 初始化调用点（Marshal.GetDelegateForFunctionPointer/GetProcAddress 链）
     → 只 patch native 自检调用、保留托管初始化
  3. 或完整分析 0600419C 的 9992 条控制流平坦化结构，找"校验失败→杀进程"的分支
  4. S2 字符串回接（dec_Factory.bin 8539 条）与窗口出现的距离已非常近

## relay 跟踪定位挂点（2026-10-27 17:xx 收官）

- **WINEDEBUG=+relay 抓 st2b（stub 版）14 秒全量 syscall**（118MB）
- **发现**：
  - WPF Dispatcher 已启动（"Message" 隐藏消息窗口 + GetMessageW/DispatchMessageW 循环在跑）
  - **无业务窗口创建**（仅 Wine 内部窗：OleMainThread/IME/WineAppBar/clipboard）
  - **文件访问极少**：仅 st2b.exe 自身 + config——**未加载任何 WPF 资源/BAML/附属程序集**
  - 末态线程 WaitForMultipleObjectsEx(alertable) 等待
- **定性**：cctor 链全通 → WPF Application 已初始化进消息循环 → **Startup 阶段（主窗口创建前）
  的 NRS 代理调用挂起**（stub 0600419C 使 chooserObject/visibleCheckerTemplatePtr 等
  native 代理字段为 null → Startup 事件里 Invoke(null) 挂起）
- **与官方对照缺口**：官方 Startup 链会读 AirExplorer.resources/UI 程序集——当前一步未走

### 下一棒精确路径（窗口只差一步）
1. **0600419C 精细重建**：分析其 9992 条控制流平坦化，区分"NRS native 自检（导致 TerminateProcess）"
   与"托管代理初始化（chooserObject 等赋值）"——保留后者 patch 前者（untamper 思路同款：
   throw→pop / 条件分支反转）
2. **或补初始化**：stub 0600419C 后，在 S1 生成代码手工补写 chooserObject 等字段的真实
   初始化（参照官方 VerifyProcessor 的初始化块语义：LoadLibrary→GetProcAddress→delegate）
3. **S2 字符串回接**（dec_Factory.bin 8539 条）——Startup 链中 NRS 取串调用仍走运行时函数
4. 全流程跑通后 → CI probe/soak 双门槛

## NRS 运行时模式破译（2026-10-27 19:xx）：父进程重启模式

### relay 决定性证据（ut1 = 保留 0600419C + untamper 06004192）
```
0024线程: CreateProcessW("C:\\airtest\\ut1.exe", "\"C:\\airtest\\ut1.exe\" ") ret=0040240f  ← JIT 代码
          WaitForSingleObject(子进程句柄 0x60) ret=004026f4
          GetExitCodeProcess(0x60) → 退出码 c0000602 ret=0040270e
          ExitProcess(c0000602) ret=0040271f   ← 传播子进程退出码
```
- **0600419C 的真实语义 = NRS 父进程逻辑**：初始化 native 运行时环境 → CreateProcess 重启自己
  （命令行 = "exe路径" 带尾空格）→ 等子进程 → 传播退出码
- **子进程**（继承 NRS 环境后）= 应执行真实程序（跳过 bootstrap）——**实测 fail-fast c0000602**
  （STATUS_FAIL_FAST_EXCEPTION）→ 父传播退出
- st2b（stub 0600419C+06004192）存活 = 绕过了父进程逻辑，但 native 运行时环境缺失 → Startup 挂

### NRS 双进程模型（对照官方行为）
- 官方 exe 在 Windows 上跑也是双进程（父=bootstrap/子=程序）——Necrobit native JIT 环境的进程边界
- 子进程判据 = 命令行（尾空格标记）+ NRS 环境继承（管道/共享内存/环境变量——relay 里待挖）
- **我们的脱壳产物没有 NRS native 运行时** → 子进程初始化时 fail-fast

### 下一棒（脱壳机的最终形态抉择）
1. **子进程 fail-fast 原因**：relay 分离子进程（003c 线程之后）的调用序列，找第一个失败 syscall
   （可能等 NRS 管道 `\\.\pipe\...` 或共享内存 section）
2. **S1 加"子进程模式"跳过**：Main 的 args 检查分支（ldarg.0/ldelem.ref）官方语义解读——
   让产物单进程直接跑（跳过 bootstrap），需要补齐 native 代理的所有真实实现
   （StopClient=GetProcAddress 包装、keogyBbmx=LoadLibrary、代理字段 lazy init 全部托管化）
3. **S2 字符串回接 + 代理字段托管重建** = 单进程模式的关键路径

## 子进程 fail-fast 现场抓获（2026-10-27 19:xx 末）

- **WINEDEBUG=+seh 抓 ut1 全程**：`RPC_S_SERVER_UNAVAILABLE (code=0x6ba)` 异常反复出现（线程 009c）
- **定性**：NRS 子进程初始化时连接 NRS native 运行时的 **RPC/COM 服务**（父进程 bootstrap 应建立的
  跨进程通道）——Wine 下该服务未建立/不可达 → 子进程 RPC 失败 → CLR fail-fast(c0000602) → 父传播退出
- **双进程模型的 Wine 障碍 = 进程间运行时通道**（RPC/共享内存），非托管层问题

### 全局状态盘点（本轮结束）
| 层 | 状态 |
|---|---|
| JIT/元数据/EH | ✅ 全通（修复16-34，injected=22930 fail=0，mono/CLR 双侧验证）|
| cctor 链 | ✅ 全通（stub 反调试族后无异常）|
| WPF Dispatcher | ✅ 已启动（消息循环运行中）|
| NRS 双进程模式 | ⚠️ 已破译（父=bootstrap+重启/子=程序），Wine 下 RPC 通道缺失 |
| NRS native 代理 | ⚠️ stub 后 Startup 挂（chooserObject 等 lazy-init 依赖 native）|
| S2 字符串池 | ⏳ 数据就绪（dec_Factory.bin 8539 条），未回接 |

### 下一棒（三选一路径，均已明确）
1. **单进程托管重建**（最工程化）：stub 全部 NRS bootstrap 方法 + 托管重建代理字段
   （VerifyProcessor 的 lazy-init 块本身就是完整的 LoadLibrary→GetProcAddress→delegate 链，
   关键是确认 Startup 挂点的具体调用并逐个补齐）
2. **S2 字符串回接先行**：ldstr 化 dec_Factory.bin（8539 条），可能消除部分 NRS 运行时依赖
3. **native 桥模拟**：分析 NRS 管道/共享内存协议，在 S1 生成托管模拟器（工程量大）

## S2 模式识别进展（2026-10-27 19:xx）

- **新工具 scans2**：扫描全产物 "ldc.i4 <n>; call <m>" 模式按目标统计
- **结论：该模式不成立**——最高频 = 06004284(VerifyScopeAnnotationInspector, token 解码器) x14，
  其余全是 1-3 次——**mt 快照 IL 里没有 "索引+解密调用" 的字符串取用模式**
- **推论**：mt 快照（内存 dump 的解密后 IL）里官方字符串的引用形态与预期不同——
  可能性：(a) NRS 在 JIT 层替换字符串引用（IL 里是池偏移 ldstr，运行时重定向）； 
  (b) 取串调用有更复杂的栈模式（ldfld 委托字段 + Invoke）；(c) mt 快照 IL 已含池引用的中间形态
- **下一棒识别方法**：
  1. 对照官方 exe 的某字符串大户方法（如 string.Format 模板 '{{ alg = {0}'所在方法）的
     官方磁盘 IL vs mt IL vs 产物 IL——看字符串引用在三种形态间的演变
  2. mono 运行时 hook：加载产物后 hook 疑似解密函数，dump 实际传入索引与返回字符串
  3. dec_Factory.bin 的相邻条目（#0-5 都是 string.Format 模板）暗示**索引即调用点顺序**——
     按方法首次调用的确定性映射可从官方 IL 重建

## 对照实验结论（2026-10-27 19:xx）：官方 exe 在 Wine/Linux 完整运行 ✅

- **官方原版 AirExplorer v5.11.0 在 Wine 下启动成功**（official-air-on-linux.png 截图）：
  主窗口/菜单栏（Explore/Accounts/Search/Synchronize/Scheduler/Options/Tools/Pro Version）/工具栏全部渲染，
  主区域黑色（WebView2 区，Wine 需装 WebView2 Runtime，可后补）
- **重大推论**：NRS 双进程模式在 Wine 下官方也能走通（native bootstrap 建立 RPC 通道成功）——
  **我们产物子进程 fail-fast 不是 Wine 的限制，是产物缺 NRS native 运行时**（mt 快照只有托管 IL，
  官方 exe 里的 native bootstrap 区域不在快照内）
- **脱壳机现状的准确表述**：
  - 托管层（JIT/元数据/EH/cctor/WPF Dispatcher）100% 打通
  - 完整独立运行需要替代 NRS native 运行时（native 代理托管重建+字符串池回接），工程量明确
  - 运行需求本身已有解：官方 exe 在 Linux/Wine 可直接跑（本项目 scripts/air-on-linux.sh 一键启动）
  - 脱壳产物的价值 = 分析/修改/重打包（去掉 NRS 后的干净托管镜像）

## "搞到能运行"路线终稿（2026-10-27 19:xx）

### 关键新情报
- **0600419C 内 ldstr 清单**：`clrjit.dll` / `m_ptr` / `m_pData` / `System.Reflection.RuntimeModule` /
  `System.Reflection.ReflectionContext` —— **NRS native 层 = clrjit hook**（JIT 层解密）+
  反射操作（RuntimeModule 字段访问），**CreateProcess 不在 0600419C 直接拼接**（在其调用树的代理方法里）
- **官方 PE 结构**：.text 9.27MB = [加密托管体区] + [尾部 native bootstrap]，EP=0x929B9E 指向尾部；
  产物 .text 5MB（mscoree thunk EP，bootstrap 缺失）
- **官方 exe 在 Wine 完整运行**（截图）——NRS 全链在 Linux 可跑

### 路线 A（推荐）：单进程托管重建
- NRS 的 native 依赖实际只有三类：
  (1) clrjit hook（单进程下不需要——体已明文）
  (2) kernel32 代理（CloseHandle/CreateProcessW 等——VerifyProcessor 的 lazy-init 链可跑，
      **只需跳过 CreateProcess 代理的调用**）
  (3) Startup 阶段对 0600419C 初始化字段的依赖（scopeUserTemplate/_NodeElementPtr 等 11 个）
- 步骤：① 0600419C 调用树里定位 CreateProcess 代理（找拼 "Process" 的 Concat 模式）
       ② 该代理调用点 patch 为跳过（其后的初始化保留）
       ③ 其余依赖 native 的代理照常走（kernel32 在 Wine 都有）
- 预期：cctor 全通 + Startup 不挂 → 窗口出现

### 路线 B：混合 PE（备用）
- 保留官方 native bootstrap + 替换托管流——需要逆向 native 解密表（数天，深水区）

## NRS 代理族定位（2026-10-27 19:xx 末）

- **新工具 scans2 concat**：扫 "ldstr+ldstr+Concat" 模式重建动态 API 名
- **抓到 NRS 危险代理**：
  - **06004182 FormatContainer = WriteProcessMemory 代理**（"Write "+"Process "+"Memory" 三段拼接）
  - **06004184 GenerateAutomatableResponder = OpenProcess 代理**（"Open "+"Process"）
- **定性**：NRS 的"父进程重启"链路 = OpenProcess(自己) → WriteProcessMemory(patch native 运行时) →
  CreateProcess(重启) —— 三个 kernel32 危险 API 全部经字符串混淆拼接 + GetDelegateForFunctionPointer 调用
- **路线 A 精确化**：stub 06004182(WriteProcessMemory 代理)/06004184(OpenProcess 代理) 及其调用点
  → NRS 无法 patch 自己/无法重启 → 父进程逻辑失效 → 程序以单进程模式继续跑
  （0600419C 保留，其初始化字段照常写入——但重启分支自然失效）
- **验证命令**：`patchstub out/m1_s1_full.exe out/nopm.exe stubfile <(echo 06004182; echo 06004184)` + wine

## 单进程模式实验 np.exe（2026-06-27 19:xx 收官）

- **实验**：stub 06004182(WriteProcessMemory)+06004184(OpenProcess) 两个危险代理 → np.exe
- **结果（Wine 实测）**：进程存活 15s+（t=3..15s 全程 procs=2）→ 之后 thread 11c 抛
  0xe0434352（未处理 CLR 异常）→ Wine 崩溃对话框
- **mono probe 佐证**：加载 np.exe → cctor FAIL → ArgumentNullException: Invalid handle
  （authenticatorNotifier default）——**触发链**：RunClassConstructor(ObserverValue) 先触发
  <Module> cctor（mono 语义）→ DispatcherInitializer cctor 失败 → 整链挂
- **结构验证**：ObserverValue TypeDef 0x0200132E 方法表完全正常（06004284 VerifyScope +
  06004287 .cctor 同类型、真体都在）——**CLR 触发语义无问题**
- **根因浮出**：**stub 的代理返回 null → 调用方 Invoke(null) → 崩**——代理不能简单 stub
  （它们被 cctor 初始化链依赖），**正确姿势 = patch 0600419C 里调用这些代理的分支**
  （跳过"重启准备"段、保留字段初始化段）

### 下一棒（单进程模式的最后一步）
1. **0600419C 控制流解剖**：9992 条平坦化里定位"调 06004182/06004184 的分支"——
   该分支 = NRS 重启准备（OpenProcess(自己)→WriteProcessMemory(自patch)→CreateProcess），
   patch 为跳过；**其余初始化段保留**
2. **或逆向代理返回语义**：给 stub 代理返回合法 delegate（new TemplateBuilder(null, IntPtr.Zero)
   ——delegate 包装的 IntPtr.Zero 函数在 Invoke 时才炸，绕过初始化期）
3. **或从 Main 侧切断**：Main 的 args[0] 检查分支（NRS 子进程标记）——让 Main 直接走"正常启动"
   路径、跳过一切 NRS 判定（需 Main IL 的分支分析）
4. 每步都离"窗口出现"更近：进程存活已证明，剩余 = 初始化链的精确切断

## 资源全对照完成 + S2 真相（2026-10-27 20:xx）

### S4 资源映射（全部 6 个官方资源 ↔ 解密文件一一对应）
| 官方资源名（NRS 混淆名） | 大小 | 解密文件 |
|---|---|---|
| ErrorReceiver.ValidatorViewer | 356328 | dec_Viewer.bin |
| ValidatorGenerator.DefinitionError | 2337031 | dec_mainlib_stream.bin |
| GlobalValidator.FactoryValidator | 398794 | dec_Factory.bin |
| ValidatorAllocator.ValidatorProc | 47915 | dec_Proc.bin |
| CollectorTransaction.ValidatorProject | 26128 | dec_Project.bin |
| ValidatorArgument.EmitterReporter | 256 | dec_Emitter.bin |
- 产物 ManifestResource 5 行（缺 FactoryValidator）——S4 = 嵌回 6 个解密资源
- dec_mainlib.bin (4.26MB) ≈ 全部资源合并体

### S2 真相修正
- **mt IL 的 ldstr 在 Slayed #US 里语义已正确**（06004192 三串验证全对："is tampered."/"SHA1"/"ValidatorArgument.EmitterReporter"）——**业务字符串的 ldstr 通路天然可用**
- **GlobalValidator.FactoryValidator = 业务字符串池**（dec_Factory.bin = [int32 len][UTF-16] × 8539，
  #0-5 全是 string.Format 模板）——**运行时由解密函数按索引取**
- 取串调用模式仍未定位（scans2 的 ldc.i4+call 与 ldc.i4+委托Invoke 均空）——
  **新假设**：池取串走 **ldc.i4 <idx> + callvirt 到接口** 或 **自定义泛型字典**，需运行时 hook
- ldstr 密度外推 ~9000 ≈ 8539 + NRS 自有串 → 两条通路并存：ldstr(#US) + 池取串

### "功能与原版一样"完成度
| 项 | 状态 |
|---|---|
| S1 体注入 | ✅ 22930/22930 |
| S3 委托表 | ✅ 3266/3266 |
| S2 字符串 ldstr 通路 | ✅ 天然可用（#US 语义对） |
| S2 池取串通路 | ⏳ 模式待定位 |
| S4 资源 | ⏳ 解密数据全齐，待嵌入 |
| 保护链短路 | ⏳ 0600419C 分支 patch（np 实验存活 15s+ 证明可行）|

## S4 嵌入完成 + 新瓶颈定位（2026-10-27 21:xx）

### 已完成
- **CmdS4 资源重嵌落地**：replaced=5 added=1 mismatch=0（6 资源全部同大小替换/添加）
  - 嵌入版（s4.exe/s4st.exe/s4addst.exe）Wine 实测
- **Windows CLR 验证框架**（Wine csc + host3/4/5）：VerifyScope token 解析链完全正常
  （authenticatorNotifier 非 default、0x02000630→TemplateBuilder 解析成功）——**mono Invalid handle 确认假阳性**
- **依赖 DLL 确认齐备**：C:\airtest\ 有全部 24 个依赖（Newtonsoft/WebView2/SharpZipLib 等），
  GetTypes 4910 类型全部加载成功

### 新瓶颈：dump 清单漏覆盖方法
- **ArgumentGateway (0x0200045A, 67 方法) 全部共享桩 rva=0x383B**（dedup 后）——
  它们的真体**不在 bodies_manifest.tsv**（dump 工具没识别到这批加密方法）
- **证据**：06004191 的 tokinfo=DispatcherInitializer::DefineRandomCompressor（49 条已注入 ✓），
  但 dumpmt 显示它在 ArgumentGateway 方法表 → **清单/类型归属需要全量校对**
- s4addst（only-add FactoryValidator）Wine 实测新死点：
  **ArgumentGateway::cctor → ArgumentOutOfRangeException**（读嵌入资源索引越界）
  ——该 cctor 依赖的方法体是共享桩（假体）→ 逻辑错乱

### 下一棒（功能等价的最后一个数据工程）
1. **dump 清单补全**：对比"Slayed 剥体方法全集" vs manifest——缺的方法从 mt 快照补 dump
   （识别判据：官方 rva≠0 + manifest 无记录 → 用官方 rva 在 mt 定位体）
2. ArgumentGateway cctor（0600413x 族）的真体补注后重测 s4addst
3. 全链通后 = 功能与原版一致（S1 体 + S3 委托 + S4 资源 + ldstr 通路全部就位）

## 修复35（2026-10-27 21:xx）：dedup 真体保护判据恢复

- **发现**：ArgumentGateway 族 67+ 方法在 manifest（dump_full）且 mt 有真体（28-34B 解密调用），
  但产物是 2 条桩——**修复16 全量化时按 Slayed 旧 RVA 分组，把已注入真体的方法误 stub**
- **修复35**：dedup 恢复"真体不动"判据（HasBody && instrs>2 || 有 EH → 跳过）——
  只有真正无体的成员才 stub（旧 RVA 悬空引用才需要）
- **结果**：dedup 从 15821 → 1769；06002F51 真体 8 条恢复（rva=0x2B9D48 独立）
- **mono Invalid handle 定性**：cctor 循环依赖（DispatcherInitializer cctor → VerifyScope →
  ObserverValue cctor → 回环）下 mono 返回 default 字段值——**Windows CLR 处理正确**（host3 已证）
- **最终版 final.exe（S1修复35+S4资源+stub 2方法）**：Windows 下进程存活 20s+ 但仍有
  Program Error（native 层，log 无托管异常）——最后一公里 = 定位残余 native crash

## 本轮收官（2026-10-27 21:xx）：完整管线聚合

### 修复35 效果确认
- dedup 15821 → 1769（真体保护恢复）
- ArgumentGateway 族真体回归（06002F51 instrs=8 rva=0x2B9D48 独立）

### 最终产物 final_ue.exe（本轮聚合形态）
- 构成：S1(修复35) + S4 全资源嵌入 + stub 0600419C/06004192 + UnhandledException 日志钩子
- **Wine 实测：存活 30s+ 零异常、零崩溃对话框**（对比：保留版 2 秒死/np 版 15 秒崩）
- 无窗口：Startup 挂点仍在（NRS 代理依赖——0600419C stub 后其 11 个初始化字段缺失）

### 修正情报
- **代理 token 修正**：FormatContainer(WriteProcessMemory)=060041A2、
  GenerateAutomatableResponder(OpenProcess)=060041A4（此前 06004182/84 为计算错误）
- **代理不能 stub** 的教训再次确认（null delegate 被调用即崩）——
  **正确姿势仍是 0600419C 分支级 patch 或字段初始化补全**

### 下一棒（单进程模式的最后冲刺）
1. **0600419C 的 11 个初始化字段清单已明**（scopeUserTemplate/_NodeElementPtr/_RegFunction/
   m_RandomTesterTemplateDist/isRecommenderObserver/m_IsDividedAnalyzerRequester/
   _SegmentedStubTemplate/m_SharerRecordDist/_IsRunnerParameter/m_RemoteNodeVal/m_TemplateManagerValue）
2. **两路**：(a) 找 Startup 读这些字段的代码 → 推断字段应有的托管值 → patchstub 新模式 initfield 补写
   (b) 0600419C 控制流解剖（9992 条平坦化）分离"初始化段"与"native 自检段"
3. **工具全就绪**：uehook(异常日志)/patchstub 全模式/scanrva/tokmap/dumpgap/resinfo/s4/findthread

## 死点再推进（2026-10-27 22:xx）：修复35 生效 + TrackCompiler 字典问题

- **修复35 实证**：ArgumentGateway cctor 的前置依赖已通——死点从"共享桩逻辑错乱"推进到
  `TrackCompiler(RuntimeTypeHandle) → Dictionary.get_Item KeyNotFoundException`
- **TrackCompiler (06004183)** = 读 ValidatorProject 资源（dec_Project.bin 26KB）建立
  RuntimeTypeHandle→映射表 的方法（业务资源的**池型资源消费**模式）
- **KeyNotFound 根因**：嵌入的 dec_Project 内容与 TrackCompiler 建字典时期望的格式/内容不匹配
  （dec_* 文件是运行时 dump 的中间态——可能含 NRS 私有头/顺序差异/未完成转换）
- **三次稳定性测试**：final.exe 每次都在同一死点崩（可复现 ✓ 非随机）

### uehook 工具状态
- 已实现（现成 token 版——引用全用产物已有 MemberRef/TypeRef）
- 遗留：<Module> cctor 的 EH 与插入指令交互细节待调（InvalidProgram）——价值降低（
  稳定测试已给出清晰死点），优先级下降

### 下一棒（功能等价的真正最后一步）
1. **dec_Project 内容验证**：与官方资源的密文对照（官方密文 26128B vs dec_Project 26128B 同大小
   ——逐字节 diff 找"解密差异规律"，推断运行时的二次处理）
2. **TrackCompiler (06004183) 反汇编**：分析字典建立逻辑（key=RuntimeTypeHandle 的来源、
   value 的构造）→ 确定资源内容的正确解析方式
3. 或 **资源还原路径修正**：dec 文件可能需要按官方解密器的"最终输出"重新 dump
   （官方运行时把解密结果交给业务代码的那一瞬间的状态）

## dec_Project 结构解码 + TrackCompiler 逻辑（2026-10-27 22:xx）

### dec_Project.bin (26128B) = [Field token][MemberRef token] 对表
- [0]=0x04002102(Field) [4]=0x0A000B10(MemberRef)、[8]=0x04002103 [12]=0x0A000B11 ……
- **与 S3 的 Project.bin（zdec）同构** —— 是委托绑定数据的池型资源版
- token 为**官方/运行时序**（Slayed 表序一致可解析）

### TrackCompiler (06004193, 633条, 3EH) 完整逻辑
```
Type t = Type.GetTypeFromHandle(arg0);
if (m_LogicalProcessorMap != null) return;          // 已初始化
lock (_VisibleStackObj) {
  dict = new Dictionary();
  asm = VerifyScopeAnnotationInspector(0x02000622) → GetTypeFromHandle → Assembly
  bytes = new BinaryReader(asm.GetManifestResourceStream("CollectorTransaction.ValidatorProject")).ReadBytes(all)
  if (bytes.Length == 0) → 无资源分支
  … 解析 token 对 → Field→Member → 按 Field 所属类型建字典 …
  m_LogicalProcessorMap = dict;  → get_Item(t) ← KeyNotFound 在此
}
```
- **InstantiateJoinedService (06004183, 821条, Byte[]→Byte[])** = 资源解密/变换函数
  （512 对齐、长度扩展计算）——**TrackCompiler 是否先调它变换资源**待确认（633 条里找 call 06004183）
- **KeyNotFound = 嵌入的 dec_Project 与 TrackCompiler 期望不一致**：可能 (a) 缺 InstantiateJoinedService
  变换步骤 (b) token 解析序问题 (c) dec_Project dump 状态非最终态
- **下一棒**：TrackCompiler 的 633 条里搜 call 06004183（确认资源变换链）→ 按链修正嵌入内容；
  token 对的 Field 归属类型应包含 ValidatorSharerRunner（查询 key）——用 dumpmt 校对

## TrackCompiler 解析细节（2026-10-27 22:xx 末）

- **资源 token 读取 = 大端重组**：`bytes[i+3]<<24 | bytes[i+2]<<16 | bytes[i+1]<<8 | bytes[i]`
  （dec_Project 的字节序需按大端解读——小端直读 0x4002102 会变成 0x02210004）
- 附带 NRS 控制流平坦化常量运算（506503628/1959015338/854276594 等魔数 mul/conv）
- **KeyNotFound 的机制假设**：TrackCompiler 大端读 token → ResolveToken（Slayed 表序）→
  Field→DeclaringType 为 key——若大端读出的 token 在表序下指向不同 Field → 类型集合不含
  查询的 ValidatorSharerRunner → KeyNotFound
- **下一棒精确修复**：dump TrackCompiler 完整解析段（IL_00A0-0x400）重建 token 提取规则 →
  对照 dec_Project 字节流验证每个 token 的解析身份 → 若 dec_Project 是"运行时重排后的序"
  则需要把官方序 token 重排为运行时序（或 vice versa）后嵌入
- **工具**：disasm /tmp/tc.txt 已存（633 条全量）

## dec_Project 字节序验证（2026-10-28 00:xx）

- **官方密文 ValidatorProject 头 32B**：2C-55-13-94-3D-93...（随机）——**与 dec_Project XOR 非循环简单密钥**（滚动/分组密码）——dec_Project = 确认的解密明文
- **dec_Project 字节序 = 小端 token 对**（02 21 00 04 → 0x04002102 Field ✓）
- **ValidatorSharerRunner 的字段在集合内**（dumpfields: inSet=1 missing=0）——**字段覆盖无缺口**
- **矛盾点**：TrackCompiler 反汇编 IL_0114-013D 段的大端重组读法与小端数据不符——
  该段可能是控制流平坦化的干扰块/或读的是别的数据段——**需精确重读 TrackCompiler 的资源
  解析段（IL_009A-0140 与 IL_0180-0x430）区分"真解析"与"平坦化干扰"**
- **KeyNotFound 机制待一次精确 IL 复核**（字典 key 集合 vs 查询 token 的实际值）——
  或运行时 dump：TrackCompiler 的字典建立后（m_LogicalProcessorMap != null 分支前）抓字典内容

### 工具新增本轮
- dumpfields（类型字段 token 对照）
- host3-6（Windows CLR 验证框架：cctor/字段/资源读取）
- scans2 concat/idxinv/resref/appdom（IL 模式识别四件套）
