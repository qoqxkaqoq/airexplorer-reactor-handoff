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
