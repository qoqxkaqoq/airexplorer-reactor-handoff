# AirExplorerUnpacker — 进度账本（tools3/unpacker）

> 汇报纪律：每步结论/产物即时写盘 + push。PASS/FAIL 只认门禁脚本输出。
> 立项书：`docs/UNPACKER_PLAN.md`；总览：`agent.md`。

## 环境与工程（2026-10-26 Linux 侧搭建）

- Linux + dotnet SDK 8.0.427（dotnet-install 装于 /usr/share/dotnet）+ NuGet **dnlib 4.4.0**（未用 NRS 捆绑 net472 dnlib）
- 工程：`tools3/unpacker/AirExplorerUnpacker.csproj`（net8.0）+ `Program.cs`（CLI）+ `CmdInspect/CmdS1/CmdEhProbe/CmdCheckSig.cs` + `build.sh`
- 仓库 clone 走代理前缀 `https://p.xixky.eu.org/https://github.com/...`（直连 github.com:443 间歇性挂死；token 拼 remote URL 已配置）

## 数据源定案（全部经全量交叉验证，血泪换来的勿重推导）

| 数据源 | 内容 | 权威性验证 |
|---|---|---|
| `work_a1_pack/memdump/module_text.bin`（9,596,928B） | **运行时模块 dump，方法布局偏移 = RVA − 0x2000**。含每个 manifest 方法的**运行时方法头**（fat：maxstack/locals token/initlocals/EH 标志）与**运行时 IL** | ① 头解析 22930/22930 全成功（tiny 12476 + fat 10454，0 异常）；② locals token 全部合法（rid ≤ 3174 = StandAloneSig 行数，0 越界）；③ **IL 与 JIT dump 全量逐字节全等（dump_full 16598/16598，0 mismatch）**；④ codesize vs zip ilSize 全等（fat 8702/8702 + tiny 7896/7896） |
| `work/dump_official_16598.zip` m_*.bin（24B 头 [tok][ilSize][maxStack][ehCount][preExtra][localsTok]） | maxStack + ehCount + IL 交叉源 | IL 与 mt 全等（见上）；maxStack 与 mt 头一致 |
| 同 zip m_*.eh（4B count + 28B/条 CORINFO clause [flags][tryOff][tryLen][hOff][hLen][cls]） | **Necrobit 方法的运行时真实 EH** | mt 的"EH 区"= 磁盘原样字节（与基线 exe 逐字节相同）→ 是 Necrobit 票据/混淆数据**不可用**；zip .eh 是 JIT hook 抓的 CORINFO 真表。与磁盘明文槽 0x41 段（fat clause）双源一致（抽样 3 例字段全对上） |
| `work/c2_pack/bodies_manifest.tsv`（22,930 行 rva/tok/name/src）+ `bodies/` | 体库清单 | Slayed 骨架 token 对齐 **22930/22930 miss=0**（NRS 保留 token） |
| `work/loc_official.zip`（8392 .loc）+ `work/c2_pack/vault_index.tsv`（5106 条） | locals 备用源 | **本轮未用**：mt 的运行时 fat 头直接给出权威 locals token，覆盖全部方法（.loc/vault 有 8049 缺口的问题由此消解） |

### 关键真相（与既有文档的差异/确认）

1. **c2_pack 的 `slot_plaintext` 5567 里有 905 个假体**：磁盘槽是 stub，`slot_body()` 解析出 `00 00 00 2a` 之类垃圾（如 06000007 .ctor 磁盘体 4B，mt 运行时体 31B `28 94 41 00...`）。**S1 一律用 mt 运行时体，不用 bodies/ 的 slot_plaintext 版本**。
2. `vault_partial` 765 的完整真体也在 mt 里（765/765 有运行时头+IL）——"部分体"问题消解，无需人工补。
3. mt 里 dump_full 方法 IL 与 JIT dump 逐字节全等 → mt 快照未被反篡改污染（或与 dump 同源），可信。
4. Slayed 骨架体检：MethodDefs=30912（基线 30886 + NRS 加 26）；**NRS rem-junks 建了 3 个 dummy 类型共 203 个方法（177 个在 manifest），签名可能被改** → S1 跳过 dummy 类型方法不注入（保持 NRS stub），其余注入体带"参数/局部变量绑定完整性校验"，不兼容即跳过。
5. 基线与 Slayed 的方法槽形态一致（NRS 没解 Necrobit 也没重排槽），元数据（StandAloneSig 3174 行、token 空间）完全保留 → **token 直通 ResolveToken 全部成立**。
6. EH 段（CLI 元数据格式）编码实证：`u32 段头 = (dsize << 8) | flags_byte`，fat clause 24B/条；CORINFO(28B/条)→CLI(fat 24B) 字段一一对应（flags 值 0=catch/1=filter/2=finally/3-4=fault 相同）。

## M1 试金石（S1 体注入）

### S1 运行统计（`out/s1_report.txt`）

```
manifest rows: 22930
zip: maxstack 16598, eh 2218
injected=22753 fail=0 no-tok=177(dummy跳过) bad-body=0
eh-dropped=292（EH 无数据源: 53 个 0x01 段头且无 zip .eh + 239 个 zip .eh 转换失败/0x41 兜底未命中, 待修）
产物: out/m1_s1_full.exe (9,214,976B)
```

### 自检（inspect 重载产物）

- MethodDefs=30912 ✓、entrypoint=06002D22 ✓、token 对齐 22930/22930 ✓
- fat 体 10427（≈mt fat 10454 − 27 dummy）、总指令数 76,658 → **1,108,331**（14.5×，体真进去了）
- StandAloneSig 3174 保留 ✓

### 已知缺口（不阻塞 M1，M2+ 处理）

- eh-dropped 292：这些方法体注入了但 EH 丢弃 → 对分定位时若死在 EH 层，先补这批
- ldstr operand：CreateCilBody 从 Slayed 的 #US（磁盘混淆堆）按 mt 的运行时 token 取串 → 内容大概率错位/乱码（token 合法、不崩 JIT）→ 这正是 S2 字符串回接的工作面
- 765 vault_partial 已全量注入（mt 真体），无遗留

## 里程碑状态

- [x] M0 骨架就绪（前置）
- [x] M1 工程侧：S1 实现 + 产物生成 + 自检（本文件）
- [ ] M1 门禁：Windows 探针 `ci/probe_iso.ps1 -WaitSec 100` + 死法分类（CI workflow `unpacker-gate.yml` 已建，ubuntu 构建 → windows-latest 探针/长稳）
- [ ] M2 字符串回接（S2）
- [ ] M3 委托重接（S3）
- [ ] M4 资源重嵌（S4+S5）
- [ ] M5 终验

## 复现命令

```bash
cd tools3/unpacker && ./build.sh s1
# 等价:
dotnet bin/Release/net8.0/AirExplorerUnpacker.dll s1 \
  ../../work_a1_pack/nrs/AirExplorer_test_Slayed.exe \
  ../../work_a1_pack/memdump/module_text.bin \
  ../../work/c2_pack/bodies_manifest.tsv \
  ../../work/dump_official_16598.zip \
  out/m1_s1_full.exe
```

CLI 子命令：`inspect`（模块体检+manifest 对齐）、`s1`（体注入）、`ehprobe`（EH 解析实验）、`checksig`（dummy/签名兼容统计）。
