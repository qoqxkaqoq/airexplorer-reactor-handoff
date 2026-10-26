# AirExplorerUnpacker 立项计划 — 自研 .NET Reactor 定制款脱壳机

> 立项：2026-10-26（业主批准方向）。状态：**M0 完成，M1 待开工**。
> 验收终点：脱壳产物在隔离探针下出真主窗 + 7 分钟长稳（与 A 线同口径），且行为与官方基线可比。

---

## 0. 一句话

用本项目已拿下的逆向资产（22,165 真方法体 + AOT 算法 + 4/6 资源密钥 + 字符串池/委托表解码 + NETReactorSlayer 剥好的干净骨架）拼装一台五段流水线脱壳机，替代 v 系列手工 bodyswap 时代的一切。

## 1. 为什么现在能成（而 v 系列一百变体全死）

| 时代 | 牌面 | 结果 |
|---|---|---|
| v59–v141（手工时代） | 护甲全在 + bodyswap 53 方法 + 人工逐层试 | 0 窗死循环/JIT 崩/Error 框，最好成绩 v139 本机出窗、CI 从未出窗 |
| 今天（本计划） | 反篡改/反调试已被 NRS 剥离的干净骨架 + **96.66% 方法体真体（0 不可还原）** + 池/表已解码 + 对分回填法成熟 | 待验证（M1 试金石） |

关键差异：当年死因集中在「方法体缺失 + 间接层靠猜」；如今方法体是全量语料，间接层（字符串池 199K、委托表 3266）已有解码数据，只差回接工程。

## 2. 参考项目（GitHub）

- **[SychicBoy/NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer)**（GPLv3）— 架构蓝本：模块化分阶段（dec-methods / dec-strings / dec-rsrc / rem-antis / deob-cflow / fix-proxy / rem-calls / rem-junks），dnlib 写出，`--preserve-all` / `--keep-max-stack` 旗标齐备。对本目标实测：标准层全过、Necrobit 体解密与资源解密空引用崩（定制方案不兼容）——我们的差异价值正在这两层。
- **[de4dot](https://github.com/de4dot/de4dot)** — 业界标准框架参考（ICodedKey 解密器接口、cflow 去混淆、assembly 重建流程）。
- **[notprab/.net-deobfuscator](https://github.com/notprab/.net-deobfuscator)** — 品类清单，后续按需取材（字符串解密器写法、ProxyCall 修复思路）。
- 本仓库自有遗产：`tools2/bodyswap.cs`（三件套一体替换）、v 系列 CI 矩阵经验、`work/c2_pack`（体库+清单）、`work_a1/`（算法/密钥/工具链）。

**License 注意**：若直接拷贝 NRS 源码段须遵 GPLv3 传染条款；本计划只参考架构思想，实现走自家代码 + 自家资产，产物不作开源分发（业主私有），规避冲突。

## 3. 资产盘点（全部在盘，路径为证）

| 资产 | 路径 | 状态 |
|---|---|---|
| 方法体库 22,165 + 765 部分 | `work/c2_pack/bodies/`、`bodies_manifest.tsv` | ✅ 0 不可还原 |
| Viewer 条目表（体头结构） | `work_a1/dec_Viewer.bin`（[RVA][t1][fat0][t2][locals][body][t2][nxtRVA] 双源验证） | ✅ |
| AOT 解密算法 | `work/decrypt_prng.py`（LE 直 XOR，bswap 表述已勘误） | ✅ |
| 资源密钥 4/6 | Viewer/mainlib/Factory/Project(零)；Proc/Emitter 无 key（内容=明文表/AES 载体，非 keyed 密文） | ✅ |
| 解密资源 4/6 | `work/c2_pack/dec/`（roundtrip 双重校验） | ✅ |
| 字符串池 199K | `work_a1/dec_FactoryValidator.bin` | ✅ 已解、回接未做 |
| 委托绑定表 3266 | `work_a1/zdec/Project.bin`（`[seq 0x21 00 04][0b1x token]`） | ✅ 已解、回接未做 |
| 卫星资源 626 | `work_a1/mlres/` | ✅ |
| 干净骨架（反篡改/反调试已除） | `work_a1/nrs/work/AirExplorer_test_Slayed.exe`（5.06MB）+ NRS v6.4 工具包 | ✅ |
| RVA↔MethodDef 映射 | `work/mdrva.py` + `work/c2_pack/c2_coverage.json` | ✅ |
| 验收 harness | `ci/probe_iso.ps1` / `ci/soak_iso.ps1`（隔离环境） | ✅ |
| 对分回填法 | v 系列 CI 经验（board XII 前各节） | ✅ |

## 4. 架构：五段流水线 + 一条验收线

```
官方基线(md5 a12b5c57)                     【业主资产，只读】
      │
      ▼
[NRS v6.4 预处理]  反篡改/反调试剥离, cflow去混淆, 垃圾清除, 150静态字符串
      │            (已验证可行, 产物= Slayed 骨架)
      ▼
┌─ AirExplorerUnpacker (自研, dnlib, net472) ─────────────────────┐
│ S1 体注入: bodies/ (RVA→token) 写回每个 MethodDef                │
│ S2 字符串回接: 取串调用→ldstr (池199K + 静态150)                 │
│ S3 委托重接: Project表3266处 间接调用→直调 callvirt/call         │
│ S4 资源重嵌: dec/ 4资源替换密文资源 + 卫星资源626                │
│ S5 写出: dnlib PreserveAll|KeepOldMaxStack                       │
└──────────────────────────────────────────────────────────────────┘
      │
      ▼
[验收线] probe_iso (真窗?) → soak_iso (7min) → 行为diff官方
      │ 反馈
      └── 对分回填: 哪段引入死→半量写回二分定位 (log2 收敛)
```

工具形态：`tools3/unpacker/`（C# net472 单工程 + csc 编译脚本；不依赖 SDK，用 NETReactorSlayer 包里自带的 dnlib.dll）。

## 5. 里程碑（每段独立验收 + 死法分类）

| 里程碑 | 内容 | 验收判据 | 预算 | Kill 条件 |
|---|---|---|---|---|
| **M0** 骨架就绪 | NRS 预处理产物入库 | 已完成（本计划） | — | — |
| **M1** 体注入试金石 | 只做 S1，跑探针 | 死法分类信号：崩在哪（JIT/启动链/资源缺）决定后续优先级 | 1 会话 | 若 Slayed 骨架连 Main 都进不去且元数据已残 → 换自建元数据路线（工作量×2 再评估） |
| **M2** 字符串回接 | S2 全量 | 探针不死在字符串层；抽 20 方法反汇编抽查 ldstr 正确 | 1-2 会话 | 单点遗漏可对分定位；若取串 API 形态超预期（>3 种签名）加预算 |
| **M3** 委托重接 | S3 全量 3266 | 探针过启动链 | 1 会话 | — |
| **M4** 资源重嵌 | S4+S5 全量 | 探针出窗 | 1 会话 | — |
| **M5** 终验 | 全链 | probe PASS + soak 7min + 与官方 UI 行为肉眼 diff | 0.5 会话 | — |

每里程碑产物：exe 变体 + 探针日志 + board 记录（沿用 v 系列纪律）。

## 6. 风险登记册（v 系列死法 → 缓解）

| 风险 | 历史 | 缓解 |
|---|---|---|
| 0 窗死循环（启动链断一环即死） | v139 CI 从未出窗 | 对分回填法 + JIT dump 差分预言机（先知哪个方法将崩） |
| 间接层遗漏 | bodyswap 时代全靠猜 | 池/表已解码，回接是确定性工程；每段先全量枚举再动手 |
| 765 部分体 | — | M1 先探其命中路径；命中者走 vault 部分体 + 人工补 |
| Slayed 骨架暗伤（NRS 剥离副作用） | 本轮实测 2.5s 崩（无体） | M1 区分「无体崩」vs「骨架残」；后者触发 Kill 条件换路线 |
| WPF/WinForms 初始化敏感 | v68 Dictionary 崩 | PreserveAll 保 token；不重排元数据 |
| GPLv3 传染 | — | 只参考思想不拷码（§2） |

## 7. 工程约束（与 A 线同源，不可违反）

1. 基线只读：一切产物自 `exes/AirExplorer_baseline_verified.exe`（md5 `a12b5c573e1b54e98cccc29351eaa066`）副本。
2. dnlib 写出必须 `PreserveAll | KeepOldMaxStack`。
3. 交付物禁注入（无 DLL 劫持/Loader/Profiler/Harmony 于最终形态；开发期 NRS 预处理工具链不受此限，因其产出为静态 exe）。
4. 本计划产物**不触碰 overlay** 约束相对基线副本自动满足（重建产物是全新文件）。
5. 一切进程测试走 `ci/probe_iso.ps1` / `ci/soak_iso.ps1` 隔离口径，结束杀净。
6. 每步落盘、board 记账，防会话丢失。

## 8. 目录规划

```
airexplorer-reactor-handoff/
├── docs/UNPACKER_PLAN.md          ← 本文件
├── tools3/unpacker/
│   ├── build.cmd                  (csc + dnlib 打包编译)
│   ├── src/*.cs                   (S1-S5 五段 + CLI)
│   ├── out/                       (产物变体, gitignore 大文件)
│   └── PROGRESS.md                (里程碑账本)
└── agent.md                      (本计划战况记于此)
```

## 9. 决定记录

- 2026-10-26：业主批准自研脱壳机立项（参考 GitHub 生态：NETReactorSlayer/de4dot），计划先行落库。激活①（A 线）维持 C3 定案不受本项目影响；本项目目标=干净可运行的脱壳产物（其上任何后续修改不再受 Authenticode 墙约束，因为重建产物不含该校验层）。
