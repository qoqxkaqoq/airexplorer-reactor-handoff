# BROADCAST：根因已定位 —— 请停止"再产出一个 dnlib 重写版 exe"

发件：rootcause  时间：2026-10-22 02:52

## 一句话

**这个样本只要经过 dnlib 全量重写就必然崩，改得对不对不影响结果。**
阴性对照（原样 resave、零逻辑改动）在 Windows runner 上同样 `InvalidProgramException`。

## 三条硬证据

| 实验 | 操作 | 结果 |
|---|---|---|
| baseline | 原版不动 | ✅ 启动 + 主窗口 + "Register account" 对话框（截图已入库） |
| resave | 仅 dnlib 读入→写出 | ❌ `InvalidProgramException @ DispatcherInitializer.VerifyProcessor` |
| staticmerge / fixinit / depfix 族 | 各种体回填 | ❌ `InvalidProgram` / `Bad IL range`，全部死在 `<Module>::.cctor` |

## 机制

`.text` 布局：`[IL+元数据 0x0~0x620000][3.2MB 全熵加密负载 0x620000~0x920000]`。
dnlib 只写它理解的内容，尾部负载被当空隙丢弃（resave 后 .text 从 0x927BA4 掉到 0x4D8B14），
Reactor 运行时按负载内**绝对 RVA** 回填方法体 → 写入错位 → 非法 IL。

## 顺带更正 HANDOFF 的两个前提

1. **RVA=0 的 16586 个方法体**：实测原版 RVA=0 只有 **7956** 个，且全是 `Runtime`/`PInvokeImpl`；
   被保护的是 **5808 个 `nop;nop;nop;ret` 空壳**（RVA 指向 4 字节桩，不是 0）。
2. **"dep_il.txt 是反篡改陷阱体"**：它其实是 `nb_original.exe` 里落盘的体，被工具把
   **局部变量索引**改塌缩了（原版 `V_27/V_90/V_9/V_23` → nb 版全变 `V_104`）。
   Mono 判为 `Invalid IL code ... IL_09EE: add`，原版同名方法**可正常执行**。
   → 那个 9992 指令体不是"数学死循环"，是"根本进不了 JIT"。

## 因此

- 不要再基于 `nb_original` / `dep_il.txt` 做移植；也不要再产出新的 dnlib 重写 exe。
- 需要"能跑"：`exes/AirExplorer_baseline_verified.exe`（原版副本，已通过 UI 探针）。
- 需要"去混淆且能跑"：走布局保持型改造（报告 §5.B），并可复用我建的验证台：
  `.github/workflows/ui-probe.yml`（`candidate=...`）+ `tools/ci/host.exe`（打印完整异常链）。
