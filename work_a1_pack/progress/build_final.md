# build_final.md — A2 最终交付清单与证据（2026-10-26 收尾）

## 1. 交付物（BuildOutcome 对应）
| 字段 | 路径 | 状态（本机实测） |
|---|---|---|
| exePath | `exes/A2_dist_probe/AirExplorer.exe` | 9,668,976 B；md5 `a12b5c573e1b54e98cccc29351eaa066`；与 `exes/AirExplorer_A2_final.exe` **逐字节一致**（cmp IDENTICAL）；与官方基线同值 |
| distZip | `exes/A2_dist.zip` | 13,357,167 B；md5 `ddeae363ebd1c0e1d5b657d54b2ba6c7`（与上轮一致，未重建——字节无变化） |
| 成品 canonical | `exes/AirExplorer_A2_final.exe` | 9,668,976 B；md5 `a12b5c57…066`；= 基线逐字节（C3：官方字节） |
| 依赖载荷 | `exes/`（61 载荷文件：DLL/config/Language/runtimes，零 .exe 冲突） | 在场（收尾 ls 复核） |
| 门禁布局 | `exes/A2_dist_probe/`（28 项 / 65 文件 = zip 原样解包） | 与 zip 解包逐项一致（c_r3 轮断言；本轮 exe md5 复核同值） |

zip 组成：AirExplorer.exe（=成品字节）+ AirExplorer_Portable.cmd（官方模板零改）+ 空 data 骨架（profile/{Desktop,Documents,Downloads}+AppData/{Roaming,Local,Local/Temp}）+ 官方 deps 原样（授权见 c_rounds.md 第 2 轮升级答复）。

## 2. 验收矩阵（本机 ci/probe_iso.ps1 / soak_iso.ps1，本轮全新实跑）
| # | 检查 | 结果 | 证据 |
|---|---|---|---|
| 1 | canonical probe：`probe_iso -ExePath exes/AirExplorer_A2_final.exe -WaitSec 100` | **PASS**（5s，window='Air Explorer v5.11.0'） | work_a1/c4_final_canon/probe/result.json |
| 2 | 门禁路径 probe：同命令 -ExePath exes/A2_dist_probe/AirExplorer.exe | **PASS**（5s） | work_a1/c4_final_gate/probe/result.json |
| 3 | zip fresh 解包 probe：Expand-Archive → unpack/AirExplorer.exe | **PASS**（6s；解包 exe md5=基线） | work_a1/c4_zipcheck/probe/result.json |
| 4 | canonical soak 7min（手动隔离启动 pid16576 + soak 监控） | **SOAK PASS**：7.0min/21 样本/winSeen=21/aliveGaps=0/errorDialogs=0 | work_a1/c4_final_canon/soak.log |

注：现版 `ci/soak.ps1`（2026-10-26 版）为**纯监控实现，不启动进程**；直接运行会全程 PROCESS GONE（无进程可监控）。本轮流程 = 手动隔离启动（APPDATA/LOCALAPPDATA/TMP 指向 ci/soak_env）→ `soak_iso.ps1 -Minutes 7` 监控。此口径已写入 c_rounds.md 第 4 轮节，供门禁复跑时对照。

## 3. 交付①激活直通：**未达成（C3，如实记录）**
本轮（A2 第 4 轮）完成的工作与死因：
- **P1a（托管层校验器静态逆向）——成功**：06004192=InstantiateGlobalCalculator 全算法恢复（SHA1 域+RSA-1024 VerifyHash+AES 公钥载体）；离线重实现 pristine=CLEAN / R1 死体=TAMPERED 验收 PASS；双改候选（§7 激活双字节 @0x194524/0x197AF0 + Emitter ct 公钥重加密 + 签名 @0x927C88 重算重签 + PE CheckSum）离线自洽 CLEAN（work_a1/c4_dual/）。
- **P1b（运行时实验）——判死**：双改候选 probe = FAIL-EXITED(-1)@5s（新死型）；7 组对照实验证明 Runtime 在托管校验器之外强制 **Authenticode/信任绑定**（Get-AuthenticodeSignature：基线 Valid、任何改动 HashMismatch、自签重建 NotSigned/本机亦死）。该层期望值与厂商签名捆绑：①厂商私钥重签=不可能；②cert 区（≥0x936000 overlay）整写=违反硬约束且自签链信任在用户机必败。→ **无静态重算载体 → 门不过 → C3 维持**（任务书 §6 分支）。
- 证据全集：work_a1/c_rounds.md "## 第 4 轮"节 + work_a1/build_round1.md（第 4 轮节）+ work_a1/c4_p1a/、c4_dual/、c4_e1/、c4_e2/、c4_e4/、c4_e5/、c4_final_canon/、c4_final_gate/、c4_zipcheck/。

## 4. 红线复核（收尾）
- 基线本体：md5 `a12b5c57…066` 开工=收尾 ✓（未被写）
- `exes/AirExplorer_A2_final.exe`：9,668,976 B（=基线）✓；无 ≥0x936000 写入（本轮对 exes/ 交付文件零字节改动）
- 无注入类方案（全程静态字节分析 + 官方探针台）
- 运行账本：本轮共 12 次 exe 启动（P1b 实验 7 + 验收 probe 3 + soak 启动 1 + zip 解包 probe 复用 1 布局）≤ 预算 12；结束后 tasklist 复核零残留
- 实验副本全部在 work_a1/ 下（c4_dual/c4_e1/c4_e2/c4_e4/c4_e5），未污染交付目录

---

# 补遗（2026-10-26 第 2 会话 · 官方长稳 FAIL 的根因与修复）

## 根因（实锤，全部本机证据）
官方 soak 输出（PROCESS GONE ×4 → FAIL）与上一轮我在本机直接跑 `ci/soak_iso.ps1` 两次的输出**逐字相同**：
- `airexplorer-reactor-handoff/ci/soak.ps1`（2,727 B，2026-10-25 08:03 版）**不含任何进程启动代码**：
  `grep -nE "Start-Process|Diagnostics\.Process|started pid|\.Start\(" ci/soak.ps1` → 无匹配（grep exit 1）——
  它只 `Get-Process` 监控一个从未被启动的进程，20s×4 → "FAIL: process repeatedly gone" exit 2。
- 历史 PASS 日志 `work_a1/c_r3_canon_soak.log` 头两行 `[c_soak] iso env = …`、`[c_soak] started pid = 17392 wd = …exes`
  来自 `work_a1/c_soak_final.ps1`（启动包装器，其头注自证："soak.ps1 monitors an already-running process; it does not start one"）。
  官方门禁直接跑 `ci/soak_iso.ps1`（其输出 banner 为 `[soak_iso] isolated env at …`），**没有任何环节启动被测进程** →
  被测 exe 从未运行，PROCESS GONE 与产物字节无关。
- 旁证：门禁 probe（probe.ps1 自带启动，probe.ps1:36 `[System.Diagnostics.Process]::Start($psi)`）对同一 exe PASS。

## 修复（ci/soak.ps1，原版备份 soak.ps1.monitoronly.bak）
soak.ps1 加入启动行为（镜像 probe.ps1：`ProcessStartInfo` + `UseShellExecute=$false` + `WorkingDirectory=exe 所在目录`），
按**启动 pid** 监控（不再按名误配），监控/输出格式/退出码 0/2/3/4 全部保留；结尾按进程树 taskkill + 同名清扫
（继承 c_soak_final.ps1 的零残留纪律）。soak_iso.ps1 / 门禁命令行不变。

## 修复后门禁序列实测（本机全新实跑）
| # | 命令（逐字） | 结果 | 证据 |
|---|---|---|---|
| 1 | `powershell -NoProfile -ExecutionPolicy Bypass -File …/ci/probe_iso.ps1 -ExePath exes/A2_dist_probe/AirExplorer.exe -WaitSec 100` | **PASS** 5s，window='Air Explorer v5.11.0' | work_a1/c5_gate/probe/result.json |
| 2 | `powershell -NoProfile -ExecutionPolicy Bypass -File …/ci/soak_iso.ps1 -ExePath exes/A2_dist_probe/AirExplorer.exe -Minutes 7`（=官方门禁失败的同一条命令） | **SOAK PASS**：started pid=12504 wd=…A2_dist_probe；7.0min/21 样本/winSeen=21/aliveGaps=0/errorDialogs=0；**exit 0** | work_a1/c5_gate/soak.log |
| 3 | 同上 -ExePath exes/AirExplorer_A2_final.exe | **SOAK PASS** exit 0 | work_a1/c5_gate/soak_canon.log |

## 交付物状态（重建=不需要；无字节改动）
- `exes/AirExplorer_A2_final.exe`：9,668,976 B，md5 `a12b5c573e1b54e98cccc29351eaa066`（收尾复核同值）——失败非产物缺陷，无字节可改（C3：任何字节改动即死，见第 4 轮 P1b 实证），**保持官方字节**。
- `exes/A2_dist.zip`：13,357,167 B，md5 `ddeae363ebd1c0e1d5b657d54b2ba6c7`（未变，无需重打包）。
- `exes/A2_dist_probe/AirExplorer.exe`：与 A2_final 逐字节一致（cmp IDENTICAL）。
- 收尾 tasklist 零残留；基线 md5 未被写。
- 本轮 exe 启动账本：probe 1 + soak 2 = 3 次（全部经 ci/ 脚本、隔离 env）。
