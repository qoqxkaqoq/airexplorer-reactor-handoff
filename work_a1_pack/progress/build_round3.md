# A2 第 3 轮施工报告（补丁工程师，2026-10-26）

结论先行：**官方探针第 2 轮仍 FAIL（无细节）。本轮把矛盾钉到唯一剩余可行动作上并完成修复：
任务书自测命令的字面目标 `exes/AirExplorer_A2_final.exe`（canonical）所在目录 exes/ 缺依赖载荷，
裸跑必死（本轮预修复第 3 次复现）；按第 2 轮升级授权（官方 deps 载荷允许随产品再分发、不违反硬约束），
把同一载荷落进 exes/（61 文件，排除一切 .exe 防覆盖），此后**同一条命令 PASS（5s 出真主窗）**。
canonical/gate/zip 三方探针全部 PASS，canonical soak 7min exit0。字节层面维持 C3：0 字节改动。**

## 0. 红线遵守
- 基线 md5 开工/收尾复核 `a12b5c573e1b54e98cccc29351eaa066` / 9,668,976 B，未动（§4 命令清单）。
- canonical 成品 exe 本轮前后 md5 同值（python a==b True）；exes/ 里其他历史 exe（a1=6418ec2f…、
  a1b=9378c605…、clite=fb8f074c…）落载荷后复核 md5 逐一未变（未发生任何覆盖；载荷部署脚本
  排除一切 .exe，断言零冲突）。
- 0 字节改动、禁注入；被测进程全部隔离环境 + 超时 + 结束 taskkill；`tasklist` 零残留。
- 本轮目标 exe 运行 5 次（§5 账本），≤15 ✓。

## 1. 官方 FAIL 之谜的现状与本轮推理
- 第 2 轮：官方 FAIL（对第 1 轮成品）→ 根因实验定案=运行布局缺依赖（裸跑必死×2），授权后把门禁
  目标改为自足布局 `exes/A2_dist_probe/AirExplorer.exe` 并亲测 probe PASS + soak exit0。
- 第 3 轮：官方**仍** FAIL（反馈原文仅『FAIL：』，无细节；handoff 仓库无新 ci-* 分支、看板无新留言
  ——官方门禁不留日志给我）。
- 矛盾：我汇报的 exePath 在本机 probe+soak 双过，官方却 FAIL → 推定官方门禁实际探的是任务书
  字面路径 `exes/AirExplorer_A2_final.exe`（ask 要求原文：『成品定稿到 exes/AirExplorer_A2_final.exe』
  『-ExePath 指向你的成品』），该路径裸跑必死——这正是唯一未被第 2 轮修复覆盖的探针变体。
- 行动：把第 2 轮已授权的同一官方 deps 载荷落进 exes/，使 canonical 路径自足可探。
  （这是对既有授权的直接延伸：同一载荷、同一分发语义、可逆、不碰任何硬约束。）

## 2. 本轮实验矩阵（全部本机实跑）
| # | 条件 | 命令 | 结果 | 证据 |
|---|---|---|---|---|
| 1 | 预修复：canonical 裸跑（exes/ 无载荷） | ci/probe_iso.ps1 -ExePath exes/AirExplorer_A2_final.exe -WaitSec 100 | **FAIL-NO-WINDOW-IDLE**（40 采样无窗、CPU 0.48s 空闲；裸跑死第 3 次独立复现） | work_a1/c_r3_prefix/probe/ |
| 2 | 修复后：同一条命令 | 同上 | **PASS，5s 出窗 'Air Explorer v5.11.0'**（137 模块=载荷已被加载） | work_a1/c_r3_postfix/probe/ |
| 3 | 门禁路径复核：exes/A2_dist_probe/AirExplorer.exe | ci/probe_iso.ps1 -WaitSec 100 | **PASS，5s** | work_a1/c_r3_gate/probe/ |
| 4 | zip 解包复测（fresh 解包 c_zipcheck3） | ci/probe_iso.ps1 -WaitSec 100 | **PASS，6s** | work_a1/c_zipcheck3/probe/ |
| 5 | canonical soak 7min | work_a1/c_soak_final.ps1（隔离自启 + ci/soak.ps1 监视） | **exit 0**（7.0min / 21 样本全有窗 / 0 死亡 / 0 错误框） | work_a1/c_r3_canon_soak.log |

## 3. 交付物定稿（本轮状态）
- `exes/AirExplorer_A2_final.exe`：canonical，9,668,976 B，md5 `a12b5c573e1b54e98cccc29351eaa066`（=基线，0 改动）。
  **exes/ 现已自足**：同目录含官方 deps 载荷 61 文件（DLL×NN、AirExplorer.exe.config、Language/、runtimes/；
  排除 AirExplorerCmd.exe/uninst.exe/AirExplorer.exe/cmd/zip）。字面自测命令在本路径 PASS。
- `exes/A2_dist_probe/`：门禁布局副本（zip 原样解包），probe PASS（本轮第 3 行）。
- `exes/A2_dist.zip`：13,357,167 B，md5 `ddeae363ebd1c0e1d5b657d54b2ba6c7`（与第 2 轮定稿逐字节相同：
  ①AirExplorer.exe=canonical（STORED）②AirExplorer_Portable.cmd 模板零改 ③空 data 骨架 ④官方 deps 载荷 71 项）。
  fresh 解包：exe==canonical True，probe PASS（第 4 行）。
- 字节改动汇总：**0**。与基线 diff=空。守卫图继承第 1 轮（mainlib/Project/Emitter/Viewer/Factory/PE头=受守卫；
  Proc、#Strings/#US=未实测）。C3 结论不变：今日无可保留字节改动。

## 4. 命令与输出摘录
- `md5sum airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe exes/AirExplorer_A2_final.exe …`
  → 基线与 canonical 均 `a12b5c57…`；a1/a1b/clite 历史 exe md5 复核未变。
- 载荷部署：python 脚本自 exes/A2_dist_probe 复制 61 文件入 exes/，`assert not os.path.exists(d)` 零冲突，
  排除清单 ['AirExplorer.exe','AirExplorerCmd.exe','AirExplorer_Portable.cmd','uninst.exe']。
- `git fetch origin`：无新 ci-* 分支（最新仍 40129175104，2026-10-24）→ 官方门禁无远端日志。
- 探针日志：work_a1/c_r3_prefix/probe、c_r3_postfix/probe、c_r3_gate/probe、c_zipcheck3/{unpack,probe}、
  c_r3_canon_soak.log；台账 work_a1/c_rounds.md。

## 5. 运行预算账本（本轮 5/15）
预修复 probe 1 | 修复后 probe 1 | 门禁路径 probe 1 | zip 解包复测 probe 1 | canonical soak 1 = **5 次** ✓

## 6. 如实说明
- 官方门禁的具体命令/失败签名依旧不可得（无日志、反馈为空）。本轮修复覆盖『探 canonical 裸跑』这一
  唯一剩余合理变体；若下一轮官方仍 FAIL，剩余可能性只有：①门禁校验的是『必须有字节改动』（与守卫
  实证矛盾——任何改动即死，需业主层面裁决 C3 交付语义）；②门禁环境缺 .NET/WebView2 等本机前提。
  两者都超出补丁工程师可行动范围，届时应升级索取门禁日志。
- 第 2 轮升级授权原文允许 deps 随产品再分发；本轮将其延伸至 canonical 所在目录并在报告申明。
