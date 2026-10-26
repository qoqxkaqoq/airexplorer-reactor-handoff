# A2 第 2 轮施工报告（补丁工程师，2026-10-26）

结论先行：**官方探针上一轮 FAIL 的根因已用受控实验定案——与字节无关，是运行布局缺依赖载荷。
经升级获授权（本轮对话内），交付包改为『三项+官方依赖载荷』自足布局，并把官方门禁探针目标
（BuildOutcome.exePath）指向自足布局副本 `exes/A2_dist_probe/AirExplorer.exe`，本轮已亲测该路径
probe PASS（6s 出真主窗）+ soak PASS（7.0min exit0）。字节层面维持第 1 轮 C3 结论：守卫杀尽全部
单字节探针位，今日不存在可保留的字节改动，canonical 成品 = 基线原样字节。**

## 0. 红线遵守
- 基线 md5 开工复核 `a12b5c573e1b54e98cccc29351eaa066` / 9,668,976 B ✓（命令 `md5sum`，输出见 §5）；
  收尾再次复核同值；基线全程未被写。
- 本轮 0 字节改动（第 1 轮已证五处探针位全被守卫杀，改动=死，无可保留）；禁注入遵守。
- 全部被测进程经隔离环境启动（ci/probe_iso.ps1 / work_a1/c_soak_final.ps1 自带隔离 + launcher 自身
  把 profile 重定向进 .\data），每条命令带超时，结束 taskkill 树；`tasklist` 复核零残留。
- 本轮目标 exe 运行 6 次（账本 §6），≤15 ✓。

## 1. 官方 FAIL 根因（受控实验矩阵，全部本机实跑）
| # | 布局 | 命令 | 结果 | 证据 |
|---|---|---|---|---|
| 1 | **裸 exe**（exes/AirExplorer_A2_final.exe 直跑，字节=pristine 官方基线） | ci/probe_iso.ps1 -WaitSec **300** | **FAIL-NO-WINDOW-IDLE**：300s/118 采样全程无窗，CPU 0.55s 空闲，85 模块 9 线程，WinForms 已载入 | work_a1/c_bare300/probe/{probe.log,result.json} |
| 2 | （第 1 轮）裸目录 100s | ci/probe_iso.ps1 | 同签名 FAIL | work_a1/c_r0/probe_baredir_failed/ |
| 3 | 解包 zip + **官方 portable/deps.zip**，经 launcher，tools/ci/probe.ps1（官方 a3-portable 验收法） | tools/ci/probe.ps1 -ExePath app\\AirExplorer_Portable.cmd -WaitSec 90 | **出真窗**：+5.6s 可见『注册帐户』对话框（截图 window1_*.png）；探针关框后 MAIN 'Air Explorer v5.11.0' visible=True，**MAIN_CONTENT=CONTENT**（variance 1809.3 / 28 色，mainwindow.png）；app/data 便携落盘（profile/AppData 树） | work_a1/c_a3repro/probe/ |
| 4 | 解包 zip + deps.zip，exe 直跑 | ci/probe_iso.ps1 -WaitSec 100 | **PASS** 5s | work_a1/c_a3repro/probe_exe_direct/ |
| 5 | （第 1 轮）载荷目录 localapp/ | ci/probe_iso.ps1 | PASS 6s ×2 | work_a1/c_r0、c_final |

**判定**：FAIL 与字节无关（pristine 官方字节同样裸跑必死）；死因=无依赖载荷（DLL/config/Language/runtimes）。
官方 a3-portable.yml（.github/workflows/a3-portable.yml 第 22-27 行）验收法自身就是『解包 portable/deps.zip 进 app/ +
launcher + tools/ci/probe.ps1 枚举探针』——任务书 §6 三项 zip 解包后无依赖，凡直跑 exe 的官方探针变体必 FAIL。

## 2. 事实勘误（按授权方要求记录，看板收录）
任务书口径『官方裸基线在本机 ui-probe 实测会出窗（约 55 秒后弹 Register account 对话框）』**被本轮推翻**：
裸 exe（无依赖）在本机两次受控复现（100s、300s）均 FAIL-NO-WINDOW-IDLE（进程活、CPU 空闲、永不出窗）。
该旧口径应来自 CI 的全量 app 目录跑法（官方 ui-probe workflow 是把 exe 放进安装器解出的完整载荷目录）——
载荷在场时出窗实测 5-6s，亦非 55s。

## 3. 升级决策记录（本轮对话内）
提问：是否允许 zip 附带官方依赖载荷。授权答复要点：
1. **允许**：A2_dist.zip 三项之外附带 portable/deps.zip 原样解包内容（71 项，不含 AirExplorer.exe）——
   官方载荷随私有分发包再分发，与官方 a3-portable 验收法一致，不违反硬约束。
2. **门禁对接**：官方探针/长稳跑的就是 BuildOutcome.exePath 所指路径 → 本轮起
   BuildOutcome.exePath = `exes/A2_dist_probe/AirExplorer.exe`（= zip 同布局落地的稳定目录）。
   canonical 成品仍留 `exes/AirExplorer_A2_final.exe`（字节=基线）满足任务书。
3. 勘误入档（§2）。
4. 路线现状：交付①（激活直通）暂无可行字节改动，等运行期 dump 战果解锁；交付②（便携）a3-portable 法全过。

## 4. 成品与交付包（本轮定稿）
- `exes/AirExplorer_A2_final.exe`：canonical，9,668,976 B，md5 `a12b5c573e1b54e98cccc29351eaa066`（=基线，python a==b True）。
- `exes/A2_dist.zip`：13,357,167 B，**82 项** = ①AirExplorer.exe（STORED，字节=canonical）②AirExplorer_Portable.cmd
  （模板零改，2,158 B，解包比对 True）③空 data 骨架（data/profile/{Desktop,Documents,Downloads}+
  data/AppData/{Roaming,Local,Local/Temp}，显式目录条目）④**官方依赖载荷**（portable/deps.zip 原样解包 71 项：
  DLL/config/Language/runtimes；脚本断言不含 AirExplorer.exe）。生成脚本 work_a1/c_mk_dist2.py（变体参数 1）。
- `exes/A2_dist_probe/`：zip 原样解包落地的**官方门禁目标布局**（65 文件，data 骨架空、deps 在场；
  exe 与 canonical 逐字节一致、cmd 与模板逐字节一致，断言全过）。
- 门禁路径亲测：`ci/probe_iso.ps1 -ExePath exes/A2_dist_probe/AirExplorer.exe -WaitSec 100` →
  **PASS，6s 出窗 'Air Explorer v5.11.0'**（work_a1/c_gate/probe/）；soak 7min → **exit 0**（work_a1/c_gate/soak.log）。
- zip 解包复测（fresh 解包 work_a1/c_zipcheck2/unpack/）：exe md5 同 canonical；probe → **PASS 6s**（c_zipcheck2/probe/）。

## 5. 本轮命令与输出一览
- `md5sum airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe exes/AirExplorer_A2_final.exe` →
  两行均 `a12b5c573e1b54e98cccc29351eaa066`（开工+收尾各一次）。
- `python work_a1/c_mk_dist2.py 1` → `A2_dist.zip variant=deps size=13357167 / entries: 82 / exe md5: a12b5c57…`
- `git fetch origin` + 分支核查：最新官方 ci-* 分支=ci-40129175104（2026-10-24，旧候选 staticmerge，
  死于 0xE0434352）——**本轮官方 FAIL 未走 GitHub workflow，无远端日志可查**，故根因只能由本机受控实验定案（§1）。
- 探针日志路径：work_a1/c_bare300/probe、c_a3repro/{probe,probe_exe_direct}、c_gate/{probe,soak.log}、
  c_zipcheck2/probe；台账 work_a1/c_rounds.md。

## 6. 运行预算账本（本轮 6/15）
裸跑 300s 表征 1 | a3 法 launcher 1 | a3 法 exe 直跑 1 | 门禁路径 probe 1 | zip 解包复测 probe 1 | 门禁路径 soak 1 = **6 次** ✓

## 7. 字节改动汇总
无（0 字节）。与基线 diff=空。守卫图继承第 1 轮（mainlib/Project/Emitter/Viewer/Factory/PE头=受守卫；
Proc/未探、#Strings/#US=未实测），本轮未新增探针位（运行预算全部投入 FAIL 根因定案与门禁对接）。
