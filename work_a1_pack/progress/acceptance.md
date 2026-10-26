# acceptance.md — A 线交付物②（便携）与③（暗桩中和）验收

验收员独立实跑记录。只测不改。

> 记录说明：06:39–06:42 有一次验收会话写了 §0–§2 前半（便携+探针）后被中断；
> 本会话（06:54 起）**独立重跑全部检查**并补齐缺失的门禁②长稳。§1.2/§3.1 为本会话实测，
> 与前次记录（§1/§2）相互印证；最终结论以本会话实测为准。

## 0. 静态事实（开工实测）

命令：`md5sum airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe exes/A2_dist_probe/AirExplorer.exe exes/AirExplorer_A2_final.exe`

| 文件 | 大小 | md5 |
|---|---|---|
| 基线 `airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe` | 9,668,976 | `a12b5c573e1b54e98cccc29351eaa066`（与任务书一致 ✓） |
| 成品 `exes/A2_dist_probe/AirExplorer.exe` | 9,668,976 | `a12b5c573e1b54e98cccc29351eaa066` —— **与基线相同 = 官方原版字节，非静态篡改** |
| `exes/AirExplorer_A2_final.exe` | 9,668,976 | `a12b5c573e1b54e98cccc29351eaa066`（同上） |

zip：`exes/A2_dist.zip` = 13,357,167 B，md5 `ddeae363ebd1c0e1d5b657d54b2ba6c7`（与 build_final.md 记录一致）。
zip 内 `AirExplorer.exe`（`unzip -p … | md5sum`）= `a12b5c573e1b54e98cccc29351eaa066` = 官方字节；
zip 内 `AirExplorer_Portable.cmd` md5 `ba53368b6e9d7ad0323de83a152a38c2` = `airexplorer-reactor-handoff/portable/AirExplorer_Portable.cmd` 模板逐字节一致（零改）。

（动态门禁实跑见下文，逐步补充。）

## 1. 便携测试（交付物②）—— 实跑 PASS

流程（任务书口径）：zip 解到全新 scratch → 跑 `AirExplorer_Portable.cmd` → 等 70 秒 → 查 data\ 与窗口 → taskkill 整树。

- 解包：`rm -rf work_a1/acc_portable_scratch && mkdir … && unzip -q ../../exes/A2_dist.zip` → exit 0；解包内 `AirExplorer.exe` md5 = `a12b5c573e1b54e98cccc29351eaa066`（官方字节）、`AirExplorer_Portable.cmd` md5 = `ba53368b6e9d7ad0323de83a152a38c2`（模板零改）。
- 启动：`Start-Process cmd.exe '/c AirExplorer_Portable.cmd' -WorkingDirectory <scratch>` → **CMD_PID=12528**，06:40:04.146。
- t+70s（06:41:23.513）检查：
  - **窗口出现**：AirExplorer pid=5812（06:40:04 启动），MainWindowHandle=11010970，title=`Air Explorer v5.11.0`，Responding=True，CPU=1.6s，WS=345MB。
  - **data\ 生成用户数据文件**：共 16 个文件。关键证据 `data\profile\AppData\Roaming\AirExplorer\Accounts.xml`（104B，内容 `<CloudAccounts version="1.0"><accounts /><categories /></CloudAccounts>` —— 本次全新运行写出）；另 15 个为 `data\profile\AppData\Local\Microsoft\Windows\Explorer\iconcache_*.db`（经重定向 USERPROFILE/LOCALAPPDATA 落入 data\）。
  - **真用户目录未被触碰**：`C:\Users\xaxka\AppData\Roaming\AirExplorer` 最后写入时间 04:20/04:26（早于本次 06:40 运行），本次运行零写入。
- 清理：`taskkill /PID 12528 /T /F` → 成功终止 PID 5468、5812（AirExplorer）、12528（cmd）三个进程；复核 `cmd 12528 alive: False`，AirExplorer 残留=0，AirExplorerCmd 残留=0。

**结论②：便携 PASS —— zip 自包含可解包，启动器把用户数据（Accounts.xml 等）重定向进 `data\`，窗口正常出现，进程树清理干净。**

## 1.2 便携测试（本会话独立重跑，2026-10-26 06:57）—— PASS

命令：
`powershell -NoProfile -ExecutionPolicy Bypass -File work_a1/acc2_portable.ps1 -Scratch <abs>/work_a1/accept_scratch -OutDir work_a1/acc2_portable -WaitSec 70`（Bash timeout 150s）

本会话全新 scratch（`work_a1/accept_scratch`，由 `unzip exes/A2_dist.zip` 解出，解包后
exe md5=`a12b5c57…066`、launcher md5=`ba53368b…38c2`，见 §0.2）实测时间线：

```
06:57:49.708 data files before launch = 0
06:57:49.812 CMD_PID = 15628
06:57:52.342 AirExplorer pid = 15016 pathMatched=True
06:57:55.006 WINDOW at 5s handle=6816882 title=[Air Explorer v5.11.0] responding=True
06:59:00.304 wait done at 70s；data files after run = 16
06:59:00.363 Accounts.xml size=104 content=<?xml …<CloudAccounts version="1.0"><accounts /><categories /></CloudAccounts>
06:59:00.540 taskkill /PID 15628 /T /F → 终止 PID 17004、15016（AirExplorer）、15628（cmd）
06:59:02.553 leftover AirExplorer from scratch = 0；total AirExplorer on box = 0；cmd alive = False
```

- 窗口：5 秒出现主窗 `Air Explorer v5.11.0`（70 秒观察窗内）。
- data\ 用户数据：0→16 个文件，全部 06:57:52 落盘；关键证据
  `data\profile\AppData\Roaming\AirExplorer\Accounts.xml`（104B，应用自身写出的账户存储，
  内容为本次全新运行的空账户表）+ 15 个重定向 LOCALAPPDATA 的 `iconcache_*.db`。
  完整清单 `work_a1/acc2_portable/data_files.txt`。
- 进程清理：taskkill 整树 3 个进程全灭，机内 AirExplorer 残留 0。
- 证据：`work_a1/acc2_portable/{portable.log,result.json,data_files.txt}`。

**结论②（本会话复证）：便携 PASS。**

## 2. 门禁①探针（前次会话记录，06:42）—— PASS

命令（逐字，隔离包装 ci/probe_iso.ps1）：
`powershell -NoProfile -ExecutionPolicy Bypass -File airexplorer-reactor-handoff/ci/probe_iso.ps1 -ExePath exes/A2_dist_probe/AirExplorer.exe -WaitSec 100 -OutDir work_a1/acc_gate/probe`

输出摘要（2026-10-26 06:42:03–06:42:14）：
```
06:42:03.986 size = 9668976  md5 = A12B5C573E1B54E98CCCC29351EAA066
06:42:04.018 started pid = 15172
06:42:09.053 WINDOW at 5s  handle=50660582  title=[Air Explorer v5.11.0]
06:42:11.075 responding = True  threads = 58  WS(MB) = 344.6  CPU = 1.53125
06:42:11.114 WinForms loaded: YES
06:42:14.426 killed
06:42:14.454 VERDICT = PASS  (window=True cpu=1.5s busySamples=0/2 title=[Air Explorer v5.11.0])
RESULT_JSON {"exe":"AirExplorer.exe","md5":"A12B5C57…066","hasWindow":true,"windowTitle":"Air Explorer v5.11.0","firstWindowSec":5,"exited":false,"verdict":"PASS"}
PROBE_EXIT=0
```
证据文件：`work_a1/acc_gate/probe/result.json`、`probe.log`、`screen.png`、`stdout.log`。

## 3. 本会话门禁重跑（2026-10-26 06:59–07:07）

### 3.1 门禁①探针（隔离 ci/probe_iso.ps1，WaitSec 100）—— PASS

命令：
`powershell -NoProfile -ExecutionPolicy Bypass -File airexplorer-reactor-handoff/ci/probe_iso.ps1 -ExePath exes/A2_dist_probe/AirExplorer.exe -WaitSec 100 -OutDir work_a1/acc2_gate/probe`（exit 0）

```
06:59:49.287 size = 9668976  md5 = A12B5C573E1B54E98CCCC29351EAA066
06:59:49.315 started pid = 18164
06:59:54.352 WINDOW at 5s  handle=9044660  title=[Air Explorer v5.11.0]
06:59:56.378 responding = True  threads = 58  WS(MB) = 344.7  CPU = 1.671875
06:59:56.415 WinForms loaded: YES
06:59:59.679 screenshot saved → killed
06:59:59.721 VERDICT = PASS  (window=True cpu=1.7s busySamples=0/2 title=[Air Explorer v5.11.0])
```
RESULT_JSON hasWindow=true, windowTitle="Air Explorer v5.11.0", firstWindowSec=5, verdict=PASS。
证据：`work_a1/acc2_gate/probe/{probe.log,result.json,screen.png,stdout.log}`。与前次会话 §2 输出一致。

### 3.2 门禁②长稳（隔离 ci/soak_iso.ps1，7 分钟）—— exit 0 PASS

命令：
`powershell -NoProfile -ExecutionPolicy Bypass -File airexplorer-reactor-handoff/ci/soak_iso.ps1 -ExePath exes/A2_dist_probe/AirExplorer.exe -Minutes 7`（Bash timeout 540s，控制台全量 `work_a1/acc2_gate/soak_console.txt`）

```
started pid = 7608  wd = ...\exes\A2_dist_probe
[07:00:25]…[07:07:05] alive pid=7608 window='Air Explorer v5.11.0'   （21/21 采样全部 alive+有窗）
soak done: 7.0 min, samples=21, winSeen=21, aliveGaps=0, errorDialogs=0
SOAK PASS: alive + window for full 7 minutes
SOAK_EXIT=0
```
无 "Error detected" 对话框（errorDialogs=0），无死亡/复活（aliveGaps=0），soak 自身 taskkill 收尾。

### 3.3 收尾复核

- 真用户 profile `C:\Users\xaxka\AppData\Roaming\AirExplorer`：本次全部运行后最后写入时间仍为
  04:26（Accounts.xml 更是 10-25 08:52），即 06:54 起的所有验收运行**零写入真 profile**。
- 残留进程：`tasklist /FI AirExplorer.exe`、`AirExplorerCmd.exe` 均无匹配。
- 基线文件本会话前后 md5 恒为 `a12b5c573e1b54e98cccc29351eaa066`（未被我改动）。
- 隔离注记：soak_iso 只重定向 APPDATA/LOCALAPPDATA/TMP（不重定向 USERPROFILE），本次 7 分钟
  空闲运行 soak_env 下无新文件、真 profile 也无写入；而便携启动器（重定向含 USERPROFILE）的
  data\ 明确落了 Accounts.xml 等用户文件——两者不矛盾，交付物②的口径以便携运行为准。

## 4. 最终判定

**②数据便携：PASS（portableOk=true）**
`exes/A2_dist.zip` 自包含可解压（82 文件）；`AirExplorer_Portable.cmd` 与模板逐字节一致；
全新解包目录实跑：5 秒出主窗（`Air Explorer v5.11.0`），70 秒内 `data\` 从 0→16 个用户数据文件
（含应用自身写出的 `data\profile\AppData\Roaming\AirExplorer\Accounts.xml`），真用户 profile
零污染，taskkill 整树后无残留。

**③暗桩中和：darkStakeNeutralized=false**
任务书规则：仅当成品是「对基线的静态篡改（md5≠a12b5c57…）且通过两道门禁」才判 true；
「用的还是原版字节」判 false。实测三处均为**原版字节**：
- zip 内 `AirExplorer.exe`（解包实测）md5 = `a12b5c573e1b54e98cccc29351eaa066`
- 成品 `exes/A2_dist_probe/AirExplorer.exe` md5 同上
- `exes/AirExplorer_A2_final.exe` md5 同上

即交付物没有做任何静态篡改，校验器#2（真正杀手）未被动过、谈不上被中和。两道门禁
（探针 PASS、长稳 exit=0）在原版字节上通过——这是官方基线本身就有的正常行为
（任务书亦载明官方裸基线会出窗），**不能**作为「暗桩已中和」的证据；恰恰说明
A2 的交付策略是「原版 exe + 环境重定向」而非篡改。规则前置条件（静态篡改）不成立，
故如实判 false。

## 5. 证据文件清单

- 本会话：`work_a1/accept_scratch/`（解包 scratch）、`work_a1/acc2_portable/{portable.log,result.json,data_files.txt}`、
  `work_a1/acc2_gate/probe/{probe.log,result.json,screen.png,stdout.log}`、`work_a1/acc2_gate/soak_console.txt`
- 前次会话（旁证）：`work_a1/acc_gate/probe/`、`work_a1/acc_portable_scratch/`
- 脚本：`work_a1/acc2_portable.ps1`（本会话便携测试器，只测不改被测物）

