# A2 施工说明（路线 C：差分 bisect）—— 写给补丁工程师（自包含）

## 0. 路线判定（已定，勿复议）
选 C。依据：
- A 线前提不成立：校验器#2 未静态定位（方法体不在任何明文/已解密语料；π=0x04242420 无静态指纹；FailFast 无元数据引用；06004192 为条件死代码）。
- B 线前提不成立：Proc/Emitter key 未攻出（7 次运行未触发解密、key 从不在堆上；t26_solver.py 就绪但无 ct/pt 对）；orchestrator 已声明走 bisect、不需 Proc key。
- C 线保留 A 线优点：已知 keystream 块的改动 = 同位置字节 XOR 回写，重加密零成本（本轮实测复核）。
C 线目标：每轮只改一类字节 → 隔离探针判生死 → 画出守卫覆盖图 → 再把绑定手术 / tripwire 中和 / 激活改动落到存活区。

## 1. 硬约束（违反任一 = 产物作废）
1) 基线只用 `airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe`（md5 `a12b5c573e1b54e98cccc29351eaa066`，9,668,976 B，本轮已两次复核）。一切改动在副本上；开工前与每轮结束各复核一次基线 md5。
2) 绝不写文件偏移 ≥0x936000；成品大小必须 = 9,668,976 B。
3) 禁注入（DLL 劫持/Loader/CLR Profiler/Harmony），只做静态字节修改。
4) 跑被测 exe 一律 `ci/probe_iso.ps1` / `ci/soak_iso.ps1`（自带隔离 APPDATA/LOCALAPPDATA/TMP），每条命令带超时，结束后 taskkill 自启进程。
5) 中间结论/产物即时写盘：进度 = `work_a1/c_rounds.md`（每轮：轮次 / 改动字节表 / 死亡签名 / 判定 / 产物路径），逐轮产物 = `work_a1/c_r{n}/`。
6) 做不到就如实写『做不到』，绝不编造；指令矛盾即升级提问。

## 2. 资源块地图（本轮逐字节复核，可信）
cor20 大 blob 自 0x6213C0 起，每块前紧贴 4B LE 长度前缀；六块首尾相接占 [0x6213C0, 0x9264CC)，全部 < 0x936000：

| 块 | 前缀@ | ct@ | len | key | 备注 |
|---|---|---|---|---|---|
| Viewer | 0x6213C0 | 0x6213C4 | 0x56FE8 | `f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943` | 方法体 vault；已解密 `work_a1/dec_Viewer.bin`（~9153 个 RVA 条目） |
| Emitter | 0x6783AC | 0x6783B0 | 0x100 | 未知 | 运行期从不读取 |
| Proc | 0x6784B0 | 0x6784B4 | 0xBB2B | 未知 | 从不解密 |
| Project | 0x683FDF | 0x683FE3 | 0x6610 | 全零 | 委托绑定表 8B×3266；已解密 `work_a1/zdec/Project.bin`（与参考解密器输出逐字节一致） |
| mainlib | 0x68A5F3 | 0x68A5F7 | 0x23A907 | `cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481` | **守卫范围已被 a1 之死实证**；已解密 `work_a1/mainlib_plain.bin`（4,260,864 B）；keystream 文件 `work_a1/mainlib_ks.bin`（2,337,031 B） |
| Factory | 0x8C4EFE | 0x8C4F02 | 0x615CA | `37038b1c606ca165c7f772c0e2a6ff545e4a9d0ea55139779f7ecb7404fa9a3a` | Necrobit 字符串池 |

尾区 K/A/B @0x9298C8/0x929A28/0x929A38 = 驱动器消费、托管 IL 零引用 → 任何轮次禁改。

字节级算法（实测）：`pt_file_byte[k] = ct_file_byte[k] XOR ks_file_byte[k]`（同 index；参考实现 `airexplorer-reactor-handoff/work/decrypt_prng.py`：pt_dw = ks_dw ^ LE(ct_dw)；任务书公式里的 bswap 指大端载入约定，工程上直接用 decrypt_prng.py / mainlib_ks.bin 即可）。带 key 块的 keystream 生成序 = state=0；每 dword：state=(state+key_dw[i%8])&0xffffffff → state=prng_round(state)（本轮与 mainlib_ks.bin 前 1024 dword 实测一致）。

mainlib 重加密管线（已端到端实证：ct XOR ks → raw-deflate inflate == mainlib_plain.bin，无尾渣）：
`new_ct = raw-deflate(new_plain, level=9, memLevel=9, wbits=-15)` → 补零到 0x23A907 → XOR `work_a1/mainlib_ks.bin` → 写回 0x68A5F7。模板 `work_a1/a2_build.py`。

可验证重加密块集 = {Viewer, Project, mainlib, Factory}；Proc/Emitter key 未知 → 除 §4 单字节探针外禁改（改了无法重加密验证）。

## 3. 探针协议（每轮同型）
a) cp 基线 → `work_a1/c_r{n}/AirExplorer_c_r{n}.exe`；
b) 施加该轮唯一一类字节改动；
c) `md5sum` 复核基线未动；
d) `powershell -NoProfile -ExecutionPolicy Bypass -File airexplorer-reactor-handoff/ci/probe_iso.ps1 -ExePath <work exe> -WaitSec 100 -OutDir c_r{n}`（约 55 秒后出真主窗 = 正常；官方裸基线弹 Register account 对话框 = 正常不算失败；PASS = 出真主窗）；
e) 判定：篡改死 = int3 → 0x04242420（π=0x31415927，FailFast）→ e06d7363 → e0434352 完整链 = 守卫杀；其他死亡（孤立 e0434352 / 异常对话框 / 挂起）= 连带损伤，不得记为守卫证据；
f) 存活者补跑 `soak_iso.ps1 -ExePath <exe> -Minutes 7`（exit 0 = PASS；2 = 进程死 3 = 无窗 4 = 错误对话框）；
g) 判定与字节表写入 `c_rounds.md`；h) 失败即回写原字节。
每轮 1 次 probe（存活者 +1 次 soak）；目标 exe 全程 ≤15 次运行。

## 4. 轮次表（顺序执行，分支见判定）
- **R0 控制组**：基线原样副本跑 probe_iso → 期待 PASS（校验环境）。
- **R0b 校准**：跑已知死体 `exes/AirExplorer_baseline_verified_a1.exe`（注意在【工作区根目录 exes/】，不在 handoff/exes/；md5 `6418ec2f085deae6f16ffa49a1ab9568`）→ 必须复现完整篡改链，以校准死亡签名捕获。勿用 `exes/AirExplorer_baseline_verified_a1b.exe`（md5 `9378c605…`，出处未标注）。
- **R1 Project 块 + B1**（双目的：守卫探针 + 绑定切断；决策者已实证算术）：改 1 字节 @0x6879C7：0xBF→0xBE。效果（全量重解密实证）：rec1852（VerifyChecker 绑定）handler 0x4A00117C→0x4A00117D，即 0x0A00117C=VerifyChecker → 0x0A00117D=add_MouseUp（签名不符，可能绑定抛异常——正是要判定项）。施改前静态断言：基线 0x6879C7==0xBF；decrypt_prng.py 重解 Project 块确认 rec1852（@zdec+0x39E0）field=0x0400283E handler=0x4A00117C；施改后重解全块 diff 原解密结果必须恰 1 字节（明文侧 0x7C→0x7D）。判定三分支：PASS → Project 块不受守卫且切断存活 → soak → 保留进 R5｜完整篡改链死 → Project 块受守卫 → 回写 0xBF｜孤立 e0434352 死 → 块不受守卫但绑定抛死 → 回写 0xBF 并做 R1b。
- **R1b**（仅 R1 第三分支）：备选①从 zdec/Project.bin 找与 0x0A00117C 同签名的 MemberRef token 替换（先静态核签名再跑）；备选②field 侧 @0x6879C3：0x99→0x98（实证效果：field 0x0400283E→0x0400283F）。各 1 轮，仍死即放弃 B1。
- **R2 Emitter 块探针**：改 1 字节 @0x6784AF（先读原值，任翻一位）。该块运行期从不读取 → 纯守卫探针。
- **R3 Viewer 块探针**：改 1 字节 @0x6783AB（vault 末字节）。PASS → 解锁 C2 主攻线（§5）。
- **R4 Factory 块探针**：改 1 字节 @0x9264CB（块末字节）。（mainlib 已证受守卫，不再花探针。）
- **R5**（仅当 R1 存活）绑定手术扩展——ConvertibleWrapperValidator（TypeDef#4908）绑定族逐条（决策者已解码，记录首字节文件偏移 = 0x683FE3+rec×8，handler 在 +4）：
  rec730 GetSigner field=0x040023DC handler=0x0A000D7A（记录@0x6856B3）；rec733 GenerateSignature 0x040023DF/0x4A000D7D（@0x6856CB）；rec738 VerifySignature 0x040023E4/0x4A000D80（@0x6856F3）；rec747 DecryptKey 0x040023ED/0x0A000D89（@0x68573B）；rec958 ComputeHash 0x040024C0/0x4A00099F（@0x685DD3）；rec2032 CreateFromSignedFile 0x040028F2/0x0A001221（@0x687F63）。每轮只动一条（handler 或 field 单字节，翻转到什么先静态算出明文效果），probe 判生死；存活累计保留，死亡回写该条。注意 rec730/747/2032 的 handler 未带 0x40000000 标志，翻转前先核标志位语义。
- **R6**（仅当 R3 存活）tripwire 普查与中和：杀手在启动 cctor 风暴中运行，~4,633 个 cctor 调用 tripwire（.cctor 链实证样例 06000002：call 0600419C; call 06004192; call 06004194; call 06000001）。用 `work_a1/ildis.py` + `airexplorer-reactor-handoff/work/mdrva.py`（可复用 `a3_dis_*.txt`、`s26_bodies.pkl`、`s26_scan_results.pkl`）统计所有 cctor 体 call 目标直方图 → 取被最多 cctor 调用的 MethodDef token → 按 RVA 在 `work_a1/dec_Viewer.bin` 条目表（[RVA][tag][fat0][tag][locals][body8][tag][nxtRVA]）找其体。体在 vault → 体首指令改 ret（0x2A）：tiny 体 = 首字节后第 1 字节，fat 体 = +12 处，keystream 同位 XOR 回写，大小不变；施改前后全 vault 重解密 diff 断言只动目标字节。体在 mapped image（.text）→ 该线作废（.text 篡改已证死）。红线：0600419C 是 vault 解密器本体，禁碰其体。
- **R7**（仅当 R1-R4 全受守卫）blob 外类别普查：PE 头 / metadata（#Strings 空隙、#US）等，每轮一类 1 字节，只为补全守卫图；预期诚实结论 = 『今日不存在静态单点中和/激活补丁』，走 §5-C3 收尾。

## 5. 收尾三案（按守卫图组装）
- **C1**（Project 块不受守卫）：成品 = B1/R5 存活字节集的累计体——校验语义接线层（VerifyChecker/GetSigner/VerifySignature/DecryptKey/ComputeHash/CreateFromSignedFile 绑定）逐条切断的静态中和。
- **C2**（Viewer 块不受守卫且 tripwire 体在 vault）：成品 = tripwire ret 中和 + mainlib 激活补丁。⚠ 激活补丁点必须重新推导：旧两点已证伪（0x194518 位于 PNG：0x19435A 处 PNG 签名=True，补丁 = IDAT 载荷 +0x1BE；0x197AE4 容器 @0x197A07 处 PNG 签名=False、未识别，但同为资源载荷；两处均与激活语义无关——本轮端到端实证 a1 inflate 后恰只改这两字节）。重推导线索：license 门串 `The command line features are only valid for Air Explorer Pro`（AirExplorerCmd 实测 exit 1）→ 在 mainlib_plain 定位检查方法与分支。⚠ 激活改动只有 tripwire 中和后方可落 mainlib（该块已证受守卫）。
- **C3**（无可行组合）：A2_final.exe = 基线原样拷贝（md5 同基线），交付包照出，守卫图如实上报——『无可行补丁』本身是合法交付结果。

## 6. 成品与交付包
- 成品 = `exes/AirExplorer_A2_final.exe`（工作区根目录 exes/），9,668,976 B，与基线 diff 全部 <0x936000 且仅含已 probe/soak 验证的存活字节；终品亲自 probe_iso PASS，组合改动另过 soak_iso exit 0。
- 交付包 = `exes/A2_dist.zip`：① `AirExplorer.exe`（= A2_final 字节）；② `AirExplorer_Portable.cmd`（模板 `airexplorer-reactor-handoff/portable/` 原样零改；data 骨架 = profile/{Desktop,Documents,Downloads} + AppData/{Roaming,Local,Local/Temp}；launcher 只要求同目录存在 AirExplorer.exe，与字节无关）；③ 空 data 骨架（按上述目录树预建空目录）。
- 打包后解包，对 zip 内 exe 再跑一次 probe_iso。

## 7. 红线与纪律
禁碰：基线本体、≥0x936000、尾区 K/A/B、0600419C 体、Proc/Emitter（除单字节探针）。不投运行预算抓 key（B 线复活线索存档：`work_a1/t26_checkerHints.md`——PanelSyncManager 同步任务 UI 需已配置云账户，属路线 B 范畴）。所有判定只认本机实跑结果，报告与 c_rounds.md 一字不差对应。

## 8. 决策者本轮实测存档（可抽查）
- `work_a1/c_route_decision.md`：决策 + 更正记录。
- `work_a1/c_route_verify.py/.txt`：基线 md5/大小；六块前缀断言（全部相符、相接、<0x936000）；Project 解密 == zdec/Project.bin（26,128 B）；rec1852 = field 0x0400283E / handler 0x4A00117C（ct bf772469@0x6879C7）；B1 三种候选翻转全量重解密实证；目标 handler 0x4A00117D 所需 ct 断言。
- `work_a1/c_route_verify2.py/.txt`：ct XOR mainlib_ks.bin → inflate == mainlib_plain.bin（无尾渣）；a1 端到端（inflate 后恰两字节 0x194518:49→48、0x197AE4:03→02）；a1 diff 2,327,619 B 共 9,370 段全部在 mainlib ct 内、外部 0 字节；PNG 签名（0x19435A=True、0x197A07=False）；key 序 == ks 文件。
- `work_a1/c_route_verify3.py/.txt`：绑定族七条记录解码 + MemberRef 名解析（0x0A00117C=VerifyChecker、0x0A00117D=add_MouseUp、GetSigner/GenerateSignature/VerifySignature/DecryptKey/ComputeHash/CreateFromSignedFile）。
- 关键更正：① checker 原案 bf→be@0x6879C7 经参考解密器实证**正确**（决策者最初手推否决系 bswap 载入约定误用，已自纠并以重解密实证）；② a1 实际在根目录 `exes/` 而非 handoff/exes/；③ 『两处激活字节均在 PNG』仅一点成立，但两点均为资源载荷、非激活语义的结论不变。
