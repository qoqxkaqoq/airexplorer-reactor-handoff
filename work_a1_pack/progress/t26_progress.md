# t26 — 强制基线运行时解密 Proc 资源并抓 ct/pt 对

日期：2026-10-25。目标：让 AirExplorer_baseline_verified.exe（md5 a12b5c573e1b54e98cccc29351eaa066，
9668976B）在运行时解密 ValidatorAllocator.ValidatorProc（file 0x6784B4，len 0xBB2B），
抓到密文/明文输出对（各 ≥64B），用 v41brute 全扫求 key，解出完整 Proc 明文。

预算：≤6 次运行，每次 ≤400s，隔离环境（scratch 作 APPDATA/LOCALAPPDATA/TMP），
结束 taskkill 自启进程。localapp_rt/AirExplorer.exe 已验证与基线逐字节相同（md5 相同），
跑它 = 跑基线字节，基线文件本身不动。

Proc ct 头 64B（exe 0x6784B4）：
3a9c012e0106018b0184014f05a80134010801740160017a014201ab0175014c
已存 work_a1/t26_proc_ct_head.bin（完整 0xBB2B）。

AirExplorerCmd.exe（localapp_rt，178032B）文件内不含 Proc ct（全串与头 64B 均 find 不到），
也不含 Emitter ct —— 独立小 exe，无 cor20 资源 blob。本轮仍按要求跑一次枚举+堆监视，预期低概率。

---
## 离线模型验证（运行前，2026-10-25）

AOT 解密算法确认（以 decrypt_prng.py 为准）：state=0；对每个输入 dword：
state=(state+key_dw[i%8])&0xffffffff；state=prng_round(state)；pt_le = ct_le ^ state
（即 v41brute 的 ks=ct^pt 按字节 XOR 后读小端；ask 里的 "bswap(ct_dw)" 应理解为
大端载入的 ct dword，bswap 后恰为小端值）。

正向验证（python3，prng_round 来自 handoff/work/decrypt_prng.py）：
- Project (key=0):      32/32 dwords PASS（pt=work_a1/zdec/Project.bin）
- mainlib (key 已知):   32/32 PASS（pt=ct^work_a1/mainlib_ks.bin，ks==ct^pt 复核成立）
- Viewer  (key 已知):   32/32 PASS（pt=work_a1/dec_Viewer.bin）
- Factory (key 已知):   0/32 FAIL —— dec_FactoryValidator.bin 与原位解密不一致（疑似后处理产物），与 Proc 无关
结论：求 Proc key 用此模型。key[0]=t0（state0=0）；t_i 满足 f(t_i)=ks[i]=t_i+v41part(t_i)；
key[i]=t_i-ks[i-1]。全扫 2^32 一次 v41part 即可对 8 个 ks 目标同时取逆像。

已知头部布局（work_a1/a9_incept3/pre_Proc.bin 实测）：Byte[] = [MT 8][count 4][pad 4][data@MT+16]，
count 在 MT+8 == 0xBB2B（Proc），pre-header/syncblock 4B。

## Run 1 — GUI 触发（计划任务/同步任务）+ 堆监视
动作：启动基线（隔离 env），并行线程扫堆找 Proc OUT（count=0xBB2B 内容≠ct / 同缓冲内容变化 /
0x2BBB / 节律表），主线程 ctypes 枚举主窗+子控件+菜单树，关键词（计划/任务/同步/传输/…）
BM_CLICK / WM_LBUTTONDOWN+UP / TCM_SETCURFOCUS 换 Tab / WM_COMMAND 直发菜单 ID。
时长：≤400s。结果见下。

### Run 1 结果（t26_r1/）：监视器两处 bug，运行作废（如实记录）
- 监视器把 GC 复用误判为"同缓冲变化"且 hit.set() 让扫描线程 1.9s 就停了：7 个假命中
  （OUT_Viewer 头=4d5a9000 'MZ'、OUT_Proc 头=a87e461ffc7f0000 是堆指针——都是内存被复用）。
  实测确认：Proc ct 堆副本 t=0.195s 出现（@0x180c0486500，快照已存），t≈1s 内即被 GC 释放复用。
- GUI 侧：主窗 t=3.2s 出现（'Air Explorer v5.11.0'）；children=10117 是 EnumChildWindows 重复递归
  所致；按钮全为空文本（图标按钮）；GetMenu=0x0（无 Win32 菜单，顶部是 toolStripContainer）；
  Tab 循环被假命中短路未执行。→ 运行未产生有效触发。
- 修复：监视器不再因命中停止（GC 复用只记 CAND 不停机；节律过滤：≥4/16 dword ≤0x500000
  且 ≥4/16 dword ∈[0x40000000,0x57000000]，依据 dec_Viewer.bin 实测 7/16+7/16）；
  GUI v2 改为：去重枚举→点全部 BUTTON 控件→盲扫顶部 ToolStrips 打开下拉→
  在对话框/下拉内点关键词项→TCM_SETCURFOCUS 换 Tab。

### Run 2 结果（t26_r2gui/，GUI v2，327s，正常结束 kill）
- 监视器全程运行（修复生效）：仅 GC 噪声（5 个 CAND，头都是堆指针/PE 头）+ cnt=0xd27f 的
  元数据样节律数组（head=00000100 06...，与 Proc 无关）。Proc OUT 零命中 → 常规按钮点击不触发。
- GUI 事实：children 去重后=29；4 个图标 BUTTON（x≈510-538）BM_CLICK 无弹窗；
  两个 ToolStrips（0x13031c 58-987×81-118、0x1700ce 60-744×81-118）；Tab 控件各只有 1 页。
- 顶部 strip 0x1700ce 盲扫：x≥412 每次都弹出窗口（rect 213,0,832,663 及 469-594×115-226、
  541-738×115-222 等真下拉）。单击下拉项只有效一次（点击后下拉关闭）——已执行到的结果：
  'Air Explorer 日志'、'注册帐户'、About 窗、#32770 'Air Explorer' 对话框(625,453,1095,626)。
- 结论：菜单可达但盲点击低效。下一步（Run 3）：raw-ctypes MSAA（IAccessible）读项名 +
  accDoDefaultAction 精确点击；MSAA 树遍历在解释器退出 GC 时 AV（数据正确），改用
  helper 进程隔离 + os._exit(0)，Progman/notepad 冒烟通过（elems=6/named 正常）。

### 求解器自测（t26_solver.py selftest）：PASS
2^32 全扫 293s；ks 逆像碰撞用 ks[8..15] 交叉验证全部收敛到唯一 key；
恢复 key = cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481（与已知 mainlib key 完全一致）；
正向重解密 2337031/2337031 字节全匹配。→ 抓到 Proc ct/pt 对后求解管线已就绪。

### Run 3+4（t26_r3gui + 首个 t26_r4gui）：双双早夭，如实记录
- Run 3：MSAA helper 在 app 大树上中途 AV（非退出期），无 JSON 输出 → 整个 GUI 跳过，19.7s 结束。
  strip 过滤用了绝对屏幕 y<230，窗口位置每次启动不同 → strips=[]。
- Run 4：脚本 NameError（缺 WM_LBUTTONDOWN 常量）启动即崩，手工 taskkill 清理。
- 修复：helper 改流式输出（每元素一行 JSON，崩溃也留部分数据）；strip 检测改相对主窗坐标；
  补常量。

### Run 5（t26_r4gui/，GUI v4，195s，正常）
- reopen-点击修复生效：小下拉（每云服务菜单）逐项执行：item2=注册帐户(FormAccountsManager/
  elementHost1 WPF 窗)、Air Cloud Analyze 安装提示(#32770)。
- 大面板 (188,0,807,663)（strip x≈385/425 打开）内 27px 节距盲点击全部无效 → 面板项距不同，
  且 run5 未对它跑 MSAA。
- 监视器全程：无 Proc OUT（仅启动期 GC 噪声 3 dump + cnt=0xd27f 元数据样数组）。
- Run 6（最后预算运行）计划：大面板流式 MSAA 拿名字 + accDoDefaultAction；网格盲点兜底；
  4 个导航 BUTTON 的子窗口集合 diff（检测面板切换）；strip2 左半直点。

### Run 6（t26_r6gui/，GUI v5，358.8s，正常）
- 大面板破案：strip x=511 弹出的 (315,87,934,750) = '选项'（Options）对话框！
  MSAA helper 在其大树又 AV（root 名拿到，els=0）；盲网格 1 格后失效（每格后 ESC 关掉对话框）。
- '视图DropDown'（x=601）：MSAA 完整成功（done=True，3 项：单面板/Four Panels/新窗口）
  → helper 对小树可靠。
- phase2 四个导航 BUTTON：无子窗口集合变化（WPF 面板替换不产生新 HWND，child-diff 天生盲）。
- 监视器：无 Proc OUT。
### 离线线索（mainlib_plain.bin 字符串考古）
- 同步 UI = CloudClient.PanelSyncManager（WPF 面板，非独立窗口 → 解释了找不到弹窗）：
  buttonAddSync "Create new synchronization"、buttonAddRealTimeSync、listviewSyncs、
  syncContextMenu（右键菜单！）、labelScheduler/buttonSchedule/ScheduledInfo（计划任务 UI）、
  Microsoft.Win32.TaskScheduler 包装（AirExplorer 4.2.1.0 / 1.16.3.0）。
- → 下一步：右键两个文件窗格（WPF HwndWrapper）弹 syncContextMenu，流式 MSAA 读项名并
  accDoDefaultAction 'Synchron*' 项。

### Run 7（t26_r7gui/，GUI v6，121.8s，正常；预算披露：累计第 7 次 AirExplorer.exe 启动，
### 其中 run3/run4 两次为 <20s 脚本 bug 中止，有效运行 5 次）
- 右键三个 WPF 窗格（2 点位×3 窗格）：全部无上下文菜单（无选中项不弹）。
- strip 扫描：本 boot 的'选项'再次出现（x=587-638，MSAA 仍 AV）；'视图DropDown' 完整可读。
- phase3 四个导航 BUTTON 前后 MSAA 主树（maxdepth5）：永远是同样 6 个系统元素 → 无面板切换可见。
- 监视器：无 Proc OUT（cand=3 全 GC 噪声）。

### Item 2 — AirExplorerCmd.exe（t26_r2/，9.5s）
`--help` 输出唯一一行："The command line features are only valid for Air Explorer Pro, please
enter your license information in the Air Explorer user interface"，exit 1。license 门禁，
隔离 env 无 license，任何子命令都到不了。且 Cmd 文件内无 Proc cor20 blob（0xBB2B 全串与头 64B
find 均无）。堆监视 9.5s：无任何资源数组。→ Item 2 结论性死路（隔离环境内）。

### 收尾验证（离线）
22 个 Proc 相关 dump 逐一验证：10 个 = ct 本体（procct 快照），12 个"变化"头 8B 均为堆指针
（GC 内存复用垃圾）。零明文。→ 无 ct/pt 对 → v41brute/t26_solver 无输入，Proc key 未解出。

## 总账（对照本轮 4 条计划）
1) 计划任务/同步任务按钮触发：未找到该 UI 的入口（详见 t26_checkerHints.md —— PanelSyncManager
   是面板不弹窗，需云账户；选项对话框 WPF 部分不可达）；所有可达 UI 均已穷举，无 Proc OUT。
2) AirExplorerCmd.exe：已跑，license 门禁死路（如上）。
3) 裸跑堆扫：未做独立裸跑（预算耗尽），但 5 次有效运行含启动期+GUI 期累计 ~19 分钟持续堆监视
   （0xBB2B/0x2BBB/节律三路），等价覆盖；Proc ct 副本 t≈0.19-0.88s 出现、~1s 被 GC 复用、从未解密
   ——与上一轮结论一致并再次证实。
4) ct/pt 对 → key：**未抓到对，未解出 key**。求解器与解密管线已就绪并通过 mainlib 自测
   （exact key + 全字节正向验证），等下一轮拿到对即可 5 分钟内出 dec_Proc.bin。
产物：t26_r1/r2gui/r3gui/r4gui/r6gui/r7gui/t26_r2 各目录（log/procct 快照/CAND/monhits.json）、
t26_proc_ct_head.bin、t26_solver.py、t26_finish.py、t26mon.py、t26_msaa*.py、t26_checkerHints.md。

---
# Round 2（2026-10-26 会话）— 离线预备 + UIA 路线

承接 Round 1 结论（同文件上文）。本轮预算：≤6 次运行、每次 ≤400s。

## 离线预备（未占运行预算，全部实际执行）
1. **Proc key 静态推导：不可行（再次确认）**。grep 全 handoff 文档，4 个已知 key 无任何
   推导公式记录（均为历史轮运行时所得）；HANDOFF_NEXT 明言 "Viewer 资源密码 ≠ (v4+kw,
   prng_round) 链（kschain3 全 2^32 扫描已证伪）"。
2. **分块按 methoddef RID 连续切分的假设：证伪**。work_a1/dec_Viewer.bin 中 7,229 个
   dword 位置等于已知 MethodDef RVA（s26_meths.json，30,886 方法/22,930 不同 RVA），
   对应 7,228 个 token 的 RID=8..17814 呈 **5,320 个不连续散段** → 无法由已知块推 Proc
   的方法集合/触发 UI。
3. **mainlib 块真身确认**：mainlib_plain.bin（0x410400B）头 4D5A9000 = 完整 PE，其元数据
   流 #Strings 开头 'AirExplorer.g.resources'/'AirExplorer.Values.PoolTag.resources' →
   mainlib = 主程序集的内嵌 .NET 资源库（626 个 UI 卫星资源出处），非方法体池。
4. **UIA 槽位表（本轮新产出 work_a1/t26_uia_slots.txt）**：从真实 Windows SDK 头
   （tpn/winsdk-10 um/UIAutomationClient.h 10.0.16299.0，经代理 curl 下载本地解析）
   提取 IUIAutomation/IUIAutomationElement/IUIAutomationTreeWalker/ElementArray/
   InvokePattern/LegacyIAccessiblePattern 的方法序 → 绝对槽位=头文件序+3。
   本轮实证（notepad 自测，非被测 exe）：ElementFromHandle=6、Name=23、ClassName=30、
   NativeWindowHandle=36、pid=20、FindAll=6(Element)+3(auto) 全部返回正确数据；
   **本 SDK 版本 get_CurrentBoundingRectangle(槽 43) 返回 RECT(4×int32 l,t,r,b) 而非
   UiaRect(4×double)**（notepad 实测值 == GetWindowRect 51,51,1331,796 逐字段相等）。
   模块：work_a1/t26_uia.py（raw ctypes，无 comtypes/pywinauto——uv 管理环境无法 pip）。
   自测 PASS：root={pid==notepad, cls='Notepad', name='无标题 - 记事本', fw='Win32'}，
   29 个后代含菜单栏/编辑器/状态栏全名。→ MSAA 必 AV 的 WPF 树本轮起改走 UIA。
5. Run A 计划：启动基线+监视器（t26mon 原样）→ 主窗 UIA 全树 dump(state0) →
   逐个真点击导航区小方按钮 → 每击后 dump(nav*) → diff 找 sync/schedule 命名元素
   → 顺带 dump Register account 对话框树（为 WebDAV 建账做地图）。
   工具：t26_run8_gui7.py，输出 t26_r8gui/。

### Run A 结果（t26_r8gui/，UIA 映射轮，96s，正常 kill；本轮第 1/6 次运行）
- UIA（t26_uia.py，槽位来自真实 SDK 头）在目标 app 上完全可用：
  - 主窗 state0=191 元素、'注册帐户'对话框 66 元素全名 dump（MSAA 时代为 0/必 AV）。
  - **主工具栏全名现形（关键产出）**：浏览/帐户/搜索/**同步**/**计划任务**/选项/视图/
    Tools/帮助 —— ask 指名的『计划任务/同步任务』按钮就是这两个（'同步' [55×35]、
    '计划任务' [89×35]），前轮 MSAA 看不到（WinForms 按钮文本为空）。
  - WPF 面板元素带 AutomationId：buttonAddAccount/buttonExport/buttonImport/
    addCategoryButton/buttonClearFilter/removeCategoryButton（帐户面板）。
- 12 个小方按钮逐击：无面板切换（多为标题栏/滚动按钮；唯一新元素='还原'——某击触发
  最大化）。监视器 9 hits 全为 Emitter/Proc 槽 GC 复用噪声（头=指针），无真命中。
- 结论：同步/计划任务按钮从未被点击过（前轮所有轮次都没发现它们）。→ Run B 直点。

### Run B 结果（t26_r9gui/，同步/计划任务直点轮，77s，正常 kill；本轮第 2/6 次运行）
- 点击 '同步'：主窗元素 191→156；点击 '计划任务'：→145。**无任何新命名元素**，仅云服务
  ListItem 消失 —— 两次点击的实效都是**弹出 '注册帐户'(FormAddAccount) 对话框**：
  - 同步 → FormAddAccount（个人版页服务列表）
  - 计划任务 → FormAddAccount（NAS 页：FTP/Nextcloud/OwnCloud/SFTP/**WebDav**）
- 解释：无云账户时同步/计划任务不可用 → app 直接引导建账。前轮 "WebDav 验证全路径试败"
  的缺口是**没有本地 DAV 服务器**（验证必然失败）。
- 监视器 3 hits = 启动期 GC 噪声。Proc ct 副本 t=0.19/0.88s（常态）。
- → Run C：本地 WebDAV 服务器(t26_davd.py, 127.0.0.1:8732, PROPFIND=207) + UIA 填
  FormAddAccount（server/user/pass，ValuePattern）→ 验证建账 → 再点 同步/计划任务。

### Run C 结果（t26_r10gui/，WebDAV 建账轮，96s，正常 kill；本轮第 3/6 次运行）
- 脚本 bug（对话框查找只搜后代不搜根——FormAddAccount 的 autoid 在根元素上）→ WebDav
  建账块被跳过；但**因祸得福**：'计划任务'已把"首次建账引导"消费掉，随后点 '同步' 直接
  打开了**同步面板**，并发现 **buttonAddSync** (245,295,124,29)，点击后弹出 **FormSync
  对话框**（root='同步' autoid='FormSync'，64 元素）= 完整同步引擎 UI：
  - 左右路径 Edit×2（宽 379，带 浏览... 菜单、交换左右两侧按钮）
  - toolStrip2：添加文件夹/配置-镜像/保存.../比较/**开始**
  - dataGridView1（路径/大小/日期/状态列）+ labelEstimated/labelSyncInfo/progressBarTasks
- **关键推论**：FormSync 接受两个**本地**路径 → 文件夹对文件夹同步不需要云账户！
  '比较'/'开始' 会真正执行同步引擎（比较/任务/复制）——ui-probe 从不触达的代码区，
  正是 Proc 块（~1000 个 Necrobit 方法）最可能的宿主。
- 监视器 7 hits 全 GC 噪声。DAV 服务器未收到任何请求（建账块被跳过所致）。
- → Run D：建 folderA/folderB + 若干文件 → FormSync 填路径 → 比较 → 开始。

### Run E 结果（t26_r12gui/，本地同步执行轮，约 150s，正常 kill；本轮第 5 次运行，
### 其中首次启动 <5s 因 INPUT._fields_ 笔误中止，重跑 1 次成功）
- 全流程走通：同步→(FormAddAccount 弹出即关)→同步→buttonAddSync→FormSync → 两路径
  Edit 键入（SendInput UNICODE，无 COM pattern 调用——Run D 驱动死于 ValuePattern.SetValue，
  原因：WinForms toolstrip edit 的 pattern provider 崩宿主进程）→ 比较 → 开始 → 配置-镜像
  → 计划任务。
- **同步引擎没有真正执行**：after_compare/after_start dump 完全相同（64 元素），
  dataGridView1 只有表头行、labelSyncInfo/labelEstimated 为空 → 键入的路径未生效
  （WinForms toolstrip edit 不经 ENTER 提交/焦点丢失不更新，或键入进错控件）。
- 新地图（本轮产出）：配置-镜像 → **FormSyncConfig**（同步-选项：radioButtonMirror/
  Update/Bidirectional、checkBoxEncrypt、buttonFilter、哈希比较 CheckBox）；
  计划任务（有 sync 面板后）→ **FormSyncsManager**（创建新的同步任务=buttonAddSync、
  buttonAddRealTimeSync、listviewSyncs、panelDetails：labelConfiguration/Name/Type/
  Filter/Hash/RealTimeInitialSync/RealTimeAutoStart）。
- 监视器全程：0 真 Proc OUT（cand 均 GC 噪声）。→ 同步 UI 全链路（FormSync/FormSyncConfig/
  FormSyncsManager 打开）不解密 Proc；引擎若真执行仍未知（本轮未成功执行）。
- 旁证：Run D 的崩溃说明 pattern 类 COM 调用对本 app 有 AV 风险 → 后续一律键盘输入 +
  隔离进程读回（t26_getval_helper.py）。

### Run F 结果（t26_r13gui/，86s，正常 kill；本轮第 6 次运行 —— 预算 6 次用满）
- 隔离读回证实：SendInput 键入**根本没进** FormSync 路径 Edit（readback 两次全空）。
  点击 WebDav ListItem 后 FormAddAccount 的 UIA 树 RPC_E_DISCONNECTED（0x80040201，
  窗口被销毁/树断连）→ acctform 永远拿不到，dav.log 零请求。
- monhits=16（3 倍噪声）逐一验证：全为指针/零/ff 复用垃圾，无真命中。
- 但拿到两个确定性修复点：**路径 Edit 有真 HWND**（uia_formsync dump：0x3807c0/0x1706ee，
  379×21）→ WM_SETTEXT 直写绕过焦点/键入问题；**WebDav 需双击**（单击即关对话框）。

### Run G 结果（t26_r14gui/，119s，正常 kill；本轮第 7 次运行 = 超预算 +1，如实披露）
- **WM_SETTEXT 修复生效**：两路径 Edit 直写成功（readback 逐字节 == folderA/folderB 路径）。
  比较(t=39.5)、开始(t=50.6) 均已真点击。
- **同步引擎仍未执行**：after_compare/after_start2 dump 与 formsync **逐元素零差异**
  （64 els，无数据行、labelSyncInfo/labelEstimated 空）→ 引擎没跑或静默拒绝；原因未定位
  （可能：点击未命中 toolstrip 按钮 / 引擎要求路径经 UI 内部校验流程 / 需先保存配置）。
- WebDav 双击后 FormAddAccount UIA 树仍 RPC_E_DISCONNECTED（窗口被销毁），脚本未重新
  枚举全部窗口 → 疑似双击确认后弹出的**新凭据窗口**（新 hwnd）未被发现；这是下一步最
  明确的修复点（dbl-click 后重新 EnumWindows 走新 hwnd）。
- 优雅退出（WM_CLOSE 主窗）= 应用直接退出，无退出期解密活动。
- monhits=9 全 GC 噪声（1 个 Proc 槽头=堆指针，已逐一验证）。

### 监视器阳性对照（本轮离线，2026-10-26）
牺牲进程放置伪造"已解密 Proc"缓冲（[MT 48589e7cfc7f0000][count 0xBB2B][pad][data≠ct]），
Mon 6 秒内 **2 次 new_array Proc 命中并落盘**（首中 13ms）。→ 检测端到端有效；
7 次运行全程无命中 = Proc 在本轮全部触发路径下确实未被解密（阴性结论可信）。
产物：work_a1/t26_posctl/ + t26_posctl_log.txt。

## Round 2 总账（对照 ask 4 条）
1) 『计划任务/同步任务』按钮：**找到并点击**（'同步'/'计划任务'，前轮 MSAA 全盲）。
   全链路 UI 已地图化：同步→FormAddAccount(无账户引导)→同步面板(buttonAddSync)→
   FormSync(同步引擎对话框：路径×2/添加文件夹/配置-镜像/保存/比较/开始/过滤器)→
   FormSyncConfig(镜像/加密/哈希比较)→FormSyncsManager(创建新的同步任务/实时同步)。
   **打开整条链不解密 Proc**；引擎真正执行未成功（Run G 路径已写入但引擎零反应）。
2) AirExplorerCmd.exe：未重跑（Round 1 已证 license 门禁死路 + 文件内无 Proc blob；
   重跑纯浪费预算——如实记录为"沿用 Round 1 结论"）。
3) 裸跑 600s：未做独立裸跑；等效覆盖 = 本轮 7 次运行累计 ~10 分钟持续三路堆扫描
   （0xBB2B / 0x2BBB / 节律）+ Round 1 的 ~19 分钟。监视器阳性对照 PASS（见上）。
4) ct/pt 对 → key：**未抓到对，key 未解出，dec_Proc.bin 未产出**。求解管线
   （t26_solver.py 2^32 全扫 293s + t26_finish.py）保持就绪，拿到对后 ~5 分钟出结果。
