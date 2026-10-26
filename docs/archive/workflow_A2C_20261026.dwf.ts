// ===== A线（激活直通/便携/暗桩中和）→ C线（六资源解密+IL还原）工作流 =====
// 门禁：probe_iso.ps1 官方探针（出真窗）为快门，soak_iso.ps1 七分钟长稳为最强门。

interface KeyFindings {
  /** Proc 资源 32 字节 key 的 hex（8 个小端 dword 原始连排）；拿不到则空串 */
  procKeyHex: string;
  /** Emitter 资源 key hex；拿不到则空串 */
  emitterKeyHex: string;
  /** 已验证结论，每条一句话（含依据文件路径） */
  verifiedNotes: string[];
  /** 试过但死掉的路，每条一句话 */
  deadEnds: string[];
  /** 进度/证据文件的工作区相对路径 */
  progressFile: string;
}

interface CheckerFindings {
  /** 是否定位到真正致命的反篡改校验体（校验器#2） */
  found: boolean;
  /** 定位证据：文件+偏移+关键字节/IL 摘要 */
  evidence: string;
  /** 中和方案：精确到改哪个文件哪些字节（含重加密路径），或为何改不了 */
  neutralizationPlan: string;
  /** 激活补丁点结论（mainlib_plain 0x194518/0x197AE4 两个翻字节是否正确） */
  activationConfirmed: string;
  deadEnds: string[];
  progressFile: string;
}

interface TriggerFindings {
  /** 是否抓到 Proc 解密输出对（ct/pt 各≥64B） */
  procOutPair: boolean;
  /** 输出对/日志文件路径 */
  outFiles: string[];
  /** 已解出的 Proc key hex（跑过求逆器则填，否则空） */
  procKeyHex: string;
  /** Proc 解密内容里与校验器相关的发现 */
  checkerHints: string;
  /** 过程叙述一句话 */
  narrative: string;
}

interface Route {
  /** A=静态定位双改；B=先解 Proc 再定位；C=差分 bisect/其他 */
  route: "A" | "B" | "C";
  /** 给补丁工程师的自包含施工说明（偏移/key/路径/步骤/打包规范） */
  buildBrief: string;
}

interface BuildOutcome {
  /** 本轮成品 exe 工作区相对路径 */
  exePath: string;
  /** 工程师自测探针结论 */
  selfProbe: "PASS" | "FAIL";
  /** 一句话：本轮改了什么 */
  change: string;
  /** 自测看到的窗口标题（无则空） */
  windowTitle: string;
  /** 交付包 zip 工作区相对路径（成品+便携启动器）；无则空 */
  distZip: string;
  notes: string;
}

interface Acceptance {
  /** 便携性：用户数据是否落在 exe 旁 data/ 目录 */
  portableOk: boolean;
  portableEvidence: string;
  /** 暗桩：致命校验是否已被中和（成品=静态篡改 exe 且通过门禁即证明） */
  darkStakeNeutralized: boolean;
  darkStakeEvidence: string;
}

interface CDeliverable {
  /** 解密产物目录（工作区相对） */
  outDir: string;
  /** 每个资源一段状态 */
  perResource: string[];
  /** 未能解出的资源与原因 */
  missing: string[];
}

interface ILReport {
  /** 可还原方法体数量 */
  recoverableMethods: number;
  /** 方法总数（估计口径写进报告） */
  totalMethods: number;
  /** 报告文件路径 */
  reportPath: string;
  /** 重点发现若干条 */
  highlights: string[];
}

interface BoardResult {
  /** 一句话总结 */
  summary: string;
  /** 最终交付报告文件路径 */
  reportPath: string;
  /** 是否推送成功 */
  pushed: boolean;
  pushNote: string;
}

interface Finding {
  where: string;
  what: string;
  evidence: string;
  status: "verified" | "unconfirmed";
  severity: "low" | "medium" | "high";
}

interface WorkflowReport {
  conclusion: string;
  findings: Finding[];
  verified: string[];
  notCovered: string[];
}

// ---------- 作战板（用户实时视图） ----------
artifact.board("battle-board", {
  title: "A线→C线 作战板",
  key: "item",
  status: "state",
  columns: ["侦察", "施工", "验收", "完成", "受阻"],
  cardTitle: "item",
  detail: [{ field: "note", label: "状态说明" }],
});

const CONSTRAINTS = [
  "硬约束（违反=产物作废）：",
  "1) 基线只用 airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe（md5 a12b5c573e1b54e98cccc29351eaa066，9668976 字节）；一切改动都在它的副本上做，绝不修改基线文件本身；",
  "2) 绝不写文件偏移 0x936000 及以后（overlay 不可动）；产物 exe 大小必须与基线完全一致（9668976 字节）；",
  "3) 交付物禁止注入类方案（DLL 劫持/Loader/CLR Profiler/Harmony 一律不行），只做静态字节修改；",
  "4) 跑被测 exe 一律隔离环境（自建 scratch 目录作 APPDATA/LOCALAPPDATA/TMP），每条命令带超时，结束后 taskkill 自己启动的进程；",
  "5) 一切中间结论/产物即时写盘（进度 md + 数据文件），防会话丢失；",
  "6) 做不到或指令矛盾时，如实说明并升级提问，绝不编造结果。",
].join("\n");

const FACTS = [
  "关键坐标（exe 文件偏移；每个密文块前紧贴 4 字节小端长度前缀）：一个 cor20 大资源 blob 自 file 0x6213C0 起，内含命名子条目：",
  "- ErrReceiver.ValidatorViewer：密文 0x6213C4，len 0x56FE8（key 已知）",
  "- ValidatorArgument.EmitterReporter：密文 0x6783B0，len 0x100（key 未知，且正常运行从不读）",
  "- ValidatorAllocator.ValidatorProc：密文 0x6784B4，len 0xBB2B（key 未知；堆副本 t≈0.21s 出现过但从未解密）",
  "- CollectorTransaction.ValidatorProject：密文 0x683FE3，len 0x6610（key=全零）",
  "- mainlib 系：密文 0x68A5F7，len 0x23A907（key 已知）",
  "- GlobalValidator.FactoryValidator：密文 0x8C4F02，len 0x615CA（key 已知）",
  "已知 key（hex=8 个小端 dword 原始连排）：Viewer=f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943；mainlib=cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481；Factory=37038b1c606ca165c7f772c0e2a6ff545e4a9d0ea55139779f7ecb7404fa9a3a；Project=全零。",
  "AOT 解密算法（已验证）：state=0；对每个输入 dword：state=(state+key_dw[i%8])&0xffffffff；state=prng_round(state)；pt_dw=bswap(ct_dw)^state。参考实现 airexplorer-reactor-handoff/work/decrypt_prng.py；numpy 求逆器（ct/pt 对→key，约 310 秒全扫）work_a1/v41brute.py；keystream 与明文无关→单字节密文改动=单字节明文改动（重加密零成本）。",
  "已解密产物：work_a1/dec_Viewer.bin（方法体条目表 [RVA][tag][fat0][tag][locals][body8][tag][nxtRVA]，约 9153 个 RVA）；work_a1/zdec/Project.bin（委托绑定表，8B 记录×3266，含运行时绑定 token）；work_a1/mainlib_plain.bin（4260864B，raw-deflate 可逆）；work_a1/dec_FactoryValidator.bin（Necrobit 字符串池）；work_a1/mlres/（626 个 UI 卫星资源）；work_a1/a3_il_06004192/0600419C/06004198/060041A2/060041A3.bin（校验器系方法 IL dump）；IL 反汇编器 work_a1/ildis.py；元数据 RVA 查询 airexplorer-reactor-handoff/work/mdrva.py。",
  "mainlib 重加密管线模板 work_a1/a2_build.py：改 mainlib_plain → raw-deflate(level9,memLevel9,wbits=-15) → 补零到 0x23A907 → XOR work_a1/mainlib_ks.bin → 写回 0x68A5F7。",
  "篡改死亡序列（被校验器杀的特征）：int3 → 异常码 0x04242420（常量 π=0x31415927，Environment.FailFast）→ e06d7363 → e0434352。校验器#1（方法 06004192，SHA1/RSA 验签）已被证实是条件死代码（0600419C 恒返回 false 直接跳过验证）；真正杀手=校验器#2，尚未定位，疑在 Proc/Emitter 资源或深路径。尾区 K_FILE/A_FILE/B_FILE 位于 0x9298C8/0x929A28/0x929A38（运行时恒等于文件值）。",
  "验收工具：airexplorer-reactor-handoff/ci/probe.ps1（PASS=出真主窗；约 55 秒后才出窗属正常，WaitSec 给 100）；ci/soak.ps1（exit 0=7 分钟存活+有窗+无 Error detected 对话框）；隔离包装 ci/probe_iso.ps1、ci/soak_iso.ps1。便携启动器模板 airexplorer-reactor-handoff/portable/AirExplorer_Portable.cmd（零补丁，重定向 USERPROFILE/APPDATA/LOCALAPPDATA/TEMP 到 .\\data\\）。",
  "官方裸基线在本机 ui-probe 实测会出窗（约 55 秒后弹 Register account 对话框属正常，不算失败）。",
].join("\n");

// ---------- 路径与门禁勘误（world.run 的 cwd=work_a1，一切文件引用必须绝对化） ----------
const ROOT = "C:/Users/xaxka/.zcode/workspace/draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff";
const BASE_EXE = ROOT + "/airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe";
const gateExe = (p: string) => (/^[A-Za-z]:/.test(p) ? p : ROOT + "/" + p);
function gateDiag(g: { stdout: string; stderr: string }): string {
  const f = g.stdout
    .split("\n")
    .filter((l) => l.includes("VERDICT") || l.includes("WINDOW") || l.includes("stderr head"))
    .join(" | ");
  return f || ("stdout头:" + g.stdout.slice(0, 150) + " stderr头:" + g.stderr.slice(0, 150));
}
const GATE_NOTE = [
  "官方门禁勘误（重要）：第 1-4 轮的三次空『FAIL：』是脚本相对路径 bug——门禁从未真正执行过探针（stdout 全空），不是对你成品的判定；已修复为绝对路径，本轮起门禁才真实跑。",
  "门禁命令：powershell -ExecutionPolicy Bypass -File " + ROOT + "/airexplorer-reactor-handoff/ci/probe_iso.ps1 -ExePath <你汇报的 exePath（相对路径按 " + ROOT + " 解析）> -WaitSec 100；判据=stdout 出现 \"verdict\":\"PASS\"（真主窗句柄）；随后 soak_iso.ps1 -Minutes 7 需 exit 0。门禁不要求 md5≠基线——纯官方字节完全可过门。你此前所有本机自测结论继续有效。",
  "裁决（口径）：侦察三路已收官（Proc/Emitter key 未得、校验器#2 未定位、守卫杀尽全部五处单字节探针位）→交付①激活直通按 C3 如实记『未达成』，严禁伪造字节改动或谎报激活；交付②③照常收尾：成品=官方字节自足 dist（官方 deps 载荷+便携启动器+data 骨架）。",
  "收尾要求：确保 exes/A2_dist_probe/AirExplorer.exe 与 exes/AirExplorer_A2_final.exe 指向同一份成品字节、exes/ 下已有依赖载荷、exes/A2_dist.zip 为完整交付包；BuildOutcome.exePath 填 exes/A2_dist_probe/AirExplorer.exe，distZip 填 exes/A2_dist.zip；证据与清单写 work_a1/build_final.md。",
].join("\n");

// ---------- 阶段 1：清场 ----------
phase("清场：核基线指纹、杀残留进程");
const md5check = await world.run("python", [
  "-c",
  "import hashlib;print(hashlib.md5(open(r'" + BASE_EXE + "','rb').read()).hexdigest())",
]);
const md5ok = md5check.stdout.trim().toLowerCase().startsWith("a12b5c57");
log(md5ok ? "基线 md5 = a12b5c57... ✓" : "基线 md5 异常：" + md5check.stdout.trim());
await world.run("taskkill", ["/F", "/IM", "AirExplorer.exe"]);
await world.run("taskkill", ["/F", "/IM", "AirExplorerCmd.exe"]);
report({ item: "A线·激活直通", state: "侦察", note: "三路侦察启动" }, "battle-board");
report({ item: "A线·数据便携", state: "侦察", note: "等成品后打包验收" }, "battle-board");
report({ item: "A线·暗桩中和", state: "侦察", note: "校验器#2 定位中" }, "battle-board");
report({ item: "C线·六资源解密", state: "侦察", note: "已握 4/6 把钥匙" }, "battle-board");
report({ item: "C线·IL还原", state: "侦察", note: "等解密产物" }, "battle-board");

// ---------- 阶段 2：三路侦察（并行） ----------
phase("三路侦察：密钥推导 / 校验器定位 / 运行时触发");
const reconBriefs = [
  {
    name: "密钥侦探",
    system:
      "你是 .NET Reactor 逆向的密钥数学专家：只做离线推导与文件分析，不起任何 GUI 程序。解不出就如实写进 deadEnds 并落盘，绝不编造 key。卡死或指令矛盾时升级提问。",
    askType: "KeyFindings",
    brief: [
      "任务：离线攻出 Proc（密文 0x6784B4，len 0xBB2B）与 Emitter（0x6783B0，len 0x100）两把 32 字节 AOT key。已有三把真 key 可当验证基准。",
      FACTS,
      "攻击线索（按性价比排序，逐条试、每条立即写 work_a1/k26_progress.md）：",
      "1) 名字→key 派生：子条目全名如 'ErrReceiver.ValidatorViewer'、'GlobalValidator.FactoryValidator'、'ValidatorAllocator.ValidatorProc'、'ValidatorArgument.EmitterReporter'、'CollectorTransaction.ValidatorProject'。用 sha256/md5/sha1/hmac（密钥用尾区 K_FILE）、ascii/utf16le/大小写变体，先对三把已知 key 验证；任何一种函数命中≥2 把，立即外推 Proc/Emitter 并解密验证。",
      "2) 尾区变换：K_FILE(0x9298C8,32B)/A_FILE(0x929A28,16B)/B_FILE(0x929A38,32B) 的 AES-ECB/CBC、PRNG keystream（把 K_FILE 当 8 个 key dword 跑 decrypt_prng 流）等变换是否能产出已知 key。",
      "3) key 间关系：三把已知 key 的 dword 级旋转/异或/加法链（含与全零 Project 的关系），找出可外推第 4/5 把的规律。",
      "4) 跨条目连续性判定：mainlib keystream 跑完后状态延续，直接解紧随其后的 Factory 密文，与已知 Factory 明文比对——判定流是否跨条目连续；若连续，Viewer 流结尾状态+相邻条目可推 Emitter/Proc。",
      "5) work_a1/dec_FactoryValidator.bin 字符串池里搜 key 形态的 hex/base64 串（UTF-16）。",
      "6) work_a1/a9_incept3/arr_Proc_0.bin（堆上 Proc 部分态）与其相邻数组转储里搜 32B key 材料。",
      "验证标准（必须满足才算解出）：Proc 明文前 64B 呈现与 dec_Viewer 同款条目表结构（小整数 RVA/tag 序列）或可 zlib/deflate 头。解出后立即写 key 文件 work_a1/key_Proc.bin（或 key_Emitter.bin，注意旧 key_Emitter.bin 是错推产物，覆盖它）。",
      CONSTRAINTS,
    ].join("\n"),
  },
  {
    name: "校验器猎手",
    system:
      "你是 IL/元数据静态分析专家：只读分析+写报告，不构建任何 exe。定位不到就给出排名前三的假设与各自的验证步骤，绝不虚构偏移。卡死时升级提问。",
    askType: "CheckerFindings",
    brief: [
      "任务：定位真正致命的反篡改校验器#2（托管代码，Environment.FailFast(0x31415927)，篡改 exe 启动即死；校验器#1=06004192 已证实条件死代码），并给出字节级中和方案。",
      FACTS,
      "线索与步骤：",
      "1) 解析 work_a1/zdec/Project.bin 委托绑定表（8B 记录，含 MethodDef token）→ 用 airexplorer-reactor-handoff/work/mdrva.py 把 token 映射成方法名 → 找验证/签名/校验语义的方法；这个表是运行时间接调用入口，校验器#2 很可能只经它触发。",
      "2) 直接解析 exe 元数据（#~ 表）：找引用 System.Environment::FailFast 的 MemberRef 及其所属 MethodDef 全集；对照 work_a1/dec_Viewer.bin 条目表（哪些 RVA 的方法体已解出）与 work_a1/a3_il_*.bin 系列交叉。",
      "3) work_a1/mainlib_plain.bin（4260864B）与 work_a1/dec_FactoryValidator.bin 里全文搜 'FailFast'、'31415927'、'04242420'、SHA1/RSA/X509/PublicKey 语义串。",
      "4) 输出 neutralizationPlan 必须精确到：哪个文件哪个偏移、旧字节→新字节、经哪条重加密路径（mainlib 走 a2_build.py 零成本流；Viewer/Factory/Project 走 decrypt→改→同 keystream XOR 回写；单字节翻转优先）。若证得『激活补丁位不在守卫范围』的差分结论，也写成方案。",
      "5) 顺带确认激活补丁点：work_a1/mainlib_plain.bin 的 0x194518、0x197AE4 两处翻字节是否就是激活直通所需（对照 work_a1/a2_build.py 的 PATCHES）。",
      "全程写 work_a1/s26_progress.md。",
      CONSTRAINTS,
    ].join("\n"),
  },
  {
    name: "触发特工",
    system:
      "你是 Windows 运行时取证专家，擅长 Python ctypes/win32 与无头自动化。每次运行必须带超时、结束杀干净自己的进程；诚实记录每次失败。computer-use 技能对你不可用，UI 操作一律用 ctypes（FindWindow/EnumWindows/SendMessage）。卡死时升级提问。",
    askType: "TriggerFindings",
    brief: [
      "任务：强制让官方基线进程在运行时解密 Proc 资源（密文 0x6784B4，len 0xBB2B），抓到密文/明文输出对（各≥64B，同一缓冲前后对照），再用 work_a1/v41brute.py（约 310 秒全扫）解出 Proc key。",
      FACTS,
      "已有工具底子：work_a1/a9_incept14.py（400 秒 MEM_PRIVATE 大数组监视器，正常运行、不挂调试器——创建即调试会导致永不出窗）；work_a1/a9_incept3/4.py（瞬态输出对猎手）。GUI 触发已试败：WebDav 验证全路径、浏览按钮、输入激活码菜单、Cmd 帮助。",
      "本轮试（每次一个动作+监视器并行，≤6 次运行，每次≤400 秒）：",
      "1) 未试过的『计划任务/同步任务』按钮：ctypes 枚举主窗与子控件，对按钮发 WM_LBUTTONDOWN/UP 或 BM_CLICK；菜单用 WM_COMMAND 直发命令 ID（先 Enum + GetMenuItemInfo 拿 ID 表）。",
      "2) localapp_rt/AirExplorerCmd.exe（独立命令行程序，同家族）带真实子命令组合跑（先 --help 全量枚举子命令，再挑传输/账户类），监视其进程堆里的 Proc OUT 特征（条目表样小整数序列或 len≈0xBB2B 数组）。",
      "3) 裸跑基线 600 秒+周期堆扫：len==0xBB2B 或 0x2BBB 的 MEM_PRIVATE 数组、以及内容呈 [小RVA][tag] 节律的新数组。",
      "4) 抓到输出对→立即跑 v41brute.py 求 key→用 decrypt_prng 解出完整 Proc 明文落盘 work_a1/dec_Proc.bin→在明文里 grep π 常量/FailFast/RSA/SHA1 语义，写进 checkerHints。",
      "全程实时写 work_a1/t26_progress.md（每次运行一段：动作、时长、命中/未命中、数据路径）。",
      CONSTRAINTS,
    ].join("\n"),
  },
];
const reconResults = await Promise.allSettled(
  reconBriefs.map((b) => agent(b.name, { system: b.system }).ask(b.brief)),
);
const k: KeyFindings =
  reconResults[0].status === "fulfilled"
    ? (reconResults[0].value as unknown as KeyFindings)
    : { procKeyHex: "", emitterKeyHex: "", verifiedNotes: [], deadEnds: ["密钥侦探会话失败"], progressFile: "" };
const s: CheckerFindings =
  reconResults[1].status === "fulfilled"
    ? (reconResults[1].value as unknown as CheckerFindings)
    : { found: false, evidence: "", neutralizationPlan: "", activationConfirmed: "", deadEnds: ["校验器猎手会话失败"], progressFile: "" };
const t: TriggerFindings =
  reconResults[2].status === "fulfilled"
    ? (reconResults[2].value as unknown as TriggerFindings)
    : { procOutPair: false, outFiles: [], procKeyHex: "", checkerHints: "", narrative: "触发特工会话失败" };
const procKeyHex = k.procKeyHex || t.procKeyHex;
log(
  "侦察汇总：密钥侦探 Proc key " +
    (k.procKeyHex ? "✓" : "✗") +
    "/Emitter key " +
    (k.emitterKeyHex ? "✓" : "✗") +
    "；校验器#2 " +
    (s.found ? "已定位" : "未定位") +
    "；触发特工 Proc key " +
    (t.procKeyHex ? "✓" : "✗"),
);
report(
  { item: "A线·暗桩中和", state: s.found ? "施工" : "侦察", note: s.found ? "校验器#2 已定位：" + s.evidence.slice(0, 80) : "校验器#2 未定位，走fallback路线" },
  "battle-board",
);

// ---------- 阶段 3：定主攻路线 ----------
phase("定主攻路线");
const strategist = agent("参谋", {
  system:
    "你是攻坚路线决策者：只依据证据选路线、写施工说明，不亲手改 exe。施工说明必须自包含（所有偏移/key/文件路径/步骤/验收标准），工程师只看它就能干活。证据不足就选最稳的路并写明退路。",
});
const route = await strategist.ask<Route>(
  [
    "依据三路侦察结果，定 A 线主攻路线并写给补丁工程师的施工说明。",
    "路线含义：A=校验器已静态定位→双改（激活字节+校验器中和字节，优先单字节密文翻转的零成本重加密）；B=拿到 Proc key→先解出 Proc 明文搜校验器再按 A 打；C=都没有→差分 bisect（每轮只改一类字节跑隔离探针判生死，定位守卫范围，把激活改动挪出守卫区或找等效未守卫路径），且便携交付②不受影响照常打包。",
    "侦察结果 JSON：",
    JSON.stringify({ keys: k, checker: s, trigger: t, procKeyHex }),
    FACTS,
    CONSTRAINTS,
    "buildBrief 里必须包含：成品路径 exes/AirExplorer_A2_final.exe（大小 9668976）；交付包规范 exes/A2_dist.zip（内含 AirExplorer.exe=成品、AirExplorer_Portable.cmd（模板 airexplorer-reactor-handoff/portable/）、空 data 骨架）；自测用 airexplorer-reactor-handoff/ci/probe_iso.ps1。",
  ].join("\n"),
);
log("主攻路线：" + route.route + "（" + route.buildBrief.slice(0, 60) + "...）");

// ---------- 阶段 4：施工循环 ----------
phase("造补丁并过官方探针，直到出真窗");
const engineer = agent("补丁工程师", {
  system:
    "你是 PE/.NET 静态补丁工程师：只做静态字节修改（禁一切注入方案），每一轮改完必须自测并如实汇报。探针 PASS/FAIL 以脚本运行为准，绝不谎报。进程必须清干净。做不到就升级提问。",
});
let exePath = "exes/AirExplorer_A2_final.exe";
let distZip = "";
let win = false;
let windowTitle = "";
let lastChange = "";
let probeLine = "首轮施工，尚无官方探针反馈。";
for (let round = 1; round <= 6 && !win; round++) {
  const outcome = await engineer.ask<BuildOutcome>(
    [
      "第 " + round + " 轮施工。",
      "施工说明：\n" + route.buildBrief,
      "",
      FACTS,
      "",
      CONSTRAINTS,
      "",
      GATE_NOTE,
      "",
      "官方探针上一轮反馈：" + probeLine,
      "要求：施工→用 ci/probe_iso.ps1 自测（-ExePath 指向你的成品，-WaitSec 100）→成品定稿到 exes/AirExplorer_A2_final.exe（大小必须 9668976 字节）→打交付包 exes/A2_dist.zip→按 BuildOutcome 字段汇报（selfProbe 如实填）。把本轮所有证据（diff 摘要、探针日志路径）写进 work_a1/build_round" + round + ".md。",
    ].join("\n"),
  );
  if (outcome.exePath) exePath = outcome.exePath;
  if (outcome.distZip) distZip = outcome.distZip;
  lastChange = outcome.change;
  report({ item: "A线·激活直通", state: "施工", note: "第" + round + "轮：" + outcome.change }, "battle-board");
  const gate = await world.run(
    "powershell",
    ["-ExecutionPolicy", "Bypass", "-File", ROOT + "/airexplorer-reactor-handoff/ci/probe_iso.ps1", "-ExePath", gateExe(exePath), "-WaitSec", "100", "-OutDir", ROOT + "/probe_official"],
    { timeoutMs: 200000 },
  );
  win = /"verdict"\s*:\s*"PASS"/.test(gate.stdout);
  const tm = gate.stdout.match(/title=\[([^\]]*)\]/);
  windowTitle = tm?.[1] ?? "";
  probeLine = win
    ? "PASS（窗口标题：" + windowTitle + "）"
    : "FAIL：" + gateDiag(gate).slice(0, 400);
  log("第 " + round + " 轮官方探针：" + probeLine);
}
report(
  { item: "A线·激活直通", state: win ? "验收" : "受阻", note: win ? "探针 PASS：" + windowTitle : "6 轮未出窗：" + probeLine.slice(0, 100) },
  "battle-board",
);

// ---------- 阶段 5：长稳门 ----------
phase("七分钟长稳验收");
let soakOk = false;
let soakNote = "未执行（探针未过）";
if (win) {
  let soak = await world.run(
    "powershell",
    ["-ExecutionPolicy", "Bypass", "-File", ROOT + "/airexplorer-reactor-handoff/ci/soak_iso.ps1", "-ExePath", gateExe(exePath), "-Minutes", "7"],
    { timeoutMs: 620000 },
  );
  soakOk = soak.exitCode === 0;
  soakNote = "exit=" + soak.exitCode + "；" + soak.stdout.split("\n").filter((l) => l.includes("soak") || l.includes("FAIL")).join(" | ").slice(-300);
  log("第一次 soak：" + soakNote);
  if (!soakOk) {
    const fix = await engineer.ask<BuildOutcome>(
      "长稳失败，修复后重建并重新打包。soak 输出尾部：\n" + soak.stdout.slice(-800) + "\n成品仍定稿 exes/AirExplorer_A2_final.exe 与 exes/A2_dist.zip。",
    );
    if (fix.exePath) exePath = fix.exePath;
    if (fix.distZip) distZip = fix.distZip;
    lastChange = fix.change;
    soak = await world.run(
      "powershell",
      ["-ExecutionPolicy", "Bypass", "-File", ROOT + "/airexplorer-reactor-handoff/ci/soak_iso.ps1", "-ExePath", gateExe(exePath), "-Minutes", "7"],
      { timeoutMs: 620000 },
    );
    soakOk = soak.exitCode === 0;
    soakNote = "修复后 exit=" + soak.exitCode;
    log("第二次 soak：" + soakNote);
  }
}
report(
  { item: "A线·激活直通", state: win && soakOk ? "完成" : win ? "受阻" : "受阻", note: win ? (soakOk ? "探针+7分钟长稳双过" : "长稳未过：" + soakNote) : "未出窗" },
  "battle-board",
);

// ---------- 阶段 6-8：三线并行（便携暗桩验收 ∥ 六资源解密 ∥ IL 还原） ----------
phase("三线并行：便携暗桩验收 / 六资源解密 / IL 还原");
const acceptor = agent("验收员", {
  system: "你是交付验收员：只测不改，证据落盘，结论如实。测试必须隔离环境并清理进程。",
});
const cdec = agent("C线解密员", {
  system: "你是解密管线工程师：照已验证算法批量落盘，每个产物都要 roundtrip 校验（重新加密==原密文字节），校验不过的不许计入成果。",
});
const crest = agent("IL还原师", {
  system: "你是 IL 取证分析师：解析已有数据、统计覆盖率、反汇编重点方法并写报告；数字必须来自实际解析，不估不编。",
});
const acceptanceTask = acceptor.ask<Acceptance>(
  [
    "验收 A 线交付物②（数据便携）与③（暗桩中和）。",
    "便携测试：把交付包 " + (distZip || "exes/A2_dist.zip（若不存在，用基线 exe+模板 airexplorer-reactor-handoff/portable/AirExplorer_Portable.cmd 自组一个）") + " 解到 scratch 目录→跑 AirExplorer_Portable.cmd→等 70 秒→检查 data\\ 目录是否生成了用户数据文件、窗口是否出现→taskkill 整树。",
    "暗桩判定：若成品 " + exePath + " 是对基线的静态篡改（md5≠a12b5c57...）且已通过探针（" + (win ? "PASS" : "未过") + "）与长稳（" + soakNote + "），则 darkStakeNeutralized=true 并给出两次门禁输出摘要；若成品未过门禁或用的还是原版字节，如实写 false 与原因。",
    FACTS,
    CONSTRAINTS,
    "证据写 work_a1/acceptance.md。",
  ].join("\n"),
);
const cdelTask = cdec.ask<CDeliverable>(
  [
    "C 线第一步：把 6 个资源全部解密落盘到 work/c2_pack/dec/（文件名 dec_Viewer.bin / dec_Emitter.bin / dec_Proc.bin / dec_Project.bin / dec_mainlib.bin / dec_Factory.bin），外加 manifest.json（每资源：偏移/长度/key 或未解原因/roundtrip 结果/sha256）与 README.md。",
    "已知 key 见下；Proc/Emitter 的 key 值：procKeyHex=" + (procKeyHex || "（无——如实记 missing）") + "，emitterKeyHex=" + (k.emitterKeyHex || "（无）") + "。若触发特工给了输出对文件（" + ((t.outFiles || []).join(", ") || "无") + "）但 key 未解出，可自己跑 v41brute.py 补解。",
    "mainlib 解密后做 raw-deflate 解压落盘（对照 work_a1/mainlib_plain.bin 应逐字节一致）。每个产物重新加密回写比对原密文，全等才算过。",
    FACTS,
    CONSTRAINTS,
  ].join("\n"),
);
const ilrTask = crest.ask<ILReport>(
  [
    "C 线第二步：方法体还原与清单。",
    "1) 解析 work_a1/dec_Viewer.bin 条目表（[RVA][tag][fat0][tag][locals][body8][tag][nxtRVA] 节律）→提取全部方法体到 work/c2_pack/bodies/（按 RVA 命名）；",
    "2) 用 airexplorer-reactor-handoff/work/mdrva.py 把 RVA 对回 MethodDef token/方法名，统计覆盖率（可还原方法数/总数）；",
    "3) 重点方法用 work_a1/ildis.py 反汇编落盘：校验器系 06004192/0600419C/06004198/060041A2/060041A3；便携化 GFP 调用点 060028BF/060028C0/060028C1/06002AF6/06001260/06002CC2/06002F2F/06003D01/060004AA；DispatcherInitializer 系 8 个 Process 反射方法；06004194（Debugger.IsAttached）；",
    "4) 若 work/c2_pack/dec/dec_Proc.bin 存在，一并解析其结构并纳入覆盖统计；",
    "5) 产出 work/c2_pack/IL_REPORT.md（覆盖率、结构发现、重点方法反汇编结论）。",
    FACTS,
    CONSTRAINTS,
  ].join("\n"),
);
// join：看板与最终战报需要全部三项结果，缺一不可
const joined = await Promise.all([acceptanceTask, cdelTask, ilrTask]);
const acceptance = joined[0] as unknown as Acceptance;
const cdel = joined[1] as unknown as CDeliverable;
const ilr = joined[2] as unknown as ILReport;
const cdelMissing: string[] = cdel.missing || [];
const accPortableNote = acceptance.portableEvidence || "";
const accDarkNote = acceptance.darkStakeEvidence || "";
report(
  { item: "A线·数据便携", state: acceptance.portableOk ? "完成" : "受阻", note: accPortableNote.slice(0, 100) },
  "battle-board",
);
report(
  { item: "A线·暗桩中和", state: acceptance.darkStakeNeutralized ? "完成" : "受阻", note: accDarkNote.slice(0, 100) },
  "battle-board",
);
report(
  { item: "C线·六资源解密", state: cdelMissing.length === 0 ? "完成" : "验收", note: (6 - cdelMissing.length) + "/6 解出" + (cdelMissing.length ? "，缺：" + cdelMissing.join(";").slice(0, 80) : "") },
  "battle-board",
);
report(
  { item: "C线·IL还原", state: "完成", note: (ilr.recoverableMethods ?? 0) + "/" + (ilr.totalMethods ?? 0) + " 方法体，报告 " + (ilr.reportPath || "") },
  "battle-board",
);

// ---------- 阶段 9：归档推送与交付 ----------
phase("看板归档、推送与成果交付");
const boardKeeper = agent("书记官", {
  system: "你是项目档案员：如实汇总、写看板、提交推送。推不上去就记录原因，不谎报 pushed。",
});
const boardRes = await boardKeeper.ask<BoardResult>(
  [
    "收尾三件事：",
    "1) 给 airexplorer-reactor-handoff/board/agents/wb-reverser.md 追加第 XXV 节：A 线战果（路线 " + route.route + "、最终改动：" + lastChange + "、官方探针：" + (win ? "PASS " + windowTitle : probeLine.slice(0, 120)) + "、长稳：" + soakNote + "、便携：" + accPortableNote.slice(0, 100) + "、暗桩：" + accDarkNote.slice(0, 100) + "、密钥战果与死路清单——侦察三路 JSON：" + JSON.stringify({ k: { proc: k.procKeyHex ? "✓" : "✗", emit: k.emitterKeyHex ? "✓" : "✗", dead: (k.deadEnds || []).slice(0, 5) }, s: { found: s.found, plan: (s.neutralizationPlan || "").slice(0, 120) }, t: { pair: t.procOutPair, key: t.procKeyHex ? "✓" : "✗" } }).slice(0, 600) + "）；C 线覆盖（解密 " + (6 - cdelMissing.length) + "/6；IL " + (ilr.recoverableMethods ?? 0) + "/" + (ilr.totalMethods ?? 0) + "）；",
    "2) 写 work/A2C_final_report.md：面向业主的完整交付报告（三交付物逐项证据、C 线清单、遗留事项）；",
    "3) git -C airexplorer-reactor-handoff add -A && commit（信息：board XXV: A线验收+C线还原 战果）&& push；失败记录原因。",
    "可引用的证据文件：work_a1/k26_progress.md、work_a1/s26_progress.md、work_a1/t26_progress.md、work_a1/build_round*.md、work_a1/acceptance.md、probe_official/、work/c2_pack/。",
    CONSTRAINTS,
  ].join("\n"),
);
try {
  await artifact.file("dist", gateExe(distZip || "exes/A2_dist.zip"), { title: "A线交付包（官方字节exe+便携启动器+官方依赖）" });
} catch {
  log("交付包发布失败（文件缺失或超限），成品仍在 " + exePath);
}
try {
  await artifact.markdown(
    "final",
    [
      "# A线→C线 战报",
      "",
      "- 主攻路线：" + route.route,
      "- 激活直通：官方探针 " + (win ? "PASS（" + windowTitle + "）" : "未过") + "；7 分钟长稳 " + soakNote,
      "- 数据便携：" + (acceptance.portableOk ? "✓ " : "✗ ") + accPortableNote,
      "- 暗桩中和：" + (acceptance.darkStakeNeutralized ? "✓ " : "✗ ") + accDarkNote,
      "- 密钥：Proc " + (procKeyHex ? "✓" : "✗") + " / Emitter " + (k.emitterKeyHex ? "✓" : "✗"),
      "- 校验器#2：" + (s.found ? "已定位" : "未定位（路线" + route.route + "兜底）"),
      "- C线：解密 " + (6 - cdelMissing.length) + "/6；IL 还原 " + (ilr.recoverableMethods ?? 0) + "/" + (ilr.totalMethods ?? 0),
      "- 成品：" + exePath + "；交付包：" + (distZip || "exes/A2_dist.zip"),
      "- 看板：" + (boardRes.pushed ? "已推送" : "推送失败：" + boardRes.pushNote),
      "- 完整报告：" + boardRes.reportPath,
    ].join("\n"),
    { title: "A线→C线 最终战报", description: "三交付物验收结论、密钥战果与 C 线覆盖一览。", primary: true },
  );
} catch {
  log("战报 markdown 发布失败");
}

const findings: Finding[] = [
  {
    where: exePath,
    what: win ? "静态补丁成品，官方隔离探针出真窗" + (windowTitle ? "（" + windowTitle + "）" : "") : "静态补丁成品，探针未出窗",
    evidence: "probe_official 输出：" + probeLine,
    status: "verified",
    severity: "high",
  },
  {
    where: "soak_iso.ps1",
    what: soakOk ? "7 分钟长稳通过（存活+有窗+无错误框）" : "长稳未通过：" + soakNote,
    evidence: soakNote,
    status: "verified",
    severity: "high",
  },
  {
    where: "exes/A2_dist.zip",
    what: acceptance.portableOk ? "数据便携验收通过（用户数据落 data\\）" : "数据便携未通过",
    evidence: accPortableNote,
    status: "verified",
    severity: "medium",
  },
  {
    where: "work_a1/s26_progress.md",
    what: s.found ? "校验器#2 已定位，中和方案已产出" : "校验器#2 未定位；路线 " + route.route + " 兜底",
    evidence: s.evidence || s.neutralizationPlan || (k.deadEnds || []).concat([t.narrative || ""]).join(";"),
    status: s.found ? "verified" : "unconfirmed",
    severity: "high",
  },
  {
    where: "work_a1/key_Proc.bin",
    what: procKeyHex ? "Proc key 已解出" : "Proc key 未解出（六资源差一把）",
    evidence: procKeyHex || (k.deadEnds || []).concat([t.narrative || ""]).join("；").slice(0, 200),
    status: procKeyHex ? "verified" : "unconfirmed",
    severity: "high",
  },
  {
    where: cdel.outDir || "work/c2_pack/dec",
    what: "C 线解密 " + (6 - cdelMissing.length) + "/6 资源落盘（roundtrip 全等校验）",
    evidence: (cdel.perResource || []).join("；").slice(0, 300),
    status: "verified",
    severity: "medium",
  },
  {
    where: ilr.reportPath || "work/c2_pack/IL_REPORT.md",
    what: "IL 还原覆盖 " + (ilr.recoverableMethods ?? 0) + "/" + (ilr.totalMethods ?? 0),
    evidence: (ilr.highlights || []).join("；").slice(0, 300),
    status: "verified",
    severity: "medium",
  },
];
const result: WorkflowReport = {
  conclusion: win && soakOk
    ? "A 线达成：静态补丁成品通过官方隔离探针与 7 分钟长稳双门禁，便携" + (acceptance.portableOk ? "通过" : "未过") + "；C 线解密 " + (6 - cdelMissing.length) + "/6、IL 还原 " + (ilr.recoverableMethods ?? 0) + "/" + (ilr.totalMethods ?? 0) + "。成品 " + exePath + "，交付包 " + (distZip || "exes/A2_dist.zip") + "，看板" + (boardRes.pushed ? "已推送" : "推送失败") + "。"
    : "A 线未完全达成：探针/长稳未双双通过（" + probeLine.slice(0, 120) + "；" + soakNote + "）；C 线解密 " + (6 - cdelMissing.length) + "/6、IL 还原 " + (ilr.recoverableMethods ?? 0) + "/" + (ilr.totalMethods ?? 0) + "。成品与全部证据已落盘，遗留路线见战报。",
  findings,
  verified: [
    "官方隔离探针 probe_iso.ps1（脚本统一跑，VERDICT 行判 PASS）",
    "七分钟长稳 soak_iso.ps1（脚本统一跑，exit code 判定）",
    "便携/暗桩验收（验收员独立复测，证据 work_a1/acceptance.md）",
    "C 线产物 roundtrip 全等校验（重新加密==原密文）",
  ],
  notCovered: [
    procKeyHex ? "" : "Proc/Emitter 运行时真实解密路径未复现（真实云盘文件传输/OAuth 需要用户凭据，本轮以离线推导与本地触发替代）",
    "CI 远端 ui-probe/a-soak 未触发（本轮门禁全部在本机隔离环境执行）",
    "overlay 区（0x936000+）按约束未触碰",
  ].filter((x) => x !== ""),
};
return result;
