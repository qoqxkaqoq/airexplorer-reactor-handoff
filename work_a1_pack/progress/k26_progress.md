# k26_progress.md — Proc/Emitter AOT key 离线攻取（第 26 轮续）

任务：离线推导 ValidatorAllocator.ValidatorProc（ct@0x6784B4, len 0xBB2B）与
ValidatorArgument.EmitterReporter（ct@0x6783B0, len 0x100）两把 32B AOT key。
工具 harness：work_a1/k26/aot.py（keyed decrypt/encrypt，含 prng_round、tail-word 约定）。

## [环境勘察 2026-10-25]
- 基线 md5 = a12b5c573e1b54e98cccc29351eaa066，9668976B，未修改（只读）。
- **资源真名修订**：任务书缩写名与 exe 实际资源名对照（airexplorer-reactor-handoff/work/res_*.bin）：
  - Viewer  = `ErrorReceiver.ValidatorViewer` (0x56FE8)
  - Emitter = `ValidatorArgument.EmitterReporter` (0x100)
  - Proc    = `ValidatorAllocator.ValidatorProc` (0xBB2B)
  - Project = `CollectorTransaction.ValidatorProject` (0x6610)
  - mainlib = `ValidatorGenerator.DefinitionError` (0x23A907)  ← mainlib 真名
  - Factory = `GlobalValidator.FactoryValidator` (0x615CA)
  → 共 4 组已知 (name→key) 对（含全零 Project），派生验证基数比任务书多一组。
- 尾区已提取（work_a1/k26/{K,A,B}_FILE.bin）：
  - K_FILE@0x9298C8(32B)=f454d917a23944f8a20bad0865de435b94791f4e7d041b1e4d17f0f9f4cc63ca
  - A_FILE@0x929A28(16B)=8255f7a573fd5081433ddf8b4451d699
  - B_FILE@0x929A38(32B)=b1d255d7a148c5208026de95ee415d38dde55a42d38cfb14b3512ec595700005
- harness 验证（本轮实测，非转抄）：
  - Viewer key → 前 64B 与 work_a1/dec_Viewer.bin 完全一致 ✔
  - Project 全零 key → 前 64B 与 work_a1/zdec/Project.bin 完全一致 ✔
  - mainlib key → 前 64B 与 work_a1/zdec/mainlib_keyed.bin 完全一致 ✔
  - Factory key → 解出可读 UTF-16 字符串池（"{\n  \"alg = {0}, typ = {1}\"}}..."）✔
    （dec_FactoryValidator.bin 比密文短 2B，是另一次产物，头不对比属预期，不影响 key 正确性）

## [线索1 第一轮] name→key 派生矩阵 — 无命中
- 脚本 work_a1/k26/l1_names.py；变体空间：名字（全名/half/大小写/拼接/.resources 后缀/带NUL）×
  编码（utf8/utf16le）× 摘要（md5,sha1,sha256,sha384,sha512 头/尾/中 32B，sha3,blake2s/b，md5 双拼）×
  HMAC（md5/sha1/sha256/sha512，key=K/A/B_FILE，正反）× 哈希链（K/A/B_FILE 前后拼接）×
  PRNG 播种（DJB2(ascii/utf16/low)/FNV1/FNV1a/Joaat/CRC32 → 3 种链形 A/B/C）×
  后变换（原样/字节反转/dword bswap）≈ 1000+ 组合。
- 结果：4 组已知对 0 命中。名字直接派生（常规哈希族）排除。后续补：更深签名（如名字哈希再过 AES、
  双轮哈希、sha256(name)^K_FILE 等）暂缓，先跑 3/4/2/6。

## [后备A：runtime IL 深挖 2026-10-26]（重大架构进展）
1. **名字→key 第一轮矩阵**（work_a1/k26/l1_names.py，~1000 组合：摘要/HMAC/哈希链/PRNG 播种/大小写/编码）：0 命中。
2. **线索3 key 间关系**（l34_relcont.py）：Viewer/mainlib/Factory/零 之间 dword 级 rot/xor/add/prng 链全无；
   4M dword 全局零 key 流中无窗口命中 → key 不是全局流的切片。
3. **线索4 连续性**：mainlib 末态 0xc45a6a71 续解 Factory ≠ 已知 Factory 明文；逐条目 state=0 **DISCONTINUOUS 实证**
   （与 a12 零 key Project 从 state0 解密成功一致）。
4. **线索2 尾区**（l2_tail.py）：K/A/B_FILE 的 72 组 AES-ECB/CBC 变换、9 组直接当 key、3 组 PRNG 链 → 全无。
5. **线索5/6**（l6_heap.py）：small.pkl 415 数组×滑窗 6331 候选对 Emitter/Proc 结构打分全灭；
   全库（exe/dec_Viewer/mainlib_plain/dec_Factory/内存 dump 295 文件）搜 KV/KM/KF 原始 32B、逐 dword LE4、
   ldc.i4 模式、hex/base64 串 → 全灭。**key 不以明文形态存在于任何静态/堆产物**。
6. **资源真名修订**：mainlib = `ValidatorGenerator.DefinitionError`（0x23A907）；Emitter 名在 #US@0xA4C；
   Viewer@0xC5A、Factory@0xB00、Project@0xA90、Proc@0xDDA（#US 相对偏移）。
7. **每资源名仅 1 处 ldstr**：Project→06004193 TrackCompiler（零 key PRNG ✓ 与 decrypt_prng 一致）；
   **Viewer→0600419C DefineEfficientProfiler**（37KB 扁平化巨型方法）；Factory→06004196（经 dispatcher
   060042AD case 0x2C，SearchStrategy 包装）；**Emitter→06004192**；Proc 名无 ldstr（运行期拼串或查池）。
8. **keyed PRNG 解密器 = 0600418B GenerateAlphabeticVerifier**（arg1=key byte[]，arg3=ct；主循环
   state+=key_dw[i%(len/4)]; state=prng_round(state); pt=ct^state —— 与任务书算法一致）。无静态调用点
   → 经 TrackCompiler 用 Project 表(ResolveMethod)绑定的 delegate 调用。
9. **MD5 族 = 诱饵/死码**：06004183-92 是标准 MD5（T 表 = FieldRVA 0x207E@file0x927AE8，T[0]=0xD76AA478 ✓），
   0600418E=MD5 dispatcher；所谓"调用点"全在 stub 填充区（0600425A 实为 tiny 4B stub）→ MD5 族无真实调用方。
10. **0600419C/0600428A 各含一份内联 keyed PRNG**（K1..K4 常量在 IL_46DE/IL_1DB3）；
    0600419C 的 state+=key 形如 `v38+=v49`，v49 由 `ldelem.u1` 从字节数组拼 dword —— **key 来自运行期构造的字节数组**；
    IL 中存在数组互 XOR 循环（ldelem.u1|xor|stelem.i1）。
11. 06004192 = SHA1/RSA 校验器主体（Emitter 资源=其参数 blob，原始读入不解密 —— 与"Emitter 正常运行从不解密"吻合）；
    其扁平化代码构造 32B/16B 数组（RSA 材料，非资源 key）。
12. 工具新增：work_a1/k26/flatvm.py（扁平化状态机解释器，多 switch dispatcher、具体常量传播、fork 继承内存、
    调用/stelem 日志、数组 dump）；fieldrva.py（FieldRVA 解析）；k26/keytable_207E.bin（MD5 T 表 256B）。
13. 静态 stelem 重建（l7b_blocks.py，22930 方法）：仅 3 个巨型扁平方法有静态字节写入，构出的 32B 数组
    （06004192/0600419C/0600428A 各一）作为 Emitter/Proc key 候选（含洞爆破 65793 组合）→ 全灭。
    → 字节构造分多轮复用同一 local，需按执行序解释（flatvm 路线）。

## [后备A 续：VM/重放路线 — 阶段性受阻]
14. flatvm/k26vm 进展：签名解析（MethodDef/MemberRef sig blob → 参数数/HASTHIS）、精确消费栈、
    statics 读写、stream/reader/委托对象模型、子 VM 递归。TrackCompiler 试跑：推进到 pair 收集循环
    （loc12=131072 乃 newarr(Dyn) 默认 0x100000 所致——BinaryReader newobj 曾未建模，已修），
    但全流程贯通仍缺 EH 语义与循环开销优化，未达 PRNG 循环入口。
15. 0600419C 其余 ldstr：clrjit.dll / m_ptr / System.Reflection.RuntimeModule / m_pData /
    System.Reflection.ReflectionContext / __ → 0600419C = Necrobit JIT-host 引擎，只解 Viewer。
16. a3_flat419C.txt（上轮会话的扁平化线性化，350 块/352 dispatch，含执行序）重放：221 个 stelem 中
    126 个已解析，重建 v4(31B,1 洞)/v33(15B)；无 KV 命中 → 覆盖片段不含完整构造+XOR 循环体。
17. 堆 dump 变形搜索（295 文件）：KV/KM/KF 的 XOR-常量(×256)/ADD-常量(×256)/NOT/反转/dword-bswap → 全灭。
    **结论：现有 dump 均未覆盖 key 数组存活的时刻/区域。**
18. 【本路线卡点】key 数组由扁平化代码在运行期构造（stelem.i1 逐字节 + 数组互 XOR 循环 + 循环多重写），
    离线静态重建需完整执行序（扁平化 VM 贯通）；现有 dump 无 key 材料；无输出对（Emitter/Proc 从不解密）。
    三条路均需：贯通 VM（工程量大）或 定时运行期 dump（需起 GUI，超出本 subagent 离线权限）。

## [运行期方案（获批 4 次运行）— 结果]
19. 运行1（k26_guard.py，DEBUG_ONLY_THIS_PROCESS+6 资源页 guard+全栈窗 rbp-0x800..0x80 数组指针追踪）：
    **KV/KF 在堆上以独立托管 Byte[32] 出现**（KV@…52a0、KF@…5e5d8，头部 [Byte[]MT][count=0x20]），
    KV 后紧跟 16B 常量数组 a6ea62ce395fad93fa1a5ccd7396c8d5（跨 boot 恒定，非名字哈希、不在 exe）。
    KM（mainlib key）15 次全堆扫描均未出现。无连续 key 表（KV 与 KF 相距 0x169338）。
20. 运行2-4（Byte[32] 全量普查，动态扫描 15×/76s）：全堆仅 24 个 Byte[32]（含 KV/KF/junk/指针/UTF16 串/
    d8f47a25…——与静态重建 06004192 构造数组一致）。**Proc/Emitter key 不在任何扫描时刻的堆上**
    → key 仅在解密时构造，而 Emitter/Proc 永不解密 → 被动抓取路线对这两把 key 无效（需主动触发
    06004192 才可能让 Emitter key 短暂现形；Proc 的解密路径未知，无触发点）。
21. 逐候选测试（脚本内 E=token 形状 / P=Viewer 表结构打分）：最高 E=15/128（噪声）→ 无命中。
    捕获产物：work_a1/k26/guard1/（keyhit_*.bin ±4KB 上下文、b32/ 24 个候选、snap*_stack.bin 176 组栈窗）。
22. 【最终状态】Proc（0x6784B4,len 0xBB2B）/ Emitter（0x6783B4 前缀,0x6783B0,len 0x100）key **未攻出**。
    全部离线/运行期路线已尽：名字派生矩阵、key 间关系、尾区变换、连续性、字符串池、堆搜索、
    静态 stelem 重建、扁平化线性重放、VM 贯通（受阻于 EH/开销）、被动运行期抓取。
    交回差分 bisect 路线（按 orchestrator 指示，该路线不需要 Proc key）。

## [k27 轮 2026-10-26] 新会话（密钥侦探）— 思路：已知明文求逆 + 结构假设扫描
0. 本轮约束：纯离线（不起 GUI、不跑被测 exe）。上轮 k26 已尽路线不重复跑矩阵，主攻：
   (a) 通用多目标 2^32 求逆器（v41brute 泛化：一次扫描测多目标集合，一次扫出全部 8 个 key dword）；
   (b) Emitter/Proc 的"存储即明文"phantom-key 检验（若某资源从未被加密，pt==ct 可求出虚拟 key）；
   (c) Viewer 表结构深挖 → Proc pt 预测；
   (d) guard1 KF 伴生常量 + a6ea62ce 16B 关系。
1. 快测（本轮实测）：Proc/Emitter 用 Viewer/mainlib/Factory/全零 4 把已知 key 解密 → 前 16B 全随机，
   small-frac≈0 → 无 key 复用。✔ 排除。
2. Factory 真明文头（本轮用已知 key 现解）：34 00 00 00 | UTF-16 "{ alg = {0}, typ = {1} } {{ iss..."，
   即 [int32 长度][UTF-16]。→ pt0=0x00000034, pt1=0x007B007B 精确已知（校准点）。
   dec_FactoryValidator.bin 旧产物头与此不符（上轮已知，属另一次产物）。
3. mainlib_plain.bin = MZ 头 PE（4d 5a 90 00...4260864B）→ mainlib AOT 明文 = raw-deflate(该PE)。
   → 已知明文资源校准点齐备：Viewer(条目表)/Project(token 表 pt0=0x04002102)/Factory(0x34)。
4. Viewer 表结构统计（本轮）：89082 dword 中 32192 个 ∈[0x40000000,0x50000000)，其中 byte2==0xEE 的
   17990 个，byte3 ∈{0x45:12722, 0x54:5030, 0x43:61,...}；0x4?ee???? 重复率高（32192 次/11237 唯一）。
   (id,value) 对中 value: big 7252 / rvaish 5262 / small 272；同 id 多 value（0x45eeacdb→0x43013/
   0x11000003/0x11000004）→ id 非唯一 key。id 低 16 位全 <0x10000（游标状，+4/+8 步进）。
   未解出 0x4?ee???? 语义。

## [k27 轮结论 2026-10-26] ★★★ Proc/Emitter 无 AOT key —— 两资源为明文存储、明文消费（ premise 被推翻）★★★
本轮（密钥侦探 k27）从"已知明文求逆 + IL 常量提取"两条路切入，最终在 IL 层面证伪了任务前提。
证据链（全部本轮实测，可复核）：

1. **资源名 ldstr 全表勘误**（k26 note 7 的 token 记错；用 `72 <#US偏移> 70` 字节模式全 exe 扫描）：
   Project 0x70000A90→m_06004193；Factory 0x70000B00→m_06004196；Emitter 0x70000A4C→m_06004192；
   Viewer 0x70000C5A→m_0600419C；**Proc 0x70000DDA→m_060042AF（k26 说"Proc 名无 ldstr"是错的，ldstr 存在且唯一）**。
   每个名字在 exe 中恰 1 处 ldstr。
2. **dump↔exe 锚定**：dump_official_16598.zip 全部 18816 个 m_0600xxxx.bin 逐一回锚到 exe 文件偏移
   （工具内联在本轮脚本）。校验：Viewer PRNG 常量簇 exe@0x400766 = m_0600419C+0x46DE ✓（与 k26 note10 一致）；
   mainlib 簇 exe@0x407F83 = m_0600428A+0x1DB3 ✓。
3. **内联 keyed-PRNG 常量簇（K1=506503628 等 4 常量同现 ±400B）全 exe 仅 4 份**：
   0x3F8D70(m_0600418B=GenerateAlphabeticVerifier，共享解密器)、0x3FB69F(m_06004193=Project,零key)、
   0x400766(m_0600419C=Viewer)、0x407F83(m_0600428A=mainlib)。**Proc/Emitter 区间无任何一份。**
4. **共享解密器 0600418B 全二进制 0 个调用点**：`28 8B 41 00 06` 在 exe 与 18816 个 dump 中均无出现
   → 该 keyed 解密器是死码，任何"经它解密"的路径不存在。
5. **Proc 读者 = 060042AF（242B，已完整反汇编 → work_a1/k27/dis_060042AF_ProcReader.txt）**：
   ldstr "ValidatorAllocator.ValidatorProc" → GetManifestResourceStream（经委托域 0x040021B4，
   其 Project 表绑定 = MemberRef 0x0A0009A7 GetManifestResourceStream(string)）→ newobj 包装器 0x0A00029F
   （=BinaryReader 壳，TypeRef 名 "System.Windows.Interop.HwndSourceParameters" 是诱饵名）→
   **set_Position(2)**（跳过 2 字节头"3a 9c"）→ get_Length → **ReadBytes(全长)** → Close（委托域 0x04002D92，
   Project 表 rec3216 → 0x0A0009AA Close）。**全方法无任何解密调用。**
   Project 表（work_a1/zdec/Project.bin）= 委托域→MemberRef 绑定表：0x04002D88→get_BaseStream(rec3206)、
   0x04002483→set_Position、0x040021CC→get_Length、0x04002468→ReadBytes(int)→byte[]、0x04002D92→Close ——
   即整条"裸读管线"的每个环节都能在绑定表中对上号。
6. **Proc 字节的消费者 = m_060042B0（1040B，17 路扁平 switch → work_a1/k27/dis_060042B0_ProcTableParser.txt）**：
   `ldarg.0; newobj MemoryStream(byte[]); newobj 包装器; stsfld 0x04001FEE`，随后用
   ReadByte/ReadSingle/ReadInt32 型委托（0x04002D8D→ReadByte rec3213 等）把字节流当**结构化数据表**解析。
   060042B0 是 060042AF 的唯一直接调用者（全 dump 扫描）。
7. **Proc 内容统计证明非密文**：原始 47915B 熵 H=6.18 bits/byte，而同类加密资源（Viewer/Project 密文）
   H=7.98；跳过 2 字节头后为 (tag,值) 字节对流（01 2e | 01 06 | 01 8b | 01 84 | 01 4f | 05 a8 | ...），
   大量重复值（最大频次 492 次）——密文不可能有此结构。条目数 ≈ 23924，与方法数同量级。
8. **Emitter 读者 = 06004192（即"校验器#1"本体，8970B）**：ldstr → GetManifestResourceStream →
   newobj 06004264（RD 壳）→ set_Position(**0**) → get_Length → ReadBytes → 256B blob **原样**进入
   SHA1/RSA 验证逻辑（k26 note11 的"原始读入不解密"本轮在 IL 层面坐实，其辅助桩 060041D1~D5 逐一反汇编，
   分别转发 GetManifestResourceStream/get_BaseStream/set_Position/get_Length/ReadBytes，与 Project 表绑定一致）。
   k26 note20"若触发 06004192 可让 Emitter key 短暂现形"的假设被 IL 证据否定：无 key 可现形。
9. **任务书两处相关猜想一并证伪**：(a) "跨条目连续性"无意义——Proc/Emitter 根本不进 keyed 流；
   (b) pt==ct phantom-key 扫描被判定无意义（ks≡0 只要求 8 个独立 dword 满足 prng_round(k)=0，是弱钥类，
   即使找到也不是配置 key，且与 blob 内容无关）。
10. **对后续工作的可执行结论**：
   - Proc/Emitter 的"32B key"不存在，无法也不需要产出；任何写出的 key 都是编造（违反硬约束6）。
   - 校验器#2（真凶）消费的是 Proc 的**原始明文表**（060042B0 解析）与 Emitter 的**原始 256B blob**
     （SHA1/RSA，死码）→ 对这两资源的任何字节改动都会被裸数据校验直接感知（若校验器#2 检查它们）；
     不存在"重加密"步骤，篡改这些资源时必须保持表结构/校验和自洽，而不是保持密文一致性。
   - k26 的"静态 stelem 重建 32B 数组（06004192/0600419C/0600428A 各一）"中的 0600419C/0600428A 数组
     分别是 KV/KM（已知），06004192 的 32B 数组是 SHA1/RSA 的密钥材料（非资源 key）——全部与 Proc/Emitter 无关。
11. 本轮产物：work_a1/k27/{dis_060042AF_ProcReader.txt, dis_060042B0_ProcTableParser.txt,
    dis_06004196_FactoryReader.txt, evidence.json, k27_invert.py(求逆器，已用 Viewer 校准 ks=ct^pt 约定)}。
    未写 key_Proc.bin / key_Emitter.bin（无 key 可写）。
