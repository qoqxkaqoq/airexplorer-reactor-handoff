# C线第一步产物 — 6 资源解密落盘（work/c2_pack）

基线：`airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe`
（md5 `a12b5c573e1b54e98cccc29351eaa066`，9668976 B，**全程只读，未修改**）。
生成脚本：`work/c2_pack/c2_decrypt.py`（可重复运行，幂等）；运行日志 `c2_decrypt_log.txt`；
捕获文件分拣报告 `out_triage_report.txt`；逐资源元数据 `manifest.json`。

## 算法（已验证）

`state=0`；对每个输入 dword i：`state=(state+key_dw[i%8]) & 0xffffffff`；
`state=prng_round(state)`；`pt_dw = bswap(ct_dw) ^ state`。
字节视角等价于 `pt = ct XOR LE(state)流`（bswap 即“大端读 ct 后反转”，t26 轮已实测对小端再 bswap 全错）。
`prng_round` 参考实现：`airexplorer-reactor-handoff/work/decrypt_prng.py`。
keystream 与明文无关 → 单字节密文改动=单字节明文改动，重加密零成本。

本轮自证（c2_decrypt_log.txt §2）：
- 自实现零 key 链 == `decrypt_prng.keystream`（Project 全块 6532 dword）；
- 自实现 mainlib keystream == `work_a1/mainlib_ks.bin`（2337031/2337031 B）。

## 资源布局（本轮实测，blob 自 0x6213C0，每密文块前紧贴 4B 小端长度前缀）

| 资源 | 前缀@ | 密文@ | 长度 | key | 解密 | roundtrip |
|---|---|---|---|---|---|---|
| ErrReceiver.ValidatorViewer | 0x6213C0 | 0x6213C4 | 0x56FE8 | 已知 | ✅ | ✅ encrypt(pt)==ct |
| ValidatorArgument.EmitterReporter | 0x6783AC | 0x6783B0 | 0x100 | **无（不存在）** | ❌ passthrough | n/a |
| ValidatorAllocator.ValidatorProc | 0x6784B0 | 0x6784B4 | 0xBB2B | **无（不存在）** | ❌ passthrough | n/a |
| CollectorTransaction.ValidatorProject | 0x683FDF | 0x683FE3 | 0x6610 | 全零 | ✅ | ✅ |
| mainlib 系（真名 ValidatorGenerator.DefinitionError） | 0x68A5F3 | 0x68A5F7 | 0x23A907 | 已知 | ✅ | ✅（流级） |
| GlobalValidator.FactoryValidator | 0x8C4EFE | 0x8C4F02 | 0x615CA | 已知 | ✅ | ✅ |

六块首尾相接无空洞，blob 终点 0x9264CC < 0x936000（overlay 未触及）。

## 文件清单（dec/）

| 文件 | 内容 | 大小 | 校验 |
|---|---|---|---|
| dec_Viewer.bin | 方法体条目表（[RVA][tag][fat0][tag][locals][body8][tag][nxtRVA]，~9153 RVA） | 356328 | 与 work_a1/dec_Viewer.bin 逐字节一致；roundtrip ✅ |
| dec_Project.bin | 委托绑定表（8B×3266，含运行时绑定 token） | 26128 | 与 work_a1/zdec/Project.bin 逐字节一致；roundtrip ✅ |
| dec_mainlib.bin | 解密流 raw-deflate(wbits=-15) 解压出的 PE 明文 | 4260864 | 与 work_a1/mainlib_plain.bin 逐字节一致；eof、无尾 |
| dec_mainlib_stream.bin | 解密出的 raw-deflate 压缩流（重加密管线的输入，槽内无零垫） | 2337031 | encrypt(stream)==ct ✅ |
| dec_Factory.bin | Necrobit 字符串池（头 [int32 字节数 0x34][UTF-16 "{{ alg = {0}, typ = {1} }}"]…） | 398794 | 头结构 UTF-16 可解码 ✅；前缀 == work_a1/zdec/Factory_keyed.bin；roundtrip ✅ |
| dec_Proc.bin | **未解密**：资源原始字节 passthrough（k27 证明该资源明文存储明文消费） | 47915 | 头 2B `3a 9c`；熵 6.177 b/B（真密文 Viewer/Project ct 为 7.999/7.994） |
| dec_Emitter.bin | **未解密**：资源原始字节 passthrough（同上，从未被解密） | 256 | 熵 7.137 b/B（256B 高熵 blob，疑 RSA 材料） |

sha256 见 `manifest.json`（每个资源含 dec 与 ct 两个 sha256）。

## mainlib 的 roundtrip 说明（如实）

- **流级 roundtrip（判据）**：`encrypt(解密流) == 原密文` → **True**（解密正确性的权威校验）。
- **deflate 级重建**：把 dec_mainlib.bin 重新 deflate(level9, memLevel9, wbits=-15) 得 0x239112 B，
  **不能**逐字节复现原流（原流恰为 0x23A907 B、无零垫；zlib 生产者指纹不同）→ 由明文重建的密文 ≠ 原密文。
  这不是解密错误：work_a1/a2_build.py 的篡改管线本来就写**新流**（≤槽长、补零、XOR keystream），
  应用侧 inflate 即得篡改后明文（a1 产物已实证可运行）。

## Proc / Emitter 无 key 的证据（为何如实记 missing）

1. 任务书给定 procKeyHex / emitterKeyHex = 无；触发特工未提供输出对文件。
2. 本轮把遗留的 93 个 `work_a1/t26_*/OUT_*.bin` 运行期捕获全部重筛（out_triage_report.txt）：
   无一等于或前缀匹配任何资源密文/明文；OUT_Proc 头部皆为堆指针（GC 复用垃圾），
   与 t26 结论一致（22 个 Proc dump 非密文即垃圾，零明文）。
3. k27 轮 IL 层证据（work_a1/k26_progress.md §k27、work_a1/k27/evidence.json，本轮读取）：
   - Proc 读者 m_060042AF：`set_Position(2)`（跳 2B 头 `3a 9c`）→ `ReadBytes(全长)` → Close，**无任何解密调用**；
   - Emitter 读者 m_06004192（SHA1/RSA 校验器，已被证实条件死码）：256B blob **原样**进验签；
   - 共享 keyed 解密器 m_0600418B 全二进制 0 调用点（死码）；
   - 内联 keyed-PRNG 常量簇全 exe 仅 4 份（Project/Viewer/mainlib/死码 0600418B），Proc/Emitter 路径一份都没有；
   - Proc 熵 6.177 b/B（本轮复测），且跳头后为 (tag,值) 字节对流（本轮复测 u16 序列 2E01 0601 8B01 …与 k27 一致）。
4. v41brute.py（work_a1/v41brute.py）需要 ct/pt 对才能求逆（其 __main__ 即用 m_06002133 对）；
   无输出对时 8 dword key 为 2^256 空间，不可扫。且上列证据表明这两资源**根本没有 key**——
   任何写出的 key 都是编造（违反硬约束 6）。

## 对后续步骤的提示

- 篡改 Proc/Emitter 不存在“重加密”步骤：字节改动即数据改动（若校验器#2 检查它们，
  需保持表结构/校验和自洽，见 k27 note 10）。
- Proc 内容 = 060042B0 解析的结构化表（~23924 条目，2B 头后 (tag,值) 流）——校验器#2 头号嫌疑现场。
