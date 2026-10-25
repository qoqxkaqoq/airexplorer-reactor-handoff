# a9_pack — 第 12-18 轮战果工具与数据包（board XII-XVIII 配套）

## AOT 算法（已四 dword 现场逐字节验证）

    state = 0
    for i in range(len(ct)//4):                    # 全资源连续流，不按条目重置
        state = (state + key_dwords_le[i % 8]) & 0xFFFFFFFF
        state = prng_round(state)                   # work/decrypt_prng.py 的 prng_round
        c = ct[i*4+3]<<24 | ct[i*4+2]<<16 | ct[i*4+1]<<8 | ct[i*4]
        out_le_dword = c ^ state

流式 XOR：state 序列与明文/密文无关 → 单字节密文改动=单字节明文改动（重加密零成本）。

## data/

- `dec_Viewer.bin` — Viewer(0x56FE8) 全量解密产物；条目=[RVA][tag][fat0][tag][locals][body8][tag][nxtRVA]，9153 个 RVA 字段实证
- `snap00_arr220.bin` — **Viewer key（32B，guard7 运行时抓取）**：`f5999790 8a8bf27e 5dfba621 81d9f423 762aa085 05365daf e4274cfb dd503943`
- `arr_mainlib_1.bin` — mainlib 解密输出（raw-deflate；inflate==mainlib_plain 逐字节验证 4260864B）
- `arr_Factory_1.bin` — **FactoryValidator 解密输出=Necrobit 字符串池**（UTF-16：JWT 模板/控件名/PowerShell 命令）
- `arr_Emitter_0/1.bin` — Emitter 密文副本+输出（0e 填充态）；`arr_Proc_0.bin` — Proc 密文副本（count=0x2bbb 部分态）
- `dyn_consumer_0x7ffc1f310000.bin` — 驱动器当场快照（解密现场 0xb000 首区）
- `code_consumer_*.bin` — 解密循环命中代码 dump（+0x5b54/+0x6891 现场）
- `guard4_hits.json` — guard4 命中记录

## tools/

- `a5_keypoll.py` — 尾区 K/A 高频轮询（修正版 RVA：第二节 0x92BAA0；实测 K/A 恒=文件值）
- `a9_guard6.py` — 两段式 PAGE_GUARD（资源页→memcpy dst 堆页→消费者）＝解密器定位杀器
- `a9_guard7.py` — 解密循环命中时快照全部 rbp 槽数组（key/ct/out 抓取）
- `a9_guard10.py` — rbp 全槽大数组扫描（输出数组定位）
- `a9_guard12.py` — 多资源页持续 guard（key 按资源分类记录）
- `a9_guard16.py` — +窗口标题监控（调试模式不出窗实证）
- `a9_incept3/4.py` — **正常运行瞬态猎手**（0.10-0.34s 窗口；MEM_PRIVATE 过滤；托管数组头 [MT][count][pad][data]；输出对直取）

## 关键事实

- 创建即调试（Win32 调试 API）进程不出窗（反调试软挂起在 UI 前）→ guard 系列只够启动早期；incept（无调试）才能抓全启动瞬态
- 6 资源密文堆副本窗口 0.10-0.34s；mainlib/Factory 输出对直取绕过 key
- per-resource key：Viewer 已抓；其余惰性（正常运行启动期也不解 Emitter/Project/Proc 的 0x6891 循环）
- 遗留：完整体（phase-B 写桩）数据源未明（board XVIII §3）
