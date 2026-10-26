# PROGRESS — C线第一步（解密落盘）会话记录 2026-10-26

## 已完成
1. [读] 参考实现 airexplorer-reactor-handoff/work/decrypt_prng.py（prng_round/keystream/decrypt，
   Project 零 key 已验证版）；work_a1/v41brute.py（ct/pt 对求逆器，需输出对）；
   work_a1/a2_build.py（mainlib 重加密管线模板）；
   work_a1/c_route_verify.py + c_route_verify_out.txt（前轮 C 线复核，布局坐标来源）。
2. [读] 先验证据：work_a1/k26_progress.md（k26 全路线 + **k27 结论：Proc/Emitter 无 AOT key，
   资源明文存储明文消费**）；work_a1/k27/evidence.json；work_a1/t26_progress.md（运行期抓取失败史）；
   work_a1/t26mon.py（OUT_* 捕获文件语义：count 匹配数组/被跟踪缓冲变更，GC 复用噪声预期内）。
3. [跑] work/c2_pack/out_triage.py：93 个遗留 OUT_*.bin 全部分拣 → out_triage_report.txt。
   结论：无一为任何资源的密文副本或明文（OUT_Proc 头皆堆指针=GC 垃圾）→ 无 ct/pt 对可喂 v41brute。
4. [跑] work/c2_pack/c2_decrypt.py（本步主产物，基线只读）：
   - 布局：6 前缀全 OK、首尾相接、blob 终点 0x9264CC < 0x936000；
   - 自实现 == 参考实现（零 key 链 6532 dword；mainlib keystream == work_a1/mainlib_ks.bin 2337031B）；
   - Viewer：roundtrip ✅，== work_a1/dec_Viewer.bin（356328B 逐字节）；
   - Project：roundtrip ✅，== work_a1/zdec/Project.bin（26128B）；
   - Factory：roundtrip ✅，头 [int32 0x34 字节长][UTF-16 "{{ alg = {0}, typ = {1} }}"]，前缀 == zdec/Factory_keyed.bin；
     （首跑 utf16 检查用错单位“字符”，实为字节数，已修正后通过）；
   - mainlib：流级 roundtrip ✅；inflate(wbits=-15) eof、无尾，== work_a1/mainlib_plain.bin（4260864B）；
     re-deflate(level9,mem9)=0x239112B ≠ 原流 0x23A907B（生产者指纹不同，如实记录，不影响解密正确性）；
   - Proc/Emitter：无 key（证据见 README §Proc/Emitter），passthrough 落盘，manifest 如实记 missing。
5. [写] dec/ 7 个文件 + manifest.json + README.md + 本文件。

## 产物
- work/c2_pack/dec/{dec_Viewer,dec_Emitter,dec_Proc,dec_Project,dec_mainlib,dec_mainlib_stream,dec_Factory}.bin
- work/c2_pack/manifest.json（偏移/长度/key 或未解原因/roundtrip/sha256）
- work/c2_pack/README.md（含证据链与后续提示）
- work/c2_pack/c2_decrypt_log.txt / out_triage_report.txt

## 硬约束遵守
基线未写（只读 open）；未产出/未运行任何 exe；未触碰 ≥0x936000；中间结论即时落盘（本文件）。

## 未决（如实）
Proc/Emitter key 不存在（多源证据），无法也不应产出 key 文件；v41brute 因无输出对而不可用。
