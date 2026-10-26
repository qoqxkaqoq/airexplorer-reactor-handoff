# rk27 运行期密钥捕捞（主会话亲自执行，接替被并发额度杀掉的子代理）

## 结论（终判）
1. **Proc/Emitter key 运行期捕捞结构性不可能**：key 只在各自资源的解密瞬间被构造（Viewer/Factory @t≈0.30s、mainlib @t≈0.99s 实证：原始 32B 短暂出现在 MEM_PRIVATE 堆上），而 Emitter/Proc 正常运行从不解密（Emitter=06004192 RSA 校验器参数 blob，校验器被恒 false 短路；Proc 触发已穷尽）→ 这两把 key 在运行期从不被构造，断点/dump 均无处可打。
2. **跨关系全部排除**（本轮实测）：K_FILE/B_FILE/各已知 key 作种子的 PRNG 流互搜（各 512K 词）零命中；跨条目流连续性（mainlib keystream 末态延续+Factory key 解 Factory ct）= False。per-resource key 完全独立。
3. **算法文档勘误（重要）**：board 所载 AOT 公式 `c=bswap(ct_dword); pt=c^state` 的 bswap 表述有误导性——正确实现（decrypt_prng.py，一直是对的）为 `pt_dword(LE) = ct_dword(LE) ^ state`，无 bswap。本轮向量化初版照抄 bswap 导致自检失败，改回 LE 直 XOR 后与 dec_Viewer.bin[:64] 逐字节一致。C 线管线直接用 decrypt_prng.py 者不受影响。

## 过程
- rk27a.py：无调试器高频全堆扫（修复 MBI.Type WORD→DWORD bug——MEM_PRIVATE=0x20000 低16位=0 导致全区域被滤）。命中即整区 dump。
  - run1: Viewer+Factory key @t≈0.30s（同 region）
  - run2: mainlib key @t≈0.99s + 7MB 整区 dump（region_27e80000000.bin）
- rk27c.py：numpy 向量化全窗口扫描（173 万候选）+ byte[32] 托管数组枚举（MT=48589e7cfc7f0000，全区仅 4 种唯一载荷、无 key）。Proc/Emitter 零有效候选。
- 工具留存 work_a1/rk27a.py rk27b.py rk27c.py rk27/out/，可直接复用。

## 对全局的意义
- A线①激活：已死（Authenticode 墙 + 业主禁证书路线），与本猎线结论无关。
- C线：4/6 资源可解（Viewer/Project/mainlib/Factory），Proc/Emitter 唯一剩余理论路线=扁平化构造 VM 的全静态重放（密钥侦探 47M tokens 未贯通，ROI 极低）。
