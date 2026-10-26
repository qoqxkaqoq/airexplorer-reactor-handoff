# 路线决策记录（参谋，2026-10-26）

## 判定：路线 C（差分 bisect）
- A 线前提不成立：三侦察一致证实校验器#2 未钉死（checker：方法体未定位到 MethodDef token；π/0x04242420 无静态指纹；FailFast 无元数据引用；06004192 为条件死代码）。
- B 线前提不成立：Proc/Emitter key 未攻出（keys/trigger：7 次运行未触发解密，key 从不在堆上；solver 管线就绪但无 ct/pt 对）。orchestrator 已先行声明走 bisect、不需 Proc key。
- C 线机制含 A 线优点：已知 key 块的改动=keystream XOR 回写，零成本重加密（本轮实测再次确认）。

## 本轮实测记录（全部只读；脚本与输出在 work_a1/）
| # | 检查 | 命令/脚本 | 结果 |
|---|---|---|---|
| 1 | 基线 md5/大小 | `md5sum` + python | a12b5c573e1b54e98cccc29351eaa066 / 9,668,976 B ✓ |
| 2 | 六块长度前缀 | c_route_verify.py §2 | 六前缀全部相符，块首尾相接 [0x6213C0,0x9264CC)，全部 <0x936000 ✓ |
| 3 | Project 解密 | decrypt_prng.py（参考实现） | == zdec/Project.bin 26,128B 逐字节 ✓ |
| 4 | rec1852 | 同上 | field=0x0400283E handler=0x4A00117C（ct bf772469@0x6879C7）✓ |
| 5 | B1 翻转实证 | c_route_verify.py §4 全量重解密 | **@0x6879C7 bf→be → handler 0x4A00117D（=add_MouseUp）＝checker 原案正确**；@0x6879CA 69→68 → 0x4B00117C（0x0B 无效表）＝否决；@0x6879C3 99→98 → field 0x0400283E→0x0400283F ✓ |
| 6 | MemberRef 名 | s26_namemap.pkl['mrf'] | 0x0A00117C=VerifyChecker、0x0A00117D=add_MouseUp、rec730=GetSigner、733=GenerateSignature、738=VerifySignature、747=DecryptKey、958=ComputeHash、2032=CreateFromSignedFile ✓（类型名盘上损坏与 checker 报告一致） |
| 7 | mainlib 管线 | c_route_verify2.py §a/§e | ct XOR mainlib_ks.bin → raw-deflate inflate == mainlib_plain.bin（4,260,864B，unused_data=0）；key 序 state+=key_dw[i%8]→prng_round 与 ks 文件一致 ✓ |
| 8 | a1 端到端 | c_route_verify2.py §b/§d + 脚本1 §6 | exes/（根目录）AirExplorer_baseline_verified_a1.exe md5 6418ec2f085deae6f16ffa49a1ab9568；diff 2,327,619B 共 9,370 段全部在 mainlib ct 内、外部 0 字节；inflate 后仅 0x194518(49→48)、0x197AE4(03→02) 两字节 ✓ |
| 9 | 激活字节定性 | c_route_verify2.py §c | 0x19435A 处 PNG 签名=True（补丁在 +0x1BE）；0x197A07 处 PNG 签名=False（容器未识别）——两点均为 mainlib 资源载荷字节，非激活语义，checker 主结论成立（细节修正一处） |
| 10 | ci 接口 | 读 probe_iso.ps1/soak_iso.ps1 | probe_iso: -ExePath -WaitSec 100 -OutDir；soak_iso: -ExePath -Minutes 7，exit 0/2/3/4 |
| 11 | 便携模板 | 读 AirExplorer_Portable.cmd | data 骨架=profile/{Desktop,Documents,Downloads}+AppData/{Roaming,Local,Local/Temp}；仅要求同目录有 AirExplorer.exe |

## 关键更正（相对侦察报告）
1. checker 的 B1 候选 `bf→be @0x6879C7` **经参考解密器实证为正确**（本人最初手推曾判其错，系 bswap 载入约定误用，已自纠并在 verify 脚本中以全量重解密实证）；工程上明文/密文同 index 字节 XOR（pt_file_byte[k]=ct_file_byte[k]^ks_file_byte[k]）。
2. a1 产物实际在**工作区根目录 exes/**，不在 handoff/exes/。
3. "两处激活字节均在 PNG"仅一点成立（0x197A07 处无 PNG 签名）；但两点均为资源载荷、非激活语义的结论不变。

产物：c_route_verify{,2,3}.py 与 _out.txt、本文件。未修改任何 exe。
