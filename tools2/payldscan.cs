// payldscan — 负载表第一探：用 dump 明文 IL 对 baseline 的 3.2MB 加密负载做滑动 XOR 周期性检测。
//
// 目的：验证"负载密文 known-plaintext 重加密"路线的前置假设——
//   如果方法体在负载里是 XOR/重复 keystream 流密码（周期 1/2/4/8/16），
//   则在正确偏移 O 上 K = P_old ⊕ C_old 会呈现周期性 → 全量扫描能定位。
//   若全负 → 负载是块密码(AES族)或逐方法独立密钥，known-plaintext 死路，只剩 TTD 抓表指针。
//
// 用法: payldscan <exe> <dumpDir> [sampleN] [minIL]
//   <exe>     官方基线 (A12B5C57)
//   <dumpDir> m_*.bin 解密真体 dump 目录 (work/dump_official_16598.zip 解压)
// 输出: 每个样本在负载中的周期性命中 (offset, period)；全负则打印 VERDICT:NO-PATTERN。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

class PayldScan {
    static int Main(string[] args) {
        if (args.Length < 2) { Console.Error.WriteLine("usage: payldscan <exe> <dumpDir> [sampleN=24] [minIL=100]"); return 2; }
        var exe = File.ReadAllBytes(args[0]);
        string dumpDir = args[1];
        int sampleN = args.Length > 2 ? int.Parse(args[2]) : 24;
        int minIL = args.Length > 3 ? int.Parse(args[3]) : 100;

        // ---- 负载区: 文件偏移 0x620000..0x920000 (board 记载的熵区) ----
        int pStart = 0x620000, pEnd = Math.Min(0x920000, exe.Length);
        var P = new Span<byte>(exe, pStart, pEnd - pStart).ToArray();

        // 熵 sanity: 负载区 256 值分布是否接近均匀
        int[] hist = new int[256];
        foreach (var b in P) hist[b]++;
        double ent = 0; foreach (var c in hist) { if (c > 0) { double p = (double)c / P.Length; ent -= p * Math.Log(p, 2); } }
        Console.WriteLine($"payload region file[0x{pStart:X}..0x{pEnd:X}] len={P.Length} entropy={ent:F3} bits/byte");

        // ---- 选样本: IL 最长(最独特)的 N 个 ----
        var files = new DirectoryInfo(dumpDir).GetFiles("m_*.bin")
            .Where(f => f.Length > 24 + minIL)
            .OrderByDescending(f => f.Length)
            .Take(sampleN).ToList();
        Console.WriteLine($"samples = {files.Count} (of dir m_*.bin), ilLen from {files.Last().Length - 24} to {files.First().Length - 24}");

        int hits = 0;
        foreach (var f in files) {
            byte[] all = File.ReadAllBytes(f.FullName);
            uint tok = BitConverter.ToUInt32(all, 0);
            int ilSize = BitConverter.ToInt32(all, 4);
            var D = new Span<byte>(all, 24, ilSize).ToArray();
            int n = Math.Min(32, ilSize);
            var found = new List<(int off, int period)>();
            // 滑动全负载
            for (int O = 0; O + n <= P.Length; O++) {
                // 首字节快筛: K0 = P[O]^D[0]; 要求 P[O+1]^D[1] 等于 K0 或属于周期候选 → 先只查 period1
                int k0 = P[O] ^ D[0];
                if ((P[O + 1] ^ D[1]) != k0 && (P[O + 1] ^ D[1]) != 0) {
                    // 非常数也不为0, 继续查周期2/4/8/16: 用首 16 字节
                }
                bool allZero = true, per1 = true, per2 = true, per4 = true, per8 = true, per16 = true;
                for (int i = 0; i < n; i++) {
                    int x = P[O + i] ^ D[i];
                    if (x != 0) allZero = false;
                    if (x != k0) per1 = false;
                    if (x != (P[O + ((i >> 1) << 1)] ^ D[(i >> 1) << 1])) per2 = false;
                    if (x != (P[O + ((i >> 2) << 2)] ^ D[(i >> 2) << 2])) per4 = false;
                    if (x != (P[O + ((i >> 3) << 3)] ^ D[(i >> 3) << 3])) per8 = false;
                    if (x != (P[O + ((i >> 4) << 4)] ^ D[(i >> 4) << 4])) per16 = false;
                    if (!allZero && !per1 && !per2 && !per4 && !per8 && !per16) break;
                }
                int per = allZero ? 1 : per1 ? 1 : per2 ? 2 : per4 ? 4 : per8 ? 8 : per16 ? 16 : 0;
                if (per != 0) { found.Add((O, per)); hits++; if (found.Count > 4) break; }
            }
            if (found.Count > 0)
                foreach (var (O, pe) in found)
                    Console.WriteLine($"[HIT] {tok:X8} ilLen={ilSize} offset=0x{pStart + O:X} period={pe}");
            else
                Console.WriteLine($"[---] {tok:X8} ilLen={ilSize}: no periodic hit in payload");
        }
        Console.WriteLine(hits > 0 ? $"VERDICT:HIT total={hits} (XOR keystream 假设存活, 需人工核验命中)" : "VERDICT:NO-PATTERN (流密码/XOR假设证伪 → 负载为块密码或独立密钥, known-plaintext 死路)");
        return 0;
    }
}
