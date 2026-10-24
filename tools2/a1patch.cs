using System;
using System.Collections.Generic;
using System.IO;

// a1patch <officialDumpDir> <outPatchDir>
// 从官方真体 dump 复制 A1 激活补丁目标的 m_*.bin/.loc/.eh 三件套，并应用 IL 字节补丁。
// 之后用 bodyswap <outPatchDir> <official.exe> <out.exe> <tokensFile> 出包。
//
// 补丁集（全部门控字段写点强制"已激活"）：
//   P1 06002133 @IL 0x290  ldc.i4.0 -> ldc.i4.1   (_IsDecoratorProvider 降级点, OpenScheduledResponder)
//   P2 06002145 @IL 0x120  ldc.i4.0 -> ldc.i4.1   (_IsDecoratorProvider 降级点, ReceiveCentralInterpreter)
//   P3 0600212A  体替换 {17 2A}                   (SendFlexibleAttribute => true)
//   P4 06002157  体替换 {17 2A}                   (PlanRandomTag => true)
//   P5 06002127  体替换 {17 2A}                   (AccessibleClient::TestCollector => 1)
//   [已废弃] 060059C4 恒 true —— CI 实测定罪（run 40110092485, windows=0 CPU 100%）:
//     060059C4 有 3 个调用点, 除 0600217A 两个许可字段写入外, 06003A7F@0xC5
//     (IterableDicAggregator 配置 JSON 状态机) 把它的返回值喂 StopNode(bool),
//     恒 true 破坏 JSON 解析推进 => 启动死循环。许可直通只钉读取点(P3/P4/P5)即可。
//   注意: 手工 IL 里的 token 是小端, 0x0A000188 => {88 01 00 0A}, 别写成 {88 01 0A 0A}
class A1Patch {
    struct BP { public string tok; public int off; public byte[] from; public byte[] to; public string why; }
    static void Main(string[] a) {
        if (a.Length < 2) { Console.WriteLine("usage: a1patch <dumpDir> <outDir>"); return; }
        string src = a[0], dst = a[1];
        Directory.CreateDirectory(dst);

        // 体替换目标
        var fullRepl = new Dictionary<string, byte[]> {
            { "0600212A", new byte[] { 0x17, 0x2A } },                          // SendFlexibleAttribute => true
            { "06002157", new byte[] { 0x17, 0x2A } },                          // PlanRandomTag => true
            { "06002127", new byte[] { 0x17, 0x2A } },                          // AccessibleClient::TestCollector => 1
            // 060059C4 代理桥已废弃: 恒 true 会破坏 06003A7F 的 JSON 布尔读取(StopNode 调用点)
        };
        // 字节补丁目标
        var patches = new List<BP> {
            new BP { tok="06002133", off=0x290, from=new byte[]{0x16}, to=new byte[]{0x17}, why="P1 downgrade->true" },
            new BP { tok="06002145", off=0x120, from=new byte[]{0x16}, to=new byte[]{0x17}, why="P2 downgrade->true" },
        };

        var touched = new HashSet<string>(fullRepl.Keys);
        foreach (var p in patches) touched.Add(p.tok);

        int ok = 0;
        foreach (var tok in touched) {
            string sb = Path.Combine(src, "m_" + tok + ".bin");
            if (!File.Exists(sb)) { Console.WriteLine("[MISS] " + tok); continue; }
            var d = File.ReadAllBytes(sb);
            int ilSize = (int)BitConverter.ToUInt32(d, 4);
            if (fullRepl.TryGetValue(tok, out var nb)) {
                Console.WriteLine("[REPL] " + tok + " ilSize " + ilSize + " -> " + nb.Length);
                BitConverter.GetBytes(nb.Length).CopyTo(d, 4);
                var nd = new byte[24 + nb.Length];
                Array.Copy(d, nd, 20);                       // 头前 20 字节保留（tok/ilSize/maxStack/ehCount/preExtra）
                BitConverter.GetBytes(0).CopyTo(nd, 20);     // localsTok = 0（无局部变量）
                Array.Copy(nb, 0, nd, 24, nb.Length);
                d = nd;
                File.WriteAllBytes(Path.Combine(dst, "m_" + tok + ".bin"), d);
                File.WriteAllText(Path.Combine(dst, "m_" + tok + ".loc"), "");
                CopyEh(src, dst, tok);
                ok++;
                continue;
            }
            foreach (var p in patches) {
                if (p.tok != tok) continue;
                if (p.off + p.from.Length > ilSize) { Console.WriteLine("[OOR] " + tok + " +" + p.off.ToString("X") + " il=" + ilSize); continue; }
                for (int i = 0; i < p.from.Length; i++) {
                    if (d[24 + p.off + i] != p.from[i]) {
                        Console.WriteLine("[MISMATCH] " + tok + " +" + p.off.ToString("X") + " byte" + i +
                            " got " + d[24 + p.off + i].ToString("X2") + " want " + p.from[i].ToString("X2") + "  (" + p.why + ")");
                        goto next;
                    }
                }
                for (int i = 0; i < p.to.Length; i++) d[24 + p.off + i] = p.to[i];
                Console.WriteLine("[OK] " + tok + " +" + p.off.ToString("X") + " (" + p.why + ")");
            }
            File.WriteAllBytes(Path.Combine(dst, "m_" + tok + ".bin"), d);
            CopyLoc(src, dst, tok);
            CopyEh(src, dst, tok);
            ok++;
        next: ;
        }
        Console.WriteLine("[DONE] patched=" + ok);
        File.WriteAllLines(Path.Combine(dst, "tokens.txt"), touched);
    }
    static void CopyLoc(string src, string dst, string tok) {
        string p = Path.Combine(src, "m_" + tok + ".loc");
        if (File.Exists(p)) File.Copy(p, Path.Combine(dst, "m_" + tok + ".loc"), true);
        else File.WriteAllText(Path.Combine(dst, "m_" + tok + ".loc"), "");
    }
    static void CopyEh(string src, string dst, string tok) {
        string p = Path.Combine(src, "m_" + tok + ".eh");
        if (File.Exists(p)) File.Copy(p, Path.Combine(dst, "m_" + tok + ".eh"), true);
    }
}
