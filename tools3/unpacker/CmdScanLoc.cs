using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>scanloc &lt;slayed&gt; &lt;baseline&gt; &lt;manifest&gt; &lt;mt&gt; — 对比注入方法的 localsTok 在基线 vs Slayed 的 StandAloneSig 解析结果。</summary>
public static class CmdScanLoc
{
    public static int Run(string[] args)
    {
        if (args.Length < 5) { Console.WriteLine("usage: scanloc <slayed> <baseline> <manifest> <mt>"); return 2; }
        var slayed = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var bmod = (ModuleDefMD)ModuleDefMD.Load(args[2]);
        var man = new Dictionary<string, (string rva, string name, string src)>();
        foreach (var ln in File.ReadLines(args[3]).Skip(1))
        {
            var p = ln.Split('\t');
            if (p.Length >= 4) man[p[1]] = (p[0], p[2], p[3]);
        }
        var mt = File.ReadAllBytes(args[4]);

        int mismatch = 0, match = 0, noLoc = 0, unres = 0;
        foreach (var kv in man)
        {
            var tok = kv.Key;
            var rva = Convert.ToUInt32(kv.Value.rva, 16);
            int off = (int)(rva - 0x2000);
            uint localsTok = 0;
            byte b0 = mt[off];
            if ((b0 & 3) == 3) localsTok = BitConverter.ToUInt32(mt, off + 8);
            if (localsTok == 0) { noLoc++; continue; }

            var bs = bmod.ResolveToken(localsTok) as StandAloneSig;
            var ss = slayed.ResolveToken(localsTok) as StandAloneSig;
            if (bs == null || ss == null) { unres++; if (unres <= 5) Console.WriteLine("[unres] {0} loc={1:X8} baseline={2} slayed={3}", tok, localsTok, bs != null, ss != null); continue; }

            string keyB = LocKey(bs);
            string keyS = LocKey(ss);
            if (keyB != keyS)
            {
                mismatch++;
                if (mismatch <= 12)
                    Console.WriteLine("[loc-mismatch] {0} loc={1:X8}\n   baseline: {2}\n   slayed  : {3}", tok, localsTok, keyB, keyS);
            }
            else match++;
        }
        Console.WriteLine("[scanloc] match={0} MISMATCH={1} noLoc={2} unres={3}", match, mismatch, noLoc, unres);
        return 0;
    }

    static string LocKey(StandAloneSig s)
    {
        if (s?.LocalSig == null) return "(null)";
        var parts = new List<string>();
        foreach (var t in s.LocalSig.Locals)
        {
            string tn;
            try { tn = t != null ? t.FullName : "null"; }
            catch { tn = "(err)"; }
            parts.Add(tn);
        }
        return "[" + string.Join(", ", parts) + "]";
    }
}
