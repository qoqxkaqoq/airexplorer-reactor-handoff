using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>scaneh &lt;slayed&gt; &lt;baseline&gt; &lt;zip&gt; &lt;manifest&gt; — 对比 EH catch 类型 token 在基线 vs Slayed 的解析, 找错位。</summary>
public static class CmdScanEh
{
    public static int Run(string[] args)
    {
        if (args.Length < 5) { Console.WriteLine("usage: scaneh <slayed> <baseline> <zip> <manifest>"); return 2; }
        var slayed = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var bmod = (ModuleDefMD)ModuleDefMD.Load(args[2]);
        var man = new HashSet<string>();
        foreach (var ln in File.ReadLines(args[4]).Skip(1))
        {
            var p = ln.Split('\t');
            if (p.Length >= 4) man.Add(p[1]);
        }

        using var zip = new System.IO.Compression.ZipArchive(File.OpenRead(args[3]));
        int mismatch = 0, match = 0, zeroCls = 0, checkedN = 0;
        foreach (var entry in zip.Entries)
        {
            if (!entry.FullName.EndsWith(".eh")) continue;
            var tok = entry.FullName[2..^3];
            if (!man.Contains(tok)) continue;
            using var es = entry.Open();
            var cor = new byte[entry.Length];
            new BinaryReader(es).Read(cor, 0, cor.Length);
            if (cor.Length < 4) continue;
            int cnt = BitConverter.ToInt32(cor, 0);
            for (int i = 0; i < cnt; i++)
            {
                int b = 4 + i * 28;
                uint f = BitConverter.ToUInt32(cor, b);
                uint cls = BitConverter.ToUInt32(cor, b + 20);
                if (cls == 0) { zeroCls++; continue; }
                // 只有 catch (f=0) 用 cls
                if ((f & 0xFF) != 0) { zeroCls++; continue; }
                checkedN++;
                string kb = "?", ks = "?";
                if (bmod.ResolveToken(cls) is ITypeDefOrRef tb) kb = tb.FullName;
                if (slayed.ResolveToken(cls) is ITypeDefOrRef ts) ks = ts.FullName;
                if (kb != ks)
                {
                    mismatch++;
                    if (mismatch <= 15)
                        Console.WriteLine("[eh-mismatch] {0:X8} clause{1} cls={2:X8}\n   baseline: {3}\n   slayed  : {4}",
                            Convert.ToUInt32(tok, 16), i, cls, kb, ks);
                }
                else match++;
            }
        }
        Console.WriteLine("[scaneh] catch-clauses={0} match={1} MISMATCH={2} no-type={3}", checkedN, match, mismatch, zeroCls);
        return 0;
    }
}
