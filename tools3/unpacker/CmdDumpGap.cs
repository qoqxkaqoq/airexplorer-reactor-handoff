using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>dumpgap — 找官方有方法体但 manifest 没记录的方法（dump 漏覆盖）。</summary>
public static class CmdDumpGap
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: dumpgap <official.exe> <manifest.tsv> <out.txt>"); return 2; }
        var official = ModuleDefMD.Load(args[1]);
        var manifest = new HashSet<string>(File.ReadLines(args[2])
            .Select(l => l.Split('\t')[1].Trim().Replace("0x", "").ToUpperInvariant()));
        var missing = new List<string>();
        int total = 0, inManifest = 0;
        foreach (var t in official.GetTypes())
            foreach (var m in t.Methods)
            {
                if (m.RVA == 0 || m.IsAbstract || (m.ImplMap != null)) continue;
                total++;
                var tok = ((uint)m.MDToken.Raw).ToString("X8");
                if (manifest.Contains(tok)) { inManifest++; continue; }
                missing.Add(tok);
            }
        Console.WriteLine("[dumpgap] official body-able={0} in-manifest={1} MISSING={2}", total, inManifest, missing.Count);
        File.WriteAllLines(args[3], missing);
        Console.WriteLine("[dumpgap] -> " + args[3]);
        return 0;
    }
}
