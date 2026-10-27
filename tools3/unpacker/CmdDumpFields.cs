using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>dumpfields — 列出类型的全部字段 token，并对照一个 token 集合文件。</summary>
public static class CmdDumpFields
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: dumpfields <exe> <typeName> [tokset.txt]"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        HashSet<uint>? toks = null;
        if (args.Length > 3)
        {
            toks = new HashSet<uint>();
            foreach (var line in File.ReadLines(args[3]))
            {
                var t2 = line.Trim().Replace("0x", "");
                if (t2.Length > 0 && uint.TryParse(t2, System.Globalization.NumberStyles.HexNumber, null, out var v))
                    toks.Add(0x04000000 | v);   // 文件里可能只有 rid
            }
        }
        foreach (var t in mod.GetTypes())
        {
            if (!t.FullName.Contains(args[2])) continue;
            Console.WriteLine("TypeDef 0x{0:X8} {1} fields={2}:", (uint)t.MDToken.Raw, t.FullName, t.Fields.Count);
            int inSet = 0, outSet = 0;
            foreach (var f in t.Fields)
            {
                bool has = toks != null && toks.Contains((uint)f.MDToken.Raw);
                if (has) inSet++; else outSet++;
                Console.WriteLine("  [0x{0:X8}] {1} type={2} inSet={3}", (uint)f.MDToken.Raw, f.Name, f.FieldSig?.Type.FullName, has);
            }
            Console.WriteLine("  => inSet={0} missing={1}", inSet, outSet);
        }
        return 0;
    }
}
