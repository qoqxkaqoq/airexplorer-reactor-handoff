using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>tsmap — 官方 vs 产物: TypeSpec/StandAloneSig/MethodSpec 全表逐 rid 身份对齐检查。</summary>
public static class CmdTsMap
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: tsmap <official.exe> <prod.exe>"); return 2; }
        var off = ModuleDefMD.Load(args[1]);
        var prod = ModuleDefMD.Load(args[2]);

        Check(off, prod, 0x1B, i => off.ResolveToken(0x1B000000 | i) as TypeSpec, ts => "TypeSpec " + ts?.TypeSig.FullName);
        Check(off, prod, 0x11, i => off.ResolveToken(0x11000000 | i) as StandAloneSig,
            sa => "StandAloneSig " + (sa?.Signature is LocalSig ls ? string.Join(",", ls.Locals.Select(v => v.FullName)) : "?"));
        Check(off, prod, 0x2B, i => off.ResolveToken(0x2B000000 | i) as MethodSpec, ms => "MethodSpec " + ms?.Method?.FullName);
        return 0;
    }

    static void Check<T>(ModuleDef off, ModuleDef prod, byte tbl, Func<int, T> get, Func<T, string> desc) where T : class
    {
        int diff = 0, checkedN = 0, offMiss = 0, prodMiss = 0;
        for (int rid = 1; rid <= 200000; rid++)
        {
            object o1 = null, o2 = null;
            try { o1 = off.ResolveToken((uint)(tbl << 24) | (uint)rid); } catch { }
            try { o2 = prod.ResolveToken((uint)(tbl << 24) | (uint)rid); } catch { }
            if (o1 == null && o2 == null) break;
            if (o1 == null) { offMiss++; continue; }
            if (o2 == null) { prodMiss++; continue; }
            checkedN++;
            string d1 = desc((T)o1), d2 = desc((T)o2);
            if (d1 != d2)
            {
                diff++;
                if (diff <= 15) Console.WriteLine($"  tbl 0x{tbl:X2} rid {rid}: OFF[{d1}]  PROD[{d2}]");
            }
        }
        Console.WriteLine($"[tsmap] table 0x{tbl:X2}: checked={checkedN} diff={diff} officialMiss={offMiss} prodMiss={prodMiss}");
    }
}
