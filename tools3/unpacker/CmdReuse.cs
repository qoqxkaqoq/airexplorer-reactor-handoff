using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>reuse &lt;slayed&gt; &lt;baseline&gt; — 统计 NRS rid 复用规模: dummy 方法/字段 与基线同 token 的身份差异。</summary>
public static class CmdReuse
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: reuse <slayed> <baseline>"); return 2; }
        var slayed = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var bmod = (ModuleDefMD)ModuleDefMD.Load(args[2]);

        int mReuse = 0, mSame = 0, mNoBase = 0;
        var reuseMethods = new List<(uint tok, string sName, string bOwner, string bName)>();
        foreach (var t in slayed.GetTypes())
        {
            if (!t.FullName.Contains("dummy")) continue;
            foreach (var m in t.Methods)
            {
                var tok = m.MDToken.Raw;
                if (bmod.ResolveToken(tok) is not MethodDef bm) { mNoBase++; continue; }
                string bOwner = bm.DeclaringType?.FullName ?? "?";
                if (bm.Name != m.Name || bOwner != t.FullName)
                {
                    mReuse++;
                    if (reuseMethods.Count < 12)
                        reuseMethods.Add((tok, m.Name, bOwner, bm.Name));
                }
                else mSame++;
            }
        }
        Console.WriteLine("[methods] rid-reused={0} identity-same={1} no-baseline={2}", mReuse, mSame, mNoBase);
        foreach (var x in reuseMethods)
            Console.WriteLine("  {0:X8}: slayed={1} baseline={2}::{3}", x.tok, x.sName, x.bOwner, x.bName);

        int fReuse = 0, fSame = 0;
        var reuseFields = new List<(uint tok, string sName, string bOwner, string bName, string bType)>();
        foreach (var t in slayed.GetTypes())
        {
            if (!t.FullName.Contains("dummy")) continue;
            foreach (var f in t.Fields)
            {
                var tok = f.MDToken.Raw;
                if (bmod.ResolveToken(tok) is not FieldDef bf) continue;
                string bOwner = bf.DeclaringType?.FullName ?? "?";
                if (bf.Name != f.Name || bOwner != t.FullName)
                {
                    fReuse++;
                    if (reuseFields.Count < 12)
                        reuseFields.Add((tok, f.Name, bOwner, bf.Name, bf.FieldSig?.Type?.FullName ?? "?"));
                }
                else fSame++;
            }
        }
        Console.WriteLine("[fields] rid-reused={0} identity-same={1}", fReuse, fSame);
        foreach (var x in reuseFields)
            Console.WriteLine("  {0:X8}: slayed={1} baseline={2}::{3} ({4})", x.tok, x.sName, x.bOwner, x.bName, x.bType);
        return 0;
    }
}
