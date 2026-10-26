using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>checkgp &lt;slayed&gt; &lt;baseline&gt; — 对比 dummy_ptr 方法恢复签名后的 GenericParam 行完整性。</summary>
public static class CmdCheckGP
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: checkgp <slayed-or-prod> <baseline>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var bmod = (ModuleDefMD)ModuleDefMD.Load(args[2]);
        var bGp = new Dictionary<string, int>(); // tok -> gp count
        foreach (var t in bmod.GetTypes())
            foreach (var m in t.Methods)
                bGp[m.MDToken.Raw.ToString("X8")] = (int)m.GenericParameters.Count;

        int mismatch = 0, checkedN = 0;
        foreach (var t in mod.GetTypes())
        {
            if (!t.FullName.Contains("dummy")) continue;
            foreach (var m in t.Methods)
            {
                var tok = m.MDToken.Raw.ToString("X8");
                if (!bGp.TryGetValue(tok, out var bCount)) continue;
                checkedN++;
                int now = (int)m.GenericParameters.Count;
                int sigGp = (int)(m.MethodSig?.GenParamCount ?? 0);
                if (now != bCount || sigGp != bCount)
                {
                    mismatch++;
                    if (mismatch <= 10)
                        Console.WriteLine("[gp-mismatch] {0} rows={1} sigGenParamCount={2} baseline={3}",
                            tok, now, sigGp, bCount);
                }
            }
        }
        Console.WriteLine("[checkgp] dummy methods with baseline GP: {0}, mismatches: {1}", checkedN, mismatch);
        return 0;
    }
}
